"""Deterministic rule-based and graph-based Threat Detection Engine.

Strictly deterministic — contains zero AI, LLMs, or machine learning models.
Supports out-of-order event arrival and distributed clock offsets within a
documented timing range (+/- 300 seconds), flagging uncertain event ordering.
"""

from __future__ import annotations

import bisect
import json
import sqlite3
import statistics
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import utc_now_iso

# Documented Clock-Skew & Out-of-Order Timing Envelope
SUPPORTED_CLOCK_SKEW_SECONDS = 300.0  # +/- 5 minutes supported clock offset tolerance
OUT_OF_ORDER_GRACE_SECONDS = 300.0    # Events arriving up to 5 minutes behind watermark are re-sorted
UNCERTAIN_ORDER_THRESHOLD_SECONDS = 1.0  # Reordering > 1s or non-zero skew flags uncertain ordering

# Allowed Zero-Trust directed service-to-service topology edges
ALLOWED_SERVICE_EDGES: dict[str, set[str]] = {
    "client": {"node-a", "control-plane"},
    "control-plane": {"control-plane", "node-a", "node-b", "node-c", "key-vault"},
    "node-a": {"node-a", "node-b", "node-c", "key-vault"},
    "node-b": {"node-b", "node-c"},
    "node-c": {"node-c"},
    "key-vault": set(),
    "system": {"control-plane", "node-a", "node-b", "node-c", "key-vault"},
}

ADMIN_ONLY_ACTIONS = {"rotate", "revoke", "admin", "backup", "restore", "tamper-test", "manage-nodes"}
WRITE_ACTIONS = {"write", "create", "delete", "send"} | ADMIN_ONLY_ACTIONS


@dataclass
class SecurityEventInput:
    user_identity: str
    role: str
    device_id: str | None
    device_status: str  # ACTIVE | REVOKED | UNKNOWN
    source_service: str
    destination_service: str
    resource: str
    action: str
    decision: str  # ALLOW | DENY
    event_time: str
    key_status: str = "ACTIVE"
    reason_code: str = ""
    event_id: str = field(default_factory=lambda: f"sec-{uuid.uuid4().hex[:10]}")
    clock_offset_seconds: float = 0.0


def _parse_ts(ts_str: str) -> float:
    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _best_span_window(
    entries: list[tuple[float, str, str]], target_ts: float, window_seconds: float
) -> list[tuple[float, str, str]]:
    """Find the richest contiguous subset containing target_ts whose timestamps span <= window_seconds."""
    candidates = [e for e in entries if abs(e[0] - target_ts) <= window_seconds]
    if not candidates:
        return []
    best: list[tuple[float, str, str]] = []
    right = 0
    for left in range(len(candidates)):
        while right < len(candidates) and (candidates[right][0] - candidates[left][0]) <= window_seconds:
            right += 1
        window_slice = candidates[left:right]
        if any(e[0] == target_ts for e in window_slice) and len(window_slice) >= len(best):
            best = window_slice
    return best


class DeterministicThreatEngine:
    """Stateful deterministic rule + directed-graph analyzer with clock-skew & reordering support."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Sorted lists of (normalized_ts, event_id, value)
        self._user_services: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
        self._user_denials: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
        self._user_key_ops: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
        self._user_watermark: dict[str, float] = {}

    def _prune(self, items: list[tuple[float, str, str]], watermark: float, max_age: float) -> None:
        cutoff = watermark - max_age
        while items and items[0][0] < cutoff:
            items.pop(0)

    def evaluate_event(self, event: SecurityEventInput) -> list[dict[str, Any]]:
        """Evaluate one security event with clock normalization and out-of-order window sorting."""
        with self._lock:
            return self._evaluate_event_locked(event)

    def _evaluate_event_locked(self, event: SecurityEventInput) -> list[dict[str, Any]]:
        start_ns = time.perf_counter_ns()
        raw_ts = _parse_ts(event.event_time)
        offset = float(event.clock_offset_seconds)
        # Normalize reported timestamp into reference UTC using node clock offset
        ts = raw_ts - offset

        prev_watermark = self._user_watermark.get(event.user_identity)
        ordering_status = "IN_ORDER"
        ordering_uncertain = False
        skew_exceeded = abs(offset) > SUPPORTED_CLOCK_SKEW_SECONDS

        if prev_watermark is not None and ts < prev_watermark:
            lag = prev_watermark - ts
            if lag > OUT_OF_ORDER_GRACE_SECONDS:
                ordering_status = "CLOCK_SKEW_EXCEEDED"
                ordering_uncertain = True
            elif lag >= UNCERTAIN_ORDER_THRESHOLD_SECONDS or abs(offset) >= UNCERTAIN_ORDER_THRESHOLD_SECONDS:
                ordering_status = "OUT_OF_ORDER_UNCERTAIN"
                ordering_uncertain = True
            else:
                ordering_status = "OUT_OF_ORDER_RECOVERED"
        elif skew_exceeded:
            ordering_status = "CLOCK_SKEW_EXCEEDED"
            ordering_uncertain = True
        elif abs(offset) >= UNCERTAIN_ORDER_THRESHOLD_SECONDS:
            ordering_status = "CLOCK_OFFSET_ADJUSTED"
            ordering_uncertain = True

        watermark = ts if prev_watermark is None else max(prev_watermark, ts)
        self._user_watermark[event.user_identity] = watermark

        alerts: list[dict[str, Any]] = []

        def add_alert(
            severity: str,
            rule: str,
            reason: str,
            related: list[str] | None = None,
        ) -> None:
            elapsed_ms = max(0.001, (time.perf_counter_ns() - start_ns) / 1_000_000.0)
            rel_list = related or [event.event_id]
            alerts.append(
                {
                    "alert_id": f"alt-{uuid.uuid4().hex[:14]}",
                    "user_identity": event.user_identity,
                    "source_service": event.source_service,
                    "destination_service": event.destination_service,
                    "event_time": event.event_time,
                    "severity": severity,
                    "reason": reason,
                    "rule_triggered": rule,
                    "detection_latency_ms": round(elapsed_ms, 4),
                    "ordering_status": ordering_status,
                    "ordering_uncertain": ordering_uncertain,
                    "related_events": rel_list,
                }
            )

        if skew_exceeded or ordering_status == "CLOCK_SKEW_EXCEEDED":
            add_alert(
                "MEDIUM",
                "RULE_CLOCK_SKEW_ANOMALY",
                f"Event timestamp/offset outside supported +/-{int(SUPPORTED_CLOCK_SKEW_SECONDS)}s range "
                f"(offset={offset}s); event ordering is uncertain.",
            )

        # Rule 1: Access from a revoked device
        if event.device_status == "REVOKED" or event.reason_code == "REVOKED_DEVICE":
            add_alert(
                "CRITICAL",
                "RULE_REVOKED_DEVICE_ACCESS",
                f"Access attempted from revoked device '{event.device_id or 'unknown'}' "
                f"targeting {event.destination_service}/{event.resource}.",
            )

        # Rule 2: Unusual service-to-service access path (directed graph topology check)
        allowed_targets = ALLOWED_SERVICE_EDGES.get(event.source_service, set())
        if event.destination_service not in allowed_targets:
            add_alert(
                "HIGH",
                "RULE_UNUSUAL_SERVICE_PATH",
                f"Disallowed service-graph edge '{event.source_service} -> {event.destination_service}' "
                f"bypasses Zero-Trust gateway or performs lateral traversal.",
            )

        # Rule 3: Unexpected privilege escalation
        is_priv_esc = False
        if event.role == "Viewer" and event.action in WRITE_ACTIONS:
            is_priv_esc = True
        elif event.role == "Employee" and (
            event.action in ADMIN_ONLY_ACTIONS or event.resource in {"users", "keys", "backups"}
        ):
            is_priv_esc = True
        elif event.reason_code == "PRIVILEGE_ESCALATION":
            is_priv_esc = True

        if is_priv_esc:
            add_alert(
                "HIGH",
                "RULE_PRIVILEGE_ESCALATION",
                f"Role '{event.role}' attempted privileged action '{event.action}' on '{event.resource}'.",
            )

        # Rule 4: Suspicious key operations
        if event.key_status in {"EXPIRED_CUTOFF", "REVOKED"} or event.reason_code in {
            "EXPIRED_KEY_USAGE",
            "REVOKED_KEY_USAGE",
            "UNAUTHORIZED_KEY_OP",
        }:
            add_alert(
                "CRITICAL",
                "RULE_SUSPICIOUS_KEY_OP",
                f"Key policy violation ({event.key_status or event.reason_code}) on resource '{event.resource}'.",
            )
        elif event.resource == "keys" and event.action in {"rotate", "revoke"}:
            kq = self._user_key_ops[event.user_identity]
            bisect.insort(kq, (ts, event.event_id, event.action))
            self._prune(kq, watermark, 60.0 + OUT_OF_ORDER_GRACE_SECONDS)
            win = _best_span_window(kq, ts, 60.0)
            if len(win) >= 3:
                add_alert(
                    "HIGH",
                    "RULE_SUSPICIOUS_KEY_OP",
                    f"Rapid consecutive key operations ({len(win)} within 60s) by '{event.user_identity}'.",
                    related=[e[1] for e in win],
                )

        # Rule 5: Session hijack attempt
        if event.reason_code == "SESSION_TAKEOVER":
            add_alert(
                "CRITICAL",
                "RULE_SESSION_HIJACK_ATTEMPT",
                f"Unauthorized identity '{event.user_identity}' attempted to resume or hijack another peer's session.",
            )

        # Rule 6: Unusual access to multiple services (graph fan-out in 120s window, excluding control-plane UI calls)
        if event.destination_service != "control-plane":
            sq = self._user_services[event.user_identity]
            bisect.insort(sq, (ts, event.event_id, event.destination_service))
            self._prune(sq, watermark, 120.0 + OUT_OF_ORDER_GRACE_SECONDS)
            win = _best_span_window(sq, ts, 120.0)
            distinct_services = {svc for _, _, svc in win}
            fanout_threshold = 3 if event.role != "Admin" else 4
            if len(distinct_services) >= fanout_threshold:
                add_alert(
                    "MEDIUM" if event.role == "Admin" else "HIGH",
                    "RULE_MULTI_SERVICE_FANOUT",
                    f"User '{event.user_identity}' ({event.role}) touched {len(distinct_services)} distinct "
                    f"services ({', '.join(sorted(distinct_services))}) within 120s.",
                    related=[e[1] for e in win],
                )

        # Rule 7: Repeated denied requests (>= 3 denials in 180s, sorted by event time)
        if event.decision == "DENY":
            dq = self._user_denials[event.user_identity]
            bisect.insort(dq, (ts, event.event_id, event.resource))
            self._prune(dq, watermark, 180.0 + OUT_OF_ORDER_GRACE_SECONDS)
            win = _best_span_window(dq, ts, 180.0)
            if len(win) >= 3:
                add_alert(
                    "HIGH",
                    "RULE_REPEATED_DENIALS",
                    f"{len(win)} denied access attempts for '{event.user_identity}' within 180s.",
                    related=[e[1] for e in win],
                )

        return alerts


# Shared live engine instance for platform runtime
live_threat_engine = DeterministicThreatEngine()


def get_timing_policy() -> dict[str, Any]:
    return {
        "supported_clock_skew_seconds": SUPPORTED_CLOCK_SKEW_SECONDS,
        "out_of_order_grace_seconds": OUT_OF_ORDER_GRACE_SECONDS,
        "uncertain_order_threshold_seconds": UNCERTAIN_ORDER_THRESHOLD_SECONDS,
        "policy_summary": (
            f"Events arriving with clock offsets or out-of-order lag up to +/-{int(SUPPORTED_CLOCK_SKEW_SECONDS)}s "
            f"are normalized and sorted into sliding windows; lag > {int(UNCERTAIN_ORDER_THRESHOLD_SECONDS)}s "
            f"is flagged as OUT_OF_ORDER_UNCERTAIN, and lag/offset > {int(SUPPORTED_CLOCK_SKEW_SECONDS)}s raises CLOCK_SKEW_EXCEEDED."
        ),
    }


def process_and_store_event(
    conn: sqlite3.Connection, event: SecurityEventInput
) -> list[dict[str, Any]]:
    """Evaluate a live security event and persist any generated alerts to SQLite."""
    alerts = live_threat_engine.evaluate_event(event)
    for alert in alerts:
        conn.execute(
            """
            INSERT INTO threat_alerts (
                alert_id, user_identity, source_service, destination_service,
                event_time, severity, reason, rule_triggered, detection_latency_ms,
                ordering_status, related_events
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["alert_id"],
                alert["user_identity"],
                alert["source_service"],
                alert["destination_service"],
                alert["event_time"],
                alert["severity"],
                alert["reason"],
                alert["rule_triggered"],
                alert["detection_latency_ms"],
                alert["ordering_status"],
                json.dumps(alert["related_events"]),
            ),
        )
    if alerts:
        conn.commit()
    return alerts


def list_threat_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT alert_id, user_identity, source_service, destination_service,
               event_time, severity, reason, rule_triggered, detection_latency_ms,
               ordering_status, related_events, acknowledged
        FROM threat_alerts
        ORDER BY event_time DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        try:
            item["related_events"] = json.loads(item["related_events"] or "[]")
        except Exception:
            item["related_events"] = []
        out.append(item)
    return out


def build_service_graph_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Build observed directed service-graph edge counts from access_decisions."""
    rows = conn.execute(
        """
        SELECT source_service, destination_service, decision, COUNT(*) AS count
        FROM access_decisions
        GROUP BY source_service, destination_service, decision
        """
    ).fetchall()
    edges = []
    for row in rows:
        src = row["source_service"]
        dst = row["destination_service"]
        allowed_in_policy = dst in ALLOWED_SERVICE_EDGES.get(src, set())
        edges.append(
            {
                "source": src,
                "destination": dst,
                "decision": row["decision"],
                "count": row["count"],
                "policy_allowed": allowed_in_policy,
            }
        )
    return {
        "allowed_topology": {k: sorted(v) for k, v in ALLOWED_SERVICE_EDGES.items()},
        "observed_edges": edges,
        "timing_policy": get_timing_policy(),
    }


def load_synthetic_dataset_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "synthetic_security_logs.json"


def evaluate_synthetic_dataset(dataset_path: Path | None = None) -> dict[str, Any]:
    """Run the deterministic engine over the labelled synthetic log dataset and compute real metrics."""
    path = dataset_path or load_synthetic_dataset_path()
    records = json.loads(path.read_text(encoding="utf-8"))

    engine = DeterministicThreatEngine()
    tp = fp = tn = fn = 0
    malicious_latencies_ms: list[float] = []
    rule_hits: dict[str, int] = defaultdict(int)
    category_breakdown: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "detected": 0}
    )

    for rec in records:
        evt = SecurityEventInput(
            user_identity=rec["user_identity"],
            role=rec["role"],
            device_id=rec.get("device_id"),
            device_status=rec.get("device_status", "ACTIVE"),
            source_service=rec["source_service"],
            destination_service=rec["destination_service"],
            resource=rec["resource"],
            action=rec["action"],
            decision=rec["decision"],
            event_time=rec["event_time"],
            key_status=rec.get("key_status", "ACTIVE"),
            reason_code=rec.get("reason_code", ""),
            event_id=rec.get("event_id", f"syn-{uuid.uuid4().hex[:8]}"),
            clock_offset_seconds=float(rec.get("clock_offset_seconds", 0.0)),
        )
        alerts = engine.evaluate_event(evt)
        predicted_malicious = len(alerts) > 0
        actual_malicious = bool(rec["is_malicious"])
        category = rec.get("attack_category", "benign")

        for a in alerts:
            rule_hits[a["rule_triggered"]] += 1

        if actual_malicious:
            category_breakdown[category]["total"] += 1
            if predicted_malicious:
                tp += 1
                category_breakdown[category]["detected"] += 1
                malicious_latencies_ms.append(alerts[0]["detection_latency_ms"])
            else:
                fn += 1
        else:
            if predicted_malicious:
                fp += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    benign_total = tn + fp
    false_alerts_per_1000 = (fp / benign_total) * 1000.0 if benign_total > 0 else 0.0
    median_alert_ms = (
        statistics.median(malicious_latencies_ms) if malicious_latencies_ms else 0.0
    )

    return {
        "dataset_path": str(path),
        "total_events": len(records),
        "benign_events": benign_total,
        "malicious_events": tp + fn,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "median_alert_time_ms": round(median_alert_ms, 4),
        "false_alerts_per_1000_benign": round(false_alerts_per_1000, 4),
        "rule_hits": dict(rule_hits),
        "category_breakdown": dict(category_breakdown),
        "evaluated_at": utc_now_iso(),
    }
