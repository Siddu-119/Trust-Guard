"""Deterministic rule-based and graph-based Threat Detection Engine.

Strictly deterministic — contains zero AI, LLMs, or machine learning models.
Evaluates live platform security events and labelled synthetic datasets using
a directed zero-trust service topology graph and stateful sliding-window rules.
"""

from __future__ import annotations

import json
import sqlite3
import statistics
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import utc_now_iso

# Allowed Zero-Trust directed service-to-service topology edges
ALLOWED_SERVICE_EDGES: dict[str, set[str]] = {
    "client": {"node-a"},
    "node-a": {"node-a", "node-b", "node-c", "key-vault"},
    "node-b": {"node-b", "node-c"},
    "node-c": {"node-c"},
    "key-vault": set(),
    "system": {"node-a", "node-b", "node-c", "key-vault"},
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


def _parse_ts(ts_str: str) -> float:
    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


class DeterministicThreatEngine:
    """Stateful deterministic rule + directed-graph analyzer."""

    def __init__(self) -> None:
        # Per-user sliding windows of (epoch_seconds, destination_service)
        self._user_services: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        # Per-user sliding windows of DENY timestamps
        self._user_denials: dict[str, deque[float]] = defaultdict(deque)
        # Per-user sliding windows of key rotation timestamps
        self._user_key_ops: dict[str, deque[float]] = defaultdict(deque)

    def evaluate_event(self, event: SecurityEventInput) -> list[dict[str, Any]]:
        """Evaluate one security event and return any triggered alerts."""
        start_ns = time.perf_counter_ns()
        ts = _parse_ts(event.event_time)
        alerts: list[dict[str, Any]] = []

        def add_alert(severity: str, rule: str, reason: str) -> None:
            elapsed_ms = max(0.001, (time.perf_counter_ns() - start_ns) / 1_000_000.0)
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
                }
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
            kq.append(ts)
            while kq and (ts - kq[0]) > 60.0:
                kq.popleft()
            if len(kq) >= 3:
                add_alert(
                    "HIGH",
                    "RULE_SUSPICIOUS_KEY_OP",
                    f"Rapid consecutive key operations ({len(kq)} within 60s) by '{event.user_identity}'.",
                )

        # Rule 5: Unusual access to multiple services (graph fan-out in 120s window)
        sq = self._user_services[event.user_identity]
        sq.append((ts, event.destination_service))
        while sq and (ts - sq[0][0]) > 120.0:
            sq.popleft()
        distinct_services = {svc for _, svc in sq}
        fanout_threshold = 3 if event.role != "Admin" else 4
        if len(distinct_services) >= fanout_threshold:
            add_alert(
                "MEDIUM" if event.role == "Admin" else "HIGH",
                "RULE_MULTI_SERVICE_FANOUT",
                f"User '{event.user_identity}' ({event.role}) touched {len(distinct_services)} distinct "
                f"services ({', '.join(sorted(distinct_services))}) within 120s.",
            )

        # Rule 6: Repeated denied requests (>= 3 denials in 180s)
        if event.decision == "DENY":
            dq = self._user_denials[event.user_identity]
            dq.append(ts)
            while dq and (ts - dq[0]) > 180.0:
                dq.popleft()
            if len(dq) >= 3:
                add_alert(
                    "HIGH",
                    "RULE_REPEATED_DENIALS",
                    f"{len(dq)} denied access attempts for '{event.user_identity}' within 180s.",
                )

        return alerts


# Shared live engine instance for platform runtime
live_threat_engine = DeterministicThreatEngine()


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
                event_time, severity, reason, rule_triggered, detection_latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
    if alerts:
        conn.commit()
    return alerts


def list_threat_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT alert_id, user_identity, source_service, destination_service,
               event_time, severity, reason, rule_triggered, detection_latency_ms, acknowledged
        FROM threat_alerts
        ORDER BY event_time DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


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
