"""Generate a clean, human-styled 2-Page Project Brief PDF for TrustGuard.

Usage:
    backend/.venv/Scripts/python.exe docs/generate_brief_pdf.py
    backend/.venv/Scripts/python.exe docs/generate_brief_pdf.py --video-url "https://youtu.be/YOUR_LINK"
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle

PAGE_W, PAGE_H = A4
MARGIN = 14 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#4b5563")
ACCENT = colors.HexColor("#1e3a8a")
BORDER = colors.HexColor("#d1d5db")
TINT = colors.HexColor("#f9fafb")
HEADER_BG = colors.HexColor("#f3f4f6")


def _draw_title_block(c: canvas.Canvas, title: str, subtitle: str, video_url: str, show_meta: bool) -> float:
    y = PAGE_H - MARGIN
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 15)
    c.drawString(MARGIN, y - 4.5 * mm, title)

    c.setFillColor(MUTED)
    c.setFont("Helvetica", 9)
    c.drawString(MARGIN, y - 9.5 * mm, subtitle)

    y_line = y - 12.5 * mm
    c.setStrokeColor(ACCENT)
    c.setLineWidth(1.4)
    c.line(MARGIN, y_line, MARGIN + CONTENT_W, y_line)

    if show_meta:
        meta_y = y_line - 12.5 * mm
        c.setFillColor(TINT)
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.7)
        c.rect(MARGIN, meta_y, CONTENT_W, 10.5 * mm, fill=1, stroke=1)

        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 8.2)
        c.drawString(MARGIN + 3 * mm, meta_y + 6.3 * mm, "Source Repository:")
        c.setFont("Courier", 8.0)
        c.drawString(MARGIN + 35 * mm, meta_y + 6.3 * mm, "https://github.com/Siddu-119/Trust-Guard")

        c.setFont("Helvetica-Bold", 8.2)
        c.drawRightString(MARGIN + CONTENT_W - 3 * mm, meta_y + 6.3 * mm, "Track 4: Trust, but verify")

        c.setFont("Helvetica-Bold", 8.2)
        c.drawString(MARGIN + 3 * mm, meta_y + 2.1 * mm, "5-Min Demo Video:")
        c.setFont("Courier", 8.0)
        c.setFillColor(ACCENT)
        c.drawString(MARGIN + 35 * mm, meta_y + 2.1 * mm, video_url)
        return meta_y - 4.5 * mm

    return y_line - 4.5 * mm


def _heading(c: canvas.Canvas, y_top: float, text: str) -> float:
    y = y_top - 4.5 * mm
    c.setFillColor(ACCENT)
    c.setFont("Helvetica-Bold", 10.2)
    c.drawString(MARGIN, y, text)
    c.setStrokeColor(BORDER)
    c.setLineWidth(0.7)
    c.line(MARGIN, y - 1.5 * mm, MARGIN + CONTENT_W, y - 1.5 * mm)
    return y - 4 * mm


def _para(c: canvas.Canvas, y_top: float, html: str, size: float = 8.7, leading: float = 12.0) -> float:
    style = ParagraphStyle("Body", fontName="Helvetica", fontSize=size, leading=leading, textColor=INK)
    p = Paragraph(html, style)
    _, ph = p.wrap(CONTENT_W, 80 * mm)
    p.drawOn(c, MARGIN, y_top - ph)
    return y_top - ph - 3 * mm


def _draw_arch_box(c: canvas.Canvas, y_top: float) -> float:
    box_h = 54 * mm
    y = y_top - box_h
    c.setFillColor(colors.white)
    c.setStrokeColor(BORDER)
    c.setLineWidth(0.8)
    c.rect(MARGIN, y, CONTENT_W, box_h, fill=1, stroke=1)

    # Left: Frontend
    fx, fy, fw, fh = MARGIN + 3.5 * mm, y + 14 * mm, 32 * mm, 26 * mm
    c.setFillColor(TINT)
    c.setStrokeColor(ACCENT)
    c.setLineWidth(1.0)
    c.rect(fx, fy, fw, fh, fill=1, stroke=1)
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 8.3)
    c.drawCentredString(fx + fw / 2, fy + 18.5 * mm, "React + TS UI")
    c.setFont("Helvetica", 7.3)
    c.setFillColor(MUTED)
    c.drawCentredString(fx + fw / 2, fy + 13.5 * mm, "9 Console Views")
    c.drawCentredString(fx + fw / 2, fy + 9.2 * mm, "Tailwind + Recharts")
    c.setFont("Courier", 6.5)
    c.drawCentredString(fx + fw / 2, fy + 3.8 * mm, "Bearer + X-Device-ID")

    # Arrow UI -> Backend
    c.setStrokeColor(INK)
    c.setLineWidth(1.0)
    c.line(fx + fw, y + 27 * mm, fx + fw + 6.5 * mm, y + 27 * mm)

    # Center: FastAPI Backend
    bx, by, bw, bh = fx + fw + 6.5 * mm, y + 3.5 * mm, 94 * mm, 47 * mm
    c.setFillColor(TINT)
    c.setStrokeColor(INK)
    c.setLineWidth(0.9)
    c.rect(bx, by, bw, bh, fill=1, stroke=1)
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 8.3)
    c.drawCentredString(bx + bw / 2, by + 42.5 * mm, "FastAPI Backend (Python 3.14)")

    mods = [
        ("Auth & Access Control", "scrypt, HMAC tokens, RBAC", 0, 0),
        ("Post-Quantum Crypto", "ML-KEM-768, ML-DSA-65, AES-GCM", 1, 0),
        ("Key Lifecycle & Backup", "PENDING -> COMMITTED, cutoff", 0, 1),
        ("Session Messaging", "Ephemeral RAM keys, replay guard", 1, 1),
        ("Threat Detection", "Rules, graph, +-300s clock window", 0, 2),
        ("Audit Log Chain", "Canonical JSON SHA-256 chain", 1, 2),
    ]
    mw, mh = 43.5 * mm, 11.2 * mm
    for title, sub, ci, ri in mods:
        mx = bx + 2.5 * mm + ci * (mw + 2 * mm)
        my = by + 28.8 * mm - ri * (mh + 1.8 * mm)
        c.setFillColor(colors.white)
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.7)
        c.rect(mx, my, mw, mh, fill=1, stroke=1)
        c.setFillColor(ACCENT)
        c.setFont("Helvetica-Bold", 7.3)
        c.drawCentredString(mx + mw / 2, my + 6.8 * mm, title)
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 6.5)
        c.drawCentredString(mx + mw / 2, my + 2.5 * mm, sub)

    # Right: Nodes & SQLite
    rx = bx + bw + 6.5 * mm
    rw = MARGIN + CONTENT_W - 3.5 * mm - rx
    c.setStrokeColor(INK)
    c.setLineWidth(1.0)
    c.line(bx + bw, y + 36.5 * mm, rx, y + 36.5 * mm)
    c.line(bx + bw, y + 14.5 * mm, rx, y + 14.5 * mm)

    c.setFillColor(TINT)
    c.setStrokeColor(ACCENT)
    c.rect(rx, y + 26 * mm, rw, 24.5 * mm, fill=1, stroke=1)
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 7.8)
    c.drawCentredString(rx + rw / 2, y + 46 * mm, "3 Service Nodes")
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 6.8)
    c.drawCentredString(rx + rw / 2, y + 40.5 * mm, "Node A: Identity Gateway")
    c.drawCentredString(rx + rw / 2, y + 35.8 * mm, "Node B: Messaging Broker")
    c.drawCentredString(rx + rw / 2, y + 31.1 * mm, "Node C: Vault & Archive")
    c.drawCentredString(rx + rw / 2, y + 27.2 * mm, "Persistent sync state")

    c.setFillColor(TINT)
    c.setStrokeColor(INK)
    c.rect(rx, y + 3.5 * mm, rw, 19.5 * mm, fill=1, stroke=1)
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 7.8)
    c.drawCentredString(rx + rw / 2, y + 18.2 * mm, "SQLite (WAL Mode)")
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 6.7)
    c.drawCentredString(rx + rw / 2, y + 13.0 * mm, "Encrypted keys, sessions,")
    c.drawCentredString(rx + rw / 2, y + 8.8 * mm, "hash-chained audit logs,")
    c.drawCentredString(rx + rw / 2, y + 4.8 * mm, "node revocation timings")

    return y - 4.5 * mm


def _draw_footer(c: canvas.Canvas, label: str) -> None:
    y = MARGIN - 4 * mm
    c.setStrokeColor(BORDER)
    c.setLineWidth(0.6)
    c.line(MARGIN, y + 3.5 * mm, MARGIN + CONTENT_W, y + 3.5 * mm)
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 7.5)
    c.drawString(MARGIN, y, "TrustGuard Project Brief")
    c.drawRightString(MARGIN + CONTENT_W, y, label)


def build_pdf(output_path: Path, video_url: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(output_path), pagesize=A4)
    c.setTitle("TrustGuard - Project Brief and Threat Model")

    # =========================================================================
    # PAGE 1: PROJECT OVERVIEW, USP & SYSTEM ARCHITECTURE
    # =========================================================================
    y = _draw_title_block(
        c,
        "TrustGuard: Post-Quantum Zero Trust Security Platform",
        "Protecting confidential messages, keys, and services across rotations, revocations, and crashes",
        video_url,
        show_meta=True,
    )

    y = _heading(c, y, "1. What Problem TrustGuard Solves (USP)")
    y = _para(
        c,
        y,
        "Many security demos only check happy-path logins. Real failures happen when state changes: a device is lost, "
        "a key rotation crashes halfway through, a valid account accesses an unexpected internal service, or logs arrive "
        "out of order across nodes with different clocks. TrustGuard focuses on keeping security guarantees intact during "
        "every one of these transitions.",
    )

    points = [
        "<b>Real Post-Quantum Cryptography:</b> Uses standardized NIST algorithms via <i>pqcrypto 1.0.0</i> (ML-KEM-768 for key exchange, ML-DSA-65 for signatures) and <i>cryptography 50.0.2</i> (HKDF-SHA256 + AES-256-GCM). No custom crypto or simulated checks.",
        "<b>Per-Step Ephemeral Forward Secrecy:</b> Each message and each step of a resumed session generates a one-time ML-KEM-768 keypair in RAM. Once delivered, the ephemeral secret key is overwritten with zeros and deleted.",
        "<b>Recoverable Key Rotation &amp; Cutoff:</b> Key rotations move from <i>PENDING</i> to <i>COMMITTED</i> in SQLite WAL. If the server crashes mid-rotation, startup recovery verifies and finishes or rolls back the pending key, while old keys past the grace window are rejected.",
        "<b>Cross-Node Revocation &amp; Session Binding:</b> Device and key revocations propagate across Service Nodes A, B, and C with measured latency (ms) and catch-up sync after outages. Resumable sessions lock to the original user, device, and peer.",
        "<b>Deterministic Detection (No AI/ML):</b> Uses 7 explainable rules and a directed service graph. Out-of-order events within +-300 seconds are re-sorted by timestamp and flagged if ordering is uncertain.",
    ]
    bstyle = ParagraphStyle("List1", fontName="Helvetica", fontSize=8.2, leading=11.0, textColor=INK)
    for pt in points:
        p = Paragraph(f"• {pt}", bstyle)
        _, ph = p.wrap(CONTENT_W, 25 * mm)
        p.drawOn(c, MARGIN, y - ph)
        y -= ph + 1.5 * mm
    y -= 2.5 * mm

    y = _heading(c, y, "2. System Architecture")
    y = _draw_arch_box(c, y)

    y = _heading(c, y, "3. Implementation Stack & Verified Results")
    th = ParagraphStyle("TH", fontName="Helvetica-Bold", fontSize=7.8, leading=10, textColor=INK)
    tc = ParagraphStyle("TC", fontName="Helvetica", fontSize=7.8, leading=10, textColor=INK)
    stack_rows = [
        [Paragraph("Component", th), Paragraph("Technology & Dependencies", th), Paragraph("Verified Result", th)],
        [
            Paragraph("Backend &amp; DB", tc),
            Paragraph("Python 3.14, FastAPI 0.165.0, Pydantic 2.14.4, SQLite (WAL), per-request DB connections", tc),
            Paragraph("Cold init ~518 ms; 32 concurrent calls 0 errors", tc),
        ],
        [
            Paragraph("Cryptography", tc),
            Paragraph("pqcrypto 1.0.0 (ML-KEM-768, ML-DSA-65), cryptography 50.0.2 (HKDF-SHA256, AES-256-GCM)", tc),
            Paragraph("Private keys wrapped at rest; never logged/returned", tc),
        ],
        [
            Paragraph("Threat Engine", tc),
            Paragraph("Pure Python rules + directed service graph + bisect window sorting (+-300s clock skew)", tc),
            Paragraph("1,058 logs: P=1.0, R=0.9565, F1=0.9778, 0.0 FP/1k", tc),
        ],
        [
            Paragraph("Frontend &amp; Tests", tc),
            Paragraph("React 18.3, TypeScript 5.7, Tailwind CSS 4.1, Recharts 2.15, pytest 9.2.0", tc),
            Paragraph("21 / 21 automated tests pass; offline (~5.7 MB RAM)", tc),
        ],
    ]
    stbl = Table(stack_rows, colWidths=[28 * mm, 92 * mm, 62 * mm])
    stbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("GRID", (0, 0), (-1, -1), 0.6, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3.2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.2),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    _, sth = stbl.wrap(CONTENT_W, 60 * mm)
    stbl.drawOn(c, MARGIN, y - sth)

    _draw_footer(c, "Page 1 of 2 - Project Brief & Architecture")
    c.showPage()

    # =========================================================================
    # PAGE 2: ONE-PAGE THREAT MODEL
    # =========================================================================
    y = _draw_title_block(
        c,
        "One-Page Threat Model: TrustGuard",
        "Protected assets, realistic attackers, implemented controls, assumptions, and known limits",
        video_url,
        show_meta=False,
    )

    y = _heading(c, y, "1. Protected Assets")
    assets = [
        "<b>Confidential Messages &amp; Session Secrets:</b> Plaintext payloads encrypted with ephemeral ML-KEM-768 shared secrets and AES-256-GCM; ephemeral RAM keys are zeroized right after delivery.",
        "<b>Identity &amp; Transport Keys:</b> ML-DSA-65 and ML-KEM-768 private keys wrapped at rest with AES-256-GCM under <i>TRUSTGUARD_MASTER_KEY</i>.",
        "<b>User Accounts, Devices &amp; Sessions:</b> scrypt password hashes, HMAC-SHA256 bearer tokens, active/revoked device status, and peer-bound resumable sessions.",
        "<b>Audit Trail &amp; Key Backups:</b> Hash-chained <i>audit_logs</i> starting at GENESIS, plus AES-256-GCM encrypted and ML-DSA-65 signed backups.",
    ]
    for a in assets:
        p = Paragraph(f"• {a}", bstyle)
        _, ph = p.wrap(CONTENT_W, 20 * mm)
        p.drawOn(c, MARGIN, y - ph)
        y -= ph + 1.2 * mm
    y -= 2.5 * mm

    y = _heading(c, y, "2. Threat Actors, Attack Scenarios & Mitigations")
    t_cel = ParagraphStyle("TC2", fontName="Helvetica", fontSize=7.5, leading=9.8, textColor=INK)
    t_rows = [
        [Paragraph("Attacker / Scenario", th), Paragraph("How They Attack", th), Paragraph("Control Implemented in TrustGuard", th), Paragraph("Test", th)],
        [
            Paragraph("<b>Passive Eavesdropper / Quantum Threat</b>", t_cel),
            Paragraph("Captures ciphertexts today to decrypt later, or steals identity keys later.", t_cel),
            Paragraph("ML-KEM-768 + AES-256-GCM; fresh ephemeral KEM keypair per step is zeroized in RAM after delivery so old traffic stays unreadable.", t_cel),
            Paragraph("test_18", t_cel),
        ],
        [
            Paragraph("<b>Lost or Stolen Device</b>", t_cel),
            Paragraph("Uses an existing token or tries logging in from a revoked laptop.", t_cel),
            Paragraph("Revocation updates Nodes A/B/C with measured ms latency; requests from revoked devices get 403 and raise a CRITICAL alert.", t_cel),
            Paragraph("test_05<br/>test_06", t_cel),
        ],
        [
            Paragraph("<b>Malicious Insider / Lateral Movement</b>", t_cel),
            Paragraph("Valid user tries admin actions or unexpected node path (node-c to node-a).", t_cel),
            Paragraph("Server-side RBAC + resource overrides block privilege escalation; service graph flags disallowed edges even when credentials are valid.", t_cel),
            Paragraph("test_02<br/>test_12<br/>test_13", t_cel),
        ],
        [
            Paragraph("<b>Network Tampering, Replay &amp; Hijack</b>", t_cel),
            Paragraph("Replays message ID, swaps recipient, flips bytes, or reuses someone's session_id.", t_cel),
            Paragraph("Unique message_id blocks replays (409); AAD + ML-DSA-65 bind recipient; resumable sessions reject other identities/devices (403).", t_cel),
            Paragraph("test_15-17<br/>test_20", t_cel),
        ],
        [
            Paragraph("<b>Crash, Bad Backup, or Stale Key</b>", t_cel),
            Paragraph("Server stops during key rotation; corrupted backup or old key is submitted.", t_cel),
            Paragraph("PENDING-&gt;COMMITTED recovers on boot; backups require AES-GCM + SHA-256 + non-revoked ML-DSA sig; cutoff rejects old keys.", t_cel),
            Paragraph("test_04<br/>test_07-09", t_cel),
        ],
        [
            Paragraph("<b>Log Tampering &amp; Clock Drift</b>", t_cel),
            Paragraph("Edits SQLite audit rows, injects newlines/JSON, or sends out-of-order logs.", t_cel),
            Paragraph("Canonical JSON SHA-256 chain detects edits; server auth sets actor; engine sorts windows across +-300s skew and flags uncertainty.", t_cel),
            Paragraph("test_10<br/>test_11<br/>test_14", t_cel),
        ],
    ]
    ttbl = Table(t_rows, colWidths=[35 * mm, 42 * mm, 88 * mm, 17 * mm])
    ttbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, TINT]),
                ("GRID", (0, 0), (-1, -1), 0.6, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    _, tth = ttbl.wrap(CONTENT_W, 130 * mm)
    ttbl.drawOn(c, MARGIN, y - tth)
    y -= tth + 5 * mm

    y = _heading(c, y, "3. Assumptions and Honest Limitations")
    gap = 4 * mm
    cw = (CONTENT_W - gap) / 2
    bh = 56 * mm
    for idx, (ctitle, cbody) in enumerate(
        [
            (
                "Security Assumptions",
                "<b>1. Environment Secrets:</b> <i>TRUSTGUARD_MASTER_KEY</i> and <i>TRUSTGUARD_TOKEN_SECRET</i> are kept in local env vars and never committed.<br/>"
                "<b>2. Short RAM Window:</b> Server RAM is not dumped during the millisecond between ephemeral key creation and zeroization.<br/>"
                "<b>3. Clock Skew Bound:</b> Node clocks stay within <b>+-300 seconds</b>; larger offsets trigger <i>RULE_CLOCK_SKEW_ANOMALY</i>.<br/>"
                "<b>4. Server Enforcement:</b> Every permission, cutoff, and device check runs on the FastAPI backend.",
            ),
            (
                "Known Limitations (Prototype Scope)",
                "<b>1. Single Process &amp; Mock Nodes:</b> Ephemeral RAM keys live in one Python process; Nodes A, B, and C are simulated in SQLite rather than separate servers.<br/>"
                "<b>2. Inbox Reload Storage:</b> After ephemeral transport decryption, <i>inbox_sealed_b64</i> is sealed with <i>TRUSTGUARD_MASTER_KEY</i> so recipients can reload their inbox.<br/>"
                "<b>3. Slow-Probe Boundary:</b> 120s/180s sliding windows keep false alerts at 0.0/1k, so probes hours apart are missed (2 test cases in dataset).<br/>"
                "<b>4. Software Key Wrap:</b> Uses software HKDF/AES-GCM instead of a hardware HSM or TPM.",
            ),
        ]
    ):
        cx = MARGIN + idx * (cw + gap)
        cy = y - bh
        c.setFillColor(TINT)
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.7)
        c.rect(cx, cy, cw, bh, fill=1, stroke=1)
        c.setFillColor(ACCENT)
        c.setFont("Helvetica-Bold", 8.5)
        c.drawString(cx + 3 * mm, y - 4.5 * mm, ctitle)
        p = Paragraph(cbody, ParagraphStyle("Lim", fontName="Helvetica", fontSize=7.6, leading=10.1, textColor=INK))
        _, ph = p.wrap(cw - 6 * mm, bh - 7 * mm)
        p.drawOn(c, cx + 3 * mm, y - 6.5 * mm - ph)

    y -= bh + 4.5 * mm
    bot_p = Paragraph(
        f"<b>5-Min Demo Video:</b> <code>{video_url}</code> &nbsp;|&nbsp; "
        "<b>Automated Suite:</b> <code>pytest backend/tests/test_trustguard.py -v</code> (21/21 Pass)",
        ParagraphStyle("BotNote", fontName="Helvetica", fontSize=7.4, leading=10, textColor=MUTED),
    )
    _, bph = bot_p.wrap(CONTENT_W, 14 * mm)
    bot_p.drawOn(c, MARGIN, y - bph)

    _draw_footer(c, "Page 2 of 2 - One-Page Threat Model")
    c.save()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate TrustGuard 2-Page Project Brief PDF")
    parser.add_argument(
        "--video-url",
        default="[Add your 5-minute unlisted YouTube / Google Drive link here]",
        help="Public/unlisted 5-minute demo walkthrough video URL",
    )
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent / "TrustGuard_Project_Brief.pdf"),
        help="Output PDF path",
    )
    args = parser.parse_args()
    out_path = Path(args.out)
    build_pdf(out_path, args.video_url)
    reader = PdfReader(str(out_path))
    print(f"Generated {out_path} ({len(reader.pages)} pages, {out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
