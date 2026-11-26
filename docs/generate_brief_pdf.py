"""Generate the 2-Page TrustGuard Project Brief PDF (USP, Architecture & Threat Model).

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
MARGIN = 12 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

NAVY = colors.HexColor("#0f172a")
SLATE_700 = colors.HexColor("#334155")
SLATE_600 = colors.HexColor("#475569")
SLATE_200 = colors.HexColor("#cbd5e1")
SLATE_100 = colors.HexColor("#f1f5f9")
SLATE_50 = colors.HexColor("#f8fafc")
CYAN_600 = colors.HexColor("#0891b2")
CYAN_400 = colors.HexColor("#22d3ee")
CYAN_200 = colors.HexColor("#a5f3fc")
CYAN_50 = colors.HexColor("#ecfeff")
EMERALD = colors.HexColor("#047857")
INDIGO = colors.HexColor("#4338ca")
AMBER = colors.HexColor("#b45309")
ROSE = colors.HexColor("#be185d")


def _draw_header(c: canvas.Canvas, title: str, subtitle: str, right_top: str, right_bot: str) -> float:
    box_h = 18 * mm
    y = PAGE_H - MARGIN - box_h
    c.setFillColor(NAVY)
    c.roundRect(MARGIN, y, CONTENT_W, box_h, 5, fill=1, stroke=0)
    c.setFillColor(CYAN_400)
    c.rect(MARGIN, y, 2.2 * mm, box_h, fill=1, stroke=0)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 13.5)
    c.drawString(MARGIN + 5.5 * mm, y + 10.5 * mm, title)
    c.setFillColor(CYAN_200)
    c.setFont("Helvetica", 8.2)
    c.drawString(MARGIN + 5.5 * mm, y + 4.5 * mm, subtitle)

    c.setFillColor(colors.HexColor("#cbd5e1"))
    c.setFont("Courier", 7.6)
    c.drawRightString(MARGIN + CONTENT_W - 4 * mm, y + 10.8 * mm, right_top)
    c.drawRightString(MARGIN + CONTENT_W - 4 * mm, y + 4.8 * mm, right_bot)
    return y - 4 * mm


def _draw_video_banner(c: canvas.Canvas, y_top: float, video_url: str, label: str) -> float:
    box_h = 9.5 * mm
    y = y_top - box_h
    c.setFillColor(CYAN_50)
    c.setStrokeColor(CYAN_600)
    c.setLineWidth(1)
    c.setDash(3, 2)
    c.roundRect(MARGIN, y, CONTENT_W, box_h, 4, fill=1, stroke=1)
    c.setDash()

    c.setFillColor(CYAN_600)
    c.setFont("Helvetica-Bold", 8.2)
    c.drawString(MARGIN + 3 * mm, y + 3.4 * mm, label)

    c.setFillColor(NAVY)
    c.setFont("Courier-Bold", 8.0)
    c.drawRightString(MARGIN + CONTENT_W - 3 * mm, y + 3.4 * mm, video_url)
    return y - 4 * mm


def _draw_section_heading(c: canvas.Canvas, y_top: float, text: str) -> float:
    y = y_top - 4.2 * mm
    c.setFillColor(NAVY)
    c.setFont("Helvetica-Bold", 9.6)
    c.drawString(MARGIN, y, text)
    c.setStrokeColor(SLATE_200)
    c.setLineWidth(1.2)
    c.line(MARGIN, y - 1.5 * mm, MARGIN + CONTENT_W, y - 1.5 * mm)
    return y - 3.5 * mm


def _draw_card(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    w: float,
    h: float,
    title: str,
    body_html: str,
    accent: colors.Color = CYAN_600,
) -> None:
    y = y_top - h
    c.setFillColor(SLATE_50)
    c.setStrokeColor(SLATE_200)
    c.setLineWidth(0.8)
    c.roundRect(x, y, w, h, 4, fill=1, stroke=1)

    c.setFillColor(accent)
    c.setFont("Helvetica-Bold", 8.5)
    c.drawString(x + 3 * mm, y_top - 4.5 * mm, title)

    style = ParagraphStyle(
        "CardBody",
        fontName="Helvetica",
        fontSize=7.7,
        leading=10.0,
        textColor=SLATE_700,
    )
    p = Paragraph(body_html, style)
    pw, ph = p.wrap(w - 6 * mm, h - 7 * mm)
    p.drawOn(c, x + 3 * mm, y_top - 6.2 * mm - ph)


def _draw_architecture_diagram(c: canvas.Canvas, y_top: float) -> float:
    box_h = 56 * mm
    y = y_top - box_h
    c.setFillColor(colors.white)
    c.setStrokeColor(SLATE_200)
    c.setLineWidth(0.9)
    c.roundRect(MARGIN, y, CONTENT_W, box_h, 5, fill=1, stroke=1)

    # Left: React UI
    ui_x, ui_y, ui_w, ui_h = MARGIN + 3 * mm, y + 15 * mm, 33 * mm, 26 * mm
    c.setFillColor(NAVY)
    c.setStrokeColor(CYAN_400)
    c.setLineWidth(1.2)
    c.roundRect(ui_x, ui_y, ui_w, ui_h, 4, fill=1, stroke=1)
    c.setFillColor(CYAN_200)
    c.setFont("Helvetica-Bold", 8.5)
    c.drawCentredString(ui_x + ui_w / 2, ui_y + 18.5 * mm, "React + TS UI")
    c.setFillColor(colors.white)
    c.setFont("Helvetica", 7.3)
    c.drawCentredString(ui_x + ui_w / 2, ui_y + 13.5 * mm, "9 Security Tabs")
    c.drawCentredString(ui_x + ui_w / 2, ui_y + 9.2 * mm, "Recharts & Tailwind")
    c.setFillColor(colors.HexColor("#94a3b8"))
    c.setFont("Courier", 6.4)
    c.drawCentredString(ui_x + ui_w / 2, ui_y + 3.5 * mm, "Bearer + X-Device-ID")

    # Arrow UI -> Control Plane
    c.setStrokeColor(CYAN_600)
    c.setLineWidth(1.4)
    c.line(ui_x + ui_w, y + 28 * mm, ui_x + ui_w + 6 * mm, y + 28 * mm)

    # Center: FastAPI Control Plane
    cp_x, cp_y, cp_w, cp_h = ui_x + ui_w + 6 * mm, y + 3 * mm, 96 * mm, 50 * mm
    c.setFillColor(SLATE_50)
    c.setStrokeColor(SLATE_700)
    c.setLineWidth(1.1)
    c.roundRect(cp_x, cp_y, cp_w, cp_h, 4, fill=1, stroke=1)
    c.setFillColor(NAVY)
    c.setFont("Helvetica-Bold", 8.3)
    c.drawCentredString(cp_x + cp_w / 2, cp_y + 45.2 * mm, "FastAPI Zero-Trust Control Plane (Python)")

    modules = [
        ("Zero-Trust Auth & RBAC", "scrypt • HMAC • Device Check", CYAN_600, 0, 0),
        ("Post-Quantum Crypto", "ML-KEM-768 • ML-DSA-65 • AES", EMERALD, 1, 0),
        ("Key Lifecycle & Backup", "PENDING->COMMITTED • Cutoff", INDIGO, 0, 1),
        ("Forward-Secret Messaging", "Ephemeral RAM • Resumption", CYAN_600, 1, 1),
        ("Threat Detection Engine", "7 Rules • Graph • +-300s Skew", AMBER, 0, 2),
        ("Tamper-Evident Audit", "Canonical JSON SHA-256 Chain", ROSE, 1, 2),
    ]
    mw, mh = 44.5 * mm, 12.2 * mm
    for mtitle, msub, mcol, col_i, row_i in modules:
        mx = cp_x + 2.5 * mm + col_i * (mw + 2 * mm)
        my = cp_y + 30.8 * mm - row_i * (mh + 2 * mm)
        c.setFillColor(colors.white)
        c.setStrokeColor(mcol)
        c.setLineWidth(0.9)
        c.roundRect(mx, my, mw, mh, 3, fill=1, stroke=1)
        c.setFillColor(mcol)
        c.setFont("Helvetica-Bold", 7.3)
        c.drawCentredString(mx + mw / 2, my + 7.2 * mm, mtitle)
        c.setFillColor(SLATE_600)
        c.setFont("Helvetica", 6.5)
        c.drawCentredString(mx + mw / 2, my + 2.8 * mm, msub)

    # Arrows Control Plane -> Nodes & SQLite
    right_x = cp_x + cp_w + 6 * mm
    right_w = MARGIN + CONTENT_W - 3 * mm - right_x
    c.setStrokeColor(SLATE_700)
    c.setLineWidth(1.2)
    c.line(cp_x + cp_w, y + 38 * mm, right_x, y + 38 * mm)
    c.line(cp_x + cp_w, y + 14 * mm, right_x, y + 14 * mm)

    # Service Nodes
    c.setFillColor(NAVY)
    c.setStrokeColor(EMERALD)
    c.roundRect(right_x, y + 27 * mm, right_w, 25 * mm, 4, fill=1, stroke=1)
    c.setFillColor(colors.HexColor("#6ee7b7"))
    c.setFont("Helvetica-Bold", 7.8)
    c.drawCentredString(right_x + right_w / 2, y + 47.2 * mm, "3 Service Nodes")
    c.setFillColor(colors.white)
    c.setFont("Helvetica", 6.8)
    c.drawCentredString(right_x + right_w / 2, y + 41.5 * mm, "Node A: Gateway")
    c.drawCentredString(right_x + right_w / 2, y + 36.8 * mm, "Node B: Messaging")
    c.drawCentredString(right_x + right_w / 2, y + 32.1 * mm, "Node C: Vault")
    c.setFillColor(colors.HexColor("#94a3b8"))
    c.setFont("Helvetica", 6.3)
    c.drawCentredString(right_x + right_w / 2, y + 28.2 * mm, "Sync & Catch-Up")

    # SQLite DB
    c.setFillColor(SLATE_100)
    c.setStrokeColor(SLATE_700)
    c.roundRect(right_x, y + 4 * mm, right_w, 20 * mm, 4, fill=1, stroke=1)
    c.setFillColor(NAVY)
    c.setFont("Helvetica-Bold", 7.8)
    c.drawCentredString(right_x + right_w / 2, y + 19.2 * mm, "SQLite WAL DB")
    c.setFillColor(SLATE_600)
    c.setFont("Helvetica", 6.7)
    c.drawCentredString(right_x + right_w / 2, y + 14.0 * mm, "Wrapped Keys • Sessions")
    c.drawCentredString(right_x + right_w / 2, y + 9.5 * mm, "Audit Chain • Alerts")
    c.drawCentredString(right_x + right_w / 2, y + 5.2 * mm, "No Plaintext Logs")

    return y - 4 * mm


def _draw_footer(c: canvas.Canvas, page_label: str) -> None:
    y = MARGIN - 3 * mm
    c.setStrokeColor(SLATE_200)
    c.setLineWidth(0.7)
    c.line(MARGIN, y + 3.5 * mm, MARGIN + CONTENT_W, y + 3.5 * mm)
    c.setFillColor(SLATE_600)
    c.setFont("Helvetica", 7.3)
    c.drawString(MARGIN, y, "TrustGuard — Post-Quantum Zero Trust Security Platform")
    c.drawRightString(MARGIN + CONTENT_W, y, page_label)


def build_pdf(output_path: Path, video_url: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(output_path), pagesize=A4)
    c.setTitle("TrustGuard — 2-Page Project Brief & Threat Model")
    c.setAuthor("TrustGuard Team")

    # =========================================================================
    # PAGE 1: USP & SYSTEM ARCHITECTURE
    # =========================================================================
    y = _draw_header(
        c,
        "TrustGuard — Post-Quantum Zero Trust Platform",
        "Protecting confidential messages, keys & services across rotations, revocations & crashes",
        'Track 4: "Trust, but verify"',
        "github.com/Siddu-119/Trust-Guard",
    )
    y = _draw_video_banner(c, y, video_url, "5-Minute Demo Walkthrough Video (Fallback):")

    y = _draw_section_heading(c, y, "1. Unique Selling Proposition (USP)")
    intro_style = ParagraphStyle("Intro", fontName="Helvetica", fontSize=8.3, leading=11.0, textColor=SLATE_700)
    intro = Paragraph(
        "Most security prototypes protect static happy-path requests—yet breaches happen during <b>state transitions</b>: "
        "lost laptops, interrupted key rotations, lateral movement with valid credentials, or skewed timestamps. "
        "<b>TrustGuard</b> enforces verifiable post-quantum Zero Trust across every transition:",
        intro_style,
    )
    _, ih = intro.wrap(CONTENT_W, 20 * mm)
    intro.drawOn(c, MARGIN, y - ih)
    y = y - ih - 3 * mm

    gap = 4 * mm
    cw = (CONTENT_W - gap) / 2
    ch = 26 * mm
    _draw_card(
        c, MARGIN, y, cw, ch,
        "Post-Quantum + Ephemeral Forward Secrecy",
        "Uses standardized <b>ML-KEM-768</b> (FIPS 203) &amp; <b>ML-DSA-65</b> (FIPS 204) via <i>pqcrypto</i>, paired with "
        "<b>HKDF-SHA256 + AES-256-GCM</b>. Every message and resumed session step creates a fresh RAM-only ephemeral keypair, zeroized immediately upon delivery.",
        CYAN_600,
    )
    _draw_card(
        c, MARGIN + cw + gap, y, cw, ch,
        "Crash-Safe Rotation & Multi-Node Revocation",
        "Two-phase <b>PENDING -&gt; COMMITTED</b> rotation recovers automatically on boot, rejects keys past cutoff, and propagates "
        "device &amp; key revocations across 3 persistent service nodes with measured ms latency and offline catch-up.",
        EMERALD,
    )
    y -= ch + 3 * mm
    _draw_card(
        c, MARGIN, y, cw, ch,
        "Explainable Detection Under Clock Skew (No AI/ML)",
        "Deterministic rules + directed service-topology graph catch privilege escalation and lateral paths (even with valid credentials), "
        "re-sorting out-of-order events across <b>+-300s</b> clock offsets with uncertainty flags.",
        AMBER,
    )
    _draw_card(
        c, MARGIN + cw + gap, y, cw, ch,
        "Tamper-Evident Audit & Signed Backups",
        "Canonical JSON SHA-256 hash chain from <b>GENESIS</b> blocks log injection and secret leaks, while AES-256-GCM + ML-DSA-65 signed backups "
        "reject 1-byte corruption or revoked signers and never resurrect revoked keys.",
        INDIGO,
    )
    y -= ch + 4 * mm

    y = _draw_section_heading(c, y, "2. System Architecture")
    y = _draw_architecture_diagram(c, y)

    y = _draw_section_heading(c, y, "3. Verified Implementation Metrics & Dependencies")
    kw = (CONTENT_W - 3 * 3 * mm) / 4
    kh = 16.5 * mm
    kpis = [
        ("20 / 20", "Security Tests Passing"),
        ("0.9778", "Threat F1 (P=1.0, R=0.9565)"),
        ("0.0 / 1k", "False Alerts (1,058 Logs)"),
        ("0.0064 ms", "Median Detection Latency"),
    ]
    for idx, (val, lbl) in enumerate(kpis):
        kx = MARGIN + idx * (kw + 3 * mm)
        c.setFillColor(SLATE_50)
        c.setStrokeColor(SLATE_200)
        c.roundRect(kx, y - kh, kw, kh, 4, fill=1, stroke=1)
        c.setFillColor(NAVY)
        c.setFont("Courier-Bold", 11)
        c.drawCentredString(kx + kw / 2, y - 7.5 * mm, val)
        c.setFillColor(SLATE_600)
        c.setFont("Helvetica", 7.1)
        c.drawCentredString(kx + kw / 2, y - 13 * mm, lbl)
    y -= kh + 3 * mm

    deps = Paragraph(
        "<b>Pinned Dependencies:</b> Backend: <i>fastapi==0.165.0, pqcrypto==1.0.0, cryptography==50.0.2, pydantic==2.14.4, "
        "uvicorn==0.54.0, pytest==9.2.0</i>. Frontend: <i>react@18.3.1, typescript@5.7.3, tailwindcss@4.1.3, recharts@2.15.1</i>. "
        "Verified fully offline with ~5.74 MB peak Python traced memory.",
        ParagraphStyle("Deps", fontName="Helvetica", fontSize=7.7, leading=10.2, textColor=SLATE_600),
    )
    _, dh = deps.wrap(CONTENT_W, 18 * mm)
    deps.drawOn(c, MARGIN, y - dh)

    _draw_footer(c, "Page 1 of 2 — USP & System Architecture")
    c.showPage()

    # =========================================================================
    # PAGE 2: ONE-PAGE THREAT MODEL
    # =========================================================================
    y = _draw_header(
        c,
        "One-Page Threat Model — TrustGuard",
        "Protected Assets, Threat Actors, Verified Mitigations, Security Assumptions & Limits",
        "NIST FIPS 203 & FIPS 204",
        "github.com/Siddu-119/Trust-Guard",
    )

    y = _draw_section_heading(c, y, "1. Protected Assets")
    assets = [
        "<b>Confidential Messages &amp; Ephemeral Keys:</b> Payloads encrypted via ephemeral ML-KEM-768 + HKDF-SHA256 + AES-256-GCM; RAM session keys destroyed on delivery.",
        "<b>Identity &amp; Transport Keys:</b> ML-DSA-65 signing keys &amp; ML-KEM-768 keys wrapped at rest under <i>TRUSTGUARD_MASTER_KEY</i>; never exposed in APIs/logs.",
        "<b>Identities, Devices &amp; Sessions:</b> scrypt credentials, HMAC-SHA256 tokens, device trust states, and peer-bound resumable <i>messaging_sessions</i>.",
        "<b>Audit Trail &amp; Key Backups:</b> Canonical JSON SHA-256 hash chain from GENESIS and AES-256-GCM + ML-DSA-65 signed key backups.",
    ]
    bstyle = ParagraphStyle("Bullet", fontName="Helvetica", fontSize=7.9, leading=10.3, textColor=SLATE_700)
    for item in assets:
        p = Paragraph(f"• {item}", bstyle)
        _, ph = p.wrap(CONTENT_W, 15 * mm)
        p.drawOn(c, MARGIN, y - ph)
        y -= ph + 1.2 * mm
    y -= 2 * mm

    y = _draw_section_heading(c, y, "2. Threat Actors, Attack Vectors & Verified Mitigations")
    t_hdr = ParagraphStyle("TH", fontName="Helvetica-Bold", fontSize=7.6, leading=9.5, textColor=colors.white)
    t_cel = ParagraphStyle("TC", fontName="Helvetica", fontSize=7.4, leading=9.5, textColor=SLATE_700)
    rows = [
        [Paragraph("Threat / Attacker", t_hdr), Paragraph("Attack Vector", t_hdr), Paragraph("TrustGuard Mitigation", t_hdr), Paragraph("Test", t_hdr)],
        [
            Paragraph("<b>Quantum / HNDL Eavesdropper</b>", t_cel),
            Paragraph("Harvests ciphertexts now to decrypt later, or later compromises identity keys.", t_cel),
            Paragraph("NIST ML-KEM-768 &amp; ML-DSA-65; fresh ephemeral KEM keys per message/step zeroized from RAM immediately after delivery.", t_cel),
            Paragraph("test_18", t_cel),
        ],
        [
            Paragraph("<b>Lost / Stolen Device</b>", t_cel),
            Paragraph("Attacker reuses valid session token from a lost endpoint.", t_cel),
            Paragraph("Device revocation propagates to Nodes A/B/C with measured ms latency; revoked device gets 403 + CRITICAL alert.", t_cel),
            Paragraph("test_05<br/>test_06", t_cel),
        ],
        [
            Paragraph("<b>Insider / Lateral Mover</b>", t_cel),
            Paragraph("Valid credentials attempt privilege escalation or bypass gateway (node-c -&gt; node-a).", t_cel),
            Paragraph("Server-side RBAC + resource overrides block escalation; directed service graph flags disallowed edges even on ALLOW.", t_cel),
            Paragraph("test_02<br/>test_12<br/>test_13", t_cel),
        ],
        [
            Paragraph("<b>Replay / Tamper / Hijacker</b>", t_cel),
            Paragraph("Replays message ID, alters recipient, flips ciphertext, or hijacks session_id.", t_cel),
            Paragraph("Unique message_id rejects replay (409); AAD + ML-DSA-65 bind recipient; resumable sessions enforce (initiator, device, peer) binding.", t_cel),
            Paragraph("test_15-17<br/>test_20", t_cel),
        ],
        [
            Paragraph("<b>Crash / Bad Backup / Old Key</b>", t_cel),
            Paragraph("Crash mid-rotation, corrupted backup restore, or use of retired key past cutoff.", t_cel),
            Paragraph("PENDING-&gt;COMMITTED recovers on boot; backups verify AES-GCM + SHA-256 + non-revoked ML-DSA sig; cutoff blocks stale keys.", t_cel),
            Paragraph("test_04<br/>test_07-09", t_cel),
        ],
        [
            Paragraph("<b>Log Tamper / Skew Evasion</b>", t_cel),
            Paragraph("Alters SQLite logs, injects fake newline/JSON events, or sends skewed logs.", t_cel),
            Paragraph("SHA-256 hash chain detects edits; server auth sets actor; engine sorts sliding windows across +-300s skew &amp; flags uncertainty.", t_cel),
            Paragraph("test_10<br/>test_11<br/>test_14", t_cel),
        ],
    ]
    tbl = Table(rows, colWidths=[35 * mm, 44 * mm, 88 * mm, 19 * mm])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SLATE_50]),
                ("GRID", (0, 0), (-1, -1), 0.6, SLATE_200),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    _, th = tbl.wrap(CONTENT_W, 130 * mm)
    tbl.drawOn(c, MARGIN, y - th)
    y -= th + 5 * mm

    # Assumptions & Limitations side by side
    y = _draw_section_heading(c, y, "3. Security Assumptions & 4. Known Scope Limitations")
    box_h = 56 * mm
    _draw_card(
        c, MARGIN, y, cw, box_h,
        "Security Assumptions",
        "<b>1. Secret Hygiene:</b> <i>TRUSTGUARD_MASTER_KEY</i> &amp; <i>TRUSTGUARD_TOKEN_SECRET</i> are provided via env vars and never leaked.<br/>"
        "<b>2. Volatile RAM Integrity:</b> Server memory is not dumped during the brief millisecond window before ephemeral key zeroization.<br/>"
        "<b>3. Clock Range:</b> Node clocks stay within <b>+-300s</b>; larger offsets trigger <i>RULE_CLOCK_SKEW_ANOMALY</i>.<br/>"
        "<b>4. Server Enforcement:</b> All RBAC, cutoff, and device checks execute server-side in FastAPI.",
        CYAN_600,
    )
    _draw_card(
        c, MARGIN + cw + gap, y, cw, box_h,
        "Known Scope & Limitations",
        "<b>1. Single-Process Prototype:</b> Ephemeral RAM keys live in one Python process; Nodes A/B/C are simulated in SQLite rather than separate containers.<br/>"
        "<b>2. Inbox Persistence Trade-off:</b> After ephemeral decryption, <i>inbox_sealed_b64</i> is stored under <i>TRUSTGUARD_MASTER_KEY</i> for UI reload viewing.<br/>"
        "<b>3. Slow-Recon Window:</b> Sliding windows (120s/180s) prioritize 0 false alerts; probes spaced hours apart are outside the window.<br/>"
        "<b>4. Software Key Wrap:</b> Uses software HKDF/AES-GCM rather than hardware HSM/TPM.",
        AMBER,
    )
    y -= box_h + 5 * mm

    _draw_video_banner(c, y, video_url, "5-Minute Demo Video & Test Command (pytest -v: 20/20 Pass):")
    _draw_footer(c, "Page 2 of 2 — One-Page Threat Model")
    c.save()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate TrustGuard 2-Page Project Brief PDF")
    parser.add_argument(
        "--video-url",
        default="[INSERT UNLISTED YOUTUBE / GOOGLE DRIVE LINK HERE]",
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
