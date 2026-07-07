"""Generate FRAUD-X project documentation PDF."""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import ListFlowable, ListItem
from datetime import datetime

# ── Colour palette ──────────────────────────────────────────────────────────
DARK_NAVY   = colors.HexColor("#0D1B2A")
MID_BLUE    = colors.HexColor("#1A3A5C")
ACCENT_BLUE = colors.HexColor("#2196F3")
ACCENT_CYAN = colors.HexColor("#00BCD4")
DANGER_RED  = colors.HexColor("#F44336")
WARN_ORANGE = colors.HexColor("#FF9800")
SAFE_GREEN  = colors.HexColor("#4CAF50")
LIGHT_BG    = colors.HexColor("#F5F8FC")
TEXT_DARK   = colors.HexColor("#1A1A2E")
TEXT_MID    = colors.HexColor("#37474F")
BORDER_CLR  = colors.HexColor("#B0BEC5")
TABLE_HDR   = colors.HexColor("#1565C0")
TABLE_ALT   = colors.HexColor("#E3F2FD")
WHITE       = colors.white

W, H = A4  # 595.27 x 841.89 pt


# ── Style helpers ────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()

    def add(name, **kw):
        base.add(ParagraphStyle(name=name, **kw))

    # Cover
    add("Cover_Title",
        fontName="Helvetica-Bold", fontSize=36, textColor=WHITE,
        alignment=TA_CENTER, spaceAfter=6)
    add("Cover_Sub",
        fontName="Helvetica", fontSize=16, textColor=ACCENT_CYAN,
        alignment=TA_CENTER, spaceAfter=4)
    add("Cover_Meta",
        fontName="Helvetica", fontSize=11, textColor=colors.HexColor("#CFD8DC"),
        alignment=TA_CENTER, spaceAfter=2)

    # Headings
    add("H1", fontName="Helvetica-Bold", fontSize=20, textColor=DARK_NAVY,
        spaceBefore=18, spaceAfter=6, borderPadding=(0, 0, 4, 0))
    add("H2", fontName="Helvetica-Bold", fontSize=15, textColor=MID_BLUE,
        spaceBefore=14, spaceAfter=4)
    add("H3", fontName="Helvetica-Bold", fontSize=12, textColor=ACCENT_BLUE,
        spaceBefore=10, spaceAfter=3)
    add("H4", fontName="Helvetica-BoldOblique", fontSize=10, textColor=TEXT_MID,
        spaceBefore=8, spaceAfter=2)

    # Body
    add("Body", fontName="Helvetica", fontSize=9.5, textColor=TEXT_DARK,
        leading=14, spaceAfter=4, alignment=TA_JUSTIFY)
    add("BodyBold", fontName="Helvetica-Bold", fontSize=9.5, textColor=TEXT_DARK,
        leading=14, spaceAfter=4)
    add("FXBullet", fontName="Helvetica", fontSize=9, textColor=TEXT_DARK,
        leading=13, leftIndent=14, spaceAfter=2,
        bulletIndent=4, bulletFontName="Helvetica", bulletFontSize=9)
    add("FXCode", fontName="Courier", fontSize=8, textColor=TEXT_DARK,
        backColor=colors.HexColor("#ECEFF1"), leading=12,
        leftIndent=8, rightIndent=8, spaceAfter=3,
        borderPadding=(4, 6, 4, 6))
    add("Note", fontName="Helvetica-Oblique", fontSize=8.5,
        textColor=colors.HexColor("#546E7A"), leading=12, spaceAfter=3)
    add("TOC_H1", fontName="Helvetica-Bold", fontSize=11,
        textColor=DARK_NAVY, spaceAfter=3, spaceBefore=5)
    add("TOC_H2", fontName="Helvetica", fontSize=10,
        textColor=MID_BLUE, leftIndent=16, spaceAfter=2)

    return base

S = make_styles()


# ── Page template callbacks ───────────────────────────────────────────────────
def header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    page = doc.page

    if page == 1:
        # Solid cover background
        canvas.setFillColor(DARK_NAVY)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        # Decorative top bar
        canvas.setFillColor(ACCENT_BLUE)
        canvas.rect(0, h - 8*mm, w, 8*mm, fill=1, stroke=0)
        # Bottom bar
        canvas.setFillColor(MID_BLUE)
        canvas.rect(0, 0, w, 14*mm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT_CYAN)
        canvas.setFont("Helvetica", 8)
        canvas.drawCentredString(w/2, 5*mm,
            "CONFIDENTIAL – Final Year Project | FRAUD-X | Sentinel AI Platform")
        canvas.restoreState()
        return

    # Every other page: header stripe
    canvas.setFillColor(DARK_NAVY)
    canvas.rect(0, h - 11*mm, w, 11*mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT_BLUE)
    canvas.rect(0, h - 12.5*mm, w, 1.5*mm, fill=1, stroke=0)

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(WHITE)
    canvas.drawString(1.5*cm, h - 7.5*mm, "FRAUD-X  |  Sentinel AI Fraud Detection Platform")
    canvas.drawRightString(w - 1.5*cm, h - 7.5*mm, "Final Year Project Documentation")

    # Footer
    canvas.setFillColor(LIGHT_BG)
    canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
    canvas.setStrokeColor(BORDER_CLR)
    canvas.line(0, 10*mm, w, 10*mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(TEXT_MID)
    canvas.drawString(1.5*cm, 3.5*mm, f"Generated {datetime.now().strftime('%d %B %Y')}")
    canvas.drawCentredString(w/2, 3.5*mm, "FRAUD-X – Multi-Layer AI Fraud Detection System")
    canvas.drawRightString(w - 1.5*cm, 3.5*mm, f"Page {page}")

    canvas.restoreState()


# ── Utility builders ─────────────────────────────────────────────────────────
def hr(color=ACCENT_BLUE, thick=1):
    return HRFlowable(width="100%", thickness=thick, color=color,
                      spaceAfter=4, spaceBefore=2)

def h1(txt): return Paragraph(txt, S["H1"])
def h2(txt): return Paragraph(txt, S["H2"])
def h3(txt): return Paragraph(txt, S["H3"])
def h4(txt): return Paragraph(txt, S["H4"])
def body(txt): return Paragraph(txt, S["Body"])
def bold(txt): return Paragraph(txt, S["BodyBold"])
def note(txt): return Paragraph(txt, S["Note"])
def code(txt): return Paragraph(txt.replace(" ", "&nbsp;").replace("\n", "<br/>"), S["FXCode"])
def sp(n=6): return Spacer(1, n)

def bullets(items, style=None):
    st = style or S["FXBullet"]
    return [Paragraph(f"• {i}", st) for i in items]

def section_banner(txt, color=MID_BLUE):
    data = [[Paragraph(f"<b>{txt}</b>",
                       ParagraphStyle("_sb", fontName="Helvetica-Bold",
                                      fontSize=11, textColor=WHITE))]]
    t = Table(data, colWidths=[W - 3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), color),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ]))
    return t

def make_table(headers, rows, col_widths=None):
    data = [headers] + rows
    if not col_widths:
        col_widths = [(W - 3*cm) / len(headers)] * len(headers)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND",    (0,0), (-1,0), TABLE_HDR),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 9),
        ("ALIGN",         (0,0), (-1,-1), "LEFT"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,1), (-1,-1), 8.5),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, TABLE_ALT]),
        ("GRID",          (0,0), (-1,-1), 0.5, BORDER_CLR),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
    ]
    t.setStyle(TableStyle(style))
    return t

def info_box(title, items, box_color=LIGHT_BG, border=ACCENT_BLUE):
    content = [Paragraph(f"<b>{title}</b>",
               ParagraphStyle("_ib", fontName="Helvetica-Bold",
                              fontSize=10, textColor=DARK_NAVY, spaceAfter=4))]
    for item in items:
        content.append(Paragraph(f"• {item}", S["Bullet"]))
    data = [[content]]
    t = Table(data, colWidths=[W - 3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), box_color),
        ("LINEAFTER",     (0,0), (0,-1), 3, border),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    return t


# ── Document builder ─────────────────────────────────────────────────────────
def build_pdf(path="FRAUDX_Project_Documentation.pdf"):
    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.3*cm,
        title="FRAUD-X – Sentinel AI Fraud Detection Platform",
        author="MVCK Final Year Project",
        subject="Project Documentation"
    )

    story = []

    # ================================================================
    # PAGE 1 – COVER (drawn purely in canvas callback)
    # ================================================================
    # We place invisible placeholder paragraphs to push content down
    # The real cover art is done in header_footer()
    for _ in range(14):
        story.append(Spacer(1, 14))

    def cov(txt, sty): return Paragraph(txt, S[sty])

    story += [
        cov("FRAUD-X", "Cover_Title"),
        sp(4),
        cov("Sentinel AI Fraud Detection Platform", "Cover_Sub"),
        sp(8),
        cov("Final Year Project — Full Documentation", "Cover_Meta"),
        sp(3),
        cov("Team MVCK  |  2025 – 2026", "Cover_Meta"),
        sp(3),
        cov(f"Generated: {datetime.now().strftime('%d %B %Y')}", "Cover_Meta"),
        sp(20),
        cov("Multi-Layer Protection  •  12 Scanner Types  •  AI-Powered Analysis", "Cover_Meta"),
        cov("Real-Time Dashboard  •  Chrome Extension  •  Blockchain Audit Log", "Cover_Meta"),
        PageBreak(),
    ]

    # ================================================================
    # PAGE 2 – TABLE OF CONTENTS
    # ================================================================
    story.append(h1("Table of Contents"))
    story.append(hr())
    story.append(sp(4))

    toc = [
        ("1.", "Project Overview", "3"),
        ("2.", "Technology Stack", "3"),
        ("3.", "Architecture Overview", "4"),
        ("4.", "Backend Components", "5"),
        ("  4.1", "main.py – FastAPI Application", "5"),
        ("  4.2", "database.py – SQLite Persistence", "8"),
        ("  4.3", "ml_engine.py – Bayesian Scoring", "10"),
        ("  4.4", "ml_url_model.py – Random Forest Classifier", "10"),
        ("  4.5", "scoring_engine.py – Adaptive Thresholds", "11"),
        ("  4.6", "behavior_engine.py – Anomaly Detection", "12"),
        ("  4.7", "graph_engine.py – Entity Graph", "13"),
        ("  4.8", "xai_engine.py – Explainable AI", "14"),
        ("  4.9", "payment_gateway_analyzer.py", "15"),
        ("5.", "Frontend Components", "16"),
        ("  5.1", "index.html – Sentinel Dashboard", "16"),
        ("  5.2", "login.html & signup.html", "17"),
        ("6.", "Chrome Extension", "18"),
        ("  6.1", "background.js – Service Worker", "18"),
        ("  6.2", "content.js – Page Integration", "19"),
        ("  6.3", "popup.html & popup.js", "19"),
        ("7.", "API Endpoints Reference", "20"),
        ("8.", "Database Schema", "21"),
        ("9.", "ML Model Details", "22"),
        ("10.", "Security Architecture", "23"),
        ("11.", "Installation & Running", "24"),
        ("12.", "Testing", "25"),
        ("13.", "Project Highlights", "25"),
    ]
    for num, title, pg in toc:
        indent = 32 if num.startswith("  ") else 0
        dots = "." * max(2, 60 - len(num) - len(title) - len(pg))
        row_style = "TOC_H2" if num.startswith("  ") else "TOC_H1"
        story.append(Paragraph(
            f'<font name="Helvetica-Bold">{num}</font>&nbsp;&nbsp;'
            f'{title}&nbsp;<font color="#90A4AE">{dots}</font>&nbsp;{pg}',
            S[row_style]))
    story.append(PageBreak())

    # ================================================================
    # SECTION 1 – PROJECT OVERVIEW
    # ================================================================
    story.append(section_banner("1. Project Overview"))
    story.append(sp(6))
    story.append(body(
        "<b>FRAUD-X (Sentinel)</b> is a full-stack, AI-powered fraud detection platform built as a "
        "Final Year Project by Team MVCK. It provides real-time scanning across <b>12 distinct threat "
        "vectors</b> using a five-layer protection architecture: heuristic analysis, machine-learning "
        "classification, graph-based risk propagation, behavioural anomaly detection, and explainable "
        "AI reasoning powered by <b>Google Gemini 2.0 Flash</b>."
    ))
    story.append(sp(4))
    story.append(body(
        "The system is accessible via a responsive <b>web dashboard</b> (Sentinel) and a "
        "<b>Chrome browser extension</b> that passively scans every page a user visits, providing "
        "instant on-screen warnings for phishing sites and malicious payment pages."
    ))
    story.append(sp(6))

    story.append(info_box("Core Capabilities", [
        "12 scan types: URL, Email, Phone, SMS, File, Merchant, Social Media, QR Code, IP Address, Cryptocurrency, Bulk URL, Payment Gateway",
        "Five-layer detection: Heuristics + ML + Graph + Behavioural + Gemini AI",
        "Real-time WebSocket alert feed with live dashboard ticker",
        "Blockchain-style SHA-256 chained audit ledger with integrity verification",
        "Chrome Manifest V3 extension with passive & payment-page overlays",
        "JWT authentication with bcrypt password hashing, Mobile OTP, Google OAuth",
        "Explainable AI (XAI) – every score broken down by contributing factor",
        "Adaptive thresholds that drift based on observed per-category fraud rates",
        "Campaign detection: auto-promotes repeat targets to 'Active Campaign' status",
        "NetworkX entity graph with PageRank influence scoring",
    ]))
    story.append(sp(8))

    # ================================================================
    # SECTION 2 – TECHNOLOGY STACK
    # ================================================================
    story.append(section_banner("2. Technology Stack"))
    story.append(sp(6))
    story.append(make_table(
        [bold("Layer"), bold("Technology"), bold("Version / Notes")],
        [
            ["Backend Framework",    "FastAPI (Python)",          "0.136.1, async, OpenAPI auto-docs"],
            ["ASGI Server",          "Uvicorn",                   "0.46.0, hot-reload dev mode"],
            ["AI / LLM",            "Google Gemini 2.0 Flash",   "httpx REST, deep reasoning"],
            ["Machine Learning",     "Scikit-learn – Random Forest", "1.8.0, 22 URL features"],
            ["Graph Engine",         "NetworkX",                  "3.2.1, PageRank + BFS"],
            ["Database",             "SQLite 3 (WAL mode)",       "serverless, concurrent safe"],
            ["Authentication",       "PyJWT + bcrypt",            "2.8.0 / 5.0.0"],
            ["Data Validation",      "Pydantic v2",               "2.13.3"],
            ["Frontend",             "Vanilla HTML / CSS / JS",   "Chart.js 4.4.0"],
            ["Browser Extension",    "Chrome Manifest V3",        "Service worker architecture"],
            ["Real-time Transport",  "WebSocket",                 "/ws/alerts endpoint"],
            ["Environment Secrets",  "python-dotenv",             "1.2.2"],
        ],
        col_widths=[5*cm, 6.5*cm, 6*cm]
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 3 – ARCHITECTURE OVERVIEW
    # ================================================================
    story.append(section_banner("3. Architecture Overview"))
    story.append(sp(6))
    story.append(body(
        "FRAUD-X follows a <b>layered, pipeline-style architecture</b>. A scan request enters "
        "through one of 12 FastAPI endpoints. It is processed through five sequential detection "
        "layers, each contributing signals (scored reasons) to the final risk score. The aggregated "
        "result is persisted in SQLite, broadcast over WebSocket, and chained into the audit ledger."
    ))
    story.append(sp(6))

    arch_data = [
        ["Layer", "Module", "Contribution"],
        ["① Heuristics",       "main.py",                    "150+ brand list, 42 suspicious TLDs, 60+ phishing keywords, DGA entropy, leet-speak, homograph"],
        ["② Machine Learning", "ml_url_model.py",            "22-feature Random Forest (F1 ≈ 0.87), trained on 2,000 synthetic URL samples"],
        ["③ Entity Graph",     "graph_engine.py",            "NetworkX nodes/edges, BFS guilt-by-association, PageRank influence, fraud-cluster detection"],
        ["④ Behavioural",      "behavior_engine.py",         "Velocity detection, campaign clustering, domain sweep, persistence, burst, system-wide spike"],
        ["⑤ AI Reasoning",     "main.py → Gemini 2.0 Flash","Deep contextual analysis, semantic phishing detection, structured JSON rationale"],
        ["Calibration",        "scoring_engine.py",          "Adaptive thresholds (EMA), weighted signal calibrator, session context correlation"],
        ["Explainability",     "xai_engine.py",              "Impact-scored factor breakdown, confidence levels, primary threat extraction"],
        ["Persistence",        "database.py",                "SQLite WAL, alerts, ledger, entity_links, scan_patterns tables"],
        ["Real-time",          "main.py WebSocket",          "Broadcast to all connected dashboard clients instantly"],
    ]
    story.append(make_table(
        [bold(h) for h in arch_data[0]],
        arch_data[1:],
        col_widths=[4*cm, 4.5*cm, 9*cm]
    ))
    story.append(sp(8))

    story.append(h2("Data Flow"))
    story.append(body(
        "Client → POST /api/scan/{type} → Heuristic Scoring → ML Score → "
        "Behavior Engine → Graph Engine → Gemini AI → WeightedCalibrator → "
        "AdaptiveThresholds → XAI Breakdown → SQLite save → Ledger chain → "
        "WebSocket broadcast → Response JSON"
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 4 – BACKEND COMPONENTS
    # ================================================================
    story.append(section_banner("4. Backend Components"))
    story.append(sp(6))

    # 4.1 main.py
    story.append(h2("4.1  main.py – FastAPI Application (12,000+ lines)"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "The heart of the system. Contains all 12 scan endpoint handlers, authentication routes, "
        "WebSocket manager, heuristic knowledge bases, and orchestration logic that calls all "
        "other engines in sequence."
    ))
    story.append(sp(4))
    story.append(h3("Heuristic Knowledge Bases"))
    story.append(make_table(
        [bold("Knowledge Base"), bold("Size"), bold("Purpose")],
        [
            ["Popular Brands",          "150+ entries",  "Detect impersonation & typosquatting"],
            ["Suspicious TLDs",         "42 TLDs",       ".tk, .ml, .ga, .cf, .gq, .xyz, .icu, .pw, .cc…"],
            ["URL Shorteners",          "22 services",   "bit.ly, tinyurl, ow.ly, t.co…"],
            ["Phishing Keywords",       "60+ words",     "login, verify, account, wallet, seed, confirm…"],
            ["Safe Domain Whitelist",   "400+ domains",  "Suppress false positives on trusted sites"],
            ["Email Scam Phrases",      "50+ phrases",   "urgent, verify, suspended, lottery, inheritance…"],
            ["SMS Scam Patterns",       "Regex set",     "Reward claims, urgency, OTP theft, delivery…"],
            ["Crypto Address Patterns", "6 coin types",  "Bitcoin, Ethereum, Monero, Tron, Solana, Litecoin"],
            ["Crypto Mixer Labels",     "10+ names",     "tornado, wasabi, coinjoin, blender, chipmixer…"],
            ["DGA Thresholds",          "Entropy + ratio","Detect algorithmically-generated domains"],
        ],
        col_widths=[4.5*cm, 3*cm, 10*cm]
    ))
    story.append(sp(6))

    story.append(h3("12 Scan Endpoints"))
    story.append(make_table(
        [bold("Endpoint"), bold("Input"), bold("Primary Detections")],
        [
            ["POST /api/scan/url",      "URL string",           "Phishing, typosquatting, DGA, malware, open redirect, punycode"],
            ["POST /api/scan/email",    "Email address",         "Spoofing, phishing keywords, header injection, reply-to mismatch"],
            ["POST /api/scan/phone",    "Phone number",          "Wangiri, premium rate, IRS/HMRC impersonation, robo-call flags"],
            ["POST /api/scan/sms",      "SMS text body",         "Smishing, fake delivery, OTP theft, urgency manipulation"],
            ["POST /api/scan/file",     "Binary file upload",    "Magic bytes, PE executable, VBA macros, obfuscated scripts"],
            ["POST /api/scan/merchant", "Merchant info dict",    "Brand impersonation, new account, high-risk country"],
            ["POST /api/scan/social",   "Social profile data",   "Fake profiles, low follower ratio, recent account creation"],
            ["POST /api/scan/qr",       "QR code decoded URL",   "Malicious destination, shortened links, domain mismatch"],
            ["POST /api/scan/ip",       "IP address string",     "Datacenter/VPS, Tor/VPN, dangerous open ports, high-risk geo"],
            ["POST /api/scan/crypto",   "Crypto wallet address", "Mixer detection, scam wallets, invalid address format"],
            ["POST /api/scan/bulk",     "List of ≤20 URLs",      "Parallel batch URL scanning with individual results"],
            ["POST /api/scan/payment",  "URL + page context",    "Fake checkout, brand spoofing, HTTP payment, form hijack"],
        ],
        col_widths=[4.5*cm, 3.5*cm, 9.5*cm]
    ))
    story.append(sp(6))

    story.append(h3("Authentication System"))
    story.append(make_table(
        [bold("Method"), bold("Flow"), bold("Notes")],
        [
            ["Email / Password",  "Register → bcrypt hash → JWT issued",         "12-round bcrypt, HS256 JWT"],
            ["Mobile OTP",        "Phone → 6-digit OTP → JWT issued",            "Auto-filled in dev; Twilio-ready"],
            ["Google OAuth",      "Google ID token → tokeninfo verify → JWT",    "No client-ID required in dev mode"],
        ],
        col_widths=[3.5*cm, 8*cm, 6*cm]
    ))
    story.append(sp(4))

    story.append(h3("Data & Utility Endpoints"))
    story.append(make_table(
        [bold("Endpoint"), bold("Purpose")],
        [
            ["GET /api/alerts",          "Paginated, filtered alert list (kind, level, score, search, timestamps)"],
            ["GET /api/alerts/:id",      "Single alert with full XAI explanation"],
            ["DELETE /api/alerts/:id",   "Delete individual alert record"],
            ["POST /api/alerts/:id/notes","Add analyst notes to an alert"],
            ["GET /api/ledger",          "Blockchain audit log with chain integrity badge"],
            ["GET /api/stats",           "Aggregated counts: total, by level, by kind"],
            ["GET /api/stats/trend",     "6-hour bucket timeline of risk levels"],
            ["GET /api/export",          "CSV export of all alerts"],
            ["GET /api/health",          "Server health check (uptime, DB status)"],
            ["POST /api/alerts/clear",   "Reset demo state (requires FRAUDX_CLEAR_KEY header)"],
            ["GET /ws/alerts",           "WebSocket – live broadcast of new alerts to dashboard"],
        ],
        col_widths=[5*cm, 12.5*cm]
    ))
    story.append(PageBreak())

    # 4.2 database.py
    story.append(h2("4.2  database.py – SQLite Persistence"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "Manages all persistence using a single SQLite file (<b>fraudx.db</b>) with WAL mode "
        "for concurrent read safety. Four tables handle different aspects of the system."
    ))
    story.append(sp(4))

    story.append(h3("Table: alerts"))
    story.append(make_table(
        [bold("Column"), bold("Type"), bold("Description")],
        [
            ["id",          "TEXT PK",    "UUID for the alert"],
            ["kind",        "TEXT",       "url | email | phone | sms | file | merchant | social | qr | ip | crypto"],
            ["target",      "TEXT",       "The scanned entity (domain, email address, phone number…)"],
            ["risk_score",  "INTEGER",    "0–100 composite risk score"],
            ["risk_level",  "TEXT",       "safe | caution | danger"],
            ["reasons",     "TEXT JSON",  "List of detection signal strings"],
            ["ai_analysis", "TEXT",       "Gemini AI deep-reasoning output (paragraph)"],
            ["ledger_hash", "TEXT",       "SHA-256 hash of the corresponding ledger block"],
            ["notes",       "TEXT",       "Analyst annotations"],
            ["timestamp",   "REAL",       "Unix epoch timestamp"],
        ],
        col_widths=[3*cm, 3*cm, 11.5*cm]
    ))
    story.append(sp(4))

    story.append(h3("Table: ledger_blocks  (Blockchain Audit Log)"))
    story.append(make_table(
        [bold("Column"), bold("Description")],
        [
            ["idx",          "Sequential block index (auto-increment)"],
            ["timestamp",    "Block creation time (Unix epoch)"],
            ["alert_id",     "Foreign reference to alerts.id"],
            ["payload_hash", "SHA-256(alert_id | kind | target | risk_score | timestamp)"],
            ["prev_hash",    "Hash of the preceding block (genesis = '0'*64)"],
            ["block_hash",   "SHA-256(idx | prev_hash | payload_hash)  – chain integrity link"],
        ],
        col_widths=[4*cm, 13.5*cm]
    ))
    story.append(sp(4))

    story.append(h3("Table: entity_links  (Graph Storage)"))
    story.append(make_table(
        [bold("Column"), bold("Description")],
        [
            ["src_type / src_value", "Source entity type and value (e.g. 'url', 'paypal.com')"],
            ["dst_type / dst_value", "Destination entity type and value"],
            ["relation",             "Edge label: resolves_to | sent_from_domain | in_subnet | originates_from | coin_type…"],
            ["alert_id",             "Alert that created this edge"],
            ["timestamp",            "Creation time"],
        ],
        col_widths=[4.5*cm, 13*cm]
    ))
    story.append(sp(4))

    story.append(h3("Table: scan_patterns  (Repeat Scan Tracking)"))
    story.append(body(
        "Keyed by <b>kind:target[:100]</b>. Tracks scan_count, avg_score, first_seen, last_seen. "
        "Used by the Behavior Engine to detect velocity and campaign patterns."
    ))
    story.append(sp(4))

    story.append(h3("Key Database Functions"))
    story.append(make_table(
        [bold("Function"), bold("Purpose")],
        [
            ["save_alert()",             "Persist scan result + create ledger block + update scan_patterns"],
            ["get_alerts_paginated()",   "Filtered, sorted list with pagination"],
            ["get_top_targets()",        "Most-scanned entities in the last N hours"],
            ["get_trend_from_db()",      "Per-hour counts of safe / caution / danger over last 6 hours"],
            ["get_entity_graph()",       "Traverse entity_links for graph visualisation"],
            ["verify_ledger()",          "Walk the chain and validate each block_hash matches"],
            ["get_scan_velocity()",      "Count scans on a target in a rolling time window"],
        ],
        col_widths=[5*cm, 12.5*cm]
    ))
    story.append(PageBreak())

    # 4.3 ml_engine.py
    story.append(h2("4.3  ml_engine.py – Bayesian Statistical Scoring"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "A lightweight, pure-Python calibration layer. Uses Bayesian priors per scan type to "
        "adjust raw heuristic scores before the weighted calibrator runs."
    ))
    story.append(sp(4))
    story.append(make_table(
        [bold("Scan Type"), bold("Fraud Prior"), bold("Rationale")],
        [
            ["url",     "18%", "Baseline – most URLs are benign"],
            ["email",   "22%", "Slightly higher – phishing email prevalence"],
            ["phone",   "18%", "Similar to URL baseline"],
            ["sms",     "24%", "Smishing campaigns prevalent"],
            ["crypto",  "32%", "Highest baseline – frequent scam wallets"],
            ["social",  "26%", "Fake profiles common"],
            ["ip",      "20%", "Moderate – many datacenter IPs legitimate"],
            ["file",    "20%", "Moderate – most files are benign"],
            ["merchant","22%", "Moderate – new/suspicious merchant common"],
            ["qr",      "22%", "Growing phishing vector"],
        ],
        col_widths=[4*cm, 3*cm, 10.5*cm]
    ))
    story.append(sp(4))
    story.append(body(
        "<b>Calibration logic:</b> 5+ converging signals → +10; 3+ → +5; 2+ → +2. "
        "Whitelist match → −10. Crypto/social high priors add +5 to base. Returns "
        "<i>(calibrated_score, note)</i>."
    ))
    story.append(sp(6))

    # 4.4 ml_url_model.py
    story.append(h2("4.4  ml_url_model.py – Random Forest URL Classifier"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "Scikit-learn Random Forest classifier trained on 2,000 synthetic URLs "
        "(1,000 phishing + 1,000 legitimate). Auto-trains on first startup if "
        "<b>url_model.pkl</b> is missing."
    ))
    story.append(sp(4))

    story.append(h3("22 Extracted Features"))
    feats = [
        "url_length", "host_length", "path_length", "num_dots", "num_hyphens",
        "has_at_sign", "num_digits_in_host", "num_subdomains", "url_depth",
        "num_query_params", "has_ip_host", "is_https", "has_punycode",
        "is_url_shortener", "has_suspicious_tld", "has_redirect_param",
        "digit_ratio", "special_char_ratio", "domain_entropy", "dga_consonant_ratio",
        "phish_keyword_count", "brand_min_levenshtein"
    ]
    # arrange in 3 columns
    rows = []
    for i in range(0, len(feats), 3):
        rows.append([
            feats[i] if i < len(feats) else "",
            feats[i+1] if i+1 < len(feats) else "",
            feats[i+2] if i+2 < len(feats) else "",
        ])
    story.append(make_table(
        [bold("Feature"), bold("Feature"), bold("Feature")],
        rows,
        col_widths=[5.83*cm, 5.83*cm, 5.83*cm]
    ))
    story.append(sp(4))

    story.append(h3("Model Hyperparameters"))
    story.append(make_table(
        [bold("Parameter"), bold("Value")],
        [
            ["n_estimators",   "200"],
            ["max_depth",      "15"],
            ["min_samples_leaf","2"],
            ["class_weight",   "balanced"],
            ["random_state",   "42"],
            ["n_jobs",         "-1 (all cores)"],
            ["Cross-val F1",   "≈ 0.85–0.90"],
        ],
        col_widths=[6*cm, 11.5*cm]
    ))
    story.append(PageBreak())

    # 4.5 scoring_engine.py
    story.append(h2("4.5  scoring_engine.py – Adaptive Threshold & Weighted Calibrator"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))

    story.append(h3("DynamicThresholds"))
    story.append(body(
        "Per-scan-type base thresholds that drift with observed fraud rates using an "
        "Exponential Moving Average (EMA). Drift is capped at ±10 points. Adaptation "
        "only activates after ≥20 scans to avoid premature adjustment."
    ))
    story.append(sp(3))
    story.append(make_table(
        [bold("Scan Type"), bold("Danger Threshold"), bold("Caution Threshold")],
        [
            ["url",     "65", "30"],
            ["email",   "60", "28"],
            ["phone",   "65", "30"],
            ["sms",     "62", "28"],
            ["crypto",  "55", "25"],
            ["social",  "60", "28"],
            ["ip",      "65", "30"],
            ["file",    "60", "28"],
            ["merchant","60", "28"],
            ["qr",      "65", "30"],
        ],
        col_widths=[5*cm, 5*cm, 7.5*cm]
    ))
    story.append(sp(4))

    story.append(h3("WeightedCalibrator – Signal Weights"))
    story.append(make_table(
        [bold("Signal Prefix"), bold("Weight"), bold("Source")],
        [
            ["[ML]",         "1.60", "Independent Random Forest classifier"],
            ["[AI]",         "1.40", "Gemini 2.0 Flash deep reasoning"],
            ["[Behavioral]", "1.35", "Anomaly / velocity / campaign detection"],
            ["[Graph]",      "1.30", "NetworkX guilt-by-association"],
            ["[Context]",    "1.30", "Cross-entity session correlation"],
            ["Plain heuristic", "1.00", "Regex / keyword / entropy rules"],
        ],
        col_widths=[4.5*cm, 2.5*cm, 10.5*cm]
    ))
    story.append(sp(4))

    story.append(h3("Convergence Adjustment"))
    story.append(body(
        "Weighted sum of positive signals ≥8.0 → +12; ≥5.5 → +8; ≥3.5 → +5; "
        "≥2.0 → +2; ≥1.0 → 0; &lt;1.0 → −5 (no signals detected)."
    ))
    story.append(sp(4))

    story.append(h3("ContextAwareScorer (10-minute session window)"))
    story += bullets([
        "3+ distinct scan kinds all high-risk → +15 (multi-vector campaign detected)",
        "2 scan kinds both high-risk → +8 (cross-entity corroboration)",
        "Same domain appears in multiple scan kinds → +10 (infrastructure reuse)",
        "Same target entity appears in 2+ scan kinds → +6 (entity overlap)",
    ])
    story.append(PageBreak())

    # 4.6 behavior_engine.py
    story.append(h2("4.6  behavior_engine.py – Behavioural Anomaly Detection"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))

    story.append(make_table(
        [bold("Detection Layer"), bold("Trigger Condition"), bold("Score Boost / Action")],
        [
            ["Velocity Detection",  "Same target ≥10 scans in 5 min",           "+15 'campaign velocity'"],
            ["",                    "Same target ≥5 scans in 5 min",             "+12 'high velocity'"],
            ["",                    "Same target ≥3 scans in 5 min",             "+6 'repeated scan'"],
            ["Campaign Clustering", "≥10 total or ≥5 high-risk (score≥65) hits", "Promote to Active Campaign"],
            ["Domain Sweep",        "Same domain in ≥3 distinct scan kinds",     "Create sweep campaign record"],
            ["Persistence",         "Recent 3-scan avg ≥55 AND current ≥55",     "+5 'persistent high-risk'"],
            ["Evasion Signal",      "Recent avg ≥55 BUT current &lt;20",          "Flag 'score drop – evasion'"],
            ["Burst Detection",     "≥30 scans of one kind in 60 seconds",        "+5 category spike"],
            ["Alert Spike",         "5-min count ≥3× 1-hour baseline",           "System-wide spike signal"],
        ],
        col_widths=[4.5*cm, 6.5*cm, 6.5*cm]
    ))
    story.append(sp(4))
    story.append(body(
        "Campaign records are stored in an in-memory registry keyed by <b>kind:target[:100]</b>. "
        "Each campaign tracks: alert IDs, scan count, fraud count, average score, domain, "
        "first/last seen timestamps, and trigger reason."
    ))
    story.append(sp(6))

    # 4.7 graph_engine.py
    story.append(h2("4.7  graph_engine.py – NetworkX Entity Graph"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "Builds a live, in-memory directed graph of entities encountered across all scans. "
        "Provides guilt-by-association risk propagation via BFS and PageRank."
    ))
    story.append(sp(4))

    story.append(h3("Node & Edge Types"))
    story.append(make_table(
        [bold("Relation"), bold("From Entity"), bold("To Entity")],
        [
            ["resolves_to",       "url",       "domain"],
            ["uses_tld",          "domain",    "tld"],
            ["sent_from_domain",  "email",     "domain"],
            ["originates_from",   "phone",     "country"],
            ["in_subnet",         "ip",        "subnet (/24)"],
            ["coin_type",         "crypto",    "coin_type"],
            ["contains_link_to",  "sms_sender","domain"],
        ],
        col_widths=[5*cm, 4.5*cm, 8*cm]
    ))
    story.append(sp(4))

    story.append(h3("Node Metadata (per entity)"))
    story += bullets([
        "fraud_count — times this entity appeared in scans with score ≥65",
        "total_scans — total scan appearances",
        "avg_score — rolling average of last 50 raw scores",
        "risk_scores — list of last 50 scores for trend analysis",
        "first_seen / last_seen — timestamps of first and most recent appearance",
    ])
    story.append(sp(4))

    story.append(h3("Scoring Functions"))
    story.append(make_table(
        [bold("Function"), bold("Algorithm"), bold("Output")],
        [
            ["get_entity_risk_adjustment()", "Repeat offender: fraud_count × 4 (cap 20), +5 if fraud rate ≥70%", "Score boost + reason strings"],
            ["connected_risk()",             "BFS 2-hop traversal, distance decay (÷2 per hop), only high-risk (≥65) neighbours count", "Guilt-by-association boost"],
            ["detect_fraud_clusters()",      "Connected components on undirected projection, ≥2 fraud nodes required", "Cluster list sorted by severity"],
            ["PageRank Influence",           "influence = (PageRank × 1000) + (fraud_count × 5) + (avg_score × 0.1)", "Top-10 influential entities"],
        ],
        col_widths=[4.5*cm, 7.5*cm, 5.5*cm]
    ))
    story.append(PageBreak())

    # 4.8 xai_engine.py
    story.append(h2("4.8  xai_engine.py – Explainable AI (XAI)"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "Converts raw (score, reasons) into a structured, human-readable impact breakdown. "
        "Every detection signal is mapped to an impact value and grouped by severity tier."
    ))
    story.append(sp(4))

    story.append(make_table(
        [bold("Severity Tier"), bold("Impact Range"), bold("Example Signals")],
        [
            ["Critical",      "35–50 pts", "Homograph spoofing, DGA, VBA macro, seed phrase, header injection, hash match"],
            ["High",          "20–35 pts", "Brand impersonation, typosquatting, leet-speak, crypto mixer, wire-transfer solicitation"],
            ["Medium",        "10–20 pts", "Suspicious TLD, IP as host, entropy anomaly, URL shortener, free hosting, open redirect"],
            ["Low",           "5–10 pts",  "File attachment, excessive links, grammar issues, unusual file size"],
            ["Informational", "0 / −20",   "No signals, whitelist match (−20 suppression), ML low-risk (−5)"],
        ],
        col_widths=[3.5*cm, 3*cm, 11*cm]
    ))
    story.append(sp(4))
    story.append(body(
        "<b>Proportional scaling:</b> positive impacts are scaled so their sum approximately "
        "equals the final risk score. Scale factor = max(0.25, min(1.6, target/raw_positive_sum)). "
        "Negative impacts (whitelist) are kept as-is."
    ))
    story.append(sp(4))

    story.append(h3("Confidence Levels"))
    story.append(make_table(
        [bold("Level"), bold("Condition")],
        [
            ["High",     "≥2 critical/high signals AND score ≥65"],
            ["Medium",   "≥3 positive signals AND score ≥30"],
            ["Low",      "≥1 positive signal"],
            ["Minimal",  "No positive signals detected"],
        ],
        col_widths=[4*cm, 13.5*cm]
    ))
    story.append(sp(6))

    # 4.9 payment_gateway_analyzer.py
    story.append(h2("4.9  payment_gateway_analyzer.py – Payment Protection"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "Specialised fraud detection layer for payment pages. Maintains a registry of "
        "<b>80+ trusted payment gateways</b> and applies 10 detection layers."
    ))
    story.append(sp(4))
    story.append(make_table(
        [bold("Detection Layer"), bold("Score Change"), bold("Condition")],
        [
            ["Trusted Gateway Fast-Path",    "−30",  "Domain in 80+ trusted gateway whitelist"],
            ["Payment Brand Spoofing",       "+50–65","Leet-speak substitution or Levenshtein ≤2 from known brand"],
            ["Brand as Subdomain",           "+55",  "Legitimate brand name used as subdomain on wrong domain"],
            ["HTTP on Payment Page",         "+45",  "Payment page served over plain HTTP (no TLS)"],
            ["IP-Based Payment Host",        "+75",  "Raw IP address used instead of domain"],
            ["Suspicious TLD",               "+40",  "Payment page on .tk, .ml, .ga, .cf, .xyz etc."],
            ["Free Hosting",                 "+50",  "Hosted on netlify, vercel, github.io, glitch.me…"],
            ["Cross-Domain Form Action",     "+40",  "Form submits data to a different domain than page origin"],
            ["Merchant Identity Mismatch",   "+40",  "Page claims to be Brand X but domain is unrelated"],
            ["No TLS on Payment Form",       "+35",  "Payment form fields present but page not HTTPS"],
        ],
        col_widths=[5*cm, 2.5*cm, 10*cm]
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 5 – FRONTEND
    # ================================================================
    story.append(section_banner("5. Frontend Components"))
    story.append(sp(6))

    story.append(h2("5.1  index.html – Sentinel Dashboard (18,000+ lines)"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(body(
        "The main web application. A fully responsive single-page dashboard built with "
        "Vanilla HTML/CSS/JS and Chart.js. No framework dependency."
    ))
    story.append(sp(4))

    story.append(h3("Layout Structure"))
    story.append(make_table(
        [bold("Element"), bold("Description")],
        [
            ["Sidebar (280 px)",     "Navigation links to all 7 panes, status dot, FRAUD-X logo, user avatar"],
            ["Topbar (56 px)",       "Current pane title, live stats chips (total/danger/caution/safe), user menu dropdown"],
            ["Main Content Area",    "Flex-grow scrollable pane container"],
        ],
        col_widths=[4.5*cm, 13*cm]
    ))
    story.append(sp(4))

    story.append(h3("7 Navigation Panes"))
    story.append(make_table(
        [bold("Pane"), bold("Contents")],
        [
            ["Dashboard",   "Live alert ticker (WebSocket), summary stat cards, 6-hour trend chart (stacked bar)"],
            ["Scanners",    "12 scanner input forms with real-time result panels (score, level, reasons, XAI, AI analysis)"],
            ["Alerts",      "Paginated, filterable alert table; detail modal with full XAI breakdown and analyst notes"],
            ["Ledger",      "Blockchain audit log list with chain integrity badge (valid/compromised)"],
            ["Analytics",   "Score distribution histogram, kind timeline (line chart), top targets table, campaign list"],
            ["Behavioral",  "Velocity stats, active campaigns, domain sweeps, system baselines"],
            ["Settings",    "User profile edit, theme toggle (dark/light), CSV export, API config"],
        ],
        col_widths=[3*cm, 14.5*cm]
    ))
    story.append(sp(4))

    story.append(h3("Scan Result Panel Components"))
    story += bullets([
        "Risk Score — large coloured number (red/orange/green by level)",
        "Risk Level Badge — 'SAFE' / 'CAUTION' / 'DANGER' pill",
        "Detection Reasons — auto-detected signal list with icons",
        "Confidence Pill — high / medium / low / minimal",
        "Primary Threat — top contributing signal headline",
        "XAI Breakdown — collapsible accordion: Critical → High → Medium → Low → Informational",
        "AI Analysis Block — Gemini deep-reasoning paragraph",
    ])
    story.append(sp(4))

    story.append(h3("Real-Time Features"))
    story += bullets([
        "WebSocket connection to /ws/alerts — receives new alerts instantly",
        "Live ticker at dashboard top — scrolling colour-coded alert headlines",
        "Optional audio notification on new DANGER alerts (if browser permission granted)",
        "Chart.js charts auto-refresh on new data (trend, distribution, kind timeline)",
    ])
    story.append(sp(6))

    story.append(h2("5.2  login.html & signup.html"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(make_table(
        [bold("Page"), bold("Features")],
        [
            ["login.html",  "Dual-tab: Email/password login | Mobile OTP (country picker + 6-digit entry with auto-advance) | Google Sign-In button | Link to signup"],
            ["signup.html", "Account creation: name, email, password OR phone + OTP | Validation before submit"],
        ],
        col_widths=[3.5*cm, 14*cm]
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 6 – CHROME EXTENSION
    # ================================================================
    story.append(section_banner("6. Chrome Extension (Manifest V3)"))
    story.append(sp(6))
    story.append(body(
        "A Chrome browser extension that silently scans every page the user visits. "
        "Built with Manifest V3 (service worker architecture) for modern browser security compliance."
    ))
    story.append(sp(4))

    story.append(h3("Extension File Map"))
    story.append(make_table(
        [bold("File"), bold("Role")],
        [
            ["manifest.json",  "Extension config: permissions, host permissions, action popup, service worker declaration"],
            ["background.js",  "Service worker: navigation listener, scan dispatcher, badge manager, message router, cache (5-min TTL)"],
            ["content.js",     "Injected into every page: banner builder, payment overlay, DOM payment-context extractor"],
            ["popup.html",     "Browser action popup UI (360 px wide)"],
            ["popup.js",       "Popup logic: display last scan result, manual scan buttons, ignore list, recent scans list"],
        ],
        col_widths=[3.5*cm, 14*cm]
    ))
    story.append(sp(6))

    story.append(h2("6.1  background.js – Service Worker"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))

    story.append(h3("Dual-Mode Scanner"))
    story.append(make_table(
        [bold("Mode"), bold("Trigger"), bold("Behaviour")],
        [
            ["Standard URL Scan",  "Every main-frame navigation event",       "Calls POST /api/scan/url; caches result 5 min; sends to content.js for banner"],
            ["Payment Page Scan",  "URL matches payment patterns OR content.js reports payment indicators", "Calls POST /api/scan/payment with enriched DOM context; 10s timeout"],
        ],
        col_widths=[4*cm, 5.5*cm, 8*cm]
    ))
    story.append(sp(4))

    story.append(h3("Badge System"))
    story.append(make_table(
        [bold("Badge"), bold("Color"), bold("Meaning")],
        [
            ["!",   "Red",    "DANGER – confirmed threat"],
            ["?",   "Orange", "CAUTION – suspicious"],
            ["✓",   "Green",  "SAFE – no threats detected"],
            ["…",   "Gray",   "Scanning in progress"],
            ["💳",  "Purple", "Payment page scan active"],
            ["–",   "Gray",   "Ignored page"],
        ],
        col_widths=[2.5*cm, 3*cm, 12*cm]
    ))
    story.append(sp(4))

    story.append(h3("Message Router"))
    story += bullets([
        "PAYMENT_PAGE_DETECTED — content.js found payment indicators; enrich payment scan with DOM metadata",
        "SCAN_NOW — popup triggered manual URL scan",
        "SCAN_PAYMENT_NOW — popup triggered manual payment scan",
        "IGNORE_PAGE / UNIGNORE_PAGE — manage ignore list in chrome.storage.sync",
        "CHECK_IGNORED — query ignore status for current page",
    ])
    story.append(sp(6))

    story.append(h2("6.2  content.js – Page Integration & Overlays"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(make_table(
        [bold("Mode"), bold("When Shown"), bold("Elements")],
        [
            ["Standard Alert Banner",
             "URL scan returns caution or danger",
             "Top-of-page banner: risk score pill, threat summary, top 3 factors, 'Go Back' (danger), 'Dismiss'. Auto-dismiss after 12s for caution."],
            ["Trusted Gateway Trust Badge",
             "Payment page is a verified trusted gateway",
             "Bottom-right green badge: gateway name, 'Verified Secure'. Auto-dismiss after 8s."],
            ["Caution Payment Overlay",
             "Payment page scan returns caution",
             "Orange overlay modal: risk score, threat summary, top 4 factors, signals breakdown, 'Proceed Anyway' or 'Go Back'."],
            ["Danger Payment Overlay",
             "Payment page scan returns danger",
             "Red blocking overlay modal: same as caution but form submission blocked; no 'Proceed Anyway' option."],
        ],
        col_widths=[3.5*cm, 4*cm, 10*cm]
    ))
    story.append(sp(4))
    story.append(body(
        "<b>Proactive Payment Detection:</b> On DOMContentLoaded, content.js scans the DOM for "
        "payment form indicators (card number fields, CVV, UPI ID, wallet address inputs, checkout "
        "keywords in page title). If found, reports to background.js with extracted metadata "
        "(merchant name, form action URL, field names, page title) for richer payment analysis."
    ))
    story.append(sp(6))

    story.append(h2("6.3  popup.html & popup.js"))
    story.append(hr(ACCENT_CYAN, 0.5))
    story.append(sp(4))
    story.append(make_table(
        [bold("Section"), bold("Contents")],
        [
            ["Header",           "Logo, 'FRAUD-X Shield' title, gear icon (API URL config)"],
            ["Current Page",     "Last scan result for the active tab (risk score, level badge)"],
            ["Payment Section",  "Payment scan result if the page was detected as a payment page"],
            ["Ignore Controls",  "Toggle button: 'Ignore This Page' / 'Unignore This Page'"],
            ["Manual Scan",      "'Scan Now' and 'Scan Payment' buttons"],
            ["Status Dot",       "Green = API online | Red = API offline | 'Open Dashboard' link"],
            ["Recent Scans",     "Last 30 scans list with time, scan type icon, score, and level badge"],
        ],
        col_widths=[4*cm, 13.5*cm]
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 7 – API REFERENCE
    # ================================================================
    story.append(section_banner("7. Full API Endpoints Reference"))
    story.append(sp(6))
    story.append(make_table(
        [bold("Method"), bold("Endpoint"), bold("Auth"), bold("Description")],
        [
            ["POST", "/api/auth/register",     "None",   "Create new account (email + password)"],
            ["POST", "/api/auth/login",         "None",   "Email login → JWT token"],
            ["POST", "/api/auth/send-otp",      "None",   "Send OTP to mobile number"],
            ["POST", "/api/auth/verify-otp",    "None",   "Verify OTP → JWT token"],
            ["POST", "/api/auth/google",         "None",   "Google ID token → JWT token"],
            ["POST", "/api/scan/url",            "JWT",    "Scan a URL for threats"],
            ["POST", "/api/scan/email",          "JWT",    "Scan an email address"],
            ["POST", "/api/scan/phone",          "JWT",    "Scan a phone number"],
            ["POST", "/api/scan/sms",            "JWT",    "Scan an SMS text body"],
            ["POST", "/api/scan/file",           "JWT",    "Scan a file (multipart upload)"],
            ["POST", "/api/scan/merchant",       "JWT",    "Scan merchant information"],
            ["POST", "/api/scan/social",         "JWT",    "Scan a social media profile"],
            ["POST", "/api/scan/qr",             "JWT",    "Scan a QR code decoded URL"],
            ["POST", "/api/scan/ip",             "JWT",    "Scan an IP address"],
            ["POST", "/api/scan/crypto",         "JWT",    "Scan a crypto wallet address"],
            ["POST", "/api/scan/bulk",           "JWT",    "Batch scan up to 20 URLs"],
            ["POST", "/api/scan/payment",        "API Key","Scan a payment page (extension)"],
            ["GET",  "/api/alerts",              "JWT",    "Paginated alert list with filters"],
            ["GET",  "/api/alerts/:id",          "JWT",    "Single alert detail"],
            ["DELETE","/api/alerts/:id",         "JWT",    "Delete an alert"],
            ["POST", "/api/alerts/:id/notes",    "JWT",    "Add analyst note to alert"],
            ["POST", "/api/alerts/clear",        "ClearKey","Reset all alerts (demo reset)"],
            ["GET",  "/api/ledger",              "JWT",    "Blockchain ledger with integrity status"],
            ["GET",  "/api/stats",               "JWT",    "Aggregated scan statistics"],
            ["GET",  "/api/stats/trend",         "JWT",    "6-hour timeline data"],
            ["GET",  "/api/export",              "JWT",    "CSV export of all alerts"],
            ["GET",  "/api/health",              "None",   "Server health check"],
            ["GET",  "/ws/alerts",               "None",   "WebSocket live alert feed"],
        ],
        col_widths=[1.5*cm, 5*cm, 2*cm, 9*cm]
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 8 – DATABASE SCHEMA
    # ================================================================
    story.append(section_banner("8. Database Schema (fraudx.db)"))
    story.append(sp(6))
    story.append(body("SQLite 3, WAL journal mode, auto-created on first startup."))
    story.append(sp(4))

    story.append(h3("Entity-Relationship Summary"))
    story.append(make_table(
        [bold("Table"), bold("Primary Key"), bold("Foreign Keys"), bold("Indexes")],
        [
            ["alerts",        "id (TEXT UUID)",  "None",           "kind, risk_level, timestamp, target"],
            ["ledger_blocks", "idx (INTEGER)",    "alert_id → alerts.id", "alert_id"],
            ["entity_links",  "id (AUTOINCREMENT)","alert_id → alerts.id","src_type+src_value, dst_type+dst_value"],
            ["scan_patterns", "pattern_key (TEXT)","None",           "kind, last_seen"],
        ],
        col_widths=[3.5*cm, 3.5*cm, 5*cm, 5.5*cm]
    ))
    story.append(sp(4))

    story.append(h3("Blockchain Ledger Integrity"))
    story.append(body(
        "Every alert creates a new ledger block. Each block's <b>block_hash</b> is computed as "
        "<b>SHA-256(block_idx | prev_hash | payload_hash)</b>. To verify chain integrity, "
        "<i>verify_ledger()</i> re-computes each hash and checks it matches the stored value — "
        "any tampering is immediately detected."
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 9 – ML MODEL DETAILS
    # ================================================================
    story.append(section_banner("9. ML Model Details"))
    story.append(sp(6))

    story.append(h3("Training Data Generation (train_model.py)"))
    story.append(make_table(
        [bold("Category"), bold("Count"), bold("Generation Method")],
        [
            ["Phishing — IP-based",       "~170", "http://{random IPv4}/{random path}"],
            ["Phishing — Typosquatting",  "~170", "Insert random char in brand name + suspicious TLD"],
            ["Phishing — DGA",            "~170", "Random consonant-heavy 12-20 char string + .tk/.ml"],
            ["Phishing — Leet-speak",     "~170", "Replace a→@ e→3 o→0 i→1 in brand name"],
            ["Phishing — Punycode",       "~170", "xn-- prefix + obfuscated brand character"],
            ["Phishing — Open Redirect",  "~150", "legit-site.com/redirect?url=evil.com"],
            ["Legitimate — Major Brands", "~200", "Real brand domains with normal paths"],
            ["Legitimate — Business",     "~200", "Random word combinations + .com/.net/.org"],
            ["Legitimate — E-commerce",   "~200", "shop/store prefix + brand + /product/checkout"],
            ["Legitimate — CDN/API",      "~200", "cdn./api./static. subdomains on real domains"],
            ["Legitimate — News/Blog",    "~200", "news/blog prefix + well-known publishing domains"],
        ],
        col_widths=[5*cm, 2*cm, 10.5*cm]
    ))
    story.append(sp(4))
    story.append(body(
        "<b>Training process:</b> Features extracted → StandardScaler → RandomForest fit → "
        "cross-validation → save to <i>url_model.pkl</i> via joblib. Auto-retrains on startup "
        "if pkl is missing or corrupted."
    ))
    story.append(PageBreak())

    # ================================================================
    # SECTION 10 – SECURITY ARCHITECTURE
    # ================================================================
    story.append(section_banner("10. Security Architecture"))
    story.append(sp(6))
    story.append(make_table(
        [bold("Security Control"), bold("Implementation")],
        [
            ["Password Storage",        "bcrypt with 12 work-factor rounds (adaptive cost)"],
            ["Session Tokens",          "HS256 JWT signed with FRAUDX_JWT_SECRET (from .env), stored client-side in localStorage"],
            ["API Secret Management",   ".env file (never committed to git); python-dotenv loading"],
            ["CORS Policy",             "FastAPI CORSMiddleware – localhost + same-origin only in dev"],
            ["SQLite Concurrent Safety","WAL (Write-Ahead Logging) journal mode; prevents read-write conflicts"],
            ["HTTPS Enforcement",       "Payment analyzer flags HTTP payment pages with +45 score penalty"],
            ["Extension Security",      "Manifest V3 (service workers instead of background pages); limited permissions"],
            ["Demo Reset Protection",   "POST /api/alerts/clear requires X-Clear-Key header matching FRAUDX_CLEAR_KEY env var"],
            ["Input Validation",        "Pydantic v2 models on all request bodies; automatic type coercion and error responses"],
            ["Gemini API Key",          "Server-side only, never exposed to frontend or extension"],
            ["Blockchain Audit",        "SHA-256 chained ledger detects any post-hoc modification of alert records"],
        ],
        col_widths=[5.5*cm, 12*cm]
    ))
    story.append(sp(6))
    story.append(info_box("Security Recommendations for Production Deployment", [
        "Replace SQLite with PostgreSQL for multi-process deployments",
        "Use HTTPS with a valid TLS certificate (Let's Encrypt)",
        "Set FRAUDX_JWT_SECRET to a cryptographically random 256-bit value",
        "Store .env in a secrets manager (AWS Secrets Manager, Azure Key Vault, etc.)",
        "Enable rate limiting on auth endpoints to prevent brute-force attacks",
        "Set JWT expiry to a short window (e.g., 24h) and implement refresh tokens",
        "Move localStorage JWT to httpOnly secure cookies to prevent XSS token theft",
    ], box_color=colors.HexColor("#FFF3E0"), border=WARN_ORANGE))
    story.append(PageBreak())

    # ================================================================
    # SECTION 11 – INSTALLATION
    # ================================================================
    story.append(section_banner("11. Installation & Running"))
    story.append(sp(6))

    steps = [
        ("Step 1: Clone & Navigate",
         "cd \"Kisshore Final YR PROJECT (MVCK)/fraud x\""),
        ("Step 2: Create Virtual Environment",
         "python -m venv venv\nvenv\\Scripts\\activate      # Windows\n# source venv/bin/activate  # macOS/Linux"),
        ("Step 3: Install Dependencies",
         "pip install -r requirements.txt"),
        ("Step 4: Configure Environment",
         "# Create .env in project root:\nGEMINI_API_KEY=your_gemini_api_key_here\nFRAUDX_JWT_SECRET=your_random_secret_here\nFRAUDX_CLEAR_KEY=optional_clear_key"),
        ("Step 5: Train ML Model (First Run)",
         "python train_model.py\n# Generates url_model.pkl (auto-runs on startup if missing)"),
        ("Step 6: Start the Server",
         "uvicorn main:app --reload --port 8000"),
        ("Step 7: Open the Dashboard",
         "http://localhost:8000\n# Redirects to login.html if not authenticated"),
        ("Step 8: Install Chrome Extension (Optional)",
         "1. Open chrome://extensions\n2. Enable 'Developer Mode' (top right)\n3. Click 'Load unpacked'\n4. Select the extension/ folder"),
    ]

    for title, cmd in steps:
        story.append(h3(title))
        story.append(code(cmd))
        story.append(sp(4))

    story.append(PageBreak())

    # ================================================================
    # SECTION 12 – TESTING
    # ================================================================
    story.append(section_banner("12. Testing"))
    story.append(sp(6))
    story.append(body(
        "The project includes a comprehensive accuracy test harness in <b>tests.py</b> and "
        "several smoke-test scripts for quick validation."
    ))
    story.append(sp(4))
    story.append(make_table(
        [bold("Test File"), bold("Purpose"), bold("Coverage")],
        [
            ["tests.py",       "Full accuracy harness",        "44 URL cases (16 malicious, 14 benign, 14 adversarial); 27 merchant cases; file payloads"],
            ["smoke_test.py",  "Quick end-to-end smoke test",  "Basic scan endpoint reachability and response structure"],
            ["smoke_graph.py", "Graph engine validation",      "Entity graph node/edge creation and BFS traversal correctness"],
        ],
        col_widths=[3.5*cm, 4.5*cm, 9.5*cm]
    ))
    story.append(sp(4))
    story.append(body(
        "Run tests with: <b>python tests.py</b>. Output includes per-case results, "
        "per-category statistics (true positives, false positives, true negatives, false negatives), "
        "and a summary table."
    ))
    story.append(sp(6))

    # ================================================================
    # SECTION 13 – PROJECT HIGHLIGHTS
    # ================================================================
    story.append(section_banner("13. Project Highlights"))
    story.append(sp(6))
    story.append(make_table(
        [bold("#"), bold("Highlight"), bold("Detail")],
        [
            ["1",  "Multi-Layer Detection",       "5 independent layers: Heuristics + ML + Graph + Behavioural + AI — no single point of failure"],
            ["2",  "Explainable AI (XAI)",        "Every risk score is fully decomposed by contributing signal with proportional impact values"],
            ["3",  "Payment Protection",           "80+ trusted gateway whitelist + 10 detection layers + Chrome extension blocking overlay"],
            ["4",  "Real-Time Dashboard",          "WebSocket live ticker, instant Chart.js chart updates, sound notifications on DANGER alerts"],
            ["5",  "Chrome Extension",             "Passive scanning + standard banners + payment overlays + popup with scan history"],
            ["6",  "Blockchain Audit Log",         "SHA-256 chained ledger, integrity verification, tamper detection on any historical record"],
            ["7",  "Adaptive Thresholds",          "Per-kind danger/caution levels drift via EMA based on observed fraud rates over time"],
            ["8",  "Campaign Auto-Detection",      "Repeat targets auto-promoted to 'Active Campaign' with full history and trigger reason"],
            ["9",  "Entity Graph + PageRank",      "Guilt-by-association propagation — one bad node raises scores of linked entities"],
            ["10", "12 Scan Types",                "Comprehensive coverage: URL, Email, Phone, SMS, File, Merchant, Social, QR, IP, Crypto, Bulk, Payment"],
            ["11", "Zero-Dependency Frontend",     "Sentinel dashboard is pure HTML/CSS/JS — no React, no build step, instant load"],
            ["12", "Serverless Database",          "SQLite WAL — no separate DB server needed; production-ready for moderate traffic"],
        ],
        col_widths=[1*cm, 4.5*cm, 12*cm]
    ))
    story.append(sp(6))
    story.append(hr(ACCENT_BLUE))
    story.append(sp(6))

    # Final note
    story.append(Paragraph(
        "<i>FRAUD-X – Sentinel AI Fraud Detection Platform | Team MVCK | Final Year Project 2025–2026</i>",
        ParagraphStyle("Final", fontName="Helvetica-Oblique", fontSize=9,
                       textColor=TEXT_MID, alignment=TA_CENTER)
    ))

    # ── Build ────────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"PDF saved → {path}")


if __name__ == "__main__":
    build_pdf("FRAUDX_Project_Documentation.pdf")
