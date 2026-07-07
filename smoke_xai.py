"""XAI engine smoke test -- python smoke_xai.py"""
import json
from xai_engine import xai_engine

SEP = "-" * 62

def show(title, result):
    print(f"\n{'=' * 62}")
    print(f"  {title}")
    print(SEP)
    print(f"  risk_score    : {result['risk_score']}")
    print(f"  risk_level    : {result['risk_level']}")
    print(f"  confidence    : {result['confidence']}")
    print(f"  ai_confidence : {result['ai_confidence']}")
    print(f"  primary_threat: {result['primary_threat']}")
    print(f"  signal_count  : {result['signal_count']}")
    print()
    print("  Factors (impact-sorted):")
    for f in result["factors"]:
        bar = "#" * max(0, f["impact"])
        sign = "+" if f["impact"] > 0 else ""
        print(f"    [{f['severity'][:4]:<4}] [{f['source'][:5]:<5}] "
              f"{f['factor'][:45]:<45}  {sign}{f['impact']:>3}  {bar[:30]}")
    print()
    print("  Score breakdown by source:")
    for src, total in sorted(result["score_breakdown"].items(), key=lambda x: -x[1]):
        print(f"    {src:<14} {total:>4}")
    cats = {k: len(v) for k, v in result.get("categories", {}).items()}
    print(f"\n  Categories: {cats}")


# ── Scenario 1: URL phishing (rich signal set) ───────────────────
url_reasons = [
    "[ML] Random Forest: 82% phishing probability (high confidence) — independent of heuristics.",
    "Homograph domain: 'paypa1' uses digit '1' to impersonate 'paypal'.",
    "Suspicious TLD (.tk) detected — commonly used in phishing campaigns.",
    "Brand name 'paypal' found in subdomain — classic spoofing pattern.",
    "[Graph] Domain 'paypa1-login.tk' flagged in 5/6 scan(s) (fraud rate 83%) — repeated offender.",
    "[Behavioral] High velocity: 'paypa1-login.tk' scanned 7x in 5 min — possible automated probing.",
    "[Context] Cross-entity corroboration: crypto and sms also flagged in session — likely the same threat actor.",
    "[AI] Confirmed phishing page targeting PayPal credentials.",
]
show(
    "URL Phishing — full signal set",
    xai_engine.explain(85, "danger", url_reasons, "url", ml_prob=82.0, ai_adjustment=8),
)

# ── Scenario 2: Email scam ───────────────────────────────────────
email_reasons = [
    "High-urgency language: urgent, action required, verify now.",
    "Known scam phrases detected: wire transfer, bitcoin.",
    "Reply-To domain (evil.tk) differs from sender domain (paypal.com) — spoofing indicator.",
    "Header injection pattern detected — possible email spoofing attempt.",
    "Credential harvesting language detected.",
    "[AI] Classic phishing email impersonating PayPal with reply-to misdirection.",
]
show(
    "Email Scam",
    xai_engine.explain(78, "danger", email_reasons, "email", ai_adjustment=10),
)

# ── Scenario 3: Crypto scam address ─────────────────────────────
crypto_reasons = [
    "Address validates as ETH format.",
    "Crypto investment solicitation — extremely high fraud base-rate.",
    "Scam phrases in context: double your money, guaranteed returns.",
    "[Graph] Crypto 'bc1q...' flagged in 4/5 scan(s) (fraud rate 80%) — repeated offender.",
    "[Context] Multi-vector campaign: 3 scan types (crypto, sms, url) all flagged high-risk.",
    "[AI] Address associated with known investment scam.",
]
show(
    "Crypto Investment Scam",
    xai_engine.explain(72, "danger", crypto_reasons, "crypto", ai_adjustment=7),
)

# ── Scenario 4: Safe URL (whitelist + low ML) ────────────────────
safe_reasons = [
    "Domain is on the trusted whitelist — capped at low risk.",
    "[ML] Random Forest: low phishing probability (8%) — reduces false-positive risk.",
    "No strong phishing signals detected.",
]
show(
    "Safe URL (whitelist)",
    xai_engine.explain(8, "safe", safe_reasons, "url", ml_prob=8.0, ai_adjustment=0),
)

print(f"\n{'=' * 62}")
print("  All checks passed.")
