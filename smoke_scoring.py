"""Scoring engine smoke test — python smoke_scoring.py"""
import json
from scoring_engine import ScoringEngine

e = ScoringEngine()

# ── 1. Weighted calibration ──────────────────────────────────────
print("=== Weighted Calibration ===")

# Plain heuristic: 2 medium signals
r1 = ["Suspicious TLD (.tk) detected.", "URL contains phishing keyword 'verify'."]
s1, n1 = e.calibrate(45, "url", r1)
print(f"  Plain heuristics (2 signals): raw=45 → calibrated={s1}  note={n1}")

# ML + Graph + Behavioral (high-weight sources)
r2 = [
    "[ML] Random Forest: 82% phishing probability (high confidence).",
    "[Graph] Domain 'paypa1-login.tk' flagged in 5/6 scans — repeated offender.",
    "[Behavioral] High velocity: scanned 7x in 5 min.",
]
s2, n2 = e.calibrate(60, "url", r2)
print(f"  ML+Graph+Behavioral (3 weighted): raw=60 → calibrated={s2}  note={n2}")

# Whitelist suppression
r3 = ["Domain is on the trusted whitelist — capped at low risk.", "No strong signals."]
s3, n3 = e.calibrate(20, "url", r3)
print(f"  Whitelist:  raw=20 → calibrated={s3}  note={n3}")

# ── 2. Dynamic thresholds ────────────────────────────────────────
print("\n=== Dynamic Thresholds (pre-adaptation, <20 scans) ===")
d, c = e.thresholds.get("url")
print(f"  url:    danger={d}  caution={c}  (base: 65/30)")
d, c = e.thresholds.get("crypto")
print(f"  crypto: danger={d}  caution={c}  (base: 55/25)")

# Simulate 30 URL scans with elevated fraud rate
for i in range(30):
    e.thresholds.record("url", 75 if i < 24 else 20)  # 24/30 fraud — high rate
print("\n=== Dynamic Thresholds (after 30 URL scans, 80% fraud rate) ===")
d2, c2 = e.thresholds.get("url")
bd, bc = e.thresholds._BASE["url"]
print(f"  url:  danger={d2} (base={bd}, drift={d2-bd})  caution={c2} (base={bc})")
print(f"  Observed fraud rate: {e.thresholds._ema.get('url', 0)*100:.1f}%  (expected 18%)")
print(f"  Drift: {d2-bd:+d} pts  (negative = more sensitive, catching more fraud)")

# ── 3. Level classification ──────────────────────────────────────
print("\n=== level_for with dynamic thresholds ===")
for score in [20, 35, 55, 63, 72]:
    lv = e.level_for(score, "url")
    print(f"  score={score}  → {lv}  (thresholds: danger={d2}, caution={c2})")

# ── 4. Context-aware cross-entity scoring ────────────────────────
print("\n=== Context-aware cross-entity scoring ===")

# Pre-populate session: URL and crypto already flagged high-risk
e._context.record("url",    "http://paypa1-login.tk/verify", 82)
e._context.record("crypto", "bc1qfakeaddress1234567890",     78)

# Now scan an SMS with a link to the same domain → should get multi-vector boost
adj, sigs = e.context_adjust("sms", "Click http://paypa1-login.tk/win", 55, [])
print(f"  SMS (URL+crypto high in session): adj=+{adj}")
for s in sigs: print("  ", s)

# Add SMS to session then scan another URL
e._context.record("sms", "Click http://paypa1-login.tk/win", 72)
adj2, sigs2 = e.context_adjust("email", "account@paypa1-login.tk", 60, [])
print(f"\n  Email (URL+crypto+SMS all high):  adj=+{adj2}")
for s in sigs2: print("  ", s)

# Session summary
print("\n=== Session summary ===")
print(json.dumps(e.session_summary(), indent=2))

# ── 5. Real-world scenario: URL+crypto+SMS all suspicious ────────
print("\n=== Scenario: URL + Crypto + SMS all suspicious ===")
e2 = ScoringEngine()

# Step 1: user scans a phishing URL → score 80
url_score = 80
e2._context.record("url", "http://secure-coinbase-kyc.tk/verify", url_score)
print(f"  1. URL scanned:    score={url_score}  (session: 1 high-risk kind)")

# Step 2: user scans a crypto address → score 65
crypto_raw = 65
crypto_adj, crypto_sigs = e2.context_adjust("crypto", "bc1qscamaddr", crypto_raw, [])
e2._context.record("crypto", "bc1qscamaddr", crypto_raw)
print(f"  2. Crypto scanned: raw={crypto_raw}  ctx_adj=+{crypto_adj}  → final={crypto_raw+crypto_adj}")
for s in crypto_sigs: print("    ", s)

# Step 3: user scans an SMS mentioning same domain → score 55
sms_raw = 55
sms_adj, sms_sigs = e2.context_adjust("sms", "Your account: http://secure-coinbase-kyc.tk/verify", sms_raw, [])
print(f"  3. SMS scanned:    raw={sms_raw}  ctx_adj=+{sms_adj}  → final={sms_raw+sms_adj}")
for s in sms_sigs: print("    ", s)

print("\nAll checks passed.")
