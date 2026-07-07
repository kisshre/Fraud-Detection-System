"""
FRAUD-X  ·  Explainability Engine  (XAI v2)
============================================
Converts a (score, reasons) pair into a structured, per-factor
impact-attributed explanation usable by both the API and the dashboard.

Output structure
----------------
{
  "risk_score":     85,
  "risk_level":     "danger",
  "confidence":     "high",          # overall detection confidence
  "ai_confidence":  "medium",        # confidence in AI layer specifically
  "primary_threat": "Homograph brand spoofing",
  "signal_count":   7,
  "factors": [                       # the user-facing impact list
    {"factor": "Homograph brand spoofing",   "impact": 42, "severity": "critical", "source": "heuristic"},
    {"factor": "ML Random Forest: 82%",      "impact": 14, "severity": "high",     "source": "ml"},
    {"factor": "Graph: Repeat offender",     "impact": 12, "severity": "high",     "source": "graph"},
    {"factor": "Behavioral: High velocity",  "impact": 10, "severity": "medium",   "source": "behavioral"},
    {"factor": "Context: Multi-vector …",    "impact": 13, "severity": "high",     "source": "context"},
    {"factor": "AI: Confirmed phishing …",   "impact":  5, "severity": "medium",   "source": "ai"},
    {"factor": "Trusted domain (whitelist)", "impact": -8, "severity": "informational", "source": "heuristic"},
  ],
  "score_breakdown": {               # per-source totals (pie-chart ready)
    "heuristic": 60,
    "ml": 14,
    "graph": 12,
    "behavioral": 10,
    "context": 13,
    "ai": 5,
  },
  "categories": {                    # grouped by severity (badge view)
    "critical": ["Homograph …"],
    "high":     ["ML …", "Graph …"],
    ...
  },
  "fraud_type_prior": 18.0,
}

Impact values are proportionally scaled so positive contributions sum to
approximately the final risk_score — giving an honest picture of score
composition without requiring every analyzer to instrument each `score +=`.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════
# ①  Heuristic impact table
#    Ordered: first match wins.
#    Each row: ([keywords_to_match], base_impact, severity, short_label)
# ══════════════════════════════════════════════════════════════════

_RULES: List[Tuple[List[str], int, str, str]] = [
    # ── Critical (35-50) ─────────────────────────────────────────
    (["homograph"],                     45, "critical", "Homograph brand spoofing"),
    (["hash match"],                    45, "critical", "Malware hash match"),
    (["dga characteristic"],            40, "critical", "DGA domain generation"),
    (["double extension"],              40, "critical", "Double file extension"),
    (["vba macro"],                     40, "critical", "VBA macro detected"),
    (["header injection"],              35, "critical", "Email header injection"),
    (["seed phrase"],                   45, "critical", "Seed phrase exposure"),
    (["private key"],                   45, "critical", "Private key exposure"),
    (["dangerous destination"],         40, "critical", "Dangerous redirect target"),
    (["exploit", "shellcode"],          45, "critical", "Exploit / shellcode"),
    # ── High (20-35) ─────────────────────────────────────────────
    (["impersonat"],                    35, "high", "Brand impersonation"),
    (["typosquat"],                     35, "high", "Typosquat domain"),
    (["leet"],                          30, "high", "Leet-speak brand spoofing"),
    (["brand", "spoofing indicator"],   28, "high", "Brand spoofing"),
    (["phishing keyword"],              28, "high", "Phishing keyword in URL"),
    (["scam phrase"],                   25, "high", "Known scam language"),
    (["mixer", "tumbler"],              35, "high", "Crypto mixer reference"),
    (["reply-to"],                      30, "high", "Reply-to domain mismatch"),
    (["investment solicitation"],       30, "high", "Investment scam context"),
    (["payment via dm"],                45, "high", "DM payment solicitation"),
    (["dangerous"],                     35, "high", "Linked high-risk domain"),
    (["punycode"],                      25, "high", "Punycode / IDN encoding"),
    (["does not match.*format"],        25, "high", "Invalid crypto address format"),
    (["urgency", "urgent"],             22, "high", "High-urgency language"),
    (["credential harvesting"],         25, "high", "Credential harvesting"),
    (["no-reply.*suspicious"],          25, "high", "Suspicious no-reply sender"),
    (["wire transfer"],                 22, "high", "Wire transfer request"),
    (["gift card", "western union"],    22, "high", "Unusual payment method"),
    (["bitcoin", "crypto.*request"],    20, "high", "Crypto payment request"),
    (["new account.*selling"],          25, "high", "New-account seller"),
    (["scam wallet"],                   30, "high", "Known scam wallet type"),
    # ── Medium (10-20) ───────────────────────────────────────────
    (["suspicious tld"],                20, "medium", "Suspicious TLD"),
    (["ip.*host", "hosted on ip"],      20, "medium", "IP address as host"),
    (["brand.*subdomain"],              20, "medium", "Brand name in subdomain"),
    (["entropy"],                       15, "medium", "High-entropy domain"),
    (["url shortener"],                 15, "medium", "URL shortener"),
    (["redirect"],                      15, "medium", "Open redirect parameter"),
    (["free hosting"],                  15, "medium", "Free-hosting TLD"),
    (["many subdomains", "excessive subdomains"], 15, "medium", "Excessive subdomains"),
    (["suspicious.*sender"],            20, "medium", "Suspicious sender address"),
    (["consecutive digits"],            15, "medium", "Numeric sender pattern"),
    (["reserved ip", "private ip"],     15, "medium", "Reserved IP range"),
    (["privacy coin", "monero"],        15, "medium", "Privacy coin (XMR)"),
    (["disposable wallet"],             10, "medium", "Disposable wallet entropy"),
    (["encoding.*obfuscat"],            20, "medium", "Encoded header obfuscation"),
    (["low follower"],                  15, "medium", "Low follower / following ratio"),
    (["days old", "account.*days"],     12, "medium", "New account age"),
    (["new account"],                   12, "medium", "New account"),
    (["investment.*bio", "binary option", "passive income"], 15, "medium", "Scam investment bio"),
    (["profile link.*suspicious"],      15, "medium", "Suspicious profile link"),
    # ── Informational catch-alls (before generic 'suspicious') ───
    (["no strong", "no obvious", "not detected", "normal caution"], 0, "informational", "No fraud signals"),
    (["validates as"],                    0, "informational", "Address format validated"),
    (["whitelist", "trusted whitelist"], -20, "informational", "Trusted domain (whitelist)"),
    (["reduces false-positive", "low phishing probability"], -5, "informational", "ML: Low-risk signal"),
    (["suspicious"],                    12, "medium", "Suspicious pattern"),
    # ── Low (5-10) ───────────────────────────────────────────────
    (["attachment"],                    10, "low", "Email attachments"),
    (["many link", "excessive link"],    8, "low", "Excessive links"),
    (["grammar", "typical.*scam"],       8, "low", "Scam grammar pattern"),
    (["large file", "small file"],       8, "low", "Unusual file size"),
    (["few unique"],                    10, "low", "Low character diversity"),
    (["payment request"],               10, "low", "Crypto payment context"),
    (["donation address"],               5, "low", "Donation address context"),
]


def _clean(text: str, max_len: int = 60) -> str:
    """Short, readable label from a raw reason string."""
    text = re.sub(r'^\[(?:ML|AI|Graph|Behavioral|Context|Campaign)\]\s*', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\s*[—–]\s+.*$', '', text)
    text = re.sub(r'\s*\([^)]{10,}\)\s*$', '', text)
    return text.rstrip('.').strip()[:max_len]


# ══════════════════════════════════════════════════════════════════
# ②  XAIEngine
# ══════════════════════════════════════════════════════════════════

class XAIEngine:
    """
    Converts (score, reasons, scan_type) into a full explanation dict.

    Impact values are estimated per signal then proportionally scaled so
    that positive contributions sum to approximately the final risk_score.
    """

    # ── Tagged-signal parsers ─────────────────────────────────────

    def _ml(self, reason: str, ml_prob: Optional[float]) -> Tuple[int, str]:
        pct = ml_prob
        if pct is None:
            m = re.search(r'(\d+(?:\.\d+)?)\s*%', reason)
            pct = float(m.group(1)) if m else 50.0
        if pct >= 75:
            return 15, f"ML Random Forest: {pct:.0f}% phishing"
        if pct >= 50:
            return 7,  f"ML Random Forest: {pct:.0f}% moderate"
        return -5, f"ML Random Forest: {pct:.0f}% (low risk)"

    def _graph(self, reason: str) -> Tuple[int, str]:
        r_low = reason.lower()
        m = re.search(r'(\d+)\s*fraud hit', r_low)
        if m:
            impact = min(20, int(m.group(1)) * 2 + 6)
        elif "infrastructure reuse" in r_low:
            impact = 12
        elif "repeat" in r_low:
            impact = 14
        else:
            impact = 8
        return impact, "Graph: " + _clean(reason, 50)

    def _behavioral(self, reason: str) -> Tuple[int, str]:
        r_low = reason.lower()
        if "campaign velocity" in r_low or "automated scanning" in r_low:
            impact = 15
        elif "active campaign" in r_low:
            impact = 10
        elif "velocity" in r_low:
            impact = 12
        elif "recurring target" in r_low:
            impact = 8
        elif "persistent" in r_low:
            impact = 8
        elif "cluster" in r_low:
            impact = 7
        elif "burst" in r_low:
            impact = 5
        else:
            impact = 6
        return impact, "Behavioral: " + _clean(reason, 50)

    def _context(self, reason: str) -> Tuple[int, str]:
        r_low = reason.lower()
        if "multi-vector" in r_low:
            impact = 15
        elif "corroboration" in r_low:
            impact = 8
        elif "infrastructure reuse" in r_low or "same-actor" in r_low:
            impact = 10
        else:
            impact = 6
        return impact, "Context: " + _clean(reason, 50)

    def _heuristic(self, reason: str) -> Tuple[int, str, str]:
        """Returns (impact, label, severity) for a plain heuristic reason."""
        r_low = reason.lower()
        for keywords, impact, severity, label in _RULES:
            if all(bool(re.search(kw, r_low)) for kw in keywords):
                return impact, label, severity
        return 10, _clean(reason, 60), "medium"

    # ── Core explain ──────────────────────────────────────────────

    def explain(
        self,
        score:         int,
        level:         str,
        reasons:       List[str],
        scan_type:     str,
        ml_prob:       Optional[float] = None,
        ai_adjustment: int = 0,
    ) -> Dict:
        """
        Build the full XAI explanation dict.

        Parameters
        ----------
        score         : final 0-100 risk score
        level         : "danger" | "caution" | "safe"
        reasons       : reason strings accumulated during analysis
        scan_type     : "url" | "email" | "crypto" | etc.
        ml_prob       : Random Forest output 0-100 (URL analyzer)
        ai_adjustment : signed score delta from Claude AI layer
        """
        raw: List[Dict] = []
        categories: Dict[str, List[str]] = {
            "critical": [], "high": [], "medium": [], "low": [], "informational": [],
        }

        for reason in reasons:
            r_low = reason.lstrip().lower()

            # ── Tagged sources ────────────────────────────────
            if r_low.startswith("[ml]"):
                impact, label = self._ml(reason, ml_prob)
                sev    = "critical" if impact >= 35 else "high" if impact >= 10 else "informational"
                source = "ml"

            elif r_low.startswith("[graph]"):
                impact, label = self._graph(reason)
                sev    = "high" if impact >= 14 else "medium"
                source = "graph"

            elif r_low.startswith("[behavioral]"):
                impact, label = self._behavioral(reason)
                sev    = "high" if impact >= 12 else "medium"
                source = "behavioral"

            elif r_low.startswith("[context]"):
                impact, label = self._context(reason)
                sev    = "high" if impact >= 12 else "medium"
                source = "context"

            elif r_low.startswith("[campaign]"):
                impact, label = 8, "Campaign: " + _clean(reason, 50)
                sev, source   = "high", "behavioral"

            elif r_low.startswith("[ai]"):
                # Use the actual signed delta when it was passed
                impact = ai_adjustment if ai_adjustment != 0 else 5
                label  = "AI: " + _clean(reason, 55)
                sev    = "high" if impact >= 10 else "medium" if impact >= 3 else "low"
                source = "ai"

            else:
                # ── Plain heuristic ───────────────────────────
                impact, label, sev = self._heuristic(reason)
                source = "heuristic"

            raw.append({
                "factor":   label,
                "impact":   impact,
                "severity": sev,
                "source":   source,
                "_reason":  reason,  # kept for categories; stripped from output
            })
            categories[sev].append(reason)

        # ── Proportional scaling ──────────────────────────────────
        # Scale positive impacts so their sum ≈ risk_score.
        # Negative impacts (whitelist etc.) are kept as-is.
        pos_raw = sum(f["impact"] for f in raw if f["impact"] > 0)
        neg_raw = sum(f["impact"] for f in raw if f["impact"] < 0)
        net_target = max(score - neg_raw, 0)
        if pos_raw > 0:
            scale = max(0.25, min(1.6, net_target / pos_raw))
        else:
            scale = 1.0

        factors: List[Dict] = []
        for f in raw:
            scaled = round(f["impact"] * scale) if f["impact"] > 0 else f["impact"]
            factors.append({
                "factor":   f["factor"],
                "impact":   scaled,
                "severity": f["severity"],
                "source":   f["source"],
            })

        # Sort: highest positive first, then zero, then negative
        factors.sort(key=lambda x: (-max(x["impact"], 0), x["impact"]))

        # ── Score breakdown by source ─────────────────────────────
        breakdown: Dict[str, int] = {}
        for f in factors:
            if f["impact"] != 0:
                breakdown[f["source"]] = breakdown.get(f["source"], 0) + f["impact"]

        # ── Confidence ────────────────────────────────────────────
        pos_count    = sum(1 for f in raw if f["impact"] > 0)
        crit_hi      = sum(1 for f in raw if f["severity"] in ("critical", "high") and f["impact"] > 0)
        if crit_hi >= 2 and score >= 65:
            confidence = "high"
        elif pos_count >= 3 and score >= 30:
            confidence = "medium"
        elif pos_count >= 1:
            confidence = "low"
        else:
            confidence = "minimal"

        ai_conf = (
            "high"   if abs(ai_adjustment) >= 10 else
            "medium" if abs(ai_adjustment) >= 3  else
            "low"
        )

        # ── Primary threat ────────────────────────────────────────
        primary = next(
            (f["factor"] for f in factors if f["severity"] == "critical"       and f["impact"] > 0), next(
            (f["factor"] for f in factors if f["severity"] == "high"           and f["impact"] > 0), None),
        )

        return {
            "risk_score":      score,
            "risk_level":      level,
            "confidence":      confidence,
            "ai_confidence":   ai_conf,
            "primary_threat":  primary,
            "signal_count":    sum(1 for f in raw if f["impact"] >= 0 and not f["_reason"].startswith("No ")),
            "factors":         factors,
            "score_breakdown": breakdown,
            "categories":      {k: v for k, v in categories.items() if v},
            "fraud_type_prior": round({
                "url": 18.0, "email": 22.0, "phone": 18.0, "sms": 24.0,
                "file": 12.0, "merchant": 16.0, "social": 26.0,
                "qr": 20.0,  "ip": 10.0,  "crypto": 32.0,
            }.get(scan_type, 15.0), 1),
        }


# ── Singleton ─────────────────────────────────────────────────────
xai_engine = XAIEngine()
