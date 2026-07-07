"""
FRAUD-X  ·  Payment Gateway Protection Analyzer  v1.0
======================================================
Specialized detection for fake payment pages and gateway spoofing.

Detection layers
----------------
  1. Trusted gateway whitelist  — instant ✓ verification against 80+ known processors
  2. Payment brand spoofing     — leet normalization + Levenshtein typosquat detection
  3. Subdomain / path spoofing  — brand in wrong position
  4. Transport security         — HTTP on payment page, IP-based payment host
  5. Free-hosting detection     — netlify/vercel/github.io hosting payment forms
  6. Cross-domain form action   — form submits data to different domain (exfiltration)
  7. Merchant identity mismatch — page claims to be brand X but domain is brand Y

Public API
----------
  payment_analyzer.analyze(url, host, context)  → (score_delta, reasons, gateway_info)
  payment_analyzer.is_payment_url(url)           → bool
  payment_analyzer.check_trusted_gateway(host)  → (bool, str | None)
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ══════════════════════════════════════════════════════════════════
# ①  Trusted Gateway Registry
# ══════════════════════════════════════════════════════════════════

TRUSTED_GATEWAYS: set[str] = {
    # ── Global payment processors ─────────────────────────────────
    "stripe.com", "paypal.com", "paypal.me",
    "square.com", "squareup.com",
    "braintreepayments.com", "braintreegateway.com",
    "checkout.com", "adyen.com",
    "worldpay.com", "worldline.com",
    "authorize.net", "2checkout.com",
    "mollie.com", "klarna.com",
    "afterpay.com", "clearpay.co.uk", "clearpay.com",
    "affirm.com", "sezzle.com", "laybuy.com",
    "splitit.com", "quadpay.com", "zip.co",
    "payoneer.com", "skrill.com", "neteller.com",
    "paysafecard.com", "payvision.com",
    "hyperwallet.com", "payU.com",
    # ── India-specific gateways ───────────────────────────────────
    "razorpay.com", "paytm.com", "paytmbank.com",
    "phonepe.com", "gpay.app",
    "payu.in", "billdesk.com",
    "cashfree.com", "instamojo.com", "ccavenue.com",
    "airtelbank.in", "jiomoney.com",
    "googlepay.com", "bhimupi.org.in",
    # ── Card networks (official portals) ─────────────────────────
    "visa.com", "mastercard.com",
    "americanexpress.com", "amex.com",
    "discover.com", "discovercard.com",
    "rupay.co.in", "unionpayintl.com",
    "dinersclub.com",
    # ── Big-tech payment portals ──────────────────────────────────
    "pay.google.com", "pay.amazon.com",
    "appleid.apple.com", "checkout.shopify.com",
    "payments.amazon.com",
    # ── Major bank payment portals ────────────────────────────────
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citibank.com", "usbank.com",
    "hsbc.com", "barclays.co.uk", "barclays.com",
    "santander.co.uk", "nationwide.co.uk",
    "lloydsbank.com", "halifax.co.uk",
    "starlingbank.com", "monzo.com", "revolut.com",
    "sbi.co.in", "icicibank.com", "hdfcbank.com",
    "axisbank.com", "kotak.com", "yesbank.in",
    "td.com", "rbc.com", "scotiabank.com",
    "bmo.com", "cibc.com",
    "commbank.com.au", "westpac.com.au",
    "anz.com.au", "nab.com.au",
    # ── Crypto payment gateways (legitimate) ─────────────────────
    "coinbase.com", "bitpay.com",
    "coingate.com", "nowpayments.io",
    "cryptopay.me", "opennode.com",
    # ── Buy-now-pay-later ─────────────────────────────────────────
    "humm.com", "openpay.com.au",
    "zippay.com.au", "perpay.com",
    # ── Transfer / remittance ─────────────────────────────────────
    "wise.com", "transferwise.com",
    "westernunion.com", "moneygram.com",
    "remitly.com", "xoom.com",
}

# ── Free-hosting domains that legitimate gateways never use ──────────
_FREE_HOSTING_SUFFIXES: tuple[str, ...] = (
    "000webhostapp.com", "web.app", "netlify.app",
    "pages.dev", "vercel.app", "github.io",
    "gitlab.io", "firebaseapp.com", "glitch.me",
    "repl.co", "sites.google.com", "surge.sh",
    "cloudflare.dev", "workers.dev",
)

# ── Payment brands for spoofing detection ────────────────────────────
PAYMENT_BRANDS: list[str] = [
    "stripe", "paypal", "square", "braintree", "checkout",
    "adyen", "worldpay", "authorize", "klarna", "afterpay",
    "clearpay", "affirm", "sezzle", "razorpay", "paytm",
    "phonepe", "gpay", "payu", "billdesk", "cashfree",
    "instamojo", "ccavenue", "visa", "mastercard", "amex",
    "discover", "rupay", "unionpay", "zelle", "venmo",
    "cashapp", "wise", "revolut", "monzo", "skrill",
    "neteller", "payoneer", "mollie", "bitpay", "coinbase",
    "amazonpay", "applepay", "googlepay", "samsungpay",
    "upi", "bhim", "payme", "payfast", "paytabs",
]

# ── URL path/subdomain patterns that indicate a payment page ─────────
PAYMENT_URL_PATTERNS: list[str] = [
    r"/checkout",
    r"/payment",
    r"/pay(?:/|$|\?|#)",
    r"/order[/-]?confirm",
    r"/billing",
    r"/purchase",
    r"/cart[/-]checkout",
    r"/cart/pay",
    r"/shop/pay",
    r"/complete[/-]?order",
    r"/complete[/-]?purchase",
    r"/finalize",
    r"/secure[/-]?pay",
    r"/donate",
    r"/subscription[/-]pay",
    r"/proceed[/-]?to[/-]?pay",
    r"/transactions/new",
    r"/gateway",
    r"/confirm[/-]?payment",
    r"[?&]payment[=&]",
    r"[?&]checkout[=&]",
]

PAYMENT_SUBDOMAIN_KEYWORDS: set[str] = {
    "pay", "payment", "checkout", "secure", "billing",
    "order", "cart", "buy", "purchase", "gateway",
}

# ── Page-title keywords that confirm payment context ─────────────────
PAYMENT_TITLE_KEYWORDS: list[str] = [
    "checkout", "payment", "pay now", "complete order",
    "billing", "purchase", "order summary", "confirm payment",
    "secure payment", "enter card", "place order", "buy now",
    "card details", "payment details", "transaction",
]

# ── Form-field names that confirm a payment form ─────────────────────
PAYMENT_FORM_FIELD_KEYWORDS: list[str] = [
    "card number", "card-number", "cardnumber", "card_number",
    "cvv", "cvc", "security code", "expiry", "expiration",
    "cardholder", "card holder", "billing address",
    "upi id", "upi-id", "vpa", "virtual payment address",
    "account number", "routing number", "sort code", "ifsc",
    "crypto address", "wallet address", "bitcoin address",
    "card details", "payment method",
]


# ══════════════════════════════════════════════════════════════════
# ②  Utility helpers (mirrors main.py — kept local to avoid circular import)
# ══════════════════════════════════════════════════════════════════

_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l",
})


def _leet(s: str) -> str:
    return s.lower().translate(_LEET_MAP)


def _levenshtein(a: str, b: str) -> int:
    if a == b:  return 0
    if not a:   return len(b)
    if not b:   return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _registrable_core(host: str) -> str:
    """Return the SLD without TLD (best-effort)."""
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 4:
        return labels[-3]   # handle co.uk, com.au, etc.
    return labels[-2] if len(labels) >= 2 else labels[0]


# ══════════════════════════════════════════════════════════════════
# ③  PaymentGatewayAnalyzer
# ══════════════════════════════════════════════════════════════════

class PaymentGatewayAnalyzer:
    """
    Analyzes URLs and page context for payment gateway fraud signals.

    Usage in main.py (analyze_payment)
    ------------------------------------
    1. analyze_url() → base heuristic score / reasons
    2. payment_analyzer.analyze(url, host, context) → (delta, reasons, gw_info)
    3. Extend score/reasons, then run ML → Graph → Behavioral → Scoring → AI
    4. record_alert(kind="payment", ...)
    """

    # ── Fast URL check ──────────────────────────────────────────────

    def is_payment_url(self, url: str) -> bool:
        """True when the URL path / subdomain matches payment-page patterns."""
        url_low = url.lower()
        if any(re.search(p, url_low) for p in PAYMENT_URL_PATTERNS):
            return True
        try:
            host   = urlparse(url).hostname or ""
            labels = host.split(".")
            if labels and labels[0] in PAYMENT_SUBDOMAIN_KEYWORDS:
                return True
        except Exception:
            pass
        return False

    # ── Trusted-gateway lookup ──────────────────────────────────────

    def check_trusted_gateway(self, host: str) -> Tuple[bool, Optional[str]]:
        """
        Returns (is_trusted, matched_gateway_domain).
        Checks exact host, then strips subdomains until a match is found.
        e.g. "checkout.stripe.com" → matches "stripe.com" → (True, "stripe.com")
        """
        host = host.lower().rstrip(".")
        if host in TRUSTED_GATEWAYS:
            return True, host
        labels = host.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if parent in TRUSTED_GATEWAYS:
                return True, parent
        return False, None

    # ── Core analysis ───────────────────────────────────────────────

    def analyze(
        self,
        url:     str,
        host:    str,
        context: Dict,
    ) -> Tuple[int, List[str], Dict]:
        """
        Analyze payment-specific fraud signals on top of the base URL scan.

        Parameters
        ----------
        url      : Full page URL
        host     : Parsed hostname (lowercase, already extracted by main.py)
        context  : {
                     page_title       : str | None,
                     merchant_name    : str | None,
                     has_payment_form : bool,
                     form_action_url  : str | None,
                     form_field_names : list[str],  (optional)
                   }

        Returns
        -------
        (score_delta, extra_reasons, gateway_info)
          score_delta : int to ADD to the running score (can be negative for trusted)
          extra_reasons : list of new reason strings (ready to append to reasons)
          gateway_info  : dict with keys:
              is_trusted, verified_gateway, is_payment_page,
              payment_signals, merchant_mismatch, scheme
        """
        reasons:  List[str] = []
        delta:    int        = 0
        signals:  List[str]  = []

        parsed          = urlparse(url)
        scheme          = (parsed.scheme or "http").lower()
        core            = _registrable_core(host)
        norm_core       = _leet(core)
        labels          = host.split(".")
        tld             = labels[-1] if labels else ""
        path_low        = (parsed.path or "").lower()
        has_pmt_form    = bool(context.get("has_payment_form"))
        page_title      = (context.get("page_title") or "").lower()
        merchant        = (context.get("merchant_name") or "").lower()
        form_action     = (context.get("form_action_url") or "").lower()
        form_fields     = context.get("form_field_names") or []
        is_pmt_url      = self.is_payment_url(url)
        is_pmt_context  = is_pmt_url or has_pmt_form

        # Confirm payment context from title / form fields if not caught by URL
        if not is_pmt_context:
            title_hit = any(kw in page_title for kw in PAYMENT_TITLE_KEYWORDS)
            field_hit = any(
                any(kw in f.lower() for kw in PAYMENT_FORM_FIELD_KEYWORDS)
                for f in form_fields
            )
            if title_hit or field_hit:
                is_pmt_context = True

        # ── 1. Trusted-gateway fast-path ─────────────────────────
        is_trusted, verified = self.check_trusted_gateway(host)

        if is_trusted:
            delta -= 30
            reasons.append(
                f"Verified payment gateway: '{verified}' is on the FRAUD-X trusted "
                f"gateway whitelist. ✓ Payment processing is legitimate."
            )
            signals.append("trusted_gateway")

            gateway_info = {
                "is_trusted":        True,
                "verified_gateway":  verified,
                "is_payment_page":   is_pmt_context,
                "payment_signals":   signals,
                "merchant_mismatch": False,
                "scheme":            scheme,
            }
            return delta, reasons, gateway_info

        # ── 2. Payment brand spoofing ────────────────────────────
        spoofed = False
        for brand in PAYMENT_BRANDS:
            if norm_core == brand and core != brand:
                delta += 65
                reasons.append(
                    f"Domain '{core}' is a leet-speak / character-substitution spoof of "
                    f"payment brand '{brand}' — this is a fake payment page."
                )
                signals.append("leet_brand_spoof")
                spoofed = True
                break

            dist = _levenshtein(norm_core, brand)
            if 0 < dist <= 2 and len(brand) >= 5:
                pts = 60 if dist == 1 else 50
                delta += pts
                reasons.append(
                    f"Domain '{core}' is {dist} character(s) from payment brand "
                    f"'{brand}' — likely typosquatted payment gateway."
                )
                signals.append("typosquat_gateway")
                spoofed = True
                break

            # Brand as first subdomain label on a different registrable domain
            if (len(labels) >= 3
                    and (labels[0] == brand or _leet(labels[0]) == brand)
                    and core != brand):
                delta += 55
                reasons.append(
                    f"Payment brand '{brand}' used as subdomain of '{host}' — "
                    f"the real '{brand}' gateway domain does not match."
                )
                signals.append("brand_subdomain_spoof")
                spoofed = True
                break

            # Brand keyword appears in URL path (not in the domain itself)
            if brand in path_low and not is_trusted and len(brand) >= 4:
                delta += 30
                reasons.append(
                    f"Payment brand '{brand}' appears in URL path while domain is "
                    f"'{host}' — credential-harvesting page mimicking {brand}."
                )
                signals.append("brand_in_path")
                spoofed = True
                break

        # ── 3. HTTP on a payment page ────────────────────────────
        if scheme == "http" and is_pmt_context:
            delta += 45
            reasons.append(
                "Payment page served over HTTP (not HTTPS). Card data, passwords, and "
                "UPI PINs would be transmitted in plaintext and can be intercepted."
            )
            signals.append("http_payment_page")

        # ── 4. IP-based payment host ─────────────────────────────
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) and is_pmt_context:
            delta += 75
            reasons.append(
                f"Payment page hosted on a raw IP address ({host}). No legitimate "
                f"payment gateway ever uses an IP address as its checkout URL."
            )
            signals.append("ip_based_payment_page")

        # ── 5. Suspicious TLD on payment page ────────────────────
        _SUSPICIOUS_PAYMENT_TLDS = {
            "tk", "ml", "ga", "cf", "gq", "top", "xyz",
            "click", "loan", "bid", "party", "trade",
            "icu", "cyou", "monster", "best", "rest",
        }
        if tld in _SUSPICIOUS_PAYMENT_TLDS and is_pmt_context:
            delta += 40
            reasons.append(
                f"Payment page uses suspicious TLD '.{tld}' — free or abuse-prone "
                f"domains never used by real payment processors."
            )
            signals.append("suspicious_tld_payment")

        # ── 6. Free-hosting service hosting a payment form ───────
        for suffix in _FREE_HOSTING_SUFFIXES:
            if host.endswith(suffix) and is_pmt_context:
                delta += 50
                reasons.append(
                    f"Payment form hosted on free hosting service "
                    f"('{suffix}'). Real payment gateways never use "
                    f"free hosting for checkout pages."
                )
                signals.append("free_hosting_payment")
                break

        # ── 7. Cross-domain form action (data exfiltration) ──────
        if form_action and has_pmt_form:
            try:
                action_host = urlparse(form_action).hostname or ""
                if action_host and action_host.lower() != host:
                    action_core = _registrable_core(action_host.lower())
                    if action_core != core:
                        delta += 40
                        reasons.append(
                            f"Payment form submits data to '{action_host}' "
                            f"(different domain from the page '{host}') — "
                            f"possible data exfiltration."
                        )
                        signals.append("cross_domain_form_action")
            except Exception:
                pass

        # ── 8. Merchant name / domain identity mismatch ──────────
        merchant_mismatch = False
        if merchant and not spoofed:
            merchant_norm = _leet(re.sub(r"[^a-z0-9]", "", merchant))
            if merchant_norm and merchant_norm not in norm_core and core not in merchant_norm:
                for brand in PAYMENT_BRANDS:
                    if brand in merchant_norm and brand not in norm_core:
                        merchant_mismatch = True
                        delta += 40
                        reasons.append(
                            f"Merchant claims to be '{merchant}' (a known payment brand) "
                            f"but page domain is '{host}' — likely impersonation."
                        )
                        signals.append("merchant_brand_mismatch")
                        break

        # ── 9. Unencrypted payment form with no other TLS signal ─
        if has_pmt_form and scheme not in ("https",) and "http_payment_page" not in signals:
            delta += 35
            reasons.append(
                "Payment form detected on a page not served over HTTPS — "
                "user payment data is not encrypted in transit."
            )
            signals.append("no_tls_payment_form")

        gateway_info = {
            "is_trusted":        False,
            "verified_gateway":  None,
            "is_payment_page":   is_pmt_context,
            "payment_signals":   signals,
            "merchant_mismatch": merchant_mismatch,
            "scheme":            scheme,
        }
        return delta, reasons, gateway_info


# ── Singleton ─────────────────────────────────────────────────────────
payment_analyzer = PaymentGatewayAnalyzer()
