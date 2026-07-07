"""
FRAUD-X — Multi-Agent AI Fraud Architecture  v1.0
==================================================
§20 Collaborative AI agent system for parallel fraud analysis

Agent Roster
------------
  URLAgent        — URL phishing analysis (patterns, redirects, domain age)
  BiometricsAgent — Human behavior analysis (mouse, keyboard, scroll patterns)
  ThreatAgent     — Threat intelligence analysis (IP/domain reputation feeds)
  GraphAgent      — Fraud relationship analysis (entity graph, shared signals)
  VisionAgent     — Fake payment page detection (DOM structure, form analysis)
  RiskAgent       — Final fraud scoring (aggregates all agent outputs)
  SessionAgent    — Session-level intelligence (timing, velocity, patterns)
  BrowserAgent    — Browser environment risk analysis (env fingerprint, tampering)

Orchestration Model
-------------------
  1. All agents run concurrently via ThreadPoolExecutor
  2. Each agent returns an AgentResult (score 0-100, confidence 0-1, signals[])
  3. RiskAgent collects peer results and produces the final unified decision
  4. Shared fraud memory via memory_engine (§5/§18)
  5. Confidence fusion via confidence_fusion (§17)
  6. Results cached in memory_engine for 5 minutes
"""

from __future__ import annotations

import re
import time
import threading
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from memory_engine      import memory_engine
from confidence_fusion  import confidence_fusion, SourceSignal
from signature_engine   import signature_engine

# ── Orchestration config ──────────────────────────────────────
AGENT_TIMEOUT_S     = 3.0    # max seconds to wait per agent
MAX_WORKERS         = 8
RESULT_CACHE_TTL    = 300    # 5 minutes

# ── Risk thresholds ───────────────────────────────────────────
CRITICAL_THRESHOLD  = 81
HIGH_THRESHOLD      = 61
SUSPICIOUS_THRESHOLD= 31


class AgentName(str, Enum):
    URL         = "url_analysis"
    BIOMETRICS  = "biometrics"
    THREAT      = "threat_intel"
    GRAPH       = "graph"
    VISION      = "vision"
    RISK        = "risk"
    SESSION     = "session"
    BROWSER     = "browser"


# ═════════════════════════════════════════════════════════════
# Agent result
# ═════════════════════════════════════════════════════════════

@dataclass
class AgentResult:
    agent:      AgentName
    score:      float           # 0-100 fraud score
    confidence: float           # 0-1 reliability of this result
    signals:    list[str]       # human-readable signals detected
    metadata:   dict = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error:      Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "agent":      self.agent.value,
            "score":      round(self.score, 2),
            "confidence": round(self.confidence, 3),
            "signals":    self.signals,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "error":      self.error,
        }


@dataclass
class OrchestratorResult:
    """Unified output from all agents."""
    unified_score:      float
    certainty:          float
    severity:           str           # safe|suspicious|high|critical
    recommended_action: str
    agent_results:      list[AgentResult]
    dominant_agent:     str
    active_signals:     list[str]
    uncertainty_band:   tuple[float, float]
    execution_ms:       float
    request_id:         str

    def to_dict(self) -> dict:
        return {
            "unified_score":      round(self.unified_score, 2),
            "certainty":          round(self.certainty, 2),
            "severity":           self.severity,
            "recommended_action": self.recommended_action,
            "dominant_agent":     self.dominant_agent,
            "active_signals":     self.active_signals,
            "uncertainty_band":   [round(self.uncertainty_band[0], 2),
                                   round(self.uncertainty_band[1], 2)],
            "execution_ms":       round(self.execution_ms, 1),
            "request_id":         self.request_id,
            "agents":             [r.to_dict() for r in self.agent_results],
        }


# ═════════════════════════════════════════════════════════════
# Individual Agents
# ═════════════════════════════════════════════════════════════

class URLAgent:
    """Analyzes URL structure for phishing indicators."""

    _SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
                        ".click", ".link", ".online", ".site", ".top"}
    _BRAND_KEYWORDS  = {"paypal", "amazon", "google", "microsoft", "apple",
                        "facebook", "netflix", "bank", "secure", "login",
                        "verify", "update", "account", "signin", "wallet"}
    _SHORTENERS      = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                        "buff.ly", "is.gd", "rebrand.ly"}

    def analyze(self, url: str, domain: str, **_) -> AgentResult:
        t0      = time.perf_counter()
        score   = 0.0
        signals = []

        if not url and not domain:
            return AgentResult(AgentName.URL, 0.0, 0.1, [], elapsed_ms=0.0)

        target = (url or domain).lower()

        # Domain length heuristic
        dom = domain.lower() if domain else ""
        if len(dom) > 50:
            score += 15; signals.append("Unusually long domain")

        # Excessive subdomains
        parts = dom.split(".")
        if len(parts) > 4:
            score += 20; signals.append(f"Excessive subdomains ({len(parts)-2} levels)")

        # Brand impersonation
        hits = [kw for kw in self._BRAND_KEYWORDS if kw in target]
        if hits:
            score += min(30, len(hits) * 12)
            signals.append(f"Brand impersonation keywords: {', '.join(hits[:3])}")

        # Suspicious TLD
        for tld in self._SUSPICIOUS_TLDS:
            if dom.endswith(tld):
                score += 18; signals.append(f"High-risk TLD: {tld}"); break

        # URL shortener
        for sh in self._SHORTENERS:
            if sh in target:
                score += 25; signals.append(f"URL shortener detected: {sh}"); break

        # IP address as host
        if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url or ""):
            score += 30; signals.append("IP address used as hostname")

        # Non-HTTPS
        if url and url.startswith("http://"):
            score += 12; signals.append("Unencrypted HTTP connection")

        # Known phishing domain check (memory_engine)
        if dom and memory_engine.is_phishing_domain(dom):
            score = max(score, 90); signals.append("Known phishing domain (memory cache)")

        # Signature engine match
        sig_matches = signature_engine.match(url=url or "", domain=dom)
        if sig_matches:
            score = max(score, 75)
            signals.append(f"Signature match: {sig_matches[0].get('sig_id', 'SIG')}")

        score = min(100.0, score)
        conf  = 0.85 if score > 0 else 0.60
        return AgentResult(
            agent      = AgentName.URL,
            score      = score,
            confidence = conf,
            signals    = signals,
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


class BiometricsAgent:
    """Analyzes behavioral biometrics for bot/human classification."""

    def analyze(self, biometrics: Optional[dict] = None, **_) -> AgentResult:
        t0      = time.perf_counter()
        score   = 0.0
        signals = []

        if not biometrics:
            return AgentResult(AgentName.BIOMETRICS, 0.0, 0.2,
                               ["No biometrics data"], elapsed_ms=0.0)

        risk = biometrics.get("risk_score", 0)
        flags = biometrics.get("flags", [])

        score = float(risk)
        signals = list(flags)

        # Specific checks
        mouse = biometrics.get("mouse", {})
        if mouse.get("speed_uniformity", 1.0) < 0.3:
            score += 10; signals.append("Robotic mouse movement uniformity")
        if mouse.get("straight_lines", False):
            score += 8; signals.append("Linear mouse path detected")

        kbd = biometrics.get("keyboard", {})
        if kbd.get("interval_std", 100) < 5:
            score += 15; signals.append("Inhuman typing rhythm (<5ms std dev)")

        scroll = biometrics.get("scroll", {})
        if scroll.get("no_direction_changes", False):
            score += 8; signals.append("Scroll direction never changed")

        score = min(100.0, score)
        conf  = 0.75 if biometrics else 0.20
        return AgentResult(
            agent      = AgentName.BIOMETRICS,
            score      = score,
            confidence = conf,
            signals    = signals,
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


class ThreatAgent:
    """Checks IP and domain against threat intelligence."""

    # Known malicious IP prefixes (would be feed-driven in production)
    _BAD_IP_PREFIXES = {"185.220", "5.188", "194.165", "45.142", "103.143"}
    _RESIDENTIAL_PROXY_ASNS = {"AS9009", "AS20473", "AS14061"}

    def analyze(self, ip: str = "", domain: str = "", **_) -> AgentResult:
        t0      = time.perf_counter()
        score   = 0.0
        signals = []

        # Check memory_engine threat intel cache
        if ip:
            cached = memory_engine.get_threat_intel(f"ip:{ip}")
            if cached:
                score   = max(score, cached.get("score", 0))
                signals.append(f"Cached threat intel hit: {cached.get('reason', 'known bad')}")

        if domain:
            cached = memory_engine.get_threat_intel(f"domain:{domain}")
            if cached:
                score   = max(score, cached.get("score", 0))
                signals.append(f"Cached domain threat hit: {cached.get('reason', 'known bad')}")

        # IP prefix heuristics
        if ip:
            prefix2 = ".".join(ip.split(".")[:2])
            if prefix2 in self._BAD_IP_PREFIXES:
                score += 35; signals.append(f"Malicious IP range: {prefix2}.x.x")
            if memory_engine.is_known_bad(ip):
                score = max(score, 80); signals.append("IP in recent fraud attempt list")

        # Domain in phishing list
        if domain and memory_engine.is_phishing_domain(domain):
            score = max(score, 95); signals.append("Domain confirmed phishing (threat feed)")

        score = min(100.0, score)
        conf  = 0.90 if signals else 0.50
        return AgentResult(
            agent      = AgentName.THREAT,
            score      = score,
            confidence = conf,
            signals    = signals,
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


class GraphAgent:
    """Analyzes fraud relationships across entities (shared IPs, devices, domains)."""

    def analyze(
        self,
        ip: str = "", domain: str = "",
        device_fp: str = "", session_id: str = "",
        **_,
    ) -> AgentResult:
        t0      = time.perf_counter()
        score   = 0.0
        signals = []

        # Check if this device is flagged
        if device_fp and memory_engine.is_suspicious_device(device_fp):
            score += 40; signals.append("Device fingerprint previously flagged")

        # Check session history for escalation pattern
        if session_id:
            history = memory_engine.get_session_history(session_id)
            high_score_events = [e for e in history if e.get("score", 0) >= 70]
            if len(high_score_events) >= 2:
                score += 25
                signals.append(f"Session has {len(high_score_events)} prior high-risk events")

        # Check recent fraud attempts for same IP
        if ip and memory_engine.is_known_bad(ip):
            score += 30; signals.append(f"IP {ip[:15]} linked to recent fraud attempt")

        # Active campaigns involving this domain/IP
        campaigns = memory_engine.list_campaigns()
        for camp in campaigns:
            if camp.get("entities", 0) >= 5:
                score += 20
                signals.append(f"Active fraud campaign detected ({camp['id']})")
                break

        score = min(100.0, score)
        conf  = 0.70 if signals else 0.35
        return AgentResult(
            agent      = AgentName.GRAPH,
            score      = score,
            confidence = conf,
            signals    = signals,
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


class VisionAgent:
    """Detects fake payment pages via DOM/structural analysis."""

    _PAYMENT_KEYWORDS = {"card", "cvv", "expiry", "expiration", "billing",
                         "payment", "checkout", "purchase", "ssn", "social security"}
    _TRUSTED_PAYMENT_DOMAINS = {"stripe.com", "paypal.com", "braintree.com",
                                "square.com", "adyen.com", "checkout.com"}

    def analyze(
        self, url: str = "", domain: str = "",
        page_signals: Optional[dict] = None, **_
    ) -> AgentResult:
        t0      = time.perf_counter()
        score   = 0.0
        signals = []

        dom = domain.lower() if domain else ""
        target = (url or "").lower()

        # Payment page on untrusted domain
        is_payment_page = any(kw in target for kw in self._PAYMENT_KEYWORDS)
        is_trusted      = any(td in dom for td in self._TRUSTED_PAYMENT_DOMAINS)

        if is_payment_page and not is_trusted and dom:
            score += 35; signals.append("Payment keywords on untrusted domain")

        # DOM signals from page_signals (forwarded from content.js)
        if page_signals:
            if page_signals.get("hidden_iframes", 0) > 0:
                score += 25; signals.append(f"Hidden iframes detected ({page_signals['hidden_iframes']})")
            if page_signals.get("form_replaced", False):
                score += 40; signals.append("Payment form DOM replaced (injection)")
            if page_signals.get("script_injections", 0) > 2:
                score += 20; signals.append(f"Script injections: {page_signals['script_injections']}")
            if page_signals.get("external_form_action", False):
                score += 30; signals.append("Form submits to external domain")
            if page_signals.get("overlays_detected", 0) > 0:
                score += 20; signals.append("Overlay elements covering real content")

        score = min(100.0, score)
        conf  = 0.80 if (is_payment_page or page_signals) else 0.30
        return AgentResult(
            agent      = AgentName.VISION,
            score      = score,
            confidence = conf,
            signals    = signals,
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


class SessionAgent:
    """Analyzes session-level patterns for velocity and temporal anomalies."""

    def analyze(
        self, session_id: str = "", session_score: Optional[dict] = None,
        velocity: Optional[dict] = None, **_
    ) -> AgentResult:
        t0      = time.perf_counter()
        score   = 0.0
        signals = []

        if session_score:
            fp = session_score.get("fraud_probability", 0)
            score += fp * 100 * 0.5

            if session_score.get("human_authenticity", 1.0) < 0.4:
                score += 25; signals.append("Low human authenticity score")

            if session_score.get("hesitation_score", 0) > 0.7:
                score += 10; signals.append("No hesitation on payment fields (bot-like)")

            drift = session_score.get("behavioral_drift", 0)
            if drift > 0.5:
                score += 15; signals.append(f"Behavioral drift detected ({drift:.2f})")

        if velocity:
            count = velocity.get("count", 0)
            if count >= 12:
                score += 35; signals.append(f"Critical velocity: {count} requests/minute")
            elif count >= 6:
                score += 15; signals.append(f"Elevated velocity: {count} requests/minute")

        # Session history length
        if session_id:
            hist = memory_engine.get_session_history(session_id)
            if len(hist) > 50:
                score += 10; signals.append(f"Unusually long session ({len(hist)} events)")

        score = min(100.0, score)
        conf  = 0.65 if (session_score or velocity) else 0.20
        return AgentResult(
            agent      = AgentName.SESSION,
            score      = score,
            confidence = conf,
            signals    = signals,
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


class BrowserAgent:
    """Analyzes browser environment for tampering and risk indicators."""

    def analyze(self, browser_env: Optional[dict] = None, **_) -> AgentResult:
        t0      = time.perf_counter()
        score   = 0.0
        signals = []

        if not browser_env:
            return AgentResult(AgentName.BROWSER, 0.0, 0.15,
                               ["No browser env data"], elapsed_ms=0.0)

        if browser_env.get("webdriver_detected", False):
            score += 45; signals.append("WebDriver/automation detected")

        if browser_env.get("devtools_open", False):
            score += 15; signals.append("DevTools open during session")

        popups = browser_env.get("popup_count", 0)
        if popups >= 3:
            score += 20; signals.append(f"Excessive popups: {popups}")

        redirects = browser_env.get("redirect_count", 0)
        if redirects >= 3:
            score += 25; signals.append(f"Redirect chain length: {redirects}")

        ext_count = browser_env.get("extension_count", 0)
        if ext_count == 0:
            score += 10; signals.append("No browser extensions (headless indicator)")

        if browser_env.get("canvas_blocked", False):
            score += 12; signals.append("Canvas fingerprinting blocked")

        if browser_env.get("font_count", 20) < 5:
            score += 15; signals.append("Minimal fonts — likely headless browser")

        score = min(100.0, score)
        conf  = 0.70
        return AgentResult(
            agent      = AgentName.BROWSER,
            score      = score,
            confidence = conf,
            signals    = signals,
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


class RiskAgent:
    """Final scoring agent — aggregates peer agent outputs via confidence fusion."""

    def aggregate(self, peer_results: list[AgentResult]) -> AgentResult:
        t0      = time.perf_counter()
        signals = []
        sources = []

        for r in peer_results:
            if r.agent == AgentName.RISK:
                continue
            sources.append(SourceSignal(
                name       = r.agent.value,
                score      = r.score,
                confidence = r.confidence,
            ))
            signals.extend(r.signals)

        fusion = confidence_fusion.fuse(sources)
        score  = fusion.meta_score

        # Additional risk agent logic: escalate if any agent hits critical
        critical_agents = [r for r in peer_results if r.score >= CRITICAL_THRESHOLD]
        if len(critical_agents) >= 2:
            score = max(score, 85.0)
            signals.append(f"Multi-agent critical consensus ({len(critical_agents)} agents)")

        return AgentResult(
            agent      = AgentName.RISK,
            score      = min(100.0, score),
            confidence = fusion.certainty / 100.0,
            signals    = list(set(signals)),
            metadata   = {
                "fusion":           fusion.to_dict(),
                "critical_agents":  [r.agent.value for r in critical_agents],
            },
            elapsed_ms = (time.perf_counter() - t0) * 1000,
        )


# ═════════════════════════════════════════════════════════════
# §20 Multi-Agent Orchestrator
# ═════════════════════════════════════════════════════════════

class MultiAgentOrchestrator:
    """
    Orchestrates all fraud detection agents in parallel,
    collects results, and produces a unified OrchestratorResult.
    """

    def __init__(self):
        self._url_agent        = URLAgent()
        self._biometrics_agent = BiometricsAgent()
        self._threat_agent     = ThreatAgent()
        self._graph_agent      = GraphAgent()
        self._vision_agent     = VisionAgent()
        self._session_agent    = SessionAgent()
        self._browser_agent    = BrowserAgent()
        self._risk_agent       = RiskAgent()
        self._executor         = ThreadPoolExecutor(max_workers=MAX_WORKERS,
                                                    thread_name_prefix="fraudx-agent")
        self._lock             = threading.Lock()
        self._total_requests   = 0

    def analyze(
        self,
        url:          str  = "",
        domain:       str  = "",
        ip:           str  = "",
        device_fp:    str  = "",
        session_id:   str  = "",
        biometrics:   Optional[dict] = None,
        session_score:Optional[dict] = None,
        velocity:     Optional[dict] = None,
        browser_env:  Optional[dict] = None,
        page_signals: Optional[dict] = None,
    ) -> OrchestratorResult:
        """
        Run all agents concurrently and fuse their results.
        Returns a unified OrchestratorResult with severity and action.
        """
        t0 = time.perf_counter()

        request_id = "REQ-" + hashlib.sha1(
            f"{url}{ip}{device_fp}{time.time()}".encode()
        ).hexdigest()[:8].upper()

        kwargs = dict(
            url=url, domain=domain, ip=ip, device_fp=device_fp,
            session_id=session_id, biometrics=biometrics,
            session_score=session_score, velocity=velocity,
            browser_env=browser_env, page_signals=page_signals,
        )

        # Check result cache
        cache_key = f"orchestrator:{hashlib.sha1(f'{url}{ip}{device_fp}'.encode()).hexdigest()[:12]}"
        cached = memory_engine.get_threat_intel(cache_key)
        if cached:
            return self._dict_to_result(cached)

        # Dispatch all non-risk agents concurrently
        agent_map = {
            AgentName.URL:        lambda: self._url_agent.analyze(**kwargs),
            AgentName.BIOMETRICS: lambda: self._biometrics_agent.analyze(**kwargs),
            AgentName.THREAT:     lambda: self._threat_agent.analyze(**kwargs),
            AgentName.GRAPH:      lambda: self._graph_agent.analyze(**kwargs),
            AgentName.VISION:     lambda: self._vision_agent.analyze(**kwargs),
            AgentName.SESSION:    lambda: self._session_agent.analyze(**kwargs),
            AgentName.BROWSER:    lambda: self._browser_agent.analyze(**kwargs),
        }

        futures = {
            self._executor.submit(fn): name
            for name, fn in agent_map.items()
        }

        peer_results: list[AgentResult] = []
        for future in as_completed(futures, timeout=AGENT_TIMEOUT_S + 1):
            name = futures[future]
            try:
                result = future.result(timeout=AGENT_TIMEOUT_S)
                peer_results.append(result)
            except (FuturesTimeout, Exception) as exc:
                peer_results.append(AgentResult(
                    agent      = name,
                    score      = 0.0,
                    confidence = 0.0,
                    signals    = [],
                    error      = str(exc)[:120],
                ))

        # Risk agent aggregates
        risk_result = self._risk_agent.aggregate(peer_results)
        peer_results.append(risk_result)

        final_score  = risk_result.score
        certainty    = risk_result.confidence * 100.0
        severity     = self._severity(final_score)
        action       = self._action(final_score)
        all_signals  = list({s for r in peer_results for s in r.signals})
        fusion_meta  = risk_result.metadata.get("fusion", {})
        dominant     = fusion_meta.get("dominant_source", "unknown")
        band         = tuple(fusion_meta.get("uncertainty_band", [final_score, final_score]))

        elapsed = (time.perf_counter() - t0) * 1000

        orch_result = OrchestratorResult(
            unified_score      = final_score,
            certainty          = certainty,
            severity           = severity,
            recommended_action = action,
            agent_results      = peer_results,
            dominant_agent     = dominant,
            active_signals     = all_signals[:20],
            uncertainty_band   = band,
            execution_ms       = elapsed,
            request_id         = request_id,
        )

        # Cache result
        memory_engine.cache_threat_intel(cache_key, orch_result.to_dict(), ttl=RESULT_CACHE_TTL)

        # Feed into signature engine if high-confidence fraud
        if final_score >= 70 and certainty >= 60:
            signature_engine.ingest_fraud_event(
                score     = final_score,
                url       = url,
                domain    = domain,
                ip        = ip,
                device_fp = device_fp,
            )

        with self._lock:
            self._total_requests += 1

        return orch_result

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_requests":  self._total_requests,
                "active_workers":  self._executor._work_queue.qsize(),
                "agent_count":     len(AgentName),
            }

    # ── Internal helpers ──────────────────────────────────────

    @staticmethod
    def _severity(score: float) -> str:
        if score >= CRITICAL_THRESHOLD:   return "critical"
        if score >= HIGH_THRESHOLD:       return "high"
        if score >= SUSPICIOUS_THRESHOLD: return "suspicious"
        return "safe"

    @staticmethod
    def _action(score: float) -> str:
        if score >= CRITICAL_THRESHOLD:   return "block"
        if score >= HIGH_THRESHOLD:       return "challenge"
        if score >= SUSPICIOUS_THRESHOLD: return "warn"
        return "allow"

    @staticmethod
    def _dict_to_result(d: dict) -> OrchestratorResult:
        """Reconstruct OrchestratorResult from cached dict."""
        return OrchestratorResult(
            unified_score      = d.get("unified_score", 0.0),
            certainty          = d.get("certainty", 0.0),
            severity           = d.get("severity", "safe"),
            recommended_action = d.get("recommended_action", "allow"),
            agent_results      = [],    # not re-hydrated from cache
            dominant_agent     = d.get("dominant_agent", "unknown"),
            active_signals     = d.get("active_signals", []),
            uncertainty_band   = tuple(d.get("uncertainty_band", [0.0, 0.0])),
            execution_ms       = 0.0,
            request_id         = d.get("request_id", "CACHED"),
        )


# ── Singleton ─────────────────────────────────────────────────
multi_agent_orchestrator = MultiAgentOrchestrator()
