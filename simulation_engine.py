"""
FRAUD-X — AI Fraud Simulation Engine  v1.0
===========================================
§15 Synthetic fraud scenario generation for testing and ML training

Simulation Scenarios
--------------------
  PHISHING_CAMPAIGN    — coordinated phishing attack on multiple users
  BOT_ATTACK           — automated scraping/form-submission botnet
  CREDENTIAL_STUFFING  — credential replay from leaked databases
  TRANSACTION_BURST    — rapid high-value transaction flood
  COORDINATED_CAMPAIGN — multi-vector coordinated fraud campaign
  ATO_ATTACK           — account takeover via stolen session tokens
  CARDING_TEST         — card testing (small test charges before fraud)

Each scenario generates a stream of realistic FraudEvent dicts that
can be fed through the full FRAUD-X pipeline for:
  - Model validation and regression testing
  - ML training data augmentation
  - Alert threshold calibration
  - Red-team exercises

Output format matches the real FraudEvent consumed by window_analytics.py
so simulated events can be injected transparently into the analytics pipeline.
"""

from __future__ import annotations

import hashlib
import math
import random
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Optional

# ── Simulation parameters ─────────────────────────────────────
DEFAULT_SEED        = 42
MAX_EVENTS_PER_RUN  = 10_000
BURST_DURATION_S    = 60      # simulated seconds for a burst scenario
CAMPAIGN_USERS      = 50      # number of simulated victims


class ScenarioType(str, Enum):
    PHISHING_CAMPAIGN    = "phishing_campaign"
    BOT_ATTACK           = "bot_attack"
    CREDENTIAL_STUFFING  = "credential_stuffing"
    TRANSACTION_BURST    = "transaction_burst"
    COORDINATED_CAMPAIGN = "coordinated_campaign"
    ATO_ATTACK           = "ato_attack"
    CARDING_TEST         = "carding_test"


# ═════════════════════════════════════════════════════════════
# Simulated event structure
# ═════════════════════════════════════════════════════════════

@dataclass
class SimEvent:
    """Simulated fraud event — matches FraudEvent schema in window_analytics."""
    score:      float
    severity:   str
    url:        str
    ip:         str
    session_id: str
    kind:       str
    domain:     str
    user_id:    str
    ts:         float = field(default_factory=time.time)

    # Simulation-specific extras
    scenario:   str = ""
    is_fraud:   bool = True          # ground truth label

    def to_dict(self) -> dict:
        return {
            "score":      round(self.score, 2),
            "severity":   self.severity,
            "url":        self.url,
            "ip":         self.ip,
            "session_id": self.session_id,
            "kind":       self.kind,
            "domain":     self.domain,
            "user_id":    self.user_id,
            "ts":         self.ts,
            "scenario":   self.scenario,
            "is_fraud":   self.is_fraud,
        }


@dataclass
class SimulationRun:
    """Result of a completed simulation run."""
    scenario:       ScenarioType
    events:         list[SimEvent]
    true_frauds:    int
    true_legit:     int
    mean_score:     float
    peak_score:     float
    duration_s:     float
    config:         dict

    def to_dict(self) -> dict:
        return {
            "scenario":    self.scenario.value,
            "event_count": len(self.events),
            "true_frauds": self.true_frauds,
            "true_legit":  self.true_legit,
            "mean_score":  round(self.mean_score, 2),
            "peak_score":  round(self.peak_score, 2),
            "duration_s":  round(self.duration_s, 3),
            "config":      self.config,
            "events":      [e.to_dict() for e in self.events[:100]],  # first 100 only
        }


# ═════════════════════════════════════════════════════════════
# Scenario generators
# ═════════════════════════════════════════════════════════════

class _ScenarioBase:
    """Base class with shared synthetic data helpers."""

    # Synthetic phishing domain pool
    _PHISHING_DOMAINS = [
        "paypa1-secure.xyz", "amazon-verify.tk", "secure-login-bank.ml",
        "microsoft-update.cf", "apple-id-verify.pw", "google-signin.top",
        "netflix-billing.online", "bankofamerica-secure.site",
        "paypallogin-verify.click", "amazon-order-confirm.link",
    ]
    _LEGIT_DOMAINS = [
        "amazon.com", "paypal.com", "google.com", "microsoft.com",
        "apple.com", "netflix.com", "bankofamerica.com",
    ]
    _MALICIOUS_IP_BLOCKS = [
        "185.220.{}.{}", "5.188.{}.{}", "194.165.{}.{}", "45.142.{}.{}",
    ]
    _RESIDENTIAL_IPS = [
        "72.14.{}.{}", "98.137.{}.{}", "64.233.{}.{}", "74.125.{}.{}",
    ]
    _PAYMENT_PATHS = [
        "/checkout/payment", "/billing/update", "/account/verify",
        "/secure/login", "/payment/confirm", "/card/update",
    ]

    def __init__(self, rng: random.Random):
        self._rng = rng

    def _phishing_url(self) -> tuple[str, str]:
        dom = self._rng.choice(self._PHISHING_DOMAINS)
        path = self._rng.choice(self._PAYMENT_PATHS)
        return f"https://{dom}{path}", dom

    def _legit_url(self) -> tuple[str, str]:
        dom = self._rng.choice(self._LEGIT_DOMAINS)
        path = self._rng.choice(["/", "/account", "/cart", "/search"])
        return f"https://{dom}{path}", dom

    def _mal_ip(self) -> str:
        template = self._rng.choice(self._MALICIOUS_IP_BLOCKS)
        return template.format(self._rng.randint(1, 254), self._rng.randint(1, 254))

    def _res_ip(self) -> str:
        template = self._rng.choice(self._RESIDENTIAL_IPS)
        return template.format(self._rng.randint(1, 254), self._rng.randint(1, 254))

    def _session(self) -> str:
        return "sim-" + hashlib.sha1(
            str(self._rng.random()).encode()
        ).hexdigest()[:12]

    def _user(self, i: int) -> str:
        return f"user_{i:05d}"

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 81: return "critical"
        if score >= 61: return "high"
        if score >= 31: return "suspicious"
        return "safe"


class PhishingCampaignScenario(_ScenarioBase):
    """Simulates a coordinated phishing campaign targeting many users."""

    def generate(self, n_users: int = CAMPAIGN_USERS) -> list[SimEvent]:
        events = []
        url, dom = self._phishing_url()
        ip_pool  = [self._mal_ip() for _ in range(3)]   # shared C2 IPs

        for i in range(n_users):
            user = self._user(i)
            sid  = self._session()
            ip   = self._rng.choice(ip_pool)

            # Each victim: 2-6 events (browse → click → payment form)
            for step in range(self._rng.randint(2, 6)):
                score  = self._rng.uniform(65, 98) if step >= 1 else self._rng.uniform(40, 70)
                events.append(SimEvent(
                    score      = score,
                    severity   = self._severity(score),
                    url        = url,
                    ip         = ip,
                    session_id = sid,
                    kind       = "url",
                    domain     = dom,
                    user_id    = user,
                    ts         = time.time() + step * self._rng.uniform(30, 120),
                    scenario   = ScenarioType.PHISHING_CAMPAIGN.value,
                    is_fraud   = True,
                ))

        # Add 20% legitimate noise
        for i in range(n_users // 5):
            lu, ld = self._legit_url()
            score  = self._rng.uniform(5, 25)
            events.append(SimEvent(
                score      = score,
                severity   = self._severity(score),
                url        = lu,
                ip         = self._res_ip(),
                session_id = self._session(),
                kind       = "url",
                domain     = ld,
                user_id    = self._user(n_users + i),
                scenario   = ScenarioType.PHISHING_CAMPAIGN.value,
                is_fraud   = False,
            ))

        return events


class BotAttackScenario(_ScenarioBase):
    """Simulates an automated bot scraping / form-filling attack."""

    def generate(self, n_requests: int = 200) -> list[SimEvent]:
        events = []
        bot_ip = self._mal_ip()
        bot_fp = "bot-" + hashlib.sha1(bot_ip.encode()).hexdigest()[:8]

        for i in range(n_requests):
            url, dom = (self._phishing_url() if self._rng.random() < 0.6
                        else self._legit_url())
            score = self._rng.uniform(70, 95)
            events.append(SimEvent(
                score      = score,
                severity   = self._severity(score),
                url        = url,
                ip         = bot_ip,
                session_id = f"bot-session-{i // 20}",   # same session blocks
                kind       = "bot",
                domain     = dom,
                user_id    = f"bot_user_{i // 50}",
                ts         = time.time() + i * 0.5,      # 2 req/s
                scenario   = ScenarioType.BOT_ATTACK.value,
                is_fraud   = True,
            ))

        return events


class CredentialStuffingScenario(_ScenarioBase):
    """Simulates credential stuffing: many logins from same IP/device."""

    def generate(self, n_attempts: int = 150) -> list[SimEvent]:
        events = []
        # 3-5 source IPs rotating through user accounts
        src_ips = [self._mal_ip() for _ in range(self._rng.randint(3, 5))]

        for i in range(n_attempts):
            ip    = self._rng.choice(src_ips)
            score = self._rng.uniform(55, 90)
            events.append(SimEvent(
                score      = score,
                severity   = self._severity(score),
                url        = "https://target-bank.com/login",
                ip         = ip,
                session_id = self._session(),
                kind       = "login",
                domain     = "target-bank.com",
                user_id    = self._user(i),
                ts         = time.time() + i * 2.0,
                scenario   = ScenarioType.CREDENTIAL_STUFFING.value,
                is_fraud   = True,
            ))

        return events


class TransactionBurstScenario(_ScenarioBase):
    """Simulates rapid high-value transaction flood in a short window."""

    def generate(self, n_transactions: int = 80) -> list[SimEvent]:
        events = []
        card_ip = self._mal_ip()

        for i in range(n_transactions):
            score = self._rng.uniform(72, 99)
            events.append(SimEvent(
                score      = score,
                severity   = self._severity(score),
                url        = "https://shop.example.com/checkout/payment",
                ip         = card_ip,
                session_id = self._session(),
                kind       = "payment",
                domain     = "shop.example.com",
                user_id    = self._user(self._rng.randint(0, 10)),
                ts         = time.time() + i * (BURST_DURATION_S / n_transactions),
                scenario   = ScenarioType.TRANSACTION_BURST.value,
                is_fraud   = True,
            ))

        return events


class CoordinatedCampaignScenario(_ScenarioBase):
    """Multi-vector coordinated attack: phishing + bots + credential stuffing."""

    def generate(self) -> list[SimEvent]:
        events = []
        events.extend(PhishingCampaignScenario(self._rng).generate(30))
        events.extend(BotAttackScenario(self._rng).generate(100))
        events.extend(CredentialStuffingScenario(self._rng).generate(50))
        # Sort by timestamp
        events.sort(key=lambda e: e.ts)
        for e in events:
            e.scenario = ScenarioType.COORDINATED_CAMPAIGN.value
        return events


class ATOAttackScenario(_ScenarioBase):
    """Simulates account takeover: impossible travel, device change, rapid transactions."""

    def generate(self, n_victims: int = 30) -> list[SimEvent]:
        events = []
        for i in range(n_victims):
            user = self._user(i)
            sid  = self._session()

            # Legitimate login
            score_l = self._rng.uniform(5, 20)
            events.append(SimEvent(
                score      = score_l,
                severity   = "safe",
                url        = "https://bank.example.com/login",
                ip         = self._res_ip(),
                session_id = sid,
                kind       = "login",
                domain     = "bank.example.com",
                user_id    = user,
                is_fraud   = False,
                scenario   = ScenarioType.ATO_ATTACK.value,
            ))

            # ATO login from malicious IP (impossible travel)
            score_h = self._rng.uniform(78, 99)
            events.append(SimEvent(
                score      = score_h,
                severity   = self._severity(score_h),
                url        = "https://bank.example.com/login",
                ip         = self._mal_ip(),
                session_id = self._session(),    # new session = device change
                kind       = "ato",
                domain     = "bank.example.com",
                user_id    = user,
                ts         = time.time() + 3600,  # 1 hour later (from different continent)
                is_fraud   = True,
                scenario   = ScenarioType.ATO_ATTACK.value,
            ))

        return events


class CardingTestScenario(_ScenarioBase):
    """Simulates carding: small test charges before fraud."""

    def generate(self, n_cards: int = 40) -> list[SimEvent]:
        events = []
        carding_ip = self._mal_ip()

        for i in range(n_cards):
            # Test charge ($0.01-$1.00)
            score_test = self._rng.uniform(60, 80)
            events.append(SimEvent(
                score      = score_test,
                severity   = self._severity(score_test),
                url        = "https://shop.example.com/micropay",
                ip         = carding_ip,
                session_id = self._session(),
                kind       = "carding",
                domain     = "shop.example.com",
                user_id    = f"stolen_{i:04d}",
                scenario   = ScenarioType.CARDING_TEST.value,
                is_fraud   = True,
            ))

            # Follow-up large charge if test succeeds
            if self._rng.random() < 0.7:
                score_fraud = self._rng.uniform(80, 99)
                events.append(SimEvent(
                    score      = score_fraud,
                    severity   = "critical",
                    url        = "https://shop.example.com/checkout/payment",
                    ip         = carding_ip,
                    session_id = self._session(),
                    kind       = "payment",
                    domain     = "shop.example.com",
                    user_id    = f"stolen_{i:04d}",
                    ts         = time.time() + self._rng.uniform(60, 300),
                    scenario   = ScenarioType.CARDING_TEST.value,
                    is_fraud   = True,
                ))

        return events


# ═════════════════════════════════════════════════════════════
# §15 Simulation Engine
# ═════════════════════════════════════════════════════════════

class SimulationEngine:
    """
    Generates synthetic fraud scenarios for testing and ML training.
    Scenarios are reproducible (seeded RNG) and configurable.
    """

    def __init__(self):
        self._lock          = threading.Lock()
        self._run_history:  list[dict] = []
        self._total_events  = 0

    def run(
        self,
        scenario:   ScenarioType,
        seed:       int  = DEFAULT_SEED,
        **kwargs,
    ) -> SimulationRun:
        """
        Run a simulation scenario. Returns a SimulationRun with all events.

        kwargs are passed through to the scenario generator:
          - n_users       (phishing_campaign, ato_attack)
          - n_requests    (bot_attack)
          - n_attempts    (credential_stuffing)
          - n_transactions(transaction_burst)
          - n_cards       (carding_test)
          - n_victims     (ato_attack)
        """
        t0  = time.perf_counter()
        rng = random.Random(seed)

        generators = {
            ScenarioType.PHISHING_CAMPAIGN:    PhishingCampaignScenario(rng),
            ScenarioType.BOT_ATTACK:           BotAttackScenario(rng),
            ScenarioType.CREDENTIAL_STUFFING:  CredentialStuffingScenario(rng),
            ScenarioType.TRANSACTION_BURST:    TransactionBurstScenario(rng),
            ScenarioType.COORDINATED_CAMPAIGN: CoordinatedCampaignScenario(rng),
            ScenarioType.ATO_ATTACK:           ATOAttackScenario(rng),
            ScenarioType.CARDING_TEST:         CardingTestScenario(rng),
        }

        gen    = generators[scenario]
        events = gen.generate(**kwargs)
        events = events[:MAX_EVENTS_PER_RUN]

        scores = [e.score for e in events]
        run    = SimulationRun(
            scenario    = scenario,
            events      = events,
            true_frauds = sum(1 for e in events if e.is_fraud),
            true_legit  = sum(1 for e in events if not e.is_fraud),
            mean_score  = sum(scores) / len(scores) if scores else 0.0,
            peak_score  = max(scores) if scores else 0.0,
            duration_s  = time.perf_counter() - t0,
            config      = {"seed": seed, **kwargs},
        )

        with self._lock:
            self._run_history.append({
                "scenario":    scenario.value,
                "event_count": len(events),
                "ts":          time.time(),
            })
            if len(self._run_history) > 200:
                self._run_history = self._run_history[-200:]
            self._total_events += len(events)

        return run

    def stream_events(
        self,
        scenario:  ScenarioType,
        seed:      int   = DEFAULT_SEED,
        delay_s:   float = 0.1,
        **kwargs,
    ) -> Iterator[SimEvent]:
        """
        Generator that yields events with real-time delays for live testing.
        Use delay_s=0 for batch injection.
        """
        run = self.run(scenario, seed=seed, **kwargs)
        for event in run.events:
            yield event
            if delay_s > 0:
                time.sleep(delay_s)

    def run_all(self, seed: int = DEFAULT_SEED) -> dict:
        """Run all scenarios and return a summary report."""
        results = {}
        for sc in ScenarioType:
            try:
                run = self.run(sc, seed=seed)
                results[sc.value] = {
                    "events":      len(run.events),
                    "frauds":      run.true_frauds,
                    "mean_score":  round(run.mean_score, 2),
                    "duration_ms": round(run.duration_s * 1000, 1),
                }
            except Exception as exc:
                results[sc.value] = {"error": str(exc)}
        return results

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_runs":        len(self._run_history),
                "total_events":      self._total_events,
                "recent_runs":       self._run_history[-5:],
                "available_scenarios": [s.value for s in ScenarioType],
            }


# ── Singleton ─────────────────────────────────────────────────
simulation_engine = SimulationEngine()
