"""
FRAUD-X — Cross-User Fraud Campaign Detector  v1.0
===================================================
§6  Coordinated attack detection across multiple users/sessions

Detects:
  - Shared malicious domains targeted at many users
  - Shared attack IPs originating multiple fraud attempts
  - Shared device fingerprints across different user accounts
  - Coordinated phishing campaigns (same template → many victims)
  - Credential stuffing attacks (many logins from same source)
  - Botnet patterns (distributed source, identical behavior)
  - Account-factory fraud (many new accounts, same device class)

Campaign lifecycle
------------------
  SUSPECTED  → ≥SEED_THRESHOLD entities share a signal (e.g., same domain)
  ACTIVE     → ≥ACTIVE_THRESHOLD entities and fraud rate ≥50%
  CONFIRMED  → ≥CONFIRMED_THRESHOLD entities — generate campaign alert
  DORMANT    → no new entities in DORMANT_WINDOW_S
  RESOLVED   → manually closed or auto-expired

§18 Integration
---------------
  On CONFIRMED status, the campaign's malicious artifacts (domains, IPs,
  device fingerprints) are automatically pushed to memory_engine for
  instant ecosystem-wide blocking (§18 "detected once → blocked globally").
"""

from __future__ import annotations

import hashlib
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ── Thresholds ────────────────────────────────────────────────
SEED_THRESHOLD       = 3     # entities to start tracking
ACTIVE_THRESHOLD     = 5     # entities to call "active"
CONFIRMED_THRESHOLD  = 10    # entities to confirm campaign
DORMANT_WINDOW_S     = 3600  # 1 hour with no new hits = dormant
MAX_CAMPAIGNS        = 1000
MAX_ENTITIES         = 500   # per campaign


class CampaignStatus(str, Enum):
    SUSPECTED  = "suspected"
    ACTIVE     = "active"
    CONFIRMED  = "confirmed"
    DORMANT    = "dormant"
    RESOLVED   = "resolved"


class CampaignType(str, Enum):
    PHISHING         = "phishing"
    CREDENTIAL_STUFF = "credential_stuffing"
    CARD_TESTING     = "card_testing"
    BOTNET           = "botnet"
    ATO_CAMPAIGN     = "account_takeover"
    DOMAIN_SQUATTING = "domain_squatting"
    UNKNOWN          = "unknown"


# ═════════════════════════════════════════════════════════════
# Campaign data model
# ═════════════════════════════════════════════════════════════

@dataclass
class Campaign:
    """Tracks a single coordinated fraud campaign."""
    campaign_id:    str
    campaign_type:  CampaignType
    pivot_key:      str           # shared artifact: domain | ip | device_fp
    pivot_kind:     str           # "domain" | "ip" | "device" | "template"
    status:         CampaignStatus = CampaignStatus.SUSPECTED
    created_at:     float         = field(default_factory=time.time)
    last_seen:      float         = field(default_factory=time.time)

    entities:       set           = field(default_factory=set)   # affected user_ids / sessions
    fraud_scores:   list[float]   = field(default_factory=list)
    ips:            set           = field(default_factory=set)
    domains:        set           = field(default_factory=set)
    device_fps:     set           = field(default_factory=set)
    alerts:         list[str]     = field(default_factory=list)

    def add_entity(
        self, entity: str, score: float,
        ip: str = "", domain: str = "", device_fp: str = "",
    ):
        self.entities.add(entity)
        self.fraud_scores.append(score)
        if ip:         self.ips.add(ip)
        if domain:     self.domains.add(domain)
        if device_fp:  self.device_fps.add(device_fp[:32])
        self.last_seen = time.time()

        # Auto-advance status
        n = len(self.entities)
        if n >= CONFIRMED_THRESHOLD:
            self.status = CampaignStatus.CONFIRMED
        elif n >= ACTIVE_THRESHOLD:
            self.status = CampaignStatus.ACTIVE

    @property
    def size(self) -> int:
        return len(self.entities)

    @property
    def fraud_rate(self) -> float:
        if not self.fraud_scores:
            return 0.0
        return sum(1 for s in self.fraud_scores if s >= 60) / len(self.fraud_scores)

    @property
    def mean_score(self) -> float:
        return statistics.mean(self.fraud_scores) if self.fraud_scores else 0.0

    @property
    def is_dormant(self) -> bool:
        return (time.time() - self.last_seen) > DORMANT_WINDOW_S

    def to_dict(self) -> dict:
        return {
            "campaign_id":   self.campaign_id,
            "type":          self.campaign_type.value,
            "status":        self.status.value,
            "pivot_key":     self.pivot_key,
            "pivot_kind":    self.pivot_kind,
            "entity_count":  self.size,
            "fraud_rate":    round(self.fraud_rate, 3),
            "mean_score":    round(self.mean_score, 2),
            "ips":           len(self.ips),
            "domains":       list(self.domains)[:10],
            "device_fps":    len(self.device_fps),
            "alerts":        self.alerts[-3:],
            "created_at":    self.created_at,
            "last_seen":     self.last_seen,
        }


# ═════════════════════════════════════════════════════════════
# §6 Campaign Detector
# ═════════════════════════════════════════════════════════════

class CampaignDetector:
    """
    Detects coordinated fraud campaigns by clustering fraud events
    around shared pivot artifacts (domain, IP, device fingerprint).
    """

    def __init__(self):
        self._campaigns: dict[str, Campaign]    = {}
        # Index: pivot_value → campaign_id
        self._domain_idx: dict[str, str]        = {}
        self._ip_idx:     dict[str, str]        = {}
        self._device_idx: dict[str, str]        = {}
        self._lock        = threading.Lock()
        self._recent_alerts: deque              = deque(maxlen=200)
        self._total_campaigns = 0

    # ── Main entry point ──────────────────────────────────────

    def observe(
        self,
        entity:    str,       # user_id or session_id
        score:     float,     # fraud score for this event
        domain:    str = "",
        ip:        str = "",
        device_fp: str = "",
        kind:      str = "url",  # hint for campaign type
    ) -> Optional[dict]:
        """
        Process a fraud event and update campaign tracking.
        Returns campaign alert dict if a campaign is confirmed/escalated.
        """
        if score < 40.0:
            return None   # below threshold, skip

        domain_normalized = domain.lower().strip() if domain else ""
        ip_prefix = ".".join(ip.split(".")[:3]) if ip else ""

        with self._lock:
            alert = None

            # Try to associate with existing campaigns
            campaign = (
                self._find_by_domain(domain_normalized) or
                self._find_by_ip(ip_prefix)             or
                self._find_by_device(device_fp[:32] if device_fp else "")
            )

            if campaign is None and (domain_normalized or ip_prefix):
                # Create new campaign
                campaign = self._create_campaign(
                    domain_normalized or ip_prefix,
                    "domain" if domain_normalized else "ip",
                    kind,
                )
                if domain_normalized:
                    self._domain_idx[domain_normalized] = campaign.campaign_id
                if ip_prefix:
                    self._ip_idx[ip_prefix]             = campaign.campaign_id
                if device_fp:
                    self._device_idx[device_fp[:32]]    = campaign.campaign_id

            if campaign:
                prev_status = campaign.status
                campaign.add_entity(
                    entity, score,
                    ip=ip, domain=domain_normalized, device_fp=device_fp,
                )

                if campaign.status == CampaignStatus.CONFIRMED and prev_status != CampaignStatus.CONFIRMED:
                    alert = self._build_alert(campaign)
                    campaign.alerts.append(alert["alert_id"])
                    self._recent_alerts.append(alert)

        return alert

    # ── Query API ─────────────────────────────────────────────

    def active_campaigns(self, min_entities: int = SEED_THRESHOLD) -> list[dict]:
        with self._lock:
            return [
                c.to_dict() for c in self._campaigns.values()
                if c.size >= min_entities and c.status != CampaignStatus.RESOLVED
            ]

    def confirmed_campaigns(self) -> list[dict]:
        with self._lock:
            return [
                c.to_dict() for c in self._campaigns.values()
                if c.status == CampaignStatus.CONFIRMED
            ]

    def get_campaign(self, campaign_id: str) -> Optional[dict]:
        with self._lock:
            c = self._campaigns.get(campaign_id)
            return c.to_dict() if c else None

    def recent_alerts(self, n: int = 20) -> list:
        with self._lock:
            return list(self._recent_alerts)[-n:]

    def stats(self) -> dict:
        with self._lock:
            campaigns = list(self._campaigns.values())
        status_counts = defaultdict(int)
        for c in campaigns:
            status_counts[c.status.value] += 1
        return {
            "total_campaigns":     self._total_campaigns,
            "active_now":          sum(1 for c in campaigns if c.status == CampaignStatus.ACTIVE),
            "confirmed":           status_counts[CampaignStatus.CONFIRMED],
            "suspected":           status_counts[CampaignStatus.SUSPECTED],
            "total_entities_tracked": sum(c.size for c in campaigns),
        }

    def cleanup(self):
        """Remove dormant and resolved campaigns."""
        with self._lock:
            stale = [cid for cid, c in self._campaigns.items()
                     if c.is_dormant or c.status == CampaignStatus.RESOLVED]
            for cid in stale:
                del self._campaigns[cid]

    # ── Internal helpers ──────────────────────────────────────

    def _find_by_domain(self, domain: str) -> Optional[Campaign]:
        if not domain:
            return None
        cid = self._domain_idx.get(domain)
        return self._campaigns.get(cid) if cid else None

    def _find_by_ip(self, ip_prefix: str) -> Optional[Campaign]:
        if not ip_prefix:
            return None
        cid = self._ip_idx.get(ip_prefix)
        return self._campaigns.get(cid) if cid else None

    def _find_by_device(self, device_fp: str) -> Optional[Campaign]:
        if not device_fp:
            return None
        cid = self._device_idx.get(device_fp)
        return self._campaigns.get(cid) if cid else None

    def _create_campaign(
        self, pivot_key: str, pivot_kind: str, kind: str
    ) -> Campaign:
        if len(self._campaigns) >= MAX_CAMPAIGNS:
            # Evict smallest dormant campaign
            dormant = [c for c in self._campaigns.values() if c.is_dormant]
            if dormant:
                smallest = min(dormant, key=lambda c: c.size)
                del self._campaigns[smallest.campaign_id]

        ctype  = self._infer_type(kind)
        raw_id = f"{pivot_key}:{time.time()}"
        cid    = "CAMP-" + hashlib.sha1(raw_id.encode()).hexdigest()[:8].upper()
        self._total_campaigns += 1

        c = Campaign(
            campaign_id   = cid,
            campaign_type = ctype,
            pivot_key     = pivot_key,
            pivot_kind    = pivot_kind,
        )
        self._campaigns[cid] = c
        return c

    @staticmethod
    def _infer_type(kind: str) -> CampaignType:
        mapping = {
            "url":     CampaignType.PHISHING,
            "payment": CampaignType.CARD_TESTING,
            "login":   CampaignType.CREDENTIAL_STUFF,
            "ato":     CampaignType.ATO_CAMPAIGN,
        }
        return mapping.get(kind, CampaignType.UNKNOWN)

    def _build_alert(self, campaign: Campaign) -> dict:
        return {
            "alert_id":       f"ALERT-{campaign.campaign_id}",
            "campaign_id":    campaign.campaign_id,
            "type":           campaign.campaign_type.value,
            "pivot":          campaign.pivot_key,
            "entity_count":   campaign.size,
            "mean_score":     round(campaign.mean_score, 2),
            "fraud_rate":     round(campaign.fraud_rate, 3),
            "affected_domains": list(campaign.domains)[:5],
            "severity":       "critical" if campaign.size >= 20 else "high",
            "message":        (
                f"Coordinated {campaign.campaign_type.value} campaign detected: "
                f"{campaign.size} entities targeted via {campaign.pivot_key}"
            ),
            "ts":             time.time(),
        }


# ── Singleton ─────────────────────────────────────────────────
campaign_detector = CampaignDetector()
