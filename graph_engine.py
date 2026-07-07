"""
FRAUD-X  ·  Graph-Based Fraud Detection Engine  v2
====================================================
NetworkX-powered entity graph with:
  - fraud_count / total_scans per node  (frequency tracking)
  - get_entity_risk_adjustment()        repeat-offender scoring
  - detect_fraud_clusters()             campaign cluster detection
  - BFS risk propagation with decay     guilt-by-association
  - PageRank influence scoring          top-risk node ranking
  - subgraph()                          visualisation payload

Falls back gracefully to dict-based BFS if networkx is not installed.

Node-ID format: "{entity_type}:{value[:120]}"
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    nx = None          # type: ignore[assignment]
    _NX_AVAILABLE = False

# ── Thresholds ──────────────────────────────────────────────────
FRAUD_THRESHOLD      = 65   # risk score that counts as a "fraud" incident
FREQ_MIN_HITS        = 3    # min fraud hits before frequency adjustment kicks in
MAX_FREQ_BOOST       = 20   # cap on frequency-based score adjustment
MAX_BFS_BOOST        = 25   # cap on BFS-propagation adjustment


class FraudGraph:
    """
    Entity graph linking URLs, domains, IPs, emails, phones, crypto addresses.

    Per-node tracking:
        fraud_count  — times this node appeared in high-risk (>=65) scans
        total_scans  — times this node appeared in any scan
        risk_scores  — rolling list of last 50 raw scores (memory-bounded)
        first_seen   — unix timestamp of first observation
        last_seen    — unix timestamp of most recent observation
    """

    def __init__(self) -> None:
        if _NX_AVAILABLE:
            self._g: "nx.DiGraph" = nx.DiGraph()
        # Fallback adjacency (always kept for non-NX BFS)
        self._fwd: Dict[str, List[Tuple[str, str, float, float]]] = defaultdict(list)
        self._rev: Dict[str, List[Tuple[str, str, float, float]]] = defaultdict(list)

        # Per-node metadata — maintained regardless of NX availability
        self._fraud_count: Dict[str, int] = defaultdict(int)
        self._total_scans: Dict[str, int] = defaultdict(int)
        self._scores:      Dict[str, List[float]] = defaultdict(list)
        self._first_seen:  Dict[str, float] = {}
        self._last_seen:   Dict[str, float] = {}

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def node_id(entity_type: str, value: str) -> str:
        return f"{entity_type}:{value[:120]}"

    def _avg(self, nid: str) -> float:
        s = self._scores.get(nid, [])
        return sum(s) / len(s) if s else 0.0

    # ── Node / edge management ────────────────────────────────────

    def add_node(self, entity_type: str, value: str, risk_score: float) -> None:
        nid = self.node_id(entity_type, value)
        ts  = time.time()

        # Frequency tracking
        self._total_scans[nid] += 1
        if risk_score >= FRAUD_THRESHOLD:
            self._fraud_count[nid] += 1

        # Rolling score window (last 50)
        scores = self._scores[nid]
        scores.append(risk_score)
        if len(scores) > 50:
            scores.pop(0)

        # Timestamps
        if nid not in self._first_seen:
            self._first_seen[nid] = ts
        self._last_seen[nid] = ts

        # NetworkX node attributes
        if _NX_AVAILABLE:
            avg = sum(scores) / len(scores)
            if self._g.has_node(nid):
                self._g.nodes[nid].update({
                    "fraud_count": self._fraud_count[nid],
                    "total_scans": self._total_scans[nid],
                    "avg_score":   avg,
                    "last_seen":   ts,
                })
            else:
                self._g.add_node(nid,
                    entity_type=entity_type,
                    value=value[:120],
                    fraud_count=self._fraud_count[nid],
                    total_scans=self._total_scans[nid],
                    avg_score=risk_score,
                    first_seen=ts,
                    last_seen=ts,
                )

    def add_edge(
        self,
        src_type: str, src_val: str,
        dst_type: str, dst_val: str,
        relation: str,
        weight: float = 1.0,
    ) -> None:
        src = self.node_id(src_type, src_val)
        dst = self.node_id(dst_type, dst_val)
        ts  = time.time()

        if _NX_AVAILABLE:
            self._g.add_edge(src, dst, relation=relation, weight=weight, timestamp=ts)
        # Always keep fallback adjacency
        self._fwd[src].append((dst, relation, weight, ts))
        self._rev[dst].append((src, relation, weight, ts))

    # ── Frequency-based repeat-offender scoring ───────────────────

    def get_entity_risk_adjustment(
        self, entity_type: str, value: str
    ) -> Tuple[int, List[str]]:
        """
        Score bump based on how many times this entity appeared in fraud alerts.

        Logic
        -----
        - fraud_rate  = fraud_count / total_scans
        - Only fires   when fraud_count >= FREQ_MIN_HITS (3)
        - Base boost  = min(MAX_FREQ_BOOST, fraud_count * 4)
        - Extra +5    when fraud_rate >= 70 %  (infrastructure reuse signal)

        Returns (score_adjustment: int, explanations: List[str]).
        """
        nid         = self.node_id(entity_type, value)
        fraud_count = self._fraud_count.get(nid, 0)
        total_scans = self._total_scans.get(nid, 0)

        if fraud_count < FREQ_MIN_HITS:
            return 0, []

        fraud_rate = fraud_count / total_scans if total_scans > 0 else 0.0
        adjustment = min(MAX_FREQ_BOOST, fraud_count * 4)
        explanations = [
            f"[Graph] {entity_type.capitalize()} '{value[:50]}' flagged in "
            f"{fraud_count}/{total_scans} scan(s) "
            f"(fraud rate {fraud_rate * 100:.0f}%) — repeated offender."
        ]

        if fraud_rate >= 0.70:
            adjustment = min(MAX_FREQ_BOOST, adjustment + 5)
            explanations.append(
                f"[Graph] High fraud concentration on '{value[:40]}' "
                f"({fraud_rate * 100:.0f}% fraud rate) — infrastructure reuse detected."
            )

        return adjustment, explanations

    # ── BFS guilt-by-association propagation ─────────────────────

    def connected_risk(
        self,
        entity_type: str,
        value: str,
        hops: int = 2,
    ) -> Tuple[int, List[str]]:
        """
        BFS from the given node, collecting risk from high-risk neighbours.
        Each hop halves the contribution (distance decay).

        Returns (score_adjustment: int, explanations: List[str]).
        """
        nid     = self.node_id(entity_type, value)
        visited: Set[str] = {nid}
        total_risk  = 0.0
        explanations: List[str] = []

        if _NX_AVAILABLE and self._g.has_node(nid):
            queue: deque[Tuple[str, int, float]] = deque([(nid, 0, 1.0)])
            while queue:
                node, depth, decay = queue.popleft()
                if depth >= hops:
                    continue
                neighbours = list(self._g.successors(node)) + list(self._g.predecessors(node))
                for nbr in neighbours:
                    if nbr in visited:
                        continue
                    visited.add(nbr)
                    avg = self._avg(nbr)
                    if avg >= FRAUD_THRESHOLD:
                        w = self._g[node][nbr]["weight"] if self._g.has_edge(node, nbr) else 1.0
                        total_risk += avg * decay * w
                        ntype, nval = nbr.split(":", 1) if ":" in nbr else ("entity", nbr)
                        fc = self._fraud_count.get(nbr, 0)
                        explanations.append(
                            f"[Graph] Linked {ntype} '{nval[:40]}' has high risk "
                            f"({avg:.0f}/100, {fc} fraud hit(s)) — network association."
                        )
                    queue.append((nbr, depth + 1, decay * 0.5))
        else:
            # Fallback: dict-based BFS
            def _bfs(node: str, depth: int, decay: float) -> None:
                nonlocal total_risk
                if depth == 0:
                    return
                for nbr, relation, weight, _ in (
                    self._fwd.get(node, []) + self._rev.get(node, [])
                ):
                    if nbr in visited:
                        continue
                    visited.add(nbr)
                    avg = self._avg(nbr)
                    if avg >= FRAUD_THRESHOLD:
                        total_risk += avg * decay * weight
                        ntype, nval = nbr.split(":", 1) if ":" in nbr else ("entity", nbr)
                        explanations.append(
                            f"[Graph] Linked {ntype} '{nval[:40]}' has high risk "
                            f"({avg:.0f}/100) via '{relation}' — network association."
                        )
                    _bfs(nbr, depth - 1, decay * 0.5)
            _bfs(nid, hops, 1.0)

        adjustment = min(MAX_BFS_BOOST, int(total_risk / 120))
        return adjustment, explanations[:3]

    # ── Cluster / campaign detection ─────────────────────────────

    def detect_fraud_clusters(
        self,
        min_size: int = 2,
        min_fraud_nodes: int = 2,
    ) -> List[Dict]:
        """
        Detect connected components (campaigns) where multiple nodes are high-risk.

        Uses nx.connected_components on the undirected projection.
        Falls back to manual BFS grouping when networkx is unavailable.

        Returns list of cluster dicts sorted by fraud_node_count descending.
        Each cluster dict:
          {size, fraud_node_count, avg_risk_score, total_fraud_hits, nodes: [...]}
        """
        clusters: List[Dict] = []

        def _node_dict(n: str) -> Dict:
            s = self._scores.get(n, [])
            avg = sum(s) / len(s) if s else 0.0
            ts  = self._total_scans.get(n, 0)
            fc  = self._fraud_count.get(n, 0)
            return {
                "id":           n,
                "entity_type":  n.split(":", 1)[0],
                "value":        n.split(":", 1)[1] if ":" in n else n,
                "fraud_count":  fc,
                "total_scans":  ts,
                "fraud_rate":   round(fc / ts, 3) if ts > 0 else 0.0,
                "avg_score":    round(avg, 1),
            }

        def _build_cluster(component: Set[str]) -> Optional[Dict]:
            if len(component) < min_size:
                return None
            fraud_nodes = [
                n for n in component
                if self._fraud_count.get(n, 0) >= 1
                   and self._avg(n) >= FRAUD_THRESHOLD
            ]
            if len(fraud_nodes) < min_fraud_nodes:
                return None
            all_avgs = [self._avg(n) for n in component if self._scores.get(n)]
            cluster_avg = sum(all_avgs) / len(all_avgs) if all_avgs else 0.0
            return {
                "size":             len(component),
                "fraud_node_count": len(fraud_nodes),
                "avg_risk_score":   round(cluster_avg, 1),
                "total_fraud_hits": sum(self._fraud_count.get(n, 0) for n in component),
                "nodes":            [_node_dict(n) for n in fraud_nodes],
            }

        if _NX_AVAILABLE and self._g.number_of_nodes() > 0:
            undirected = self._g.to_undirected()
            for component in nx.connected_components(undirected):
                c = _build_cluster(component)
                if c:
                    clusters.append(c)
        else:
            # Manual BFS grouping via fallback adjacency lists
            all_nodes = set(self._scores.keys())
            visited:  Set[str] = set()
            for start in all_nodes:
                if start in visited:
                    continue
                component: Set[str] = set()
                stack = [start]
                while stack:
                    cur = stack.pop()
                    if cur in visited:
                        continue
                    visited.add(cur)
                    component.add(cur)
                    for nbr, _, _, _ in (
                        self._fwd.get(cur, []) + self._rev.get(cur, [])
                    ):
                        if nbr not in visited:
                            stack.append(nbr)
                c = _build_cluster(component)
                if c:
                    clusters.append(c)

        return sorted(clusters, key=lambda c: -c["fraud_node_count"])

    # ── PageRank top-risk node ranking ────────────────────────────

    def top_risk_nodes(self, top_n: int = 10) -> List[Dict]:
        """
        Return top nodes ranked by influence = PageRank * fraud_count * avg_score.
        Falls back to fraud_count sort when networkx is unavailable or graph is trivial.
        """
        pr: Dict[str, float] = {}
        if _NX_AVAILABLE and self._g.number_of_nodes() > 1:
            try:
                pr = nx.pagerank(self._g, weight="weight")
            except Exception:
                pass

        result: List[Dict] = []
        for nid, fc in self._fraud_count.items():
            if fc == 0:
                continue
            avg     = self._avg(nid)
            ts      = self._total_scans.get(nid, 0)
            pr_val  = pr.get(nid, 0.0)
            # Combined influence: pagerank is tiny so scale it up
            influence = (pr_val * 1000) + (fc * 5) + (avg * 0.1)
            result.append({
                "id":            nid,
                "entity_type":   nid.split(":", 1)[0],
                "value":         nid.split(":", 1)[1] if ":" in nid else nid,
                "fraud_count":   fc,
                "total_scans":   ts,
                "fraud_rate":    round(fc / ts, 3) if ts > 0 else 0.0,
                "avg_risk_score": round(avg, 1),
                "pagerank":      round(pr_val, 6),
                "influence_score": round(influence, 4),
            })

        return sorted(result, key=lambda x: -x["influence_score"])[:top_n]

    # ── Subgraph for visualisation ────────────────────────────────

    def subgraph(self, entity_type: str, value: str, hops: int = 2) -> Dict:
        nid = self.node_id(entity_type, value)
        visited: Set[str] = set()
        nodes:   List[Dict] = []
        edges:   List[Dict] = []

        def _collect(node: str, depth: int) -> None:
            if node in visited or depth < 0:
                return
            visited.add(node)
            ntype, nval = node.split(":", 1) if ":" in node else ("unknown", node)
            avg = self._avg(node)
            fc  = self._fraud_count.get(node, 0)
            ts  = self._total_scans.get(node, 0)
            nodes.append({
                "id":          node,
                "type":        ntype,
                "value":       nval,
                "avg_score":   round(avg, 1),
                "fraud_count": fc,
                "total_scans": ts,
                "fraud_rate":  round(fc / ts, 3) if ts > 0 else 0.0,
                "risk_level":  "danger" if avg >= 65 else "caution" if avg >= 30 else "safe",
            })
            if _NX_AVAILABLE and self._g.has_node(node):
                for nbr in self._g.successors(node):
                    rel = self._g[node][nbr].get("relation", "linked")
                    edges.append({"source": node, "target": nbr, "relation": rel})
                    _collect(nbr, depth - 1)
                for nbr in self._g.predecessors(node):
                    rel = self._g[nbr][node].get("relation", "linked")
                    edges.append({"source": nbr, "target": node, "relation": rel})
                    _collect(nbr, depth - 1)
            else:
                for nbr, rel, _, _ in self._fwd.get(node, []):
                    edges.append({"source": node, "target": nbr, "relation": rel})
                    _collect(nbr, depth - 1)
                for nbr, rel, _, _ in self._rev.get(node, []):
                    edges.append({"source": nbr, "target": node, "relation": rel})
                    _collect(nbr, depth - 1)

        _collect(nid, hops)
        return {"nodes": nodes, "edges": edges, "center": nid}

    def stats(self) -> Dict:
        if _NX_AVAILABLE:
            num_nodes = self._g.number_of_nodes()
            num_edges = self._g.number_of_edges()
        else:
            num_nodes = len(self._scores)
            num_edges = sum(len(v) for v in self._fwd.values())

        high_risk = sum(
            1 for nid in self._scores
            if self._avg(nid) >= FRAUD_THRESHOLD
        )
        repeat_offenders = sum(
            1 for fc in self._fraud_count.values() if fc >= FREQ_MIN_HITS
        )
        return {
            "total_nodes":       num_nodes,
            "total_edges":       num_edges,
            "high_risk_nodes":   high_risk,
            "repeat_offenders":  repeat_offenders,
            "networkx_enabled":  _NX_AVAILABLE,
        }


# ── Singleton ─────────────────────────────────────────────────────
fraud_graph = FraudGraph()


# ── Convenience entity-linkers ────────────────────────────────────
# Each linker calls add_node + add_edge and also records the parent→child
# link so connected_risk() and subgraph() can traverse them.

def link_url_scan(url: str, host: str, score: float) -> None:
    fraud_graph.add_node("url",    url,  score)
    fraud_graph.add_node("domain", host, score)
    fraud_graph.add_edge("url", url, "domain", host, "resolves_to")
    labels = host.split(".")
    if len(labels) >= 2:
        tld = labels[-1]
        fraud_graph.add_node("tld", tld, score * 0.25)
        fraud_graph.add_edge("domain", host, "tld", tld, "uses_tld")


def link_email_scan(sender: str, domain: str, score: float) -> None:
    fraud_graph.add_node("email",  sender, score)
    fraud_graph.add_node("domain", domain, score * 0.6)
    fraud_graph.add_edge("email", sender, "domain", domain, "sent_from_domain")


def link_phone_scan(phone: str, country: Optional[str], score: float) -> None:
    fraud_graph.add_node("phone", phone, score)
    if country:
        fraud_graph.add_node("country", country, score * 0.15)
        fraud_graph.add_edge("phone", phone, "country", country, "originates_from")


def link_ip_scan(ip: str, score: float) -> None:
    fraud_graph.add_node("ip", ip, score)
    octets = ip.split(".")
    if len(octets) == 4:
        subnet = ".".join(octets[:3])
        fraud_graph.add_node("subnet", subnet, score * 0.4)
        fraud_graph.add_edge("ip", ip, "subnet", subnet, "in_subnet")


def link_crypto_scan(address: str, coin_type: Optional[str], score: float) -> None:
    fraud_graph.add_node("crypto", address, score)
    if coin_type:
        fraud_graph.add_node("coin_type", coin_type, score * 0.1)
        fraud_graph.add_edge("crypto", address, "coin_type", coin_type, "coin_type")


def link_sms_scan(sender: Optional[str], link_domain: Optional[str], score: float) -> None:
    if sender:
        fraud_graph.add_node("sms_sender", sender, score)
    if link_domain:
        fraud_graph.add_node("domain", link_domain, score * 0.7)
        if sender:
            fraud_graph.add_edge("sms_sender", sender, "domain", link_domain, "contains_link_to")
