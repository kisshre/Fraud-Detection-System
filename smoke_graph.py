"""Graph engine smoke test — run directly: python smoke_graph.py"""
import json
from graph_engine import FraudGraph, _NX_AVAILABLE

g = FraudGraph()

# Simulate 6 scans of the same phishing domain (5 fraud, 1 safe)
for i in range(6):
    score = 85.0 if i < 5 else 20.0
    g.add_node("domain", "paypa1-login.tk", score)
    g.add_node("url", f"http://paypa1-login.tk/page{i}", score)
    g.add_edge("url", f"http://paypa1-login.tk/page{i}", "domain", "paypa1-login.tk", "resolves_to")

# A clean domain
g.add_node("domain", "google.com", 5.0)
g.add_node("url", "https://google.com", 5.0)
g.add_edge("url", "https://google.com", "domain", "google.com", "resolves_to")

# Email linked to the phishing domain
g.add_node("email", "scammer@paypa1-login.tk", 82.0)
g.add_edge("email", "scammer@paypa1-login.tk", "domain", "paypa1-login.tk", "sent_from_domain")

# A second phishing domain sharing the same subnet
g.add_node("ip", "192.168.1.5", 78.0)
g.add_edge("domain", "paypa1-login.tk", "ip", "192.168.1.5", "resolves_to_ip")
g.add_node("domain", "secure-amazon-update.xyz", 88.0)
g.add_edge("domain", "secure-amazon-update.xyz", "ip", "192.168.1.5", "resolves_to_ip")

print("=== Stats ===")
print(json.dumps(g.stats(), indent=2))

print("\n=== Frequency adjustment — repeat offender domain ===")
adj, sigs = g.get_entity_risk_adjustment("domain", "paypa1-login.tk")
print(f"  Adjustment: +{adj}")
for s in sigs:
    print(" ", s)

print("\n=== Frequency adjustment — clean domain (expect 0) ===")
adj2, sigs2 = g.get_entity_risk_adjustment("domain", "google.com")
print(f"  Adjustment: +{adj2}")

print("\n=== BFS connected_risk — from email to high-risk domain ===")
adj3, sigs3 = g.connected_risk("email", "scammer@paypa1-login.tk")
print(f"  BFS adjustment: +{adj3}")
for s in sigs3:
    print(" ", s)

print("\n=== Cluster / campaign detection ===")
clusters = g.detect_fraud_clusters(min_size=2, min_fraud_nodes=1)
print(f"  Cluster count: {len(clusters)}")
for c in clusters:
    print(f"  Cluster: size={c['size']}  fraud_nodes={c['fraud_node_count']}  avg_score={c['avg_risk_score']}  total_hits={c['total_fraud_hits']}")
    for n in c["nodes"]:
        print(f"    [{n['entity_type']}] {n['value'][:50]}  fraud={n['fraud_count']}  rate={n['fraud_rate']:.0%}  score={n['avg_score']}")

print("\n=== Top risk nodes (PageRank influence) ===")
top = g.top_risk_nodes(top_n=6)
for n in top:
    print(f"  [{n['entity_type']}] {n['value'][:40]:<42}  fraud={n['fraud_count']}  rate={n['fraud_rate']:.0%}  score={n['avg_risk_score']}  influence={n['influence_score']}")

print("\n=== Subgraph around email node ===")
sg = g.subgraph("email", "scammer@paypa1-login.tk", hops=2)
print(f"  Nodes: {len(sg['nodes'])}  Edges: {len(sg['edges'])}")
for nd in sg["nodes"]:
    print(f"    [{nd['type']}] {nd['value'][:45]:<46}  score={nd['avg_score']}  fraud={nd['fraud_count']}  rate={nd['fraud_rate']:.0%}  level={nd['risk_level']}")

print("\nAll checks passed.")
