"""Quick smoke test for all new engines."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from database import init_db, save_alert, get_db_stats
from ml_engine import ml_engine
from graph_engine import fraud_graph, link_url_scan
from behavior_engine import behavior_engine

init_db()
print("DB initialised OK")

sc, note = ml_engine.calibrate(75, "url", ["Homograph attack detected", "Suspicious TLD .tk"])
print(f"ML calibrate: {sc}/100 — {note}")

xai = ml_engine.explain(sc, "danger", ["Homograph attack detected", "No strong phishing signals"], "url")
print(f"XAI confidence: {xai['confidence']}, signal_count: {xai['signal_count']}")
print(f"XAI categories: {list(xai['categories'].keys())}")

link_url_scan("http://paypa1.com", "paypa1.com", 80.0)
adj, sigs = fraud_graph.connected_risk("url", "http://paypa1.com")
print(f"Graph adj: {adj}, graph signals: {sigs}")

badj, bsigs = behavior_engine.analyze("url", "http://paypa1.com", 80)
behavior_engine.record("url", "http://paypa1.com", 80)
print(f"Behavior adj: {badj}, behavioral signals: {bsigs}")

stats = get_db_stats()
print(f"DB stats: {stats}")

print("\nAll smoke tests PASSED.")
