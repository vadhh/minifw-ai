"""_build_ai_explanation must attribute blocks to the right engine.

admin.py needs the web stack (passlib, jose) to import, so the function is
compiled straight from source; it only uses the stdlib `re` module.
"""
import ast
import re
from pathlib import Path

ADMIN = Path(__file__).parent.parent / "app" / "web" / "routers" / "admin.py"


def _load():
    tree = ast.parse(ADMIN.read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_build_ai_explanation")
    ns = {"re": re}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(ADMIN), "exec"), ns)
    return ns["_build_ai_explanation"]


explain = _load()


def _signals(x):
    return x["asn"] + x["tls"] + x["behavior"]


def test_explanation_ai_window_rate():
    x = explain({"reason": "ai_window_rate", "score": 97, "ai_window_n60": 42})
    assert x["category"] == "AI (connection rate)"
    assert x["behavior"] == [
        "AI connection-rate model: 42 new TCP connections from this client to one server:port "
        "in 60 s (isolates at 39+); isolated 15 min. Does not see passwords or logins."
    ]
    assert not any("Burst" in s for s in _signals(x))
    no_n60 = explain({"reason": "ai_window_rate", "score": 97})
    assert no_n60["behavior"][0].startswith("AI connection-rate model: 39+ new TCP connections")


def test_explanation_dns_denied_domain_isolation():
    x = explain({"reason": "dns_denied_domain, deny_domain_client_ipv4_isolation", "score": 100})
    assert x["asn"] == ["Deny-list domain match (client IPv4 isolated)"]
    assert "IP blocklist match" not in _signals(x)
    assert x["category"] == "Deny-list domain"
    weighted = explain({"reason": "dns_denied_domain", "score": 40})
    assert weighted["asn"] == ["Deny-list domain match"]


def test_explanation_mlp_reports_own_points_not_total():
    x = explain({"reason": "dns_denied_domain, mlp_threat_score_80", "score": 64})
    assert "MLP added 24 of max 30 points; total score 64" in x["behavior"]
    assert not any(s.startswith("AI") for s in _signals(x))


def test_explanation_sector_rule_is_not_tor():
    x = explain({"reason": "sector_rule:wire_transfer_anomaly, Unusual transfer to new IP", "score": 90})
    assert "Sector rule" in x["behavior"]
    assert not any("Tor" in s or "IP blocklist" in s for s in _signals(x))
