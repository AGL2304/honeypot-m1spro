"""Non-régression des exports défensifs (B17/B24).

Garde-fou contre le bug « 'IPv4Address' object has no attribute 'replace' » :
db.attackers() renvoie src_ip comme objet INET (ipaddress), pas comme str.
Les générateurs doivent le normaliser.
"""

from __future__ import annotations

import ipaddress

from analyzer import exports


def _fake_attackers():
    return [
        {
            "src_ip": ipaddress.ip_address("203.0.113.7"),
            "classification": "bot",
            "abuse_score": 90,
        }
    ]


def test_exports_handle_inet_objects(tmp_path, monkeypatch):
    monkeypatch.setattr(exports, "_EXPORT_DIR", tmp_path)
    monkeypatch.setattr(exports, "_RULES_DIR", tmp_path / "rules")
    monkeypatch.setattr(exports.db, "attackers", _fake_attackers)

    blocklist = exports.generate_blocklist()
    sigma = exports.generate_sigma()
    stix = exports.generate_stix()

    assert "-A INPUT -s 203.0.113.7 -j DROP" in blocklist.read_text(encoding="utf-8")
    assert sigma and "203_0_113_7" in sigma[0].name
    assert "203.0.113.7" in sigma[0].read_text(encoding="utf-8")
    assert "[ipv4-addr:value = '203.0.113.7']" in stix.read_text(encoding="utf-8")
