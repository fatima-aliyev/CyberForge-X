from __future__ import annotations

from cyberforge.intel.cve import LocalVulnDB


def test_bundled_vulnerability_database_loads() -> None:
    database = LocalVulnDB()
    assert database.load_error == ""
    assert database.record_count() > 0


def test_known_apache_version_matches_seed_record() -> None:
    matches = LocalVulnDB().lookup("Apache HTTP Server", "2.4.49")
    assert any(item.cve == "CVE-2021-41773" for item in matches)
