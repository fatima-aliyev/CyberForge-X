from __future__ import annotations

import pytest

from cyberforge.core.exceptions import ConfigurationError, ScopeViolation
from cyberforge.core.scope import Scope, ScopeConfig, load_scope


def _scope(**overrides: object) -> Scope:
    values: dict[str, object] = {
        "engagement": "Unit Test",
        "authorized_by": "Test Owner",
        "authorization_ref": "TEST-1",
        "allowed_hosts": (),
        "allowed_cidrs": ("127.0.0.1/32",),
        "allowed_ports": (),
        "max_rps": 5.0,
        "max_requests": 100,
    }
    values.update(overrides)
    return Scope(ScopeConfig(**values))


def test_ipv4_target_is_allowed() -> None:
    scope = _scope()
    scope.assert_host("127.0.0.1")
    scope.assert_url("http://127.0.0.1:8080/path")


def test_target_outside_scope_rejected() -> None:
    with pytest.raises(ScopeViolation):
        _scope().assert_host("192.0.2.10")


def test_metadata_endpoint_always_denied() -> None:
    scope = _scope(allowed_cidrs=("169.254.0.0/16",))
    with pytest.raises(ScopeViolation):
        scope.assert_host("169.254.169.254")


def test_excluded_host_rejected() -> None:
    scope = _scope(excluded_hosts=("127.0.0.1",))
    with pytest.raises(ScopeViolation):
        scope.assert_host("127.0.0.1")


def test_port_filtering() -> None:
    scope = _scope(allowed_ports=(80, 443))
    assert scope.filter_ports([22, 80, 443, 8080]) == [80, 443]
    with pytest.raises(ScopeViolation, match="port"):
        scope.assert_url("http://127.0.0.1:8080/")


def test_credential_bearing_url_rejected() -> None:
    scope = _scope()
    with pytest.raises(ScopeViolation, match="credential"):
        scope.assert_url("http://user:pass@127.0.0.1/")


def test_only_http_schemes_allowed() -> None:
    scope = _scope()
    with pytest.raises(ScopeViolation, match="http"):
        scope.assert_url("ftp://127.0.0.1/")


def test_scope_file_round_trip(tmp_path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "engagement: Round Trip\n"
        "authorized_by: Owner\n"
        "authorization_ref: REF-9\n"
        "allowed_cidrs: [127.0.0.1/32]\n"
        "allowed_ports: [80, 443]\n"
        "max_rps: 2\n"
        "max_requests: 50\n",
        encoding="utf-8",
    )
    config, scope = load_scope(path)
    assert config.engagement == "Round Trip"
    assert config.max_requests == 50
    assert scope.config.allowed_ports == (80, 443)
    assert scope.audit_metadata()["scope_sha256"]


def test_scope_requires_engagement_and_authorizer() -> None:
    with pytest.raises(ConfigurationError, match="engagement"):
        ScopeConfig.from_dict({"authorized_by": "Owner", "allowed_cidrs": ["127.0.0.1/32"]})
    with pytest.raises(ConfigurationError, match="authorized_by"):
        ScopeConfig.from_dict({"engagement": "Test", "allowed_cidrs": ["127.0.0.1/32"]})
