from __future__ import annotations

import pytest

from cyberforge.core.config import ScanConfig
from cyberforge.core.exceptions import AuthorizationError, ConfigurationError
from cyberforge.core.scope import Scope, ScopeConfig
from cyberforge.engine import ScanEngine


def test_engine_refuses_to_start_without_authorization(tmp_path) -> None:
    scope = Scope(
        ScopeConfig(
            engagement="Engine Test",
            authorized_by="Owner",
            allowed_cidrs=("127.0.0.1/32",),
            max_requests=10,
        )
    )
    config = ScanConfig(targets=["http://127.0.0.1/"], output_dir=tmp_path)
    with pytest.raises(AuthorizationError):
        ScanEngine(config, scope)


def test_engine_rejects_invalid_configuration(tmp_path) -> None:
    scope = Scope(
        ScopeConfig(
            engagement="Engine Test",
            authorized_by="Owner",
            allowed_cidrs=("127.0.0.1/32",),
            max_requests=10,
        )
    )
    config = ScanConfig(
        targets=["http://127.0.0.1/"],
        output_dir=tmp_path,
        have_authorization=True,
        accept_disclaimer=True,
        formats=["csv"],
        modules=[],
    )
    with pytest.raises(ConfigurationError):
        ScanEngine(config, scope)


def test_engine_rejects_credential_module_without_scope_permission(tmp_path) -> None:
    scope = Scope(
        ScopeConfig(
            engagement="Engine Test",
            authorized_by="Owner",
            allowed_cidrs=("127.0.0.1/32",),
            max_requests=10,
        )
    )
    config = ScanConfig(
        targets=["http://127.0.0.1/"],
        output_dir=tmp_path,
        have_authorization=True,
        accept_disclaimer=True,
        modules=["brute"],
        brute_protocols=["http-basic"],
        allow_credential_attacks=True,
    )
    with pytest.raises(ConfigurationError):
        ScanEngine(config, scope)


def test_engine_accepts_completed_gate(tmp_path, monkeypatch) -> None:
    scope = Scope(
        ScopeConfig(
            engagement="Engine Test",
            authorized_by="Owner",
            allowed_cidrs=("127.0.0.1/32",),
            max_requests=10,
        )
    )
    config = ScanConfig(
        targets=["http://127.0.0.1/"],
        output_dir=tmp_path,
        have_authorization=True,
        accept_disclaimer=True,
        modules=[],
        formats=["json"],
    )
    monkeypatch.setattr("cyberforge.engine.setup_logging", lambda **kwargs: None)
    monkeypatch.setattr("cyberforge.engine.log_banner", lambda *args: None)
    engine = ScanEngine(config, scope, {"engagement": "Engine Test"})
    bundle = engine.run()
    assert bundle.engagement == "Engine Test"
    assert engine.run_dir.exists()
    assert engine.report_paths is not None
    assert engine.report_paths.json is not None
    assert engine.report_paths.json.exists()
