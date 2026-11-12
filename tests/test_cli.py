from __future__ import annotations

import pytest

from cyberforge.cli import _build_parser, _config_from_args, main
from cyberforge.core.exceptions import AuthorizationError
from cyberforge.core.guard import AuthorizationGate
from cyberforge.core.scope import load_scope


def _write_scope(path) -> None:
    path.write_text(
        "engagement: CLI Test\n"
        "authorized_by: Owner\n"
        "authorization_ref: CLI-1\n"
        "allowed_cidrs: [127.0.0.1/32]\n"
        "allowed_ports: [80, 443]\n"
        "max_rps: 2\n"
        "max_requests: 20\n",
        encoding="utf-8",
    )


def test_modules_command() -> None:
    assert main(["modules"]) == 0


def test_version_command() -> None:
    assert main(["version"]) == 0


def test_validate_scope_command(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    _write_scope(scope_path)
    assert main(["validate-scope", "--scope", str(scope_path)]) == 0


def test_scan_requires_exact_engagement(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    _write_scope(scope_path)
    code = main(
        [
            "scan",
            "--scope",
            str(scope_path),
            "--target",
            "http://127.0.0.1/",
            "--authorization",
            "wrong",
            "--i-have-authorization",
            "--accept-disclaimer",
        ]
    )
    assert code == 2


def test_scan_rejects_multiple_scope_violations(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    _write_scope(scope_path)
    code = main(
        [
            "scan",
            "--scope",
            str(scope_path),
            "--target",
            "http://192.0.2.10/",
            "--authorization",
            "CLI Test",
            "--i-have-authorization",
            "--accept-disclaimer",
            "--modules",
            "web",
        ]
    )
    assert code == 2


def test_brute_module_requires_credential_gate(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    _write_scope(scope_path)
    code = main(
        [
            "scan",
            "--scope",
            str(scope_path),
            "--target",
            "http://127.0.0.1/",
            "--authorization",
            "CLI Test",
            "--i-have-authorization",
            "--accept-disclaimer",
            "--modules",
            "brute",
        ]
    )
    assert code == 2


def test_noninteractive_gate_requires_acceptance(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    _write_scope(scope_path)
    _, scope = load_scope(scope_path)
    with pytest.raises(AuthorizationError, match="accept-disclaimer"):
        AuthorizationGate.enforce(scope, "CLI Test", True, False, interactive=False)


def test_config_flag_mapping() -> None:
    parser = _build_parser()
    args = parser.parse_args(
        [
            "scan",
            "--target",
            "http://127.0.0.1/",
            "--modules",
            "web,api",
            "--header",
            "X-Test: one",
            "--ssrf-ports",
            "80,8080",
            "--brute-protocol",
            "ftp,ssh",
        ]
    )
    config = _config_from_args(args)
    assert config.modules == ["web", "api"]
    assert config.extra_headers == {"X-Test": "one"}
    assert config.ssrf_ports == [80, 8080]
    assert config.brute_protocols == ["ftp", "ssh"]
