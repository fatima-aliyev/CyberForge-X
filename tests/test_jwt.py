from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from types import SimpleNamespace

from cyberforge.api.jwt_analyzer import JWTAnalyzer, decode_jwt


def _token(header: dict, payload: dict, secret: bytes = b"") -> str:
    def encode(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signing_input = f"{encode(header)}.{encode(payload)}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest() if secret else b""
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def _analyzer() -> JWTAnalyzer:
    config = SimpleNamespace(
        jwt_tokens=[],
        jwt_file=None,
        jwt_secret_wordlist=None,
        jwt_test_url="",
        jwt_active_tests=False,
        api_base="",
        targets=[],
        extra_headers={},
        auth_a="",
        auth_b="",
    )
    ctx = SimpleNamespace(config=config, logger=logging.getLogger("test.jwt"))
    return JWTAnalyzer(ctx)


def test_decode_jwt_round_trip() -> None:
    token = _token({"alg": "HS256"}, {"sub": "42"}, b"secret")
    decoded = decode_jwt(token)
    assert decoded is not None
    header, payload, signature, signing_input = decoded
    assert header["alg"] == "HS256"
    assert payload["sub"] == "42"
    assert signature
    assert signing_input.count(".") == 1


def test_static_analysis_without_kid_or_exp_does_not_raise() -> None:
    findings = _analyzer()._static_tests({"alg": "HS256"}, {"sub": "42"})
    titles = {finding.title for finding in findings}
    assert "JWT has no expiration claim" in titles


def test_far_future_expiration_is_reported_without_kid() -> None:
    findings = _analyzer()._static_tests(
        {"alg": "HS256"},
        {"sub": "42", "exp": 4102444800},
    )
    titles = {finding.title for finding in findings}
    assert "JWT expiration is unusually distant" in titles


def test_weak_dictionary_secret_is_detected() -> None:
    analyzer = _analyzer()
    analyzer.ctx.config.jwt_tokens = [_token({"alg": "HS256"}, {"sub": "42"}, b"secret")]
    findings = analyzer.analyze()
    titles = {finding.title for finding in findings}
    assert "JWT signed with a weak dictionary secret" in titles


def test_alg_none_is_reported() -> None:
    findings = _analyzer()._static_tests({"alg": "none"}, {"sub": "42", "exp": 1})
    assert any("none" in finding.title for finding in findings)
