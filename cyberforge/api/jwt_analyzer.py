"""Offline JWT inspection and explicitly gated acceptance tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)
from cyberforge.core.models import Evidence, Finding, Severity
from cyberforge.core.utils import (
    format_curl,
    load_lines,
    normalize_for_diff,
    read_package_lines,
    similarity,
)

HS_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
SENSITIVE_CLAIMS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "client_secret",
    "credit_card",
    "card_number",
    "ssn",
    "social_security",
    "auth_token",
    "refresh_token",
}
BEARER_RE = re.compile(r"(?i)bearer\s+([A-Za-z0-9._~+/=-]+)")


class JWTAnalyzer:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.target = (
            ctx.config.jwt_test_url
            or ctx.config.api_base
            or next((t for t in ctx.config.targets if t.lower().startswith(("http://", "https://"))), "jwt")
        )
        self._active_done = False

    def analyze(self) -> list[Finding]:
        tokens = self._load_tokens()
        if not tokens:
            self.log.info("No JWT supplied; skipping JWT analysis")
            return []
        findings: list[Finding] = []
        for token in tokens[:5]:
            decoded = decode_jwt(token)
            if decoded is None:
                self.log.debug("Skipping malformed JWT entry")
                continue
            header, payload, signature, signing_input = decoded
            findings.extend(self._static_tests(header, payload))
            findings.extend(self._weak_secret(header, signature, signing_input))
            if (
                not self._active_done
                and self.ctx.config.jwt_active_tests
                and self.ctx.config.jwt_test_url
            ):
                self._active_done = True
                findings.extend(self._active_tests(token, header, payload))
        self.log.info("JWT analysis: %d token(s), %d finding(s)", len(tokens), len(findings))
        return findings

    # ------------------------------------------------------------------ inputs
    def _load_tokens(self) -> list[str]:
        tokens: list[str] = []
        tokens.extend(str(token).strip() for token in self.ctx.config.jwt_tokens if str(token).strip())
        if self.ctx.config.jwt_file:
            tokens.extend(load_lines(self.ctx.config.jwt_file))
        for value in list(self.ctx.config.extra_headers.values()) + [
            self.ctx.config.auth_a,
            self.ctx.config.auth_b,
        ]:
            match = BEARER_RE.search(value or "")
            if match:
                tokens.append(match.group(1))
        ordered: list[str] = []
        seen: set[str] = set()
        for token in tokens:
            token = token.strip().strip('"').strip("'")
            if token.count(".") != 2 or token in seen:
                continue
            seen.add(token)
            ordered.append(token)
        return ordered

    # ------------------------------------------------------------------ static
    def _static_tests(self, header: dict[str, Any], payload: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        alg = str(header.get("alg") or "").lower()
        if alg == "none":
            findings.append(
                self._finding(
                    "JWT declares the insecure 'none' algorithm",
                    Severity.HIGH,
                    8.1,
                    "A supplied token declares alg=none. A verifier that accepts this value permits "
                    "signature bypass.",
                    "Reject alg=none and pin the expected algorithm during verification.",
                    "Header: alg=none",
                    ["jwt", "authentication", "algorithm-confusion"],
                    "medium",
                )
            )
        for key in ("jku", "x5u"):
            if header.get(key):
                findings.append(
                    self._finding(
                        "JWT accepts a remote key reference",
                        Severity.MEDIUM,
                        5.3,
                        f"The token header contains {key}, which can cause the verifier to fetch key "
                        "material from an attacker-controlled location if not allowlisted.",
                        "Ignore untrusted jku/x5u headers or enforce a strict host allowlist.",
                        f"Header {key}: {header.get(key)}",
                        ["jwt", "authentication", "key-injection"],
                        "medium",
                    )
                )
        kid = str(header.get("kid") or "")
        if kid and any(token in kid.lower() for token in ("../", "..\\", "/", "http:", "https:", "|", ";")):
            findings.append(
                self._finding(
                    "JWT kid value contains suspicious path or URL syntax",
                    Severity.LOW,
                    4.3,
                    "The kid header contains characters commonly used for path traversal, command "
                    "injection, or key-URL manipulation. Verify how the application resolves it.",
                    "Map kid values through a fixed allowlist; never use kid as a filesystem path or SQL value.",
                    f"kid={kid[:120]}",
                    ["jwt", "authentication", "kid"],
                    "medium",
                )
            )
        now = time.time()
        exp = payload.get("exp")
        if "exp" not in payload:
            findings.append(
                self._finding(
                    "JWT has no expiration claim",
                    Severity.LOW,
                    3.7,
                    "The token has no exp claim, so it may remain valid indefinitely if not revoked.",
                    "Issue short-lived access tokens and enforce server-side expiration and revocation.",
                    "Claims present: " + ", ".join(sorted(str(key) for key in payload))[:300],
                    ["jwt", "session", "expiration"],
                    "high",
                )
            )
        elif isinstance(exp, (int, float)) and exp - now > 31536000:
            findings.append(
                self._finding(
                    "JWT expiration is unusually distant",
                    Severity.INFO,
                    None,
                    "The token expiration is more than one year in the future, increasing the impact "
                    "of token theft.",
                    "Reduce token lifetime and use refresh tokens for long-lived sessions.",
                    f"exp is approximately {int((exp - now) / 86400)} days in the future.",
                    ["jwt", "session", "expiration"],
                    "high",
                )
            )
        sensitive = sorted({str(key).lower() for key in payload if str(key).lower() in SENSITIVE_CLAIMS})
        if sensitive:
            findings.append(
                self._finding(
                    "Sensitive claim names present in JWT",
                    Severity.LOW,
                    3.1,
                    "The JWT payload contains claim names associated with secrets or personal data. "
                    "JWT payloads are readable by the client and anyone who obtains the token.",
                    "Keep secrets and sensitive personal data out of JWTs; store server-side references.",
                    "Sensitive claim names: " + ", ".join(sensitive),
                    ["jwt", "data-exposure", "claims"],
                    "high",
                )
            )
        return findings

    def _weak_secret(
        self, header: dict[str, Any], signature: bytes, signing_input: str
    ) -> list[Finding]:
        algorithm = str(header.get("alg") or "").upper()
        digest = HS_ALGORITHMS.get(algorithm)
        if not digest or not signature:
            return []
        secrets = read_package_lines("wordlists", "jwt_secrets.txt")
        if self.ctx.config.jwt_secret_wordlist:
            secrets.extend(load_lines(self.ctx.config.jwt_secret_wordlist))
        for secret in secrets[:2000]:
            expected = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), digest).digest()
            if hmac.compare_digest(expected, signature):
                return [
                    self._finding(
                        "JWT signed with a weak dictionary secret",
                        Severity.HIGH,
                        8.1,
                        "The HMAC signature matches a common password from an offline dictionary. "
                        "An attacker with the token can forge arbitrary claims.",
                        "Rotate the signing key to a high-entropy random value and use centralized key management.",
                        f"Matched dictionary entry (masked): {_mask_secret(secret)}",
                        ["jwt", "weak-crypto", "authentication"],
                        "high",
                        metadata={"algorithm": algorithm, "secret_length": len(secret)},
                    )
                ]
        return []

    # ------------------------------------------------------------------ active
    def _active_tests(
        self,
        token: str,
        header: dict[str, Any],
        payload: dict[str, Any],
    ) -> list[Finding]:
        test_url = self.ctx.config.jwt_test_url
        try:
            valid = self.ctx.session.get(test_url, headers={"Authorization": f"Bearer {token}"})
            anonymous = self.ctx.session.get(test_url)
        except (ScopeViolation, PolicyViolation):
            return []
        except RequestBudgetExceeded:
            self.log.warning("request budget exhausted during JWT active tests")
            return []
        if valid.status is None or anonymous.status is None:
            return []
        protected = valid.status in {200, 201, 202, 204} and (
            anonymous.status in {401, 403}
            or similarity(normalize_for_diff(valid.text), normalize_for_diff(anonymous.text)) < 0.9
        )
        if not protected:
            self.log.info("JWT test URL is not protected; active acceptance tests skipped")
            return []
        findings: list[Finding] = []
        none_header = dict(header)
        none_header["alg"] = "none"
        none_token = _encode_json(none_header) + "." + _encode_json(payload) + "."
        none_result = self._send_token(none_token)
        if none_result is not None and self._accepted(none_result, valid, anonymous):
            findings.append(
                self._finding(
                    "JWT alg=none accepted by verifier",
                    Severity.CRITICAL,
                    9.1,
                    "The API accepted an unsigned token with alg=none, permitting authentication bypass.",
                    "Reject alg=none; pin a single expected algorithm and verify every signature.",
                    "Unsigned token was accepted at the configured test URL.",
                    ["jwt", "auth-bypass", "algorithm-confusion"],
                    "high",
                )
            )
        public_key = self.ctx.config.jwt_public_key
        if (
            str(header.get("alg") or "").upper() in {"RS256", "RS384", "RS512"}
            and public_key
            and Path(public_key).is_file()
        ):
            try:
                key_bytes = Path(public_key).read_bytes()
            except OSError:
                key_bytes = b""
            if key_bytes:
                confusion_header = dict(header)
                confusion_header["alg"] = "HS256"
                signing = _encode_json(confusion_header) + "." + _encode_json(payload)
                signature = hmac.new(key_bytes, signing.encode("ascii"), hashlib.sha256).digest()
                confusion_token = signing + "." + _b64url_encode(signature)
                confusion_result = self._send_token(confusion_token)
                if confusion_result is not None and self._accepted(confusion_result, valid, anonymous):
                    findings.append(
                        self._finding(
                            "JWT RS256/HS256 key-confusion accepted",
                            Severity.CRITICAL,
                            9.1,
                            "A token signed with HMAC using the RSA public key was accepted, allowing "
                            "signature forgery.",
                            "Never allow the algorithm to change between verification modes; pin algorithms "
                            "and use a correct JWT library configuration.",
                            "HS256 token signed with the supplied public key was accepted.",
                            ["jwt", "auth-bypass", "algorithm-confusion"],
                            "high",
                        )
                    )
        return findings

    def _send_token(self, token: str) -> Any:
        try:
            return self.ctx.session.get(
                self.ctx.config.jwt_test_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        except (ScopeViolation, PolicyViolation):
            return None
        except RequestBudgetExceeded:
            self.log.warning("request budget exhausted during JWT active tests")
            return None

    def _accepted(self, candidate: Any, valid: Any, anonymous: Any) -> bool:
        if candidate.status not in {200, 201, 202, 204, 302}:
            return False
        candidate_text = normalize_for_diff(candidate.text)
        valid_ratio = similarity(candidate_text, normalize_for_diff(valid.text))
        anonymous_ratio = similarity(candidate_text, normalize_for_diff(anonymous.text))
        if anonymous.status in {401, 403}:
            return valid_ratio >= 0.75
        return valid_ratio >= 0.9 and valid_ratio > anonymous_ratio

    # ------------------------------------------------------------------ finding
    def _finding(
        self,
        title: str,
        severity: Severity,
        cvss: float | None,
        description: str,
        remediation: str,
        evidence: str,
        tags: list[str],
        confidence: str,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            module="api",
            target=self.target,
            description=description,
            remediation=remediation,
            evidence=Evidence(
                response_excerpt=evidence[:1000],
                request=(
                    format_curl("GET", self.ctx.config.jwt_test_url)
                    if self.ctx.config.jwt_test_url
                    else "JWT token supplied locally"
                ),
                notes="Token values are intentionally omitted from reports.",
            ),
            cvss=cvss,
            confidence=confidence,
            tags=["api", *tags],
            metadata=metadata or {},
        )


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, str] | None:
    raw = token.strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2]) if parts[2] else b""
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, signature, f"{parts[0]}.{parts[1]}"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _encode_json(value: dict[str, Any]) -> str:
    return _b64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _mask_secret(value: str) -> str:
    if len(value) <= 4:
        return "****"
    if len(value) <= 8:
        return value[0] + "****" + value[-1]
    return value[:2] + "****" + value[-2:]
