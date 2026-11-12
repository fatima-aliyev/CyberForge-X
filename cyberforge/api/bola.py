"""Bounded BOLA/IDOR checks using explicitly supplied identities."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)
from cyberforge.core.models import APIEndpoint, Evidence, Finding, Severity
from cyberforge.core.session import HttpResult, SafeSession
from cyberforge.core.utils import (
    format_curl,
    normalize_for_diff,
    parse_auth_header,
    parse_ids,
    similarity,
)

PLACEHOLDER_RE = re.compile(r"\{(?:id|user_?id|account_?id|object_?id|item_?id|order_?id|uuid)\}", re.IGNORECASE)
UNSAFE_TOKENS = {
    "delete",
    "remove",
    "destroy",
    "logout",
    "signout",
    "revoke",
    "reset",
    "deactivate",
    "disable",
    "transfer",
    "purchase",
    "checkout",
    "cancel",
    "purge",
}
IDENTIFIER_KEYS = {
    "id",
    "user_id",
    "userid",
    "owner_id",
    "ownerid",
    "account_id",
    "accountid",
    "email",
    "username",
    "uuid",
}
MAX_ENDPOINTS = 20
MAX_FINDINGS = 10


@dataclass
class BOLAResult:
    tested: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped: str = ""


class BOLATester:
    def __init__(self, ctx: ModuleContext, endpoints: list[APIEndpoint] | None = None) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.endpoints = endpoints or []
        self.result = BOLAResult()

    def run(self) -> BOLAResult:
        auth_a = parse_auth_header(self.ctx.config.auth_a)
        auth_b = parse_auth_header(self.ctx.config.auth_b)
        if not auth_a:
            self.result.skipped = "identity A not supplied; BOLA checks skipped"
            self.log.info("Skipping BOLA checks: --auth-a was not supplied")
            return self.result
        if auth_b and self.ctx.config.auth_a == self.ctx.config.auth_b:
            auth_b = {}
        session_a = self.ctx.new_session(extra_headers=auth_a, clear_cookies=True, name="api-a")
        session_b = (
            self.ctx.new_session(extra_headers=auth_b, clear_cookies=True, name="api-b") if auth_b else None
        )
        anonymous = self.ctx.new_session(clear_cookies=True, name="api-anon")
        targets = self._targets()
        if not targets:
            self.result.skipped = "no object endpoints with replaceable identifiers"
            self.log.info("Skipping BOLA checks: no object endpoints with identifiers")
            return self.result
        ids = parse_ids(self.ctx.config.bola_ids, max_ids=5)[:3]
        if not ids:
            ids = ["1"]
        findings_count = 0
        for endpoint_url in targets:
            for identifier in ids:
                if findings_count >= MAX_FINDINGS:
                    return self.result
                url = _substitute(endpoint_url, identifier)
                if not url or _unsafe_endpoint(url):
                    continue
                try:
                    response_a = session_a.get(url, headers={"Accept": "application/json, */*"})
                    if response_a.status is None or response_a.status in {401, 403, 404, 405, 429}:
                        continue
                    self.result.tested += 1
                    if session_b is not None:
                        finding = self._compare(
                            url,
                            response_a,
                            session_b.get(url, headers={"Accept": "application/json, */*"}),
                            session_b,
                            cross_user=True,
                        )
                        if finding:
                            self.result.findings.append(finding)
                            findings_count += 1
                            continue
                    finding = self._compare(
                        url,
                        response_a,
                        anonymous.get(url, headers={"Accept": "application/json, */*"}),
                        anonymous,
                        cross_user=False,
                    )
                    if finding:
                        self.result.findings.append(finding)
                        findings_count += 1
                except RequestBudgetExceeded:
                    self.log.warning("request budget exhausted during BOLA checks")
                    return self.result
                except (ScopeViolation, PolicyViolation):
                    continue
        self.log.info("BOLA checks: %d request pair(s), %d finding(s)", self.result.tested, len(self.result.findings))
        return self.result

    def _compare(
        self,
        url: str,
        response_a: HttpResult,
        response_other: HttpResult,
        session: SafeSession,
        cross_user: bool,
    ) -> Finding | None:
        if response_other.status is None:
            return None
        if response_other.status in {401, 403}:
            return None
        if response_a.status not in {200, 201, 202, 203, 204}:
            return None
        if response_other.status not in {200, 201, 202, 203, 204}:
            return None
        text_a = _canonical(response_a.text)
        text_b = _canonical(response_other.text)
        if not text_a or not text_b:
            return None
        ratio = similarity(text_a, text_b)
        marker_keys = _shared_marker_keys(text_a, text_b)
        if ratio < 0.95 and not marker_keys:
            return None
        if marker_keys:
            severity = Severity.HIGH
            cvss = 8.1
            confidence = "high"
            detail = f"Identity B received fields shared with identity A: {', '.join(marker_keys[:8])}"
            title = "Broken object-level authorization (BOLA/IDOR)"
        elif not cross_user:
            severity = Severity.HIGH
            cvss = 8.2
            confidence = "medium"
            detail = "An unauthenticated request returned the same object representation as the authenticated request."
            title = "Object endpoint accessible without authentication"
        else:
            severity = Severity.MEDIUM
            cvss = 5.3
            confidence = "medium"
            detail = "Two authenticated identities received highly similar object responses for the same identifier."
            title = "Potential broken object-level authorization (BOLA/IDOR)"
        return Finding(
            title=title,
            severity=severity,
            module="api",
            target=url,
            description=(
                "Object identifiers appear to be directly addressable without sufficient ownership checks. "
                "The result is based on response comparison and requires manual confirmation of object ownership."
            ),
            remediation=(
                "Enforce object-level authorization on every request using the authenticated subject, "
                "not client-supplied identifiers. Prefer unguessable identifiers as defense in depth."
            ),
            evidence=Evidence(
                request=format_curl("GET", url),
                response_excerpt=(
                    f"Identity A status: {response_a.status}; comparison status: {response_other.status}\n"
                    f"Response similarity: {ratio:.3f}\n{detail}"
                ),
                notes="Response bodies are not reproduced; comparison is structural.",
            ),
            cvss=cvss,
            confidence=confidence,
            tags=["api", "bola", "idor", "access-control"],
            metadata={
                "similarity": round(ratio, 3),
                "shared_marker_keys": marker_keys[:8],
                "cross_user": cross_user,
            },
        )

    def _targets(self) -> list[str]:
        targets: list[str] = []
        for endpoint in self.endpoints:
            if endpoint.method.upper() != "GET":
                continue
            if not PLACEHOLDER_RE.search(endpoint.url):
                continue
            if _unsafe_endpoint(endpoint.url):
                continue
            targets.append(endpoint.url)
        for entry in self.ctx.config.bola_endpoints:
            raw = entry.strip()
            if not raw:
                continue
            if raw.upper().startswith("GET "):
                raw = raw[4:].strip()
            base = self.ctx.config.api_base or _base_from_targets(self.ctx.config.targets)
            if "://" not in raw:
                raw = urljoin(base.rstrip("/") + "/", raw.lstrip("/"))
            if not PLACEHOLDER_RE.search(raw) and "FUZZ" not in raw:
                self.log.debug("BOLA endpoint has no identifier placeholder: %s", raw)
            targets.append(raw)
        output: list[str] = []
        seen: set[str] = set()
        for target in targets:
            try:
                self.ctx.scope.assert_url(_substitute(target, "1"))
            except (ScopeViolation, ValueError):
                continue
            if target in seen:
                continue
            seen.add(target)
            output.append(target)
            if len(output) >= MAX_ENDPOINTS:
                break
        return output


def _substitute(template: str, identifier: str) -> str:
    value = quote(str(identifier), safe="")
    result = PLACEHOLDER_RE.sub(value, template)
    result = result.replace("{id}", value).replace("{ userId }", value)
    result = result.replace("FUZZ", value).replace("<id>", value).replace(":id", value)
    return result


def _shared_marker_keys(first: str, second: str) -> list[str]:
    left = _marker_values(first)
    right = _marker_values(second)
    keys: list[str] = []
    for key, values in left.items():
        if any(value in right.get(key, set()) for value in values):
            keys.append(key)
    return sorted(set(keys))


def _marker_values(text: str) -> dict[str, set[str]]:
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return {}
    values: dict[str, set[str]] = {}
    for key, value in _walk(payload, 0):
        if key.lower() not in IDENTIFIER_KEYS or not isinstance(value, (str, int)):
            continue
        rendered = str(value)
        if len(rendered) < 4 or len(rendered) > 120:
            continue
        if rendered.lower() in {"true", "false", "null", "none"}:
            continue
        values.setdefault(key.lower(), set()).add(rendered)
    return values


def _walk(value: Any, depth: int) -> list[tuple[str, Any]]:
    if depth > 2:
        return []
    output: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            output.append((str(key), child))
            if isinstance(child, (dict, list)):
                output.extend(_walk(child, depth + 1))
    elif isinstance(value, list):
        for child in value[:10]:
            if isinstance(child, dict):
                output.extend(_walk(child, depth + 1))
    return output


def _canonical(text: str) -> str:
    try:
        payload = json.loads(text)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))[:120000]
    except (ValueError, TypeError):
        return normalize_for_diff(text)[:120000]


def _unsafe_endpoint(url: str) -> bool:
    lowered = url.lower()
    return any(token in lowered for token in UNSAFE_TOKENS)


def _base_from_targets(targets: list[str]) -> str:
    for target in targets:
        if target.lower().startswith(("http://", "https://")):
            parts = urlsplit(target)
            return f"{parts.scheme}://{parts.netloc}"
    return "http://localhost"
