"""Swagger/OpenAPI and GraphQL discovery with endpoint normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)
from cyberforge.core.models import APIEndpoint, APISurface, Evidence, Finding, Severity
from cyberforge.core.utils import format_curl, truncate

if TYPE_CHECKING:
    from cyberforge.recon.module import ReconResult

DOC_PATHS = (
    "openapi.json",
    "swagger.json",
    "v3/api-docs",
    "api-docs",
    "swagger/v1/swagger.json",
    "swagger-ui.html",
    "swagger-ui/index.html",
    "docs",
    "redoc",
)
GRAPHQL_PATHS = ("graphql", "api/graphql", "graphiql")
INTROSPECTION_QUERY = "query { __schema { queryType { name } mutationType { name } types { name kind } } }"
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


@dataclass
class DiscoveryResult:
    surfaces: list[APISurface] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[APIEndpoint] = field(default_factory=list)


class APIDiscovery:
    def __init__(self, ctx: ModuleContext, recon_result: ReconResult | None = None) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.recon_result = recon_result
        self.result = DiscoveryResult()
        self._seen_docs: set[str] = set()
        self._seen_graphql: set[str] = set()

    def discover(self) -> DiscoveryResult:
        bases = self._bases()
        if not bases:
            self.log.warning("No API base URL could be derived from the targets")
            return self.result
        for base in bases:
            try:
                self._discover_base(base)
            except RequestBudgetExceeded:
                self.log.warning("request budget exhausted during API discovery")
                break
            except ScopeViolation:
                continue
            except Exception as exc:
                self.ctx.bundle.add_error("api", f"{base}: discovery failed: {exc}")
                self.log.debug("API discovery failed for %s: %s", base, exc)
        self.log.info(
            "API discovery: %d surface(s), %d endpoint(s), %d finding(s)",
            len(self.result.surfaces),
            len(self.result.endpoints),
            len(self.result.findings),
        )
        return self.result

    # ------------------------------------------------------------------ bases
    def _bases(self) -> list[str]:
        candidates: list[str] = []
        if self.ctx.config.api_base:
            candidates.append(self.ctx.config.api_base)
        candidates.extend(
            target for target in self.ctx.config.targets if target.lower().startswith(("http://", "https://"))
        )
        if self.recon_result:
            candidates.extend(self.recon_result.web_targets)
        selected: list[str] = []
        origins: set[str] = set()
        for candidate in candidates:
            if not candidate.lower().startswith(("http://", "https://")):
                continue
            try:
                self.ctx.scope.assert_url(candidate)
            except ScopeViolation:
                continue
            parts = urlsplit(candidate)
            key = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
            if key in origins:
                continue
            origins.add(key)
            selected.append(urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", "")))
            if len(selected) >= 3:
                break
        return selected

    def _discover_base(self, base: str) -> None:
        parsed = urlsplit(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        surface = APISurface(base_url=base)
        docs_seen = False
        for path in DOC_PATHS:
            if docs_seen:
                break
            for candidate in _candidate_urls(base, origin, path):
                if candidate in self._seen_docs:
                    continue
                self._seen_docs.add(candidate)
                try:
                    result = self.ctx.session.get(candidate, headers={"Accept": "application/json, text/html"})
                except (ScopeViolation, PolicyViolation):
                    continue
                if result.status is None or result.status in {401, 403, 404}:
                    continue
                payload = result.json()
                if isinstance(payload, dict) and ("openapi" in payload or "swagger" in payload) and isinstance(
                    payload.get("paths"), dict
                ):
                    surface.docs_urls.append(result.url or candidate)
                    self._parse_openapi(surface, payload, result.url or candidate)
                    self.result.findings.append(
                        Finding(
                            title="API documentation exposed",
                            severity=Severity.INFO,
                            module="api",
                            target=result.url or candidate,
                            description=(
                                "An OpenAPI/Swagger document is readable. It exposes endpoint names, "
                                "parameters, schemas, and authentication schemes."
                            ),
                            remediation=(
                                "Require authentication for documentation in production or restrict it to "
                                "trusted networks; review exposed schema details."
                            ),
                            evidence=Evidence(
                                request=format_curl("GET", candidate),
                                response_excerpt=f"Swagger/OpenAPI document returned (HTTP {result.status})",
                            ),
                            confidence="high",
                            tags=["api", "discovery", "documentation"],
                        )
                    )
                    docs_seen = True
                    break
                page = (result.text or "").lower()
                if (
                    result.status == 200
                    and "html" in result.content_type.lower()
                    and ("swagger" in page or "openapi" in page)
                ):
                    surface.docs_urls.append(result.url or candidate)
                    docs_seen = True
                    break
        self._discover_graphql(surface, base, origin)
        if surface.endpoints or surface.docs_urls or surface.graphql_urls:
            self.result.surfaces.append(surface)
            self.ctx.bundle.add_api_surface(surface)
            self.result.endpoints.extend(surface.endpoints)
        else:
            self.log.info("No API documentation or GraphQL endpoint found at %s", base)

    # ------------------------------------------------------------------ openapi
    def _parse_openapi(self, surface: APISurface, spec: dict[str, Any], docs_url: str) -> None:
        server_base = _server_base(spec, docs_url)
        schemes = _security_schemes(spec)
        surface.security_schemes = sorted(set(surface.security_schemes) | set(schemes))
        paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
        added = 0
        out_of_scope = 0
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method in HTTP_METHODS:
                operation = item.get(method)
                if not isinstance(operation, dict):
                    continue
                url = _endpoint_url(server_base, str(path))
                try:
                    self.ctx.scope.assert_url(url)
                except ScopeViolation:
                    out_of_scope += 1
                    continue
                parameters = _parameter_names(item, operation, spec)
                body_fields = _body_fields(operation, spec)
                security = _operation_security(operation, item)
                endpoint = APIEndpoint(
                    method=method.upper(),
                    url=url,
                    summary=truncate(str(operation.get("summary") or operation.get("operationId") or ""), 300),
                    parameters=parameters,
                    body_fields=body_fields,
                    operation_id=str(operation.get("operationId") or ""),
                    security=security,
                )
                surface.endpoints.append(endpoint)
                added += 1
                if added >= 200:
                    break
            if added >= 200:
                break
        if out_of_scope:
            surface.notes.append(f"filtered {out_of_scope} endpoint(s) outside the authorized scope")
        if added:
            self.result.findings.append(
                Finding(
                    title="API endpoints mapped from documentation",
                    severity=Severity.INFO,
                    module="api",
                    target=surface.base_url,
                    description=(
                        f"The OpenAPI document described {added} endpoint(s). The mapped surface is used "
                        "for authorization checks and manual review."
                    ),
                    remediation="Confirm every documented endpoint is intended, authenticated, and authorized.",
                    evidence=Evidence(
                        notes="\n".join(
                            f"{endpoint.method} {urlsplit(endpoint.url).path}"
                            for endpoint in surface.endpoints[:40]
                        ),
                        response_excerpt=f"security_schemes={', '.join(surface.security_schemes) or 'none'}",
                    ),
                    confidence="high",
                    tags=["api", "discovery", "mapping"],
                    metadata={"endpoint_count": added},
                )
            )

    # ------------------------------------------------------------------ graphql
    def _discover_graphql(self, surface: APISurface, base: str, origin: str) -> None:
        if not self.ctx.config.graphql_discovery:
            return
        for path in GRAPHQL_PATHS:
            for candidate in _candidate_urls(base, origin, path):
                if candidate in self._seen_graphql:
                    continue
                self._seen_graphql.add(candidate)
                try:
                    result = self.ctx.session.post(
                        candidate,
                        json_body={"query": INTROSPECTION_QUERY},
                        headers={"Accept": "application/json"},
                    )
                except (ScopeViolation, PolicyViolation):
                    continue
                if result.status is None or result.status not in {200, 400, 401, 403}:
                    continue
                payload = result.json()
                if not isinstance(payload, dict):
                    continue
                data = payload.get("data")
                if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
                    surface.graphql_urls.append(result.url or candidate)
                    surface.graphql_introspection = True
                    self.result.findings.append(
                        Finding(
                            title="GraphQL introspection enabled",
                            severity=Severity.INFO,
                            module="api",
                            target=result.url or candidate,
                            description=(
                                "The GraphQL endpoint answers schema introspection queries, exposing "
                                "types, queries, and mutations to unauthenticated users."
                            ),
                            remediation=(
                                "Disable production introspection or require authentication. Apply query "
                                "depth/complexity limits and field-level authorization."
                            ),
                            evidence=Evidence(
                                request=format_curl("POST", candidate),
                                response_excerpt="Introspection response contained a __schema object.",
                            ),
                            confidence="high",
                            tags=["api", "graphql", "introspection"],
                        )
                    )
                    return
                errors = payload.get("errors")
                if isinstance(errors, list) and any(
                    "introspection" in str(item).lower() for item in errors
                ):
                    self.log.info("GraphQL introspection is disabled at %s", candidate)
                    return


def _candidate_urls(base: str, origin: str, suffix: str) -> list[str]:
    parsed = urlsplit(base)
    urls: list[str] = []
    origin_url = f"{origin.rstrip('/')}/{suffix.lstrip('/')}"
    urls.append(origin_url)
    if parsed.path and parsed.path != "/":
        base_url = f"{base.rstrip('/')}/{suffix.lstrip('/')}"
        urls.append(base_url)
    seen: set[str] = set()
    return [url for url in urls if not (url in seen or seen.add(url))]


def _server_base(spec: dict[str, Any], docs_url: str) -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        first = servers[0] if isinstance(servers[0], dict) else {}
        url = str(first.get("url") or "").strip()
        if url:
            url = url.split("{", 1)[0].rstrip("/")
            if url:
                return urljoin(docs_url, url).rstrip("/")
    host = str(spec.get("host") or "").strip()
    if host:
        schemes = spec.get("schemes") if isinstance(spec.get("schemes"), list) else []
        scheme = str(schemes[0]).lower() if schemes else urlsplit(docs_url).scheme
        base_path = str(spec.get("basePath") or "").strip()
        return f"{scheme}://{host}{base_path}".rstrip("/")
    parsed = urlsplit(docs_url)
    path = parsed.path
    for suffix in DOC_PATHS:
        marker = "/" + suffix
        if path.endswith(marker):
            path = path[: -len(marker)]
            break
    path = path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path.rstrip("/") or "/", "", "")).rstrip("/")


def _endpoint_url(server_base: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    return f"{server_base.rstrip('/')}/{path.lstrip('/')}"


def _security_schemes(spec: dict[str, Any]) -> list[str]:
    components = spec.get("components") if isinstance(spec.get("components"), dict) else {}
    schemes = components.get("securitySchemes") if isinstance(components.get("securitySchemes"), dict) else {}
    legacy = spec.get("securityDefinitions") if isinstance(spec.get("securityDefinitions"), dict) else {}
    return [str(name) for name in {**schemes, **legacy}]


def _operation_security(operation: dict[str, Any], item: dict[str, Any]) -> list[str]:
    security = operation.get("security", item.get("security"))
    if not isinstance(security, list):
        return []
    names: list[str] = []
    for entry in security:
        if isinstance(entry, dict):
            names.extend(str(key) for key in entry)
    return sorted(set(names))


def _parameter_names(item: dict[str, Any], operation: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for container in (item.get("parameters"), operation.get("parameters")):
        if not isinstance(container, list):
            continue
        for parameter in container:
            resolved = _resolve_ref(spec, parameter, 0)
            if isinstance(resolved, dict) and resolved.get("name"):
                names.append(str(resolved["name"]))
    return sorted(set(names))


def _body_fields(operation: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    fields: list[str] = []
    body = _resolve_ref(spec, operation.get("requestBody"), 0)
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, dict):
            for media in content.values():
                if not isinstance(media, dict):
                    continue
                schema = _resolve_ref(spec, media.get("schema"), 0)
                fields.extend(_schema_properties(spec, schema, 0))
    for parameter in operation.get("parameters") or []:
        resolved = _resolve_ref(spec, parameter, 0)
        if not isinstance(resolved, dict):
            continue
        if resolved.get("in") == "body":
            schema = _resolve_ref(spec, resolved.get("schema"), 0)
            fields.extend(_schema_properties(spec, schema, 0))
    return sorted(set(fields))


def _schema_properties(spec: dict[str, Any], schema: Any, depth: int) -> list[str]:
    if depth > 2:
        return []
    schema = _resolve_ref(spec, schema, depth)
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    names: list[str] = []
    for name, child in properties.items():
        names.append(str(name))
        if depth < 1:
            names.extend(_schema_properties(spec, child, depth + 1))
    return names


def _resolve_ref(spec: dict[str, Any], node: Any, depth: int) -> Any:
    if depth > 4 or not isinstance(node, dict):
        return node
    reference = node.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return node
    current: Any = spec
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return node
    return _resolve_ref(spec, current, depth + 1)
