"""Small, dependency-light helpers used across modules."""

from __future__ import annotations

import difflib
import hashlib
import ipaddress
import json
import re
import shlex
import socket
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

SECRET_KEY_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|"
    r"cookie|set-cookie|x-api-key|access[_-]?token|refresh[_-]?token)\b"
    r"(\s*[:=]\s*)([^\s,;&]{2,})"
)
BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END "
    r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)
SENSITIVE_QUERY_KEYS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "auth",
}
TEXT_CONTENT_HINTS = ("text/", "json", "xml", "javascript", "html", "x-www-form-urlencoded")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def short_id(length: int = 8) -> str:
    import secrets

    return secrets.token_hex(max(2, length // 2)).upper()[:length]


def mask_secret(value: str, show: bool = False) -> str:
    if show or not value:
        return value
    if len(value) <= 3:
        return "****"
    if len(value) <= 8:
        return value[0] + "****" + value[-1]
    return value[:2] + "****" + value[-2:]


def redact_sensitive_text(text: str, limit: int | None = None) -> str:
    """Mask secrets in free-form text before it is written into a report."""
    if not text:
        return ""
    cleaned = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    cleaned = BEARER_RE.sub(r"\1 [REDACTED]", cleaned)
    cleaned = JWT_RE.sub("[REDACTED JWT]", cleaned)
    cleaned = SECRET_KEY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", cleaned)
    if limit is not None and len(cleaned) > limit:
        cleaned = cleaned[:limit] + "\n...[truncated]"
    return cleaned


def sanitize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    sensitive = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    }
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in sensitive:
            result[key] = "[REDACTED]"
        else:
            result[key] = redact_sensitive_text(str(value), limit=400)
    return result


def sanitize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_sensitive_text(url)
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    safe_pairs = [
        (key, "[REDACTED]" if key.lower() in SENSITIVE_QUERY_KEYS else value)
        for key, value in pairs
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe_pairs), parts.fragment))


def get_header(headers: dict[str, str], name: str, default: str = "") -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return default


def is_text_content(content_type: str) -> bool:
    if not content_type:
        return True
    lowered = content_type.lower()
    return any(hint in lowered for hint in TEXT_CONTENT_HINTS)


def normalize_host(value: str) -> str:
    """Return a lower-case hostname from a URL, host:port, or bare host."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            return (urlsplit(raw).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    candidate = raw
    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing > 0:
            return candidate[1:closing].lower()
    if candidate.count(":") == 1:
        host, _, port = candidate.partition(":")
        if port.isdigit():
            candidate = host
    return candidate.strip().lower().rstrip(".")


def split_host_port(value: str, default_port: int | None = None) -> tuple[str, int | None]:
    raw = (value or "").strip()
    if not raw:
        return "", default_port
    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = parts.port or default_port
        return host, port
    if raw.startswith("["):
        closing = raw.find("]")
        if closing > 0:
            host = raw[1:closing]
            rest = raw[closing + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, default_port
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if port.isdigit():
            return host, int(port)
    return raw, default_port


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return url.strip()
    port = parts.port
    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def same_origin(first: str, second: str) -> bool:
    try:
        a = urlsplit(first)
        b = urlsplit(second)
    except ValueError:
        return False
    if a.scheme.lower() != b.scheme.lower():
        return False
    return (a.hostname or "").lower() == (b.hostname or "").lower() and _effective_port(a) == _effective_port(b)


def same_host(first: str, second: str) -> bool:
    try:
        return (urlsplit(first).hostname or "").lower() == (urlsplit(second).hostname or "").lower()
    except ValueError:
        return False


def _effective_port(parts: Any) -> int | None:
    if parts.port is not None:
        return parts.port
    if parts.scheme.lower() == "http":
        return 80
    if parts.scheme.lower() == "https":
        return 443
    return None


def join_url(base: str, link: str) -> str:
    return urljoin(base, link.strip())


def strip_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def parse_ports(spec: str, max_ports: int = 4096) -> list[int]:
    ports: set[int] = set()
    for token in (spec or "").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, _, end_text = token.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {token!r}") from exc
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise ValueError(f"port range out of bounds: {token!r}")
            if end - start > max_ports:
                raise ValueError(f"port range too large (limit {max_ports}): {token!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise ValueError(f"invalid port: {token!r}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of bounds: {port}")
            ports.add(port)
        if len(ports) > max_ports:
            raise ValueError(f"too many ports (limit {max_ports})")
    return sorted(ports)


def parse_ids(spec: str, max_ids: int = 20) -> list[str]:
    values: list[str] = []
    for token in (spec or "").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token and all(part.strip().isdigit() for part in token.split("-", 1)):
            start_text, end_text = token.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            for number in range(start, min(end, start + max_ids) + 1):
                values.append(str(number))
        else:
            values.append(token)
        if len(values) >= max_ids:
            break
    return dedupe(values)[:max_ids]


def dedupe(items: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for item in items:
        key = item
        try:
            hashable = key not in seen
        except TypeError:
            hashable = True
        if hashable and key not in seen:
            seen.add(key)
            result.append(item)
    return result


def load_lines(path: str | Path | None, fallback: Iterable[str] = ()) -> list[str]:
    lines: list[str] = list(fallback)
    if path:
        candidate = Path(path)
        if candidate.is_file():
            try:
                content = candidate.read_text(encoding="utf-8-sig", errors="ignore")
                lines = [
                    line.strip()
                    for line in content.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
            except OSError:
                pass
    return dedupe(lines)


def package_data_path(*parts: str) -> Path:
    return Path(__file__).resolve().parents[1].joinpath("data", *parts)


def read_package_lines(*parts: str) -> list[str]:
    return load_lines(package_data_path(*parts))


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def truncate(text: str, limit: int = 600) -> str:
    if text is None:
        return ""
    cleaned = text.replace("\x00", "")
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit] + "\n...[truncated]"


def safe_excerpt(text: str, limit: int = 800) -> str:
    return truncate(redact_sensitive_text(text), limit)


def similarity(first: str, second: str) -> float:
    if first == second:
        return 1.0
    if not first or not second:
        return 0.0
    a = first[:120000]
    b = second[:120000]
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def normalize_for_diff(text: str) -> str:
    lowered = re.sub(r"\s+", " ", text or "").strip().lower()
    return lowered[:120000]


def format_curl(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    data: str | None = None,
    json_body: Any | None = None,
) -> str:
    parts = ["curl", "-i", "-sS", "-X", method.upper(), shlex.quote(sanitize_url(url))]
    for key, value in sanitize_headers(headers).items():
        parts.extend(["-H", shlex.quote(f"{key}: {value}")])
    if json_body is not None:
        parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(json.dumps(json_body))])
    elif data:
        parts.extend(["--data-raw", shlex.quote(redact_sensitive_text(data))])
    return " ".join(parts)


def parse_auth_header(value: str) -> dict[str, str]:
    """Accept 'Header: value', 'Bearer token', or a raw token."""
    raw = (value or "").strip()
    if not raw:
        return {}
    if ":" in raw:
        name, _, rest = raw.partition(":")
        if name and " " not in name.strip() and rest.strip():
            return {name.strip(): rest.strip()}
    if re.match(r"(?i)^(bearer|basic|token|digest)\s+", raw):
        return {"Authorization": raw}
    if re.match(r"^[A-Za-z0-9._~+/=-]{8,}$", raw):
        return {"Authorization": f"Bearer {raw}"}
    return {"Authorization": raw}


def looks_like_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def safe_json_loads(text: str) -> Any | None:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def host_port_from_target(target: str, default_port: int = 443) -> tuple[str, int]:
    host, port = split_host_port(target, default_port)
    return host, port or default_port


def iter_lines(items: Iterable[str]) -> Iterator[str]:
    for item in items:
        value = item.strip()
        if value and not value.startswith("#"):
            yield value


def resolve_ipv4(host: str) -> list[str]:
    try:
        info = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return dedupe([entry[4][0] for entry in info])


def resolve_all(host: str) -> list[str]:
    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return dedupe([entry[4][0] for entry in info])
