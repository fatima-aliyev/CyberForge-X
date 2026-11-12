"""Signed-scope enforcement.

Every HTTP request and every network connection passes through this module.
Hostname scopes include subdomains; CIDR scopes are explicit. Link-local
metadata endpoints are always denied, even if listed, to keep active testing
away from cloud credential endpoints.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from cyberforge.core.exceptions import ConfigurationError, ScopeViolation
from cyberforge.core.utils import (
    get_header,  # noqa: F401  (re-exported convenience for legacy imports)
    is_ip_literal,
    normalize_host,
    parse_ports,
    utc_now_iso,
)

ALWAYS_DENY_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    ipaddress.ip_network("100.100.100.200/32"),
]
DNS_CACHE_TTL = 300.0


@dataclass(frozen=True)
class ScopeConfig:
    engagement: str
    authorized_by: str
    authorization_ref: str = ""
    allowed_hosts: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    excluded_cidrs: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    allow_credential_attacks: bool = False
    allow_write_tests: bool = False
    max_rps: float = 5.0
    max_requests: int = 2500
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScopeConfig:
        if not isinstance(data, dict):
            raise ConfigurationError("scope file must contain a YAML mapping")
        engagement = str(data.get("engagement") or "").strip()
        authorized_by = str(data.get("authorized_by") or "").strip()
        if not engagement:
            raise ConfigurationError("scope.engagement is required")
        if not authorized_by:
            raise ConfigurationError("scope.authorized_by is required (named authorizing person/entity)")

        allowed_hosts = _as_tuple(data.get("allowed_hosts"))
        allowed_cidrs = _as_tuple(data.get("allowed_cidrs"))
        if not allowed_hosts and not allowed_cidrs:
            raise ConfigurationError("scope requires allowed_hosts and/or allowed_cidrs")

        ports_text = data.get("allowed_ports")
        ports: list[int] = []
        if ports_text:
            if isinstance(ports_text, (list, tuple)):
                ports = parse_ports(",".join(str(item) for item in ports_text))
            else:
                ports = parse_ports(str(ports_text))

        max_rps = float(data.get("max_rps", 5.0))
        if not 0.1 <= max_rps <= 50:
            raise ConfigurationError("scope.max_rps must be between 0.1 and 50")
        max_requests = int(data.get("max_requests", 2500))
        if not 1 <= max_requests <= 50000:
            raise ConfigurationError("scope.max_requests must be between 1 and 50000")

        return cls(
            engagement=engagement,
            authorized_by=authorized_by,
            authorization_ref=str(data.get("authorization_ref") or "").strip(),
            allowed_hosts=allowed_hosts,
            allowed_cidrs=allowed_cidrs,
            excluded_hosts=_as_tuple(data.get("excluded_hosts")),
            excluded_cidrs=_as_tuple(data.get("excluded_cidrs")),
            allowed_ports=tuple(ports),
            allow_credential_attacks=bool(data.get("allow_credential_attacks", False)),
            allow_write_tests=bool(data.get("allow_write_tests", False)),
            max_rps=max_rps,
            max_requests=max_requests,
            notes=str(data.get("notes") or "").strip(),
        )


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = [str(part).strip() for part in value]
    else:
        items = [str(value).strip()]
    return tuple(dict.fromkeys(item for item in items if item))


def load_scope(path: str | Path) -> tuple[ScopeConfig, Scope]:
    scope_path = Path(path)
    if not scope_path.is_file():
        raise ConfigurationError(f"scope file not found: {scope_path}")
    try:
        raw = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"unable to parse scope file: {exc}") from exc
    config = ScopeConfig.from_dict(raw or {})
    return config, Scope(config, scope_path)


class Scope:
    def __init__(self, config: ScopeConfig, path: str | Path | None = None) -> None:
        self.config = config
        self.path = Path(path) if path else None
        self._networks: list[ipaddress._BaseNetwork] = []
        self._excluded_networks: list[ipaddress._BaseNetwork] = []
        self._hostnames: list[str] = []
        self._excluded_hostnames: list[str] = []
        self._allowed_ports = set(config.allowed_ports)
        self._dns_cache: dict[str, tuple[float, list[str]]] = {}
        self._dns_lock = threading.Lock()

        for entry in config.allowed_hosts:
            network = _parse_network(entry)
            if network is not None:
                self._networks.append(network)
            else:
                self._hostnames.append(normalize_host(entry))
        for entry in config.allowed_cidrs:
            network = _parse_network(entry)
            if network is None:
                raise ConfigurationError(f"invalid allowed CIDR: {entry!r}")
            self._networks.append(network)
        for entry in config.excluded_hosts:
            network = _parse_network(entry)
            if network is not None:
                self._excluded_networks.append(network)
            else:
                self._excluded_hostnames.append(normalize_host(entry))
        for entry in config.excluded_cidrs:
            network = _parse_network(entry)
            if network is None:
                raise ConfigurationError(f"invalid excluded CIDR: {entry!r}")
            self._excluded_networks.append(network)

        self._hostnames = [host for host in self._hostnames if host]
        self._excluded_hostnames = [host for host in self._excluded_hostnames if host]

    # ------------------------------------------------------------------ hosts
    def resolved_ips(self, host: str) -> list[str]:
        host = normalize_host(host)
        if not host:
            return []
        if is_ip_literal(host):
            return [host]
        now = time.monotonic()
        with self._dns_lock:
            cached = self._dns_cache.get(host)
            if cached and now - cached[0] < DNS_CACHE_TTL:
                return list(cached[1])
        ips: list[str] = []
        try:
            for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                ip = entry[4][0]
                if ip not in ips:
                    ips.append(ip)
        except (socket.gaierror, OSError):
            ips = []
        with self._dns_lock:
            self._dns_cache[host] = (now, ips)
        return list(ips)

    def is_hostname_allowed(self, host: str) -> bool:
        normalized = normalize_host(host)
        if not normalized:
            return False
        if self._matches_hostname(normalized, self._excluded_hostnames):
            return False
        if is_ip_literal(normalized):
            return self._is_ip_allowed(normalized)
        hostname_match = self._matches_hostname(normalized, self._hostnames)
        if hostname_match:
            ips = self.resolved_ips(normalized)
            if ips and any(self._is_always_denied(ip) for ip in ips):
                return False
            return not (ips and any(self._is_excluded_ip(ip) for ip in ips))
        if not self._networks:
            return False
        ips = self.resolved_ips(normalized)
        if not ips:
            return False
        return any(self._is_ip_allowed(ip) for ip in ips)

    def is_port_allowed(self, port: int | None) -> bool:
        if port is None:
            return True
        if not self._allowed_ports:
            return True
        return port in self._allowed_ports

    def filter_ports(self, ports: list[int]) -> list[int]:
        if not self._allowed_ports:
            return ports
        return [port for port in ports if port in self._allowed_ports]

    def assert_host(self, host: str, port: int | None = None) -> None:
        if not host:
            raise ScopeViolation(host, "empty host")
        if not self.is_hostname_allowed(host):
            raise ScopeViolation(host)
        if not self.is_port_allowed(port):
            raise ScopeViolation(f"{host}:{port}", "port is outside the authorized scope")

    def assert_url(self, url: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise ScopeViolation(url, f"unparseable URL: {exc}") from exc
        if parts.scheme.lower() not in {"http", "https"}:
            raise ScopeViolation(url, "only http/https targets are supported")
        if parts.username or parts.password:
            raise ScopeViolation(url, "credential-bearing URLs are not accepted; use --auth-header")
        if not parts.hostname:
            raise ScopeViolation(url, "URL has no hostname")
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        self.assert_host(parts.hostname, port)

    def assert_target(self, target: str) -> None:
        if "://" in target:
            self.assert_url(target)
        else:
            host, port = _split_host_port_soft(target)
            self.assert_host(host, port)

    # ------------------------------------------------------------------ internals
    def _is_always_denied(self, ip_text: str) -> bool:
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            return True
        return any(address in network for network in ALWAYS_DENY_NETWORKS)

    def _is_excluded_ip(self, ip_text: str) -> bool:
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            return True
        return any(address in network for network in self._excluded_networks)

    def _is_ip_allowed(self, ip_text: str) -> bool:
        if self._is_always_denied(ip_text):
            return False
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        if self._is_excluded_ip(ip_text):
            return False
        return any(address in network for network in self._networks)

    @staticmethod
    def _matches_hostname(host: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if host == suffix or host.endswith("." + suffix):
                    return True
            elif host == pattern or host.endswith("." + pattern):
                return True
        return False

    def describe(self) -> dict[str, Any]:
        return {
            "engagement": self.config.engagement,
            "authorized_by": self.config.authorized_by,
            "authorization_ref": self.config.authorization_ref,
            "allowed_hosts": list(self.config.allowed_hosts),
            "allowed_cidrs": list(self.config.allowed_cidrs),
            "excluded_hosts": list(self.config.excluded_hosts),
            "excluded_cidrs": list(self.config.excluded_cidrs),
            "allowed_ports": list(self.config.allowed_ports),
            "allow_credential_attacks": self.config.allow_credential_attacks,
            "allow_write_tests": self.config.allow_write_tests,
            "max_rps": self.config.max_rps,
            "max_requests": self.config.max_requests,
            "notes": self.config.notes,
            "scope_file": str(self.path) if self.path else "",
        }

    def audit_metadata(self) -> dict[str, Any]:
        digest = ""
        if self.path and self.path.is_file():
            digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        return {
            **self.describe(),
            "scope_sha256": digest,
            "authorization_timestamp": utc_now_iso(),
        }


def _parse_network(value: str) -> ipaddress._BaseNetwork | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        ipaddress.ip_address(text)
        return ipaddress.ip_network(text)
    except ValueError:
        return None


def _split_host_port_soft(value: str) -> tuple[str, int | None]:
    raw = value.strip()
    if raw.startswith("["):
        closing = raw.find("]")
        if closing > 0:
            host = raw[1:closing]
            rest = raw[closing + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if port.isdigit():
            return host, int(port)
    return raw, None
