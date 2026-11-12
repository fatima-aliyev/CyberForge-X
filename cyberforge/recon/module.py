"""Reconnaissance orchestrator."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import ScopeViolation
from cyberforge.core.models import Evidence, Finding, HostAsset, PortInfo, Severity
from cyberforge.core.utils import (
    format_curl,
    is_ip_literal,
    load_lines,
    normalize_host,
    parse_ports,
    read_package_lines,
    truncate,
    utc_now_iso,
)
from cyberforge.recon.dns_enum import (
    enumerate_subdomains,
    interesting_subdomains,
    query_dns,
    registrable_domain,
    zone_transfer,
)
from cyberforge.recon.fingerprint import favicon_hash, fingerprint_response
from cyberforge.recon.ports import (
    HTTP_PORTS,
    TLS_PORTS,
    UDP_PROBE_PORTS,
    is_http_port,
    nmap_scan,
    scan_tcp,
    scan_udp,
)

RISKY_PORTS: dict[int, tuple[str, Severity, str, str]] = {
    21: (
        "FTP service exposed",
        Severity.LOW,
        "FTP transmits credentials and data without transport encryption. Anonymous access is checked by the intelligence module.",
        "Disable FTP where possible, or enforce FTPS/SFTP and restrict source networks.",
    ),
    23: (
        "Telnet service exposed",
        Severity.HIGH,
        "Telnet provides unencrypted remote administration and is unsafe on any untrusted network.",
        "Disable Telnet and use SSH with strong authentication and network restrictions.",
    ),
    445: (
        "SMB service exposed",
        Severity.MEDIUM,
        "SMB is reachable from the assessed network. SMB exposure increases ransomware and credential-relay risk.",
        "Restrict SMB to required hosts, disable SMBv1, require signing, and enforce least privilege.",
    ),
    1433: (
        "Microsoft SQL Server exposed",
        Severity.INFO,
        "A database service is directly reachable from the assessed network.",
        "Restrict database access to application hosts, enforce TLS, and avoid exposing management ports to broad networks.",
    ),
    2375: (
        "Docker API exposed without TLS",
        Severity.HIGH,
        "The Docker Engine API is reachable over plain HTTP. Unauthenticated Docker API access can lead to host compromise.",
        "Bind Docker only to a local socket or a mutually authenticated TLS endpoint; never expose the plain API to untrusted networks.",
    ),
    2376: (
        "Docker API exposed",
        Severity.MEDIUM,
        "The Docker Engine API is reachable. Confirm that TLS client authentication is enforced and access is restricted.",
        "Restrict the Docker API to management networks and require certificate-based client authentication.",
    ),
    3306: (
        "MySQL service exposed",
        Severity.INFO,
        "A database service is directly reachable from the assessed network.",
        "Restrict database access to application hosts, enforce TLS, and review authentication controls.",
    ),
    3389: (
        "Remote Desktop Service exposed",
        Severity.MEDIUM,
        "RDP is reachable from the assessed network and is frequently targeted by credential attacks.",
        "Require VPN/zero-trust access, enable NLA and MFA, and restrict RDP to management networks.",
    ),
    5432: (
        "PostgreSQL service exposed",
        Severity.INFO,
        "A database service is directly reachable from the assessed network.",
        "Restrict database access to application hosts, enforce TLS, and review pg_hba.conf rules.",
    ),
    5601: (
        "Kibana exposed",
        Severity.MEDIUM,
        "Kibana is reachable and may expose operational data if authentication is weak or absent.",
        "Restrict Kibana to trusted networks and enforce authentication and role-based access.",
    ),
    5900: (
        "VNC service exposed",
        Severity.MEDIUM,
        "VNC is reachable from the assessed network and often uses weak or absent authentication.",
        "Tunnel VNC through an authenticated VPN, require strong credentials, and restrict source networks.",
    ),
    6379: (
        "Redis service exposed",
        Severity.MEDIUM,
        "Redis is reachable from the assessed network. Unauthenticated or weakly protected instances can leak or corrupt data.",
        "Bind Redis to localhost or a private management network, enable authentication/ACLs, and disable dangerous commands.",
    ),
    9200: (
        "Elasticsearch HTTP API exposed",
        Severity.MEDIUM,
        "The Elasticsearch API is reachable and may permit unauthenticated data access if security features are disabled.",
        "Enable Elasticsearch security features, require authentication, and restrict network access.",
    ),
    10000: (
        "Webmin exposed",
        Severity.MEDIUM,
        "Webmin is reachable from the assessed network and historically has high-impact vulnerabilities.",
        "Restrict Webmin to management networks, enforce MFA where available, and keep it fully patched.",
    ),
    11211: (
        "Memcached exposed",
        Severity.MEDIUM,
        "Memcached is reachable and typically has no authentication, exposing cached application data.",
        "Bind Memcached to localhost/private interfaces and restrict access with firewall rules.",
    ),
    15672: (
        "RabbitMQ management interface exposed",
        Severity.MEDIUM,
        "The RabbitMQ management UI is reachable and may expose messaging infrastructure to credential attacks.",
        "Restrict the management interface to trusted networks, enforce strong authentication, and disable default accounts.",
    ),
    27017: (
        "MongoDB service exposed",
        Severity.MEDIUM,
        "MongoDB is reachable from the assessed network. Misconfigured instances may permit unauthenticated access.",
        "Enable authentication, bind MongoDB to private interfaces, and restrict access to application hosts.",
    ),
}

WEB_PORTS = set(HTTP_PORTS) | TLS_PORTS


@dataclass
class ReconResult:
    assets: list[HostAsset] = field(default_factory=list)
    web_targets: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class ReconModule:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.result = ReconResult()
        self._seen_hosts: set[str] = set()
        self._seen_urls: set[str] = set()

    def run(self) -> ReconResult:
        self.log.info("Starting reconnaissance against %d target(s)", len(self.ctx.config.targets))
        for target in self.ctx.config.targets:
            try:
                self._assess_target(target)
            except ScopeViolation:
                raise
            except Exception as exc:
                self.log.exception("recon failed for %s: %s", target, exc)
                self.ctx.bundle.add_error("recon", f"{target}: {exc}")
        return self.result

    def _assess_target(self, target: str) -> None:
        parts = urlsplit(target) if "://" in target else None
        if parts:
            host = parts.hostname or ""
            scheme = parts.scheme.lower()
            explicit_port = parts.port
        else:
            host = normalize_host(target)
            scheme = ""
            explicit_port = None
            if target.count(":") == 1 and target.rsplit(":", 1)[1].isdigit():
                explicit_port = int(target.rsplit(":", 1)[1])
        if not host:
            raise ValueError(f"unable to parse target {target!r}")
        self.ctx.scope.assert_host(host, explicit_port)
        if host.lower() in self._seen_hosts:
            self._add_base_urls([target])
            return
        self._seen_hosts.add(host.lower())

        ips = self.ctx.scope.resolved_ips(host)
        if not ips:
            self.log.warning("target %s did not resolve; skipping", host)
            self.ctx.bundle.add_error("recon", f"{host}: DNS resolution failed")
            return
        if not self.ctx.config.scan_all_ips:
            ips = ips[:1]

        asset = HostAsset(host=host, ips=ips)
        self.ctx.bundle.add_asset(asset)
        self.result.assets.append(asset)
        self.log.info("Assessing %s (%s)", host, ", ".join(ips))

        self._dns_phase(host, ips, asset)
        self._subdomain_phase(host, asset)
        ports = self._port_phase(host, ips, asset)
        self._web_phase(target, scheme, explicit_port, host, ports, asset)
        self._port_findings(asset)
        self._technology_finding(asset)
        self._append_target_urls(target, scheme, host, explicit_port)
        asset.notes.append(f"recon_completed={utc_now_iso()}")

    # ------------------------------------------------------------------ DNS
    def _dns_phase(self, host: str, ips: list[str], asset: HostAsset) -> None:
        try:
            dns_info, findings = query_dns(host, ips)
        except Exception as exc:
            self.log.warning("DNS enumeration failed for %s: %s", host, exc)
            return
        self.ctx.bundle.add_findings(findings)
        for key in ("a", "aaaa", "mx", "ns", "txt", "cname", "soa", "ptr", "spf", "dmarc"):
            setattr(asset.dns, key, getattr(dns_info, key))
        asset.dns.dkim_selectors = dns_info.dkim_selectors
        if asset.dns.spf:
            self.log.info("SPF records for %s: %d", host, len(asset.dns.spf))
        if asset.dns.dmarc:
            self.log.info("DMARC policy present for %s", host)

    def _subdomain_phase(self, host: str, asset: HostAsset) -> None:
        if not self.ctx.config.subdomains or is_ip_literal(host) or host == "localhost":
            return
        base = registrable_domain(host)
        if not base or "." not in base:
            return
        if not self.ctx.scope.is_hostname_allowed(base):
            self.log.info("Skipping subdomain enumeration for %s (base domain outside scope)", host)
            return
        wordlist = load_lines(
            self.ctx.config.subdomain_wordlist,
            read_package_lines("wordlists", "subdomains.txt"),
        )
        try:
            discovered, wildcard = enumerate_subdomains(
                base,
                wordlist=wordlist,
                workers=min(16, self.ctx.config.workers * 2),
            )
        except Exception as exc:
            self.log.warning("subdomain enumeration failed for %s: %s", base, exc)
            return
        in_scope: dict[str, list[str]] = {}
        dropped = 0
        for fqdn, ips in discovered.items():
            if self.ctx.scope.is_hostname_allowed(fqdn):
                in_scope[fqdn] = ips
            else:
                dropped += 1
        if dropped:
            self.log.info("Filtered %d discovered subdomains outside the authorized scope", dropped)
        asset.dns.subdomains = in_scope
        if in_scope:
            evidence_lines = [f"{name} -> {', '.join(ips)}" for name, ips in list(in_scope.items())[:30]]
            self.ctx.bundle.add_finding(
                Finding(
                    title="Subdomains discovered",
                    severity=Severity.INFO,
                    module="recon",
                    target=base,
                    description=f"Passive DNS enumeration resolved {len(in_scope)} subdomain(s) within scope. Each host increases the externally visible attack surface.",
                    remediation="Maintain an authoritative asset inventory, decommission unused names, and monitor certificate transparency for unexpected subdomains.",
                    evidence=Evidence(notes="\n".join(evidence_lines), response_excerpt=f"wildcard_dns={wildcard}"),
                    confidence="high",
                    tags=["dns", "subdomains", "attack-surface"],
                    metadata={"count": len(in_scope)},
                )
            )
            interesting = interesting_subdomains(in_scope)
            if interesting:
                self.ctx.bundle.add_finding(
                    Finding(
                        title="Sensitive-looking subdomains exposed",
                        severity=Severity.INFO,
                        module="recon",
                        target=base,
                        description="Subdomain names suggest administrative, development, or internal services. Confirm whether these systems are intended to be internet-facing.",
                        remediation="Restrict non-production and administrative hostnames behind VPN/zero-trust access and remove unnecessary DNS records.",
                        evidence=Evidence(
                            notes="\n".join(f"{name} -> {', '.join(ips)}" for name, ips in list(interesting.items())[:20])
                        ),
                        confidence="medium",
                        tags=["dns", "subdomains", "exposure"],
                    )
                )
        if self.ctx.config.zone_transfer:
            nameservers = [ns.split()[0] for ns in asset.dns.ns]
            success, names, message = zone_transfer(base, nameservers)
            if success:
                self.ctx.bundle.add_finding(
                    Finding(
                        title="DNS zone transfer permitted",
                        severity=Severity.HIGH,
                        module="recon",
                        target=base,
                        description="An authoritative nameserver allowed an unauthenticated AXFR zone transfer, disclosing the internal DNS namespace.",
                        remediation="Restrict AXFR to authorized secondary nameservers using IP allowlists and TSIG authentication.",
                        evidence=Evidence(
                            notes=message,
                            response_excerpt=truncate("\n".join(names[:80]), 1600),
                        ),
                        confidence="high",
                        tags=["dns", "zone-transfer", "information-disclosure"],
                    )
                )
                for name in names:
                    if name not in in_scope:
                        in_scope[name] = []
            else:
                self.log.debug("zone transfer not possible: %s", message)
        if self.ctx.config.scan_subdomains and in_scope:
            self._scan_subdomain_sample(asset, in_scope)

    def _scan_subdomain_sample(self, asset: HostAsset, subdomains: dict[str, list[str]]) -> None:
        candidates = [(name, ips) for name, ips in subdomains.items() if ips]
        candidates.sort(key=lambda item: (item[0].split(".", 1)[0] not in interesting_subdomains({item[0]: item[1]}), item[0]))
        for fqdn, ips in candidates[: self.ctx.config.max_subdomains_to_scan]:
            if not self.ctx.scope.is_hostname_allowed(fqdn):
                continue
            sub_asset = HostAsset(host=fqdn, ips=ips)
            self.ctx.bundle.add_asset(sub_asset)
            try:
                ports = asyncio.run(
                    scan_tcp(
                        fqdn,
                        ips[0],
                        [port for port in (80, 443, 8080, 8443) if self.ctx.scope.is_port_allowed(port)],
                        timeout=min(2.0, self.ctx.config.connect_timeout),
                        concurrency=8,
                        grab_banners=True,
                    )
                )
            except Exception as exc:
                self.log.debug("subdomain port scan failed for %s: %s", fqdn, exc)
                continue
            for port in ports:
                sub_asset.add_port(port)
            if not ports:
                continue
            for port in ports:
                if is_http_port(port.port, port.service):
                    scheme = "https" if port.tls or port.port in TLS_PORTS else "http"
                    url = f"{scheme}://{fqdn}" + ("" if port.port in (80, 443) else f":{port.port}") + "/"
                    self._fingerprint_url(url, sub_asset)
                    self._add_base_urls([url])
            self._port_findings(sub_asset)
            self._technology_finding(sub_asset)

    # ------------------------------------------------------------------ ports
    def _port_phase(self, host: str, ips: list[str], asset: HostAsset) -> list[PortInfo]:
        try:
            ports = parse_ports(self.ctx.config.ports)
        except ValueError as exc:
            self.ctx.bundle.add_error("recon", f"invalid port specification: {exc}")
            return []
        ports = self.ctx.scope.filter_ports(ports)
        if not ports:
            self.log.warning("no ports remain after applying the scope port allowlist")
            return []
        scanned_any = False
        open_ports: list[PortInfo] = []
        for ip in ips[:4]:
            try:
                found = asyncio.run(
                    scan_tcp(
                        host,
                        ip,
                        ports,
                        timeout=min(2.0, self.ctx.config.connect_timeout),
                        concurrency=min(300, max(50, self.ctx.config.workers * 25)),
                        grab_banners=True,
                    )
                )
            except Exception as exc:
                self.log.warning("TCP scan failed for %s (%s): %s", host, ip, exc)
                continue
            scanned_any = True
            for port in found:
                port.extra["ip"] = ip
                asset.add_port(port)
                open_ports.append(port)
            if found or self.ctx.config.scan_all_ips:
                break

        if self.ctx.config.udp:
            udp_ports = [port for port in UDP_PROBE_PORTS if self.ctx.scope.is_port_allowed(port)]
            for ip in ips[:1]:
                try:
                    udp_found = asyncio.run(
                        scan_udp(host, ip, udp_ports, timeout=min(3.0, self.ctx.config.timeout))
                    )
                except Exception as exc:
                    self.log.warning("UDP probe failed for %s: %s", host, exc)
                    udp_found = []
                for port in udp_found:
                    asset.add_port(port)
                    open_ports.append(port)

        if self.ctx.config.nmap and scanned_any:
            self._nmap_phase(host, ips[0], ports, asset, open_ports)
        if not scanned_any:
            self.ctx.bundle.add_error("recon", f"{host}: no TCP scan completed")
        return open_ports

    def _nmap_phase(
        self,
        host: str,
        ip: str,
        ports: list[int],
        asset: HostAsset,
        open_ports: list[PortInfo],
    ) -> None:
        nmap_path = self.ctx.config.nmap_path
        if not (shutil.which(nmap_path) or Path(nmap_path).is_file()):
            self.log.warning("nmap was requested but not found at %r; using socket results", nmap_path)
            return
        self.log.info("Running nmap service detection against %s (this can take a minute)", host)
        try:
            nmap_ports, os_matches, error = nmap_scan(
                ip,
                ports,
                nmap_path=nmap_path,
                os_fingerprint=self.ctx.config.os_fingerprint,
                timeout=300,
            )
        except Exception as exc:
            self.log.warning("nmap enrichment failed: %s", exc)
            return
        if error:
            self.log.warning("nmap reported: %s", error)
        for port in nmap_ports:
            existing = next((item for item in open_ports if item.port == port.port), None)
            if existing:
                existing.service = port.service or existing.service
                existing.version = port.version or existing.version
                existing.extra.update(port.extra)
                asset.add_port(existing)
            else:
                asset.add_port(port)
                open_ports.append(port)
        if os_matches and not asset.os:
            asset.os = ", ".join(os_matches[:3])
            self.ctx.bundle.add_finding(
                Finding(
                    title="Operating system fingerprint",
                    severity=Severity.INFO,
                    module="recon",
                    target=host,
                    description="Nmap OS fingerprinting produced candidate operating system matches. Treat this as guidance, not certainty.",
                    remediation="No action required; use asset inventory to confirm supported OS baselines.",
                    evidence=Evidence(notes=asset.os),
                    confidence="low",
                    tags=["recon", "os-fingerprint"],
                )
            )

    def _port_findings(self, asset: HostAsset) -> None:
        for port in asset.ports:
            rule = RISKY_PORTS.get(port.port)
            if not rule:
                continue
            title, severity, description, remediation = rule
            target = f"{asset.host}:{port.port}/{port.protocol}"
            evidence = Evidence(
                request=f"{port.protocol.upper()} connect to {target}",
                notes=f"service={port.service} tls={port.tls}",
                response_excerpt=truncate(port.banner, 500),
            )
            self.ctx.bundle.add_finding(
                Finding(
                    title=title,
                    severity=severity,
                    module="recon",
                    target=target,
                    description=description,
                    remediation=remediation,
                    evidence=evidence,
                    confidence="high" if port.banner else "medium",
                    tags=["recon", "exposed-service"],
                    metadata={"port": port.port, "protocol": port.protocol, "service": port.service},
                )
            )

    # ------------------------------------------------------------------ web
    def _web_phase(
        self,
        target: str,
        scheme: str,
        explicit_port: int | None,
        host: str,
        ports: list[PortInfo],
        asset: HostAsset,
    ) -> None:
        candidates: list[str] = []
        if scheme:
            candidates.append(target)
        else:
            port_hint = explicit_port
            schemes = ["https", "http"] if not port_hint else [
                "https" if port_hint in TLS_PORTS else "http"
            ]
            for candidate_scheme in schemes:
                suffix = f":{port_hint}" if port_hint and not (
                    (candidate_scheme == "http" and port_hint == 80)
                    or (candidate_scheme == "https" and port_hint == 443)
                ) else ""
                candidates.append(f"{candidate_scheme}://{host}{suffix}/")
        for port in ports:
            if not is_http_port(port.port, port.service):
                continue
            candidate_scheme = "https" if port.tls or port.port in TLS_PORTS else "http"
            if (candidate_scheme == "http" and port.port == 80) or (
                candidate_scheme == "https" and port.port == 443
            ):
                url = f"{candidate_scheme}://{host}/"
            else:
                url = f"{candidate_scheme}://{host}:{port.port}/"
            candidates.append(url)
        for url in _dedupe(candidates)[:6]:
            if not self.ctx.scope.is_hostname_allowed(host):
                continue
            if self._fingerprint_url(url, asset):
                self._add_base_urls([url])
        if not asset.urls:
            self.log.info("No HTTP(S) service fingerprinted for %s", host)

    def _fingerprint_url(self, url: str, asset: HostAsset) -> bool:
        try:
            self.ctx.scope.assert_url(url)
        except ScopeViolation:
            return False
        result = self.ctx.session.get(url)
        if result.status is None:
            self.log.debug("web fingerprint failed for %s: %s", url, result.error)
            return False
        if result.status not in range(200, 500):
            return False
        fingerprint = fingerprint_response(result, url)
        for tech in fingerprint.technologies:
            asset.add_technology(tech)
        if fingerprint.cdn and not asset.cdn:
            asset.cdn = fingerprint.cdn
        if fingerprint.waf and not asset.waf:
            asset.waf = fingerprint.waf
        if not asset.favicon_hash:
            asset.favicon_hash = favicon_hash(self.ctx.session, url)
        if url not in asset.urls:
            asset.urls.append(url)
        self.log.info(
            "Fingerprinted %s: %s%s",
            url,
            ", ".join(tech.name + (f" {tech.version}" if tech.version else "") for tech in fingerprint.technologies[:7])
            or "no strong technology markers",
            f" | CDN={fingerprint.cdn}" if fingerprint.cdn else "",
        )
        return True

    def _technology_finding(self, asset: HostAsset) -> None:
        if not asset.technologies:
            return
        lines = [
            f"{tech.name}{(' ' + tech.version) if tech.version else ''} [{tech.category}, {tech.confidence}]"
            for tech in asset.technologies
        ]
        notes = []
        if asset.cdn:
            notes.append(f"CDN: {asset.cdn}")
        if asset.waf:
            notes.append(f"WAF: {asset.waf}")
        if asset.os:
            notes.append(f"OS candidates: {asset.os}")
        if asset.favicon_hash:
            notes.append(f"Favicon hash: {asset.favicon_hash}")
        self.ctx.bundle.add_finding(
            Finding(
                title="Technology stack identified",
                severity=Severity.INFO,
                module="recon",
                target=asset.host,
                description="Response headers, cookies, asset paths, and DOM markers revealed the following technology stack. Version disclosure can focus vulnerability research.",
                remediation="Keep frameworks and servers patched, remove unnecessary version banners, and maintain a software bill of materials.",
                evidence=Evidence(
                    request=format_curl("GET", asset.urls[0]) if asset.urls else "",
                    notes="; ".join(notes),
                    response_excerpt=truncate("\n".join(lines), 1000),
                ),
                confidence="medium",
                tags=["recon", "fingerprint", "technology"],
                metadata={
                    "technologies": [tech.to_dict() for tech in asset.technologies],
                    "cdn": asset.cdn,
                    "waf": asset.waf,
                    "favicon": asset.favicon_hash,
                },
            )
        )

    def _append_target_urls(self, target: str, scheme: str, host: str, explicit_port: int | None) -> None:
        if scheme:
            self._add_base_urls([target])
        elif explicit_port:
            candidate_scheme = "https" if explicit_port in TLS_PORTS else "http"
            self._add_base_urls([f"{candidate_scheme}://{host}:{explicit_port}/"])

    def _add_base_urls(self, urls: list[str]) -> None:
        for url in urls:
            if url not in self._seen_urls:
                self._seen_urls.add(url)
                self.result.web_targets.append(url)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
