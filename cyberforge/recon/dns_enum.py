"""DNS record enumeration, email-security checks, and subdomain discovery."""

from __future__ import annotations

import concurrent.futures
import random
import threading
from collections.abc import Iterable

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from cyberforge.core.logging import get_logger
from cyberforge.core.models import DNSInfo, Evidence, Finding, Severity
from cyberforge.core.utils import dedupe, is_ip_literal, read_package_lines, truncate

log = get_logger("recon.dns")
MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "com.br",
    "com.tr",
    "com.az",
    "co.jp",
    "co.in",
    "com.sg",
    "com.mx",
}
DKIM_SELECTORS = ["default", "google", "k1", "mail", "selector1", "selector2", "s1", "s2", "dkim"]
_thread_local = threading.local()


def _resolver() -> dns.resolver.Resolver:
    resolver = getattr(_thread_local, "resolver", None)
    if resolver is None:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        _thread_local.resolver = resolver
    return resolver


def registrable_domain(host: str) -> str:
    host = (host or "").strip(".").lower()
    if not host or is_ip_literal(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix = ".".join(labels[-2:])
    if suffix in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def query_dns(host: str, ips: list[str] | None = None) -> tuple[DNSInfo, list[Finding]]:
    info = DNSInfo()
    findings: list[Finding] = []
    if not host:
        return info, findings
    if is_ip_literal(host):
        info.ptr = _ptr(host)
        return info, findings

    resolver = _resolver()
    info.a = _resolve(resolver, host, "A")
    info.aaaa = _resolve(resolver, host, "AAAA")
    info.mx = _resolve(resolver, host, "MX")
    info.ns = _resolve(resolver, host, "NS")
    info.cname = _resolve(resolver, host, "CNAME")
    txt_records = _resolve(resolver, host, "TXT")
    info.txt = txt_records
    info.spf = [record for record in txt_records if record.lower().startswith("v=spf1")]
    soa = _resolve(resolver, host, "SOA")
    info.soa = soa[0] if soa else ""

    base = registrable_domain(host)
    dmarc_records = _resolve(resolver, "_dmarc." + base, "TXT")
    info.dmarc = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]
    for selector in DKIM_SELECTORS:
        records = _resolve(resolver, f"{selector}._domainkey.{base}", "TXT")
        if records:
            info.dkim_selectors.append(selector)
            info.txt.extend(record for record in records if record not in info.txt)

    for ip in ips or []:
        for ptr in _ptr(ip):
            if ptr not in info.ptr:
                info.ptr.append(ptr)

    findings.extend(_email_security_findings(host, base, info))
    return info, findings


def _resolve(resolver: dns.resolver.Resolver, name: str, record_type: str) -> list[str]:
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []
    except Exception as exc:  # dnspython raises a wide range of DNS errors
        log.debug("DNS %s %s failed: %s", record_type, name, exc)
        return []
    if answer.rrset is None:
        return []
    values: list[str] = []
    for item in answer.rrset:
        text = item.to_text()
        if record_type == "TXT":
            text = text.strip('"').replace('" "', " ")
        values.append(text.rstrip("."))
    return dedupe(values)


def _ptr(ip: str) -> list[str]:
    try:
        return [item.to_text().rstrip(".") for item in dns.resolver.resolve_address(ip)]
    except Exception:
        return []


def _email_security_findings(host: str, base: str, info: DNSInfo) -> list[Finding]:
    findings: list[Finding] = []
    target = base if base else host
    if not base or is_ip_literal(base):
        return findings
    if not info.spf:
        findings.append(
            Finding(
                title="SPF record missing",
                severity=Severity.LOW,
                module="recon",
                target=target,
                description="No SPF TXT record was found for the domain. This weakens protection against sender-address spoofing.",
                remediation="Publish a single SPF record that authorizes only required sending infrastructure and ends with -all.",
                evidence=Evidence(notes="Checked TXT records at the domain apex.", response_excerpt=truncate("; ".join(info.txt), 500)),
                confidence="high",
                tags=["dns", "email-security"],
            )
        )
    else:
        if len(info.spf) > 1:
            findings.append(
                Finding(
                    title="Multiple SPF records published",
                    severity=Severity.MEDIUM,
                    module="recon",
                    target=target,
                    description="More than one SPF record exists. Receivers typically treat multiple SPF records as a permanent error, weakening spoofing controls.",
                    remediation="Merge all authorized senders into a single v=spf1 record and remove duplicates.",
                    evidence=Evidence(response_excerpt=truncate("\n".join(info.spf), 800)),
                    confidence="high",
                    tags=["dns", "email-security"],
                )
            )
        for record in info.spf:
            lowered = record.lower().replace(" ", "")
            if "+all" in lowered:
                findings.append(
                    Finding(
                        title="Permissive SPF policy (+all)",
                        severity=Severity.MEDIUM,
                        module="recon",
                        target=target,
                        description="The SPF record authorizes all senders (+all), allowing trivial sender-address spoofing.",
                        remediation="Replace +all with an explicit list of authorized senders and a hard fail (-all).",
                        evidence=Evidence(payload=record),
                        confidence="high",
                        tags=["dns", "email-security"],
                    )
                )
            elif "?all" in lowered:
                findings.append(
                    Finding(
                        title="Neutral SPF policy (?all)",
                        severity=Severity.LOW,
                        module="recon",
                        target=target,
                        description="The SPF record uses a neutral all qualifier (?all), which provides no clear spoofing disposition.",
                        remediation="Use -all after confirming all legitimate senders are listed.",
                        evidence=Evidence(payload=record),
                        confidence="high",
                        tags=["dns", "email-security"],
                    )
                )
    if not info.dmarc:
        findings.append(
            Finding(
                title="DMARC record missing",
                severity=Severity.LOW,
                module="recon",
                target=target,
                description="No DMARC policy was found at _dmarc. Without DMARC, receivers have no domain-owner policy for unauthenticated mail.",
                remediation="Publish a DMARC record with at least p=quarantine or p=reject after monitoring with rua reporting.",
                evidence=Evidence(notes=f"Queried _dmarc.{base} TXT"),
                confidence="high",
                tags=["dns", "email-security"],
            )
        )
    else:
        for record in info.dmarc:
            lowered = record.lower().replace(" ", "")
            if "p=none" in lowered:
                findings.append(
                    Finding(
                        title="DMARC policy set to none",
                        severity=Severity.LOW,
                        module="recon",
                        target=target,
                        description="The DMARC record uses p=none, which only reports and does not instruct receivers to quarantine or reject failing mail.",
                        remediation="Move to p=quarantine, then p=reject, after validating reports and legitimate senders.",
                        evidence=Evidence(payload=record),
                        confidence="high",
                        tags=["dns", "email-security"],
                    )
                )
            if "rua=" not in lowered:
                findings.append(
                    Finding(
                        title="DMARC aggregate reporting not configured",
                        severity=Severity.INFO,
                        module="recon",
                        target=target,
                        description="No rua= aggregate reporting address is configured, reducing visibility into authentication failures.",
                        remediation="Add a monitored rua=mailto: address for aggregate DMARC reports.",
                        evidence=Evidence(payload=record),
                        confidence="high",
                        tags=["dns", "email-security"],
                    )
                )
    return findings


def enumerate_subdomains(
    domain: str,
    wordlist: Iterable[str] | None = None,
    workers: int = 12,
    max_results: int = 300,
) -> tuple[dict[str, list[str]], bool]:
    if not domain or is_ip_literal(domain):
        return {}, False
    words = dedupe([word.strip().lower() for word in (wordlist or read_package_lines("wordlists", "subdomains.txt")) if word.strip()])
    wildcard_ips = _wildcard_ips(domain)
    results: dict[str, list[str]] = {}

    def worker(word: str) -> tuple[str, list[str]] | None:
        fqdn = f"{word}.{domain}"
        resolver = _resolver()
        ips = _resolve(resolver, fqdn, "A")
        if not ips:
            ips = _resolve(resolver, fqdn, "AAAA")
        if not ips:
            return None
        if wildcard_ips and set(ips).issubset(wildcard_ips):
            return None
        return fqdn, ips

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(worker, word): word for word in words}
        for future in concurrent.futures.as_completed(futures):
            try:
                outcome = future.result()
            except Exception as exc:
                log.debug("subdomain worker failed for %s: %s", futures[future], exc)
                continue
            if outcome is None:
                continue
            fqdn, ips = outcome
            results[fqdn] = ips
            if len(results) >= max_results:
                break
    log.info("Subdomain enumeration for %s: %d resolved names", domain, len(results))
    return dict(sorted(results.items())), bool(wildcard_ips)


def _wildcard_ips(domain: str) -> set[str]:
    found: set[str] = set()
    for _ in range(2):
        probe = f"cfx-{random.randint(100000, 999999)}.{domain}"
        resolver = _resolver()
        ips = _resolve(resolver, probe, "A")
        if ips:
            found.update(ips)
    if found:
        log.info("Wildcard DNS detected for %s (%s); filtering wildcard answers", domain, ", ".join(sorted(found)))
    return found


def interesting_subdomains(subdomains: dict[str, list[str]]) -> dict[str, list[str]]:
    prefixes = {
        "admin",
        "administrator",
        "api",
        "app",
        "backup",
        "beta",
        "ci",
        "dashboard",
        "db",
        "demo",
        "dev",
        "developer",
        "git",
        "gitlab",
        "grafana",
        "internal",
        "jenkins",
        "jira",
        "kibana",
        "lab",
        "legacy",
        "mail",
        "manage",
        "monitoring",
        "old",
        "portal",
        "prod",
        "qa",
        "redis",
        "remote",
        "review",
        "s3",
        "smtp",
        "staging",
        "status",
        "test",
        "uat",
        "vpn",
        "webmail",
        "wiki",
    }
    interesting: dict[str, list[str]] = {}
    for fqdn, ips in subdomains.items():
        prefix = fqdn.split(".", 1)[0].lower()
        if prefix in prefixes or any(prefix.startswith(token) for token in ("dev-", "test-", "uat-", "api-")):
            interesting[fqdn] = ips
    return interesting


def zone_transfer(domain: str, nameservers: list[str], timeout: float = 8.0) -> tuple[bool, list[str], str]:
    if not nameservers:
        return False, [], "no nameservers found"
    for nameserver in nameservers[:3]:
        try:
            ns_ips = dns.resolver.resolve(nameserver, "A")
        except Exception:
            continue
        for ns_ip in ns_ips:
            address = str(ns_ip)
            try:
                xfr = dns.query.xfr(address, domain, lifetime=timeout, timeout=timeout)
                zone = dns.zone.from_xfr(xfr)
            except Exception as exc:
                log.debug("AXFR %s via %s failed: %s", domain, address, exc)
                continue
            names = sorted(
                domain if str(name) == "@" else f"{str(name).rstrip('.')}.{domain}"
                for name in zone.nodes
            )
            return True, names[:200], f"zone transfer succeeded via {nameserver} ({address})"
    return False, [], "zone transfer refused or timed out"
