"""Product/version extraction from service banners and HTTP headers."""

from __future__ import annotations

import re
from dataclasses import dataclass

from cyberforge.core.models import HostAsset
from cyberforge.core.utils import get_header, truncate
from cyberforge.intel.versioning import extract_version

SSH_RE = re.compile(r"SSH-[\d.]+-OpenSSH[_-]([0-9][A-Za-z0-9.\-_]*)", re.IGNORECASE)
FTP_RE = re.compile(
    r"(vsftpd|proftpd|pure-ftpd|filezilla server|serv-u|wu-ftpd|microsoft ftp service)"
    r"[ /_-]?([0-9][A-Za-z0-9.\-_]*)?",
    re.IGNORECASE,
)
HTTP_SERVER_RES = [
    (re.compile(r"apache/([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE), "Apache HTTP Server"),
    (re.compile(r"nginx/([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE), "Nginx"),
    (re.compile(r"microsoft-iis/([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE), "Microsoft IIS"),
    (re.compile(r"lighttpd/([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE), "lighttpd"),
    (re.compile(r"jetty\(?([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE), "Jetty"),
    (re.compile(r"werkzeug/([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE), "Werkzeug"),
    (re.compile(r"gunicorn/([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE), "Gunicorn"),
    (re.compile(r"caddy", re.IGNORECASE), "Caddy"),
]
SMTP_RE = re.compile(
    r"(postfix|exim|sendmail|microsoft esmtp mail service)[ /_-]?([0-9][0-9A-Za-z.\-_]*)?",
    re.IGNORECASE,
)
DB_RE = re.compile(r"(mysql|mariadb)[ /_-]?([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE)
GENERIC_RE = re.compile(
    r"\b(openssh|apache|nginx|tomcat|jenkins|grafana|gitlab|confluence|wordpress|drupal|"
    r"joomla|php|python|ruby|node\.?js)\b[ /_-]?v?([0-9][0-9A-Za-z.\-_]*)",
    re.IGNORECASE,
)


@dataclass
class ProductVersion:
    product: str
    version: str
    source: str
    banner: str = ""

    def key(self) -> tuple[str, str]:
        return (self.product.lower(), self.version.lower())


def parse_ssh(banner: str) -> ProductVersion | None:
    match = SSH_RE.search(banner or "")
    if not match:
        return None
    return ProductVersion("OpenSSH", match.group(1), "ssh-banner", truncate(banner, 200))


def parse_ftp(banner: str) -> ProductVersion | None:
    match = FTP_RE.search(banner or "")
    if not match:
        return None
    product = _title_product(match.group(1))
    version = match.group(2) or ""
    return ProductVersion(product, version, "ftp-banner", truncate(banner, 200))


def parse_smtp(banner: str) -> ProductVersion | None:
    match = SMTP_RE.search(banner or "")
    if not match:
        return None
    return ProductVersion(_title_product(match.group(1)), match.group(2) or "", "smtp-banner", truncate(banner, 200))


def parse_mysql(banner: str) -> ProductVersion | None:
    match = DB_RE.search(banner or "")
    if not match:
        return None
    version = match.group(2)
    return ProductVersion(_title_product(match.group(1)), version, "mysql-handshake", truncate(banner, 200))


def parse_http_server(server_header: str) -> list[ProductVersion]:
    if not server_header:
        return []
    found: list[ProductVersion] = []
    for pattern, product in HTTP_SERVER_RES:
        match = pattern.search(server_header)
        if match:
            version = match.group(1) if match.groups() else ""
            found.append(ProductVersion(product, version, "http-server-header", truncate(server_header, 200)))
    return found


def parse_generic(text: str, source: str = "banner") -> list[ProductVersion]:
    results: list[ProductVersion] = []
    for match in GENERIC_RE.finditer(text or ""):
        product = _title_product(match.group(1))
        version = match.group(2)
        results.append(ProductVersion(product, version, source, truncate(text, 200)))
    return results


def collect_product_versions(asset: HostAsset) -> list[ProductVersion]:
    """Combine fingerprint technologies and raw service banners."""
    collected: list[ProductVersion] = []
    for tech in asset.technologies:
        if tech.version:
            collected.append(
                ProductVersion(tech.name, tech.version, f"fingerprint:{tech.category}", tech.evidence)
            )
        else:
            collected.append(ProductVersion(tech.name, "", "fingerprint", tech.evidence))

    for port in asset.ports:
        banner = port.banner or ""
        service = (port.service or "").lower()
        if port.version:
            product = str(port.extra.get("product") or port.service or "Unknown service")
            collected.append(
                ProductVersion(product, port.version, f"nmap/port:{port.port}", truncate(banner, 200))
            )
        if "ssh" in service or port.port == 22:
            parsed = parse_ssh(banner)
            if parsed:
                collected.append(parsed)
        if "ftp" in service or port.port == 21:
            parsed = parse_ftp(banner)
            if parsed:
                collected.append(parsed)
        if "smtp" in service or port.port in {25, 465, 587}:
            parsed = parse_smtp(banner)
            if parsed:
                collected.append(parsed)
        if "mysql" in service or "maria" in service or port.port == 3306:
            parsed = parse_mysql(banner)
            if parsed:
                collected.append(parsed)
        for parsed in parse_http_server(banner):
            collected.append(parsed)
        for parsed in parse_generic(banner, f"service:{service or port.port}"):
            collected.append(parsed)

    deduped: dict[tuple[str, str], ProductVersion] = {}
    for item in collected:
        if not item.version:
            continue
        key = item.key()
        existing = deduped.get(key)
        if existing is None or (not existing.banner and item.banner):
            deduped[key] = item
    return list(deduped.values())


def version_from_headers(headers: dict[str, str]) -> list[ProductVersion]:
    results = parse_http_server(get_header(headers, "Server"))
    powered_by = get_header(headers, "X-Powered-By")
    if powered_by:
        results.extend(parse_generic(powered_by, "x-powered-by"))
        php_match = re.search(r"PHP/([0-9][0-9A-Za-z.\-_]*)", powered_by, re.IGNORECASE)
        if php_match:
            results.append(ProductVersion("PHP", php_match.group(1), "x-powered-by", powered_by))
        asp_match = re.search(r"ASP\.NET", powered_by, re.IGNORECASE)
        if asp_match and not any(item.product == "ASP.NET" for item in results):
            results.append(ProductVersion("ASP.NET", "", "x-powered-by", powered_by))
    return results


def _title_product(value: str) -> str:
    cleaned = " ".join(value.replace("_", " ").replace("-", " ").split())
    aliases = {
        "vsftpd": "vsftpd",
        "proftpd": "ProFTPD",
        "pure ftpd": "Pure-FTPd",
        "filezilla server": "FileZilla Server",
        "serv u": "Serv-U",
        "wu ftpd": "wu-ftpd",
        "microsoft ftp service": "Microsoft FTP Service",
        "postfix": "Postfix",
        "exim": "Exim",
        "sendmail": "Sendmail",
        "microsoft esmtp mail service": "Microsoft Exchange",
        "mysql": "MySQL",
        "mariadb": "MariaDB",
        "openssh": "OpenSSH",
        "apache": "Apache HTTP Server",
        "nginx": "Nginx",
        "tomcat": "Apache Tomcat",
        "jenkins": "Jenkins",
        "grafana": "Grafana",
        "gitlab": "GitLab",
        "confluence": "Atlassian Confluence",
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "php": "PHP",
        "python": "Python",
        "ruby": "Ruby",
        "node.js": "Node.js",
        "nodejs": "Node.js",
    }
    return aliases.get(cleaned.lower(), cleaned.title())


def normalize_detected_version(text: str) -> str:
    return extract_version(text or "")
