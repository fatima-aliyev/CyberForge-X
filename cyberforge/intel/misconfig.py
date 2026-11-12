"""Default-path, anonymous-access, and unauthenticated-service checks.

All checks are read-only: FTP listings (names only), Redis PING/INFO, Docker
/version, Elasticsearch root, Memcached version, MongoDB hello, and HTTP GETs.
No default credentials are attempted in this module.
"""

from __future__ import annotations

import contextlib
import ftplib
import re
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import ScopeViolation
from cyberforge.core.models import Evidence, Finding, HostAsset, Severity
from cyberforge.core.utils import format_curl, get_header, safe_excerpt, truncate

DEFAULT_USERS = ["admin", "administrator", "root", "manager", "tomcat", "jenkins", "grafana"]


@dataclass(frozen=True)
class PanelSpec:
    path: str
    name: str
    description: str
    remediation: str
    markers: tuple[str, ...]
    open_severity: Severity
    default_users: tuple[str, ...] = tuple(DEFAULT_USERS)
    protected_severity: Severity = Severity.INFO


PANELS: list[PanelSpec] = [
    PanelSpec(
        path="/actuator",
        name="Spring Boot Actuator",
        description="Spring Boot Actuator is exposed. Depending on enabled endpoints, this can disclose configuration, environment properties, mappings, or heap dumps.",
        remediation="Restrict actuator endpoints to internal networks, require authentication, and disable env/heapdump/threaddump endpoints in production.",
        markers=('"_links"', '"self"', "actuator"),
        open_severity=Severity.MEDIUM,
    ),
    PanelSpec(
        path="/manager/html",
        name="Apache Tomcat Manager",
        description="The Tomcat Manager application is reachable. Manager access enables deployment of web applications and is a high-value target for credential attacks.",
        remediation="Remove the manager application from production, restrict it to management networks, and enforce strong unique credentials with MFA at the network layer.",
        markers=("tomcat web application manager", "manager</title>", "tomcat-manager"),
        open_severity=Severity.HIGH,
    ),
    PanelSpec(
        path="/manager/status",
        name="Apache Tomcat Manager Status",
        description="The Tomcat Manager status page is reachable and may expose deployment and runtime details.",
        remediation="Restrict the manager status endpoint to management networks and require authentication.",
        markers=("tomcat manager", "server status"),
        open_severity=Severity.MEDIUM,
    ),
    PanelSpec(
        path="/jenkins/login",
        name="Jenkins",
        description="A Jenkins login interface is reachable. Jenkins is frequently targeted through weak credentials and plugin vulnerabilities.",
        remediation="Keep Jenkins patched, enforce SSO/MFA, remove default accounts, and restrict access to trusted networks.",
        markers=("jenkins", "jenkins-crumb", "log in [jenkins]"),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/grafana/login",
        name="Grafana",
        description="A Grafana login interface is reachable. Grafana panels frequently expose operational data and plug-in attack surface.",
        remediation="Patch Grafana, enforce strong authentication/SSO, and restrict dashboard access to trusted networks.",
        markers=("grafana", "grafana-app"),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/users/sign_in",
        name="GitLab",
        description="A GitLab sign-in interface is reachable. Source control and CI/CD systems are high-value targets.",
        remediation="Keep GitLab patched, enforce MFA/SSO, and restrict registration and public project visibility as appropriate.",
        markers=("gitlab", "gon.gitlab_url"),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/wp-login.php",
        name="WordPress Login",
        description="The WordPress login endpoint is reachable. WordPress exposure includes core, theme, and plugin vulnerabilities plus credential attacks.",
        remediation="Keep WordPress core/plugins/themes patched, enforce MFA, limit login attempts, and restrict admin access by IP where feasible.",
        markers=("wordpress", "wp-submit", "user_login"),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/administrator/",
        name="Joomla Administrator",
        description="The Joomla administrator interface is reachable.",
        remediation="Keep Joomla and extensions patched, enforce MFA, and restrict administrator access to trusted networks.",
        markers=("joomla",),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/user/login",
        name="Drupal Login",
        description="A Drupal login endpoint is reachable.",
        remediation="Keep Drupal core and modules patched, enforce MFA for privileged accounts, and limit administrative access.",
        markers=("drupal", "form_id"),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/phpmyadmin/",
        name="phpMyAdmin",
        description="A phpMyAdmin interface is reachable. Database management interfaces are high-value credential targets.",
        remediation="Restrict phpMyAdmin to management networks, enforce strong authentication, and remove it from internet-facing systems.",
        markers=("phpmyadmin", "pma_"),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/adminer.php",
        name="Adminer",
        description="An Adminer database management interface is reachable.",
        remediation="Remove Adminer from production or restrict it to trusted administrative networks.",
        markers=("adminer",),
        open_severity=Severity.INFO,
    ),
    PanelSpec(
        path="/h2-console",
        name="H2 Console",
        description="The H2 database web console is reachable. H2 console exposure can lead to database access or code execution depending on configuration.",
        remediation="Disable the H2 console in production or restrict it to localhost with authentication.",
        markers=("h2 console", "h2 database"),
        open_severity=Severity.MEDIUM,
    ),
    PanelSpec(
        path="/server-status",
        name="Apache Server Status",
        description="The Apache server-status page is reachable and may disclose request URLs, client addresses, and worker details.",
        remediation="Restrict /server-status to localhost or monitoring networks.",
        markers=("apache server status", "server status"),
        open_severity=Severity.MEDIUM,
    ),
    PanelSpec(
        path="/admin/",
        name="Generic admin interface",
        description="A generic administrative login interface is reachable.",
        remediation="Enforce strong authentication, MFA, and network restrictions for administrative interfaces.",
        markers=("password", "login", "admin"),
        open_severity=Severity.INFO,
    ),
]


class MisconfigScanner:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self._seen_panels: set[tuple[str, str]] = set()
        self._checked_services: set[tuple[str, int]] = set()

    def scan(self, asset: HostAsset) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._panel_checks(asset))
        findings.extend(self._service_checks(asset))
        return findings

    # ------------------------------------------------------------------ panels
    def _panel_checks(self, asset: HostAsset) -> list[Finding]:
        findings: list[Finding] = []
        origins: list[str] = []
        for url in asset.urls:
            parts = urlsplit(url)
            if not parts.scheme or not parts.netloc:
                continue
            origin = f"{parts.scheme}://{parts.netloc}/"
            if origin not in origins:
                origins.append(origin)
        for origin in origins[:3]:
            for spec in PANELS:
                url = urljoin(origin, spec.path.lstrip("/"))
                try:
                    self.ctx.scope.assert_url(url)
                except ScopeViolation:
                    continue
                result = self.ctx.session.get(url, allow_redirects=True)
                if result.status is None:
                    continue
                if result.status in {404, 410, 500, 502, 503, 504}:
                    continue
                body = (result.text or "").lower()
                marker_found = any(marker.lower() in body for marker in spec.markers)
                login_form = bool(
                    re.search(r'<input[^>]+type=["\']password["\']', result.text or "", re.IGNORECASE)
                )
                if spec.name == "Generic admin interface" and not login_form:
                    continue
                protected = result.status in {401, 403} or (marker_found and login_form) or (
                    result.history and any(code in {301, 302, 303} for code in result.history) and login_form
                )
                open_without_auth = result.status == 200 and marker_found and not login_form and spec.path != "/admin/"
                if not marker_found and result.status not in {401, 403} and not (spec.path == "/admin/" and login_form):
                    continue
                if not marker_found and result.status in {401, 403} and not get_header(result.headers, "WWW-Authenticate"):
                    continue
                key = (asset.host, url)
                if key in self._seen_panels:
                    continue
                self._seen_panels.add(key)
                severity = spec.open_severity if open_without_auth else spec.protected_severity
                title_suffix = "accessible without authentication" if open_without_auth else "exposed"
                if protected:
                    title_suffix = "reachable (authentication required)"
                findings.append(
                    Finding(
                        title=f"{spec.name} {title_suffix}",
                        severity=severity,
                        module="intel",
                        target=asset.host,
                        description=spec.description
                        + (" The interface responded without an authentication challenge; confirm manually." if open_without_auth else ""),
                        remediation=spec.remediation,
                        evidence=Evidence(
                            request=format_curl("GET", url),
                            notes=f"HTTP {result.status}; auth_required={protected or not open_without_auth}",
                            response_excerpt=safe_excerpt(result.text, 600),
                        ),
                        confidence="medium" if marker_found else "low",
                        tags=["default-path", "admin-panel", "misconfiguration"],
                        metadata={
                            "url": url,
                            "panel": spec.name,
                            "auth_required": protected or not open_without_auth,
                            "default_users": list(spec.default_users),
                            "status": result.status,
                        },
                        reproduction=format_curl("GET", url),
                    )
                )
                self.log.info("Detected %s at %s (HTTP %s)", spec.name, url, result.status)
        return findings

    # ------------------------------------------------------------------ services
    def _service_checks(self, asset: HostAsset) -> list[Finding]:
        findings: list[Finding] = []
        open_ports = {(port.protocol, port.port) for port in asset.ports}
        if ("tcp", 21) in open_ports:
            finding = self._ftp_anonymous(asset)
            if finding:
                findings.append(finding)
        if ("tcp", 6379) in open_ports:
            finding = self._redis(asset)
            if finding:
                findings.append(finding)
        if ("tcp", 2375) in open_ports:
            finding = self._docker(asset)
            if finding:
                findings.append(finding)
        if ("tcp", 9200) in open_ports:
            finding = self._elasticsearch(asset)
            if finding:
                findings.append(finding)
        if ("tcp", 11211) in open_ports:
            finding = self._memcached(asset)
            if finding:
                findings.append(finding)
        if ("tcp", 27017) in open_ports:
            finding = self._mongodb(asset)
            if finding:
                findings.append(finding)
        return findings

    def _can_connect(self, host: str, port: int) -> bool:
        try:
            self.ctx.scope.assert_host(host, port)
            return True
        except ScopeViolation:
            return False

    def _ftp_anonymous(self, asset: HostAsset) -> Finding | None:
        if not self._can_connect(asset.host, 21):
            return None
        ftp = ftplib.FTP()
        try:
            ftp.connect(asset.host, 21, timeout=6)
            ftp.login("anonymous", "anonymous@cyberforge.invalid")
            names: list[str] = []
            try:
                ftp.retrlines("LIST", names.append)
            except ftplib.error_perm:
                try:
                    names = ftp.nlst()[:50]
                except ftplib.error_perm:
                    names = []
            try:
                ftp.quit()
            except Exception:
                ftp.close()
        except (ftplib.all_errors, OSError):
            with contextlib.suppress(Exception):
                ftp.close()
            return None
        names = names[:50]
        risky_files = [
            name for name in names
            if re.search(r"(backup|dump|\.sql|\.zip|\.tar|\.gz|config|\.env|secret|password|\.key)", name, re.IGNORECASE)
        ]
        severity = Severity.HIGH if risky_files else Severity.MEDIUM
        return Finding(
            title="Anonymous FTP access permitted",
            severity=severity,
            module="intel",
            target=f"{asset.host}:21",
            description="The FTP server accepted anonymous credentials and returned a directory listing. Anonymous FTP can expose sensitive files and is often overlooked in cleanup efforts.",
            remediation="Disable anonymous FTP, require authenticated SFTP/FTPS, and review exposed files for sensitive content.",
            evidence=Evidence(
                payload="USER anonymous / PASS anonymous@cyberforge.invalid",
                request=f"ftp://{asset.host}:21/",
                notes="Directory names were listed; no files were downloaded.",
                response_excerpt=truncate("\n".join(names), 900),
            ),
            confidence="high",
            tags=["ftp", "anonymous-access", "misconfiguration"],
            metadata={"files": names, "risky_filenames": risky_files},
        )

    def _redis(self, asset: HostAsset) -> Finding | None:
        if not self._can_connect(asset.host, 6379):
            return None
        try:
            with socket.create_connection((asset.host, 6379), timeout=5) as sock:
                sock.settimeout(3)
                sock.sendall(b"*1\r\n$4\r\nPING\r\n")
                response = sock.recv(1024)
                if b"+PONG" not in response:
                    return None
                sock.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
                info = _recv_all(sock, 4096, 2.0)
        except OSError:
            return None
        version_match = re.search(r"redis_version:([0-9][^\r\n]*)", info.decode("utf-8", "replace"))
        version = version_match.group(1).strip() if version_match else ""
        return Finding(
            title="Redis accessible without authentication",
            severity=Severity.HIGH,
            module="intel",
            target=f"{asset.host}:6379",
            description="Redis accepted a PING and INFO command without authentication. Unauthenticated Redis access can expose or allow modification of application data and, in some configurations, lead to host compromise.",
            remediation="Enable Redis authentication/ACLs, bind to private interfaces, disable dangerous commands, and restrict network access.",
            evidence=Evidence(
                payload="PING; INFO server",
                request=f"tcp://{asset.host}:6379",
                notes=f"redis_version={version or 'unknown'}; no keys were read.",
                response_excerpt=truncate(info.decode("utf-8", "replace")[:800], 800),
            ),
            confidence="high",
            tags=["redis", "unauthenticated-access", "misconfiguration"],
            metadata={"redis_version": version},
        )

    def _docker(self, asset: HostAsset) -> Finding | None:
        if not self._can_connect(asset.host, 2375):
            return None
        url = f"http://{asset.host}:2375/version"
        try:
            self.ctx.scope.assert_url(url)
        except ScopeViolation:
            return None
        result = self.ctx.session.get(url, timeout=6)
        if result.status != 200 or not result.text:
            return None
        data = result.json()
        if not isinstance(data, dict) or not any(key in data for key in ("ApiVersion", "Version", "GitCommit")):
            return None
        return Finding(
            title="Docker Engine API accessible without TLS/authentication",
            severity=Severity.CRITICAL,
            module="intel",
            target=f"{asset.host}:2375",
            description="The Docker Engine API responded on its plain HTTP port. An unauthenticated Docker API allows container lifecycle control and can be leveraged for host compromise.",
            remediation="Never expose the Docker API over plain HTTP. Bind to a local socket or use mutual TLS with client certificates and restrict access to management networks.",
            evidence=Evidence(
                request=format_curl("GET", url),
                notes=f"Docker API version={data.get('ApiVersion', '')} engine={data.get('Version', '')}",
                response_excerpt=safe_excerpt(result.text, 500),
            ),
            confidence="high",
            tags=["docker", "unauthenticated-access", "critical"],
            metadata={"api_version": data.get("ApiVersion"), "engine_version": data.get("Version")},
            reproduction=format_curl("GET", url),
        )

    def _elasticsearch(self, asset: HostAsset) -> Finding | None:
        if not self._can_connect(asset.host, 9200):
            return None
        url = f"http://{asset.host}:9200/"
        try:
            self.ctx.scope.assert_url(url)
        except ScopeViolation:
            return None
        result = self.ctx.session.get(url, timeout=6)
        if result.status != 200:
            return None
        data = result.json()
        if not isinstance(data, dict) or "version" not in data:
            return None
        version = data.get("version", {})
        version_text = version.get("number", "") if isinstance(version, dict) else str(version)
        return Finding(
            title="Elasticsearch API accessible without authentication",
            severity=Severity.HIGH,
            module="intel",
            target=f"{asset.host}:9200",
            description="The Elasticsearch root API responded without an authentication challenge. If security features are disabled, indices may be readable or writable anonymously.",
            remediation="Enable Elasticsearch security features, enforce authentication and TLS, and restrict access to application networks.",
            evidence=Evidence(
                request=format_curl("GET", url),
                notes=f"Elasticsearch version={version_text}",
                response_excerpt=safe_excerpt(result.text, 400),
            ),
            confidence="medium",
            tags=["elasticsearch", "unauthenticated-access", "misconfiguration"],
            metadata={"version": version_text},
            reproduction=format_curl("GET", url),
        )

    def _memcached(self, asset: HostAsset) -> Finding | None:
        if not self._can_connect(asset.host, 11211):
            return None
        try:
            with socket.create_connection((asset.host, 11211), timeout=5) as sock:
                sock.settimeout(3)
                sock.sendall(b"version\r\n")
                response = sock.recv(1024).decode("utf-8", "replace").strip()
        except OSError:
            return None
        if not response.startswith("VERSION"):
            return None
        return Finding(
            title="Memcached accessible without authentication",
            severity=Severity.MEDIUM,
            module="intel",
            target=f"{asset.host}:11211",
            description="Memcached responded to a version command without authentication. Memcached is commonly used to cache session and application data.",
            remediation="Bind Memcached to localhost/private interfaces, restrict access with firewall rules, and avoid caching secrets.",
            evidence=Evidence(
                payload="version",
                request=f"tcp://{asset.host}:11211",
                response_excerpt=truncate(response, 300),
            ),
            confidence="high",
            tags=["memcached", "unauthenticated-access", "misconfiguration"],
        )

    def _mongodb(self, asset: HostAsset) -> Finding | None:
        if not self._can_connect(asset.host, 27017):
            return None
        try:
            from pymongo import MongoClient  # type: ignore
        except Exception:
            self.log.debug("pymongo is not installed; skipping MongoDB authentication check")
            return None
        client = None
        try:
            client = MongoClient(
                asset.host,
                27017,
                serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000,
                directConnection=True,
            )
            response = client.admin.command("listDatabases")
        except Exception:
            return None
        finally:
            if client is not None:
                with contextlib.suppress(Exception):
                    client.close()
        if not isinstance(response, dict) or not response.get("ok"):
            return None
        databases = response.get("databases") or []
        return Finding(
            title="MongoDB accepts unauthenticated listDatabases",
            severity=Severity.HIGH,
            module="intel",
            target=f"{asset.host}:27017",
            description="MongoDB returned the database list without authentication. This indicates that authentication/authorization is not enforced, potentially exposing collection data.",
            remediation="Enable MongoDB authentication/authorization, bind to private interfaces, and restrict access to application hosts.",
            evidence=Evidence(
                request=f"mongodb://{asset.host}:27017/ (listDatabases)",
                notes=f"database_count={len(databases)}",
            ),
            confidence="high",
            tags=["mongodb", "unauthenticated-access", "misconfiguration"],
        )


def _recv_all(sock: socket.socket, limit: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and total < limit:
        try:
            data = sock.recv(min(4096, limit - total))
        except TimeoutError:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)
