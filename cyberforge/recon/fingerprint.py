"""Technology, CDN/WAF, title, and favicon fingerprinting."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from cyberforge.core.logging import get_logger
from cyberforge.core.models import Technology
from cyberforge.core.session import HttpResult, SafeSession
from cyberforge.core.utils import get_header, truncate

log = get_logger("recon.fingerprint")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE
)
JQUERY_RE = re.compile(r"jquery[.-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js", re.IGNORECASE)
BOOTSTRAP_PATH_RE = re.compile(r"bootstrap/([0-9]+\.[0-9]+\.[0-9]+)/", re.IGNORECASE)
NG_VERSION_RE = re.compile(r'ng-version=["\']([0-9][0-9.]*)["\']', re.IGNORECASE)
SERVER_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)/([0-9][A-Za-z0-9._-]*)")
WP_VERSION_RE = re.compile(r"wordpress[ /_-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)


@dataclass
class FingerprintResult:
    technologies: list[Technology] = field(default_factory=list)
    cdn: str = ""
    waf: str = ""
    title: str = ""

    def add(self, name: str, category: str, version: str = "", confidence: str = "medium", evidence: str = "") -> None:
        key = (name.lower(), category.lower())
        for tech in self.technologies:
            if (tech.name.lower(), tech.category.lower()) == key:
                if version and not tech.version:
                    tech.version = version
                if confidence == "high":
                    tech.confidence = "high"
                return
        self.technologies.append(
            Technology(
                name=name,
                category=category,
                version=version,
                confidence=confidence,
                evidence=truncate(evidence, 300),
            )
        )


def fingerprint_response(result: HttpResult, base_url: str) -> FingerprintResult:
    fp = FingerprintResult()
    headers = result.headers
    body = result.text or ""
    lower_body = body[:300000].lower()
    server = get_header(headers, "Server")
    powered_by = get_header(headers, "X-Powered-By")
    cookies = _cookie_names(headers)

    _server_technologies(fp, headers, server)
    _header_technologies(fp, headers, powered_by)
    _cookie_technologies(fp, cookies)
    _body_technologies(fp, body, lower_body)
    _framework_signatures(fp, lower_body, body)
    fp.title = _extract_title(body)
    fp.cdn = detect_cdn(headers, lower_body)
    fp.waf = detect_waf(headers, lower_body)
    if fp.cdn and fp.cdn == "Cloudflare" and not fp.waf:
        fp.waf = "Cloudflare"
    return fp


def _server_technologies(fp: FingerprintResult, headers: dict[str, str], server: str) -> None:
    if not server:
        return
    lowered = server.lower()
    if "cloudflare" in lowered:
        fp.add("Cloudflare", "cdn", confidence="high", evidence=server)
    if "cloudfront" in lowered:
        fp.add("Amazon CloudFront", "cdn", confidence="high", evidence=server)
    if "sucuri" in lowered:
        fp.add("Sucuri", "waf", confidence="high", evidence=server)
    if "apache-coyote" in lowered:
        fp.add("Apache Tomcat", "server", confidence="high", evidence=server)
    matches = SERVER_RE.findall(server)
    for product, version in matches:
        canonical = {
            "apache": "Apache HTTP Server",
            "nginx": "Nginx",
            "microsoft-iis": "Microsoft IIS",
            "litespeed": "LiteSpeed",
            "openresty": "OpenResty",
            "caddy": "Caddy",
            "jetty": "Jetty",
            "gunicorn": "Gunicorn",
            "werkzeug": "Werkzeug",
            "uvicorn": "Uvicorn",
            "kestrel": "Kestrel",
        }.get(product.lower())
        if canonical:
            fp.add(canonical, "server", version=version, confidence="high", evidence=server)
    if "apache" in lowered and not any(t.name == "Apache HTTP Server" for t in fp.technologies):
        fp.add("Apache HTTP Server", "server", confidence="medium", evidence=server)
    if "nginx" in lowered and not any(t.name == "Nginx" for t in fp.technologies):
        fp.add("Nginx", "server", confidence="high", evidence=server)


def _header_technologies(fp: FingerprintResult, headers: dict[str, str], powered_by: str) -> None:
    if powered_by:
        lowered = powered_by.lower()
        if "php" in lowered:
            match = re.search(r"php/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", powered_by, re.IGNORECASE)
            fp.add("PHP", "language", version=match.group(1) if match else "", confidence="high", evidence=powered_by)
        if "asp.net" in lowered:
            fp.add("ASP.NET", "framework", confidence="high", evidence=powered_by)
        if "express" in lowered:
            fp.add("Express", "framework", confidence="high", evidence=powered_by)
        if "servlet" in lowered or "jsp" in lowered:
            fp.add("Java", "language", confidence="high", evidence=powered_by)
    asp_version = get_header(headers, "X-AspNet-Version")
    if asp_version:
        fp.add("ASP.NET", "framework", version=asp_version, confidence="high", evidence="X-AspNet-Version")
    mvc_version = get_header(headers, "X-AspNetMvc-Version")
    if mvc_version:
        fp.add("ASP.NET MVC", "framework", version=mvc_version, confidence="high", evidence="X-AspNetMvc-Version")
    generator = get_header(headers, "X-Generator")
    if generator:
        fp.add(generator.split()[0], "cms", confidence="medium", evidence=generator)
    jenkins = get_header(headers, "X-Jenkins")
    if jenkins:
        fp.add("Jenkins", "ci", version=jenkins, confidence="high", evidence="X-Jenkins")
    if get_header(headers, "X-Confluence-Request-Time") or get_header(headers, "X-Atlassian-Token"):
        fp.add("Atlassian Confluence", "app", confidence="high", evidence="Atlassian response headers")
    if get_header(headers, "X-Powered-By") and "next.js" in get_header(headers, "X-Powered-By").lower():
        fp.add("Next.js", "framework", confidence="high", evidence="X-Powered-By")
    request_id = get_header(headers, "X-Request-Id")
    if request_id and get_header(headers, "X-Runtime"):
        fp.add("Ruby on Rails", "framework", confidence="low", evidence="X-Runtime header")
    if get_header(headers, "X-Cache") and "cloudfront" in get_header(headers, "X-Cache").lower():
        fp.add("Amazon CloudFront", "cdn", confidence="high", evidence="X-Cache")


def _cookie_technologies(fp: FingerprintResult, cookies: dict[str, str]) -> None:
    for name in cookies:
        lowered = name.lower()
        if lowered == "phpsessid":
            fp.add("PHP", "language", confidence="medium", evidence=name)
        elif lowered == "jsessionid":
            fp.add("Java", "language", confidence="medium", evidence=name)
        elif lowered == "asp.net_sessionid":
            fp.add("ASP.NET", "framework", confidence="high", evidence=name)
        elif lowered == "csrftoken":
            fp.add("Django", "framework", confidence="medium", evidence=name)
        elif lowered == "laravel_session":
            fp.add("Laravel", "framework", confidence="high", evidence=name)
        elif lowered == "_gitlab_session":
            fp.add("GitLab", "app", confidence="high", evidence=name)
        elif lowered == "grafana_session":
            fp.add("Grafana", "app", confidence="high", evidence=name)
        elif lowered.startswith("wordpress_") or lowered == "wp-settings-time-1":
            fp.add("WordPress", "cms", confidence="high", evidence=name)
        elif lowered in {"jenkins-tribble", "jenkins_session"}:
            fp.add("Jenkins", "ci", confidence="high", evidence=name)
        elif lowered == "_rails_session" or lowered == "rbzsessionid":
            fp.add("Ruby on Rails", "framework", confidence="medium", evidence=name)


def _body_technologies(fp: FingerprintResult, body: str, lower_body: str) -> None:
    generator = META_GENERATOR_RE.search(body)
    if generator:
        value = generator.group(1).strip()
        fp.add(value.split()[0], "cms", confidence="medium", evidence=value)
        if "wordpress" in value.lower():
            version = WP_VERSION_RE.search(value)
            fp.add("WordPress", "cms", version=version.group(1) if version else "", confidence="high", evidence=value)
        if "drupal" in value.lower():
            fp.add("Drupal", "cms", confidence="high", evidence=value)
        if "joomla" in value.lower():
            fp.add("Joomla", "cms", confidence="high", evidence=value)

    if any(marker in lower_body for marker in ("/wp-content/", "/wp-includes/", "/wp-json/")):
        fp.add("WordPress", "cms", confidence="high", evidence="wp-content/wp-includes assets")
    if any(marker in lower_body for marker in ("drupal.settings", "/sites/default/files/", "data-drupal-")):
        fp.add("Drupal", "cms", confidence="high", evidence="Drupal asset paths")
    if any(marker in lower_body for marker in ("/media/system/js/", "/components/com_", "content=\"joomla!")):
        fp.add("Joomla", "cms", confidence="high", evidence="Joomla asset paths")
    if "csrfmiddlewaretoken" in lower_body or "__admin_media_prefix__" in lower_body:
        fp.add("Django", "framework", confidence="high", evidence="Django CSRF markers")
    if "whitelabel error page" in lower_body or "x-application-context" in lower_body:
        fp.add("Spring Boot", "framework", confidence="high", evidence="Spring whitelabel/context marker")
    if "spring" in lower_body and "/actuator" in lower_body:
        fp.add("Spring Boot", "framework", confidence="medium", evidence="Actuator references")
    if "__next_data__" in lower_body or "/_next/static/" in lower_body:
        fp.add("Next.js", "framework", confidence="high", evidence="Next.js hydration/assets")
    if "__nuxt__" in lower_body or "/_nuxt/" in lower_body:
        fp.add("Nuxt", "framework", confidence="high", evidence="Nuxt hydration/assets")
    if "data-reactroot" in lower_body or "__react_devtools_global_hook__" in lower_body or "react-dom" in lower_body:
        fp.add("React", "js-framework", confidence="medium", evidence="React DOM markers")
    if "data-v-" in lower_body or "__vue__" in lower_body or "vue-router" in lower_body:
        fp.add("Vue.js", "js-framework", confidence="medium", evidence="Vue markers")
    ng_version = NG_VERSION_RE.search(body)
    if ng_version:
        fp.add("Angular", "js-framework", version=ng_version.group(1), confidence="high", evidence="ng-version")
    elif "ng-app" in lower_body or "_nghost-" in lower_body:
        fp.add("Angular", "js-framework", confidence="medium", evidence="Angular directives")
    if "cdn.shopify.com" in lower_body or "shopify" in lower_body:
        fp.add("Shopify", "ecommerce", confidence="medium", evidence="Shopify assets")
    if "mage/cookies" in lower_body or "magento" in lower_body:
        fp.add("Magento", "ecommerce", confidence="medium", evidence="Magento assets")
    if "grafana" in lower_body and ("grafanaBootData" in body or "grafana_session" in lower_body):
        fp.add("Grafana", "app", confidence="high", evidence="Grafana boot data")
    if "gitlab" in lower_body and (".gitlab" in lower_body or "gon.gitlab_url" in body):
        fp.add("GitLab", "app", confidence="high", evidence="GitLab markers")
    if "confluence" in lower_body and ("ajs-version-number" in lower_body or "com.atlassian.confluence" in lower_body):
        fp.add("Atlassian Confluence", "app", confidence="high", evidence="Confluence markers")
    if "jenkins" in lower_body and ("jenkins-crumb" in lower_body or "adjuncts" in lower_body):
        fp.add("Jenkins", "ci", confidence="medium", evidence="Jenkins markers")


def _framework_signatures(fp: FingerprintResult, lower_body: str, body: str) -> None:
    jquery = JQUERY_RE.search(body)
    if jquery:
        fp.add("jQuery", "js-library", version=jquery.group(1), confidence="high", evidence=jquery.group(0))
    elif "jquery" in lower_body:
        fp.add("jQuery", "js-library", confidence="low", evidence="jQuery string")
    bootstrap = BOOTSTRAP_PATH_RE.search(body)
    if bootstrap:
        fp.add("Bootstrap", "css-framework", version=bootstrap.group(1), confidence="high", evidence=bootstrap.group(0))
    elif "bootstrap.min" in lower_body:
        version_match = re.search(r'bootstrap[.-]?v?([0-9]+\.[0-9]+\.[0-9]+)', body, re.IGNORECASE)
        fp.add(
            "Bootstrap",
            "css-framework",
            version=version_match.group(1) if version_match else "",
            confidence="low",
            evidence="Bootstrap assets",
        )
    if "angular.min.js" in lower_body or "angular.js" in lower_body:
        fp.add("AngularJS", "js-framework", confidence="medium", evidence="AngularJS asset")


def detect_cdn(headers: dict[str, str], lower_body: str = "") -> str:
    checks = [
        ("cf-ray", "Cloudflare"),
        ("x-amz-cf-id", "Amazon CloudFront"),
        ("x-akamai-transformed", "Akamai"),
        ("x-akamai-request-id", "Akamai"),
        ("x-fastly-request-id", "Fastly"),
        ("x-served-by", "Fastly"),
        ("x-azure-ref", "Azure Front Door"),
        ("x-sucuri-id", "Sucuri"),
        ("x-cdn", "Imperva"),
    ]
    for header, name in checks:
        value = get_header(headers, header)
        if value:
            if header == "x-cdn" and "imperva" not in value.lower() and "incapsula" not in value.lower():
                continue
            return name
    server = get_header(headers, "Server").lower()
    if "cloudflare" in server:
        return "Cloudflare"
    if "cloudfront" in get_header(headers, "Via").lower():
        return "Amazon CloudFront"
    if "sucuri" in server:
        return "Sucuri"
    return ""


def detect_waf(headers: dict[str, str], lower_body: str = "") -> str:
    if get_header(headers, "x-iinfo") or "incap_ses" in get_header(headers, "Set-Cookie").lower():
        return "Imperva"
    if get_header(headers, "x-sucuri-id") or "sucuri" in get_header(headers, "Server").lower():
        return "Sucuri"
    if get_header(headers, "cf-ray"):
        return "Cloudflare"
    if get_header(headers, "x-waf-event-info") or get_header(headers, "x-waf-request-id"):
        return "Generic WAF"
    server = get_header(headers, "Server").lower()
    if "barracuda" in server or "fortiweb" in server or "big-ip" in server:
        return "Network WAF/LB"
    body = lower_body[:20000]
    if "request rejected" in body and ("waf" in body or "firewall" in body):
        return "Generic WAF"
    return ""


def favicon_hash(session: SafeSession, base_url: str) -> str:
    url = urljoin(base_url, "/favicon.ico")
    result = session.get(url, timeout=5)
    if result.status != 200 or not result.raw:
        return ""
    data = result.raw
    if len(data) > 500_000:
        return ""
    sha = hashlib.sha256(data).hexdigest()
    mmh3_value = ""
    try:
        import mmh3  # type: ignore

        encoded = base64.b64encode(data)
        mmh3_value = f"mmh3:{mmh3.hash(encoded)};"
    except Exception:
        mmh3_value = ""
    return f"{mmh3_value}sha256:{sha}"


def _cookie_names(headers: dict[str, str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    raw = get_header(headers, "Set-Cookie")
    if not raw:
        return cookies
    for chunk in raw.split(","):
        pair = chunk.split(";", 1)[0].strip()
        if "=" in pair:
            name, _, value = pair.partition("=")
            if name.strip():
                cookies[name.strip()] = value.strip()
    return cookies


def _extract_title(body: str) -> str:
    match = TITLE_RE.search(body or "")
    if not match:
        return ""
    title = re.sub(r"<[^>]+>", "", match.group(1))
    title = " ".join(title.split())
    return truncate(title, 200)
