"""Optional out-of-band callback listener for RFI/SSRF verification."""

from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from cyberforge.core.exceptions import OOBError
from cyberforge.core.logging import get_logger


class _OOBHandler(BaseHTTPRequestHandler):
    server_version = "CyberForge-X-OOB"
    sys_version = ""

    def _handle(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        listener: OOBListener = self.server.listener  # type: ignore[attr-defined]
        path = urlsplit(self.path).path
        token = path.strip("/").split("/", 1)[0] or "root"
        listener.record(
            token,
            {
                "method": self.command,
                "path": self.path[:500],
                "remote_address": self.client_address[0] if self.client_address else "",
                "user_agent": (self.headers.get("User-Agent") or "")[:300],
                "timestamp": time.time(),
            },
        )
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


class OOBListener:
    """Small callback HTTP server used only for confirmation requests.

    The listener records the first few callbacks per token and never serves
    dynamic content. It must be reachable from the target to be useful; set
    ``public_host`` to a routable address or tunnel hostname.
    """

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        port: int = 0,
        public_host: str = "",
        max_hits_per_token: int = 20,
    ) -> None:
        if not public_host:
            raise OOBError("OOB listener requires a public callback host")
        self.bind_host = bind_host
        self.requested_port = port
        self.public_host = public_host
        self.max_hits_per_token = max_hits_per_token
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._hits: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self.port = port
        self.log = get_logger("oob")

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self) -> int:
        if self._server is not None:
            return self.port
        try:
            server = ThreadingHTTPServer((self.bind_host, self.requested_port), _OOBHandler)
        except OSError as exc:
            raise OOBError(f"unable to bind OOB listener on {self.bind_host}:{self.requested_port}: {exc}") from exc
        server.daemon_threads = True
        server.allow_reuse_address = True
        server.listener = self  # type: ignore[attr-defined]
        self._server = server
        self.port = int(server.server_address[1])
        self._thread = threading.Thread(target=server.serve_forever, name="cyberforge-oob", daemon=True)
        self._thread.start()
        self.log.info("OOB listener active on %s:%s (public host %s)", self.bind_host, self.port, self.public_host)
        return self.port

    def url_for(self, token: str, path: str = "") -> str:
        if not self._server:
            self.start()
        suffix = f"/{token}"
        if path:
            suffix += "/" + path.lstrip("/")
        host = self.public_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self.port}{suffix}"

    def new_token(self, prefix: str = "cfx") -> str:
        return f"{prefix}{secrets.token_hex(8)}"

    def record(self, token: str, hit: dict[str, Any]) -> None:
        with self._lock:
            hits = self._hits.setdefault(token, [])
            if len(hits) < self.max_hits_per_token:
                hits.append(hit)

    def hits(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._hits.get(token, []))

    def wait_for(self, token: str, timeout: float = 5.0) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hits = self.hits(token)
            if hits:
                return hits
            time.sleep(0.1)
        return self.hits(token)

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None
        self.log.debug("OOB listener stopped")

    def __enter__(self) -> OOBListener:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()
