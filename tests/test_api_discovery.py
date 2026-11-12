from __future__ import annotations

import json

from cyberforge.api.discovery import APIDiscovery
from cyberforge.core.config import ScanConfig
from cyberforge.core.context import ModuleContext
from cyberforge.core.models import ResultBundle
from cyberforge.core.oob import OOBListener
from cyberforge.core.scope import Scope, ScopeConfig
from cyberforge.core.session import HttpResult


class FakeSession:
    def __init__(self, base: str) -> None:
        self.base = base
        self.spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1"},
            "servers": [{"url": base}],
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
            "paths": {
                "/api/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }

    def get(self, url: str, **kwargs: object) -> HttpResult:
        if url.rstrip("/") == f"{self.base}/openapi.json":
            return HttpResult(
                requested_url=url,
                url=url,
                method="GET",
                status=200,
                headers={"Content-Type": "application/json"},
                text=json.dumps(self.spec),
            )
        return HttpResult(requested_url=url, url=url, method="GET", status=404)

    def post(self, url: str, **kwargs: object) -> HttpResult:
        return HttpResult(requested_url=url, url=url, method="POST", status=404)


def build_context(session: FakeSession, tmp_path) -> ModuleContext:
    config = ScanConfig(
        targets=["https://api.example.test"],
        have_authorization=True,
        accept_disclaimer=True,
        modules=["api"],
        formats=["json"],
        output_dir=tmp_path,
    )
    scope = Scope(
        ScopeConfig(
            engagement="API Test",
            authorized_by="Owner",
            allowed_hosts=("api.example.test",),
            max_requests=20,
        )
    )
    return ModuleContext(
        config=config,
        scope=scope,
        bundle=ResultBundle("API Test", config.targets, {}),
        session=session,
        output_dir=tmp_path,
    )


def test_openapi_discovery_records_security_schemes_and_endpoints(tmp_path) -> None:
    base = "https://api.example.test"
    ctx = build_context(FakeSession(base), tmp_path)
    result = APIDiscovery(ctx).discover()
    assert len(result.surfaces) == 1
    assert len(result.endpoints) == 1
    assert result.surfaces[0].security_schemes == ["bearerAuth"]
    assert result.endpoints[0].url == f"{base}/api/users/{{id}}"
    assert result.endpoints[0].parameters == ["id"]


def test_oob_listener_records_callback() -> None:
    import requests

    with OOBListener(bind_host="127.0.0.1", port=0, public_host="127.0.0.1") as listener:
        token = listener.new_token()
        response = requests.get(listener.url_for(token), timeout=5)
        hits = listener.wait_for(token, timeout=3)
        assert response.status_code == 200
        assert hits
