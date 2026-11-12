"""HTTP form login checks with CSRF refresh and conservative success detection."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from cyberforge.brute.base import CredentialHit, credential_hit
from cyberforge.brute.guard import AttemptBudget, CredentialGuard
from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)

FAILURE_WORDS = (
    "invalid username",
    "invalid password",
    "invalid credentials",
    "incorrect username",
    "incorrect password",
    "authentication failed",
    "login failed",
    "bad credentials",
    "username or password",
    "access denied",
    "unauthorized",
)
LOGIN_HINTS = ("login", "signin", "sign-in", "logon", "auth")
USER_NAMES = {"user", "username", "user_name", "userid", "user_id", "email", "login", "account", "account_name"}
CSRF_HINTS = ("csrf", "token", "authenticity", "nonce")


@dataclass
class LoginForm:
    page_url: str
    action_url: str
    method: str
    user_field: str
    pass_field: str
    hidden: dict[str, str] = field(default_factory=dict)
    csrf_fields: list[str] = field(default_factory=list)


class HTTPFormTester:
    def __init__(self, ctx: ModuleContext, guard: CredentialGuard, budget: AttemptBudget) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.session = ctx.session
        self.guard = guard
        self.budget = budget

    def test(self, target: str, users: list[str], passwords: list[str]) -> list[CredentialHit]:
        url = target if "://" in target else f"http://{target}"
        form = self._prepare(url)
        if form is None:
            return []
        self.log.info("Testing login form at %s (user field %s)", form.action_url, form.user_field)
        for username in users:
            for password in passwords:
                if not self.budget.consume():
                    self.log.info("Credential attempt budget exhausted")
                    return []
                try:
                    current = form
                    if form.csrf_fields:
                        refreshed = self._prepare(url)
                        if refreshed is not None:
                            current = refreshed
                    data = dict(current.hidden)
                    data[current.user_field] = username
                    data[current.pass_field] = password
                    result = self.session.post(
                        current.action_url,
                        data=data,
                        headers={"Referer": current.page_url, "Accept": "text/html,*/*"},
                    )
                except RequestBudgetExceeded:
                    self.log.warning("request budget exhausted during form authentication testing")
                    return []
                except (ScopeViolation, PolicyViolation):
                    return []
                finally:
                    self.guard.sleep()
                if result.status is None:
                    continue
                if self.guard.is_lockout(result.status, result.text):
                    self.log.warning("Possible lockout/rate limit at %s; stopping this target", target)
                    return []
                if self._success(result, current):
                    self.log.warning("Valid form credentials found for %s (username %s)", target, username)
                    return [
                        credential_hit(
                            protocol="HTTP Form",
                            target=current.action_url,
                            username=username,
                            password=password,
                            request=self._reproduction(current, username),
                            notes=(
                                f"HTTP {result.status}; final URL {result.url}; "
                                "login form accepted the credential pair."
                            ),
                            cvss=8.8,
                        )
                    ]
        return []

    def _prepare(self, url: str) -> LoginForm | None:
        try:
            result = self.session.get(url, headers={"Accept": "text/html,*/*"})
        except (ScopeViolation, PolicyViolation, RequestBudgetExceeded):
            return None
        if result.status is None or not result.text:
            self.log.info("Unable to load login page %s", url)
            return None
        soup = BeautifulSoup(result.text, "html.parser")
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method != "POST":
                continue
            inputs = form.find_all("input")
            password_input = next(
                (item for item in inputs if (item.get("type") or "").lower() == "password" and item.get("name")),
                None,
            )
            if password_input is None:
                continue
            pass_field = self.ctx.config.brute_pass_field or str(password_input.get("name"))
            user_field = self.ctx.config.brute_user_field or _find_user_field(inputs)
            if not user_field:
                continue
            if user_field not in {str(item.get("name")) for item in inputs if item.get("name")}:
                continue
            hidden: dict[str, str] = {}
            csrf: list[str] = []
            for item in inputs:
                name = item.get("name")
                if not name:
                    continue
                input_type = (item.get("type") or "text").lower()
                if input_type == "hidden":
                    hidden[str(name)] = str(item.get("value") or "")
                    if any(hint in str(name).lower() for hint in CSRF_HINTS):
                        csrf.append(str(name))
            action = form.get("action") or result.url
            action_url = urljoin(result.url, action)
            return LoginForm(
                page_url=result.url,
                action_url=action_url,
                method=method,
                user_field=user_field,
                pass_field=pass_field,
                hidden=hidden,
                csrf_fields=csrf,
            )
        self.log.info("No POST login form with password field found at %s", url)
        return None

    def _success(self, result: object, form: LoginForm) -> bool:
        text = getattr(result, "text", "") or ""
        status = getattr(result, "status", None)
        final_url = getattr(result, "url", form.action_url) or form.action_url
        lowered = text.lower()
        if self.ctx.config.brute_success_regex:
            return bool(re.search(self.ctx.config.brute_success_regex, text))
        if self.ctx.config.brute_failure_regex and re.search(self.ctx.config.brute_failure_regex, text):
            return False
        if self.ctx.config.brute_success_url:
            return final_url.startswith(self.ctx.config.brute_success_url) or self.ctx.config.brute_success_url in final_url
        if status not in {200, 201, 202, 203, 204}:
            return False
        if any(word in lowered for word in FAILURE_WORDS):
            return False
        if _has_password_form(text):
            return False
        final_path = urlsplit(final_url).path.lower()
        login_path = urlsplit(form.page_url).path.lower()
        if final_path != login_path and not any(hint in final_path for hint in LOGIN_HINTS):
            return True
        return bool(any(marker in lowered for marker in ("logout", "sign out", "dashboard", "welcome")))

    def _reproduction(self, form: LoginForm, username: str) -> str:
        return (
            f"curl -i -sS -X POST {shlex.quote(form.action_url)} "
            f"--data {shlex.quote(f'{form.user_field}={username}&{form.pass_field}=<password>')}"
        )


def _find_user_field(inputs: list) -> str:
    for item in inputs:
        name = str(item.get("name") or "")
        input_type = (item.get("type") or "text").lower()
        if name.lower() in USER_NAMES and input_type not in {"password", "hidden"}:
            return name
    for item in inputs:
        name = str(item.get("name") or "")
        input_type = (item.get("type") or "text").lower()
        if input_type in {"text", "email"} and name:
            return name
    return ""


def _has_password_form(text: str) -> bool:
    lowered = (text or "").lower()
    return "<form" in lowered and 'type="password"' in lowered

