"""Credential list loading with conservative defaults."""

from __future__ import annotations

from collections.abc import Iterator

from cyberforge.core.context import ModuleContext
from cyberforge.core.utils import load_lines, read_package_lines


def load_users(ctx: ModuleContext) -> list[str]:
    return load_lines(ctx.config.brute_users, read_package_lines("wordlists", "usernames.txt"))


def load_passwords(ctx: ModuleContext) -> list[str]:
    return load_lines(ctx.config.brute_passwords, read_package_lines("wordlists", "passwords.txt"))


def pairs(users: list[str], passwords: list[str]) -> Iterator[tuple[str, str]]:
    for user in users:
        for password in passwords:
            if user and password:
                yield user, password
