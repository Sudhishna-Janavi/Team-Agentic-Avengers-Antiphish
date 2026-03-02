from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    cors_origins: list[str]
    rate_limit_requests: int
    rate_limit_window_seconds: int
    suspicious_tlds: set[str]
    reports_dir: str
    report_ip_hash_salt: str
    report_dedupe_seconds: int
    user_login_email: str
    user_login_password: str
    admin_login_email: str
    admin_login_password: str
    auth_token_ttl_minutes: int


DEFAULT_SUSPICIOUS_TLDS = {
    "ru",
    "tk",
    "xyz",
    "top",
    "click",
    "zip",
}


def _parse_origins(value: str) -> list[str]:
    raw = [item.strip() for item in value.split(",") if item.strip()]
    return raw or ["*"]


def _parse_tlds(value: str) -> set[str]:
    if not value.strip():
        return set(DEFAULT_SUSPICIOUS_TLDS)
    return {item.strip().lower().lstrip(".") for item in value.split(",") if item.strip()}


def from_env() -> Settings:
    return Settings(
        cors_origins=_parse_origins(os.getenv("CORS_ORIGINS", "*")),
        rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "60")),
        rate_limit_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
        suspicious_tlds=_parse_tlds(os.getenv("SUSPICIOUS_TLDS", ",".join(sorted(DEFAULT_SUSPICIOUS_TLDS)))),
        reports_dir=os.getenv("REPORTS_DIR", "./reports"),
        report_ip_hash_salt=os.getenv("REPORT_IP_HASH_SALT", "change-me"),
        report_dedupe_seconds=int(os.getenv("REPORT_DEDUPE_SECONDS", "86400")),
        user_login_email=os.getenv("USER_LOGIN_EMAIL", "user@antiphish.local"),
        user_login_password=os.getenv("USER_LOGIN_PASSWORD", "user12345"),
        admin_login_email=os.getenv("ADMIN_LOGIN_EMAIL", "admin@antiphish.local"),
        admin_login_password=os.getenv("ADMIN_LOGIN_PASSWORD", "admin12345"),
        auth_token_ttl_minutes=int(os.getenv("AUTH_TOKEN_TTL_MINUTES", "720")),
    )
