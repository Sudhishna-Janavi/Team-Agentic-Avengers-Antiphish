from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class SessionUser:
    username: str
    role: str


@dataclass
class SessionRecord:
    token: str
    user: SessionUser
    expires_at: datetime


class AuthService:
    def __init__(
        self,
        user_email: str,
        user_password: str,
        admin_email: str,
        admin_password: str,
        token_ttl_minutes: int,
    ) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionRecord] = {}
        self._token_ttl_minutes = token_ttl_minutes
        self._accounts = {
            user_email.strip().lower(): {"password": user_password, "role": "user"},
            admin_email.strip().lower(): {"password": admin_password, "role": "admin"},
        }

    def signup(self, username: str, password: str) -> SessionRecord | None:
        normalized = username.strip().lower()
        if not normalized or normalized in self._accounts:
            return None
        self._accounts[normalized] = {"password": password, "role": "user"}
        return self.login(username=normalized, password=password)

    def login(self, username: str, password: str) -> SessionRecord | None:
        normalized = username.strip().lower()
        account = self._accounts.get(normalized)
        if not account or account["password"] != password:
            return None

        now = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(32)
        record = SessionRecord(
            token=token,
            user=SessionUser(username=normalized, role=account["role"]),
            expires_at=now + timedelta(minutes=self._token_ttl_minutes),
        )
        with self._lock:
            self._sessions[token] = record
        return record

    def get_user(self, token: str) -> SessionUser | None:
        now = datetime.now(timezone.utc)
        with self._lock:
            record = self._sessions.get(token)
            if not record:
                return None
            if record.expires_at <= now:
                self._sessions.pop(token, None)
                return None
            return record.user

    def logout(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)
