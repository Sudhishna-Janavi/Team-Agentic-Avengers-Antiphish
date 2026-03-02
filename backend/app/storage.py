from __future__ import annotations

import sqlite3
import threading
from datetime import datetime


class SQLiteStore:
    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    reporter_type TEXT NOT NULL,
                    reporter_user TEXT NOT NULL,
                    evidence TEXT
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC)"
            )
            self._conn.commit()

    def create_user(
        self,
        user_id: str,
        name: str,
        email: str,
        role: str,
        password_hash: str,
        created_at: datetime,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO users (user_id, name, email, role, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, name, email, role, password_hash, created_at.isoformat()),
            )
            self._conn.commit()

    def get_user_by_email(self, email: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT user_id, name, email, role, password_hash, created_at
                FROM users
                WHERE email = ?
                LIMIT 1
                """,
                (email,),
            ).fetchone()
        if row is None:
            return None
        return {
            "user_id": row["user_id"],
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
            "password_hash": row["password_hash"],
            "created_at": datetime.fromisoformat(row["created_at"]),
        }

    def insert_report(
        self,
        report_id: str,
        url: str,
        created_at: datetime,
        reason: str,
        reporter_type: str,
        reporter_user: str,
        evidence: str | None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO reports (
                    report_id, url, created_at, reason, reporter_type, reporter_user, evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    url,
                    created_at.isoformat(),
                    reason,
                    reporter_type,
                    reporter_user,
                    evidence,
                ),
            )
            self._conn.commit()

    def list_reports(self, limit: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT report_id, url, created_at, reason, reporter_type, reporter_user, evidence
                FROM reports
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "report_id": row["report_id"],
                "url": row["url"],
                "created_at": datetime.fromisoformat(row["created_at"]),
                "reason": row["reason"],
                "reporter_type": row["reporter_type"],
                "reporter_user": row["reporter_user"],
                "evidence": row["evidence"],
            }
            for row in rows
        ]

    def list_all_reports(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT report_id, url, created_at, reason, reporter_type, reporter_user, evidence
                FROM reports
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [
            {
                "report_id": row["report_id"],
                "url": row["url"],
                "created_at": datetime.fromisoformat(row["created_at"]),
                "reason": row["reason"],
                "reporter_type": row["reporter_type"],
                "reporter_user": row["reporter_user"],
                "evidence": row["evidence"],
            }
            for row in rows
        ]

    def count_reports(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()
        return int(row["c"])
