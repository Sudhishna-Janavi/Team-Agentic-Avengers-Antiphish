from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import ReportRequest


@dataclass
class ReportResult:
    status: str
    report_id: str
    timestamp: datetime
    deduped: bool
    message: str | None = None


@dataclass
class IndexEntry:
    report_id: str
    timestamp: datetime


class JsonlReportStore:
    _BOOTSTRAP_MAX_LINES = 5000

    def __init__(
        self,
        reports_dir: str,
        salt: str,
        dedupe_seconds: int,
        now_provider=None,
    ) -> None:
        self.reports_dir = reports_dir
        self.salt = salt
        self.dedupe_seconds = dedupe_seconds
        self._now = now_provider or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._recent_index: dict[str, IndexEntry] = {}
        self._bootstrap_recent_index()

    @property
    def report_file(self) -> str:
        return os.path.join(self.reports_dir, "reports.jsonl")

    def _hash_ip(self, ip: str) -> str:
        payload = f"{self.salt}:{ip}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _prune_index(self, now: datetime) -> None:
        cutoff = now.timestamp() - self.dedupe_seconds
        stale = [
            url
            for url, entry in self._recent_index.items()
            if entry.timestamp.timestamp() < cutoff
        ]
        for url in stale:
            self._recent_index.pop(url, None)

    def _bootstrap_recent_index(self) -> None:
        path = self.report_file
        if not os.path.exists(path):
            return

        cutoff = self._now().timestamp() - self.dedupe_seconds
        with open(path, "r", encoding="utf-8") as handle:
            lines = deque(handle, maxlen=self._BOOTSTRAP_MAX_LINES)

        for line in reversed(lines):
            try:
                row = json.loads(line)
                normalized_url = str(row.get("normalizedUrl") or "").strip()
                report_id = str(row.get("reportId") or "").strip()
                timestamp_raw = str(row.get("timestamp") or "").strip()
                if not (normalized_url and report_id and timestamp_raw):
                    continue

                parsed_ts = datetime.fromisoformat(timestamp_raw)
                if parsed_ts.tzinfo is None:
                    parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
                if parsed_ts.timestamp() < cutoff:
                    continue
                if normalized_url in self._recent_index:
                    continue
                self._recent_index[normalized_url] = IndexEntry(
                    report_id=report_id,
                    timestamp=parsed_ts,
                )
            except Exception:
                continue

    def write_report(
        self,
        payload: ReportRequest,
        normalized_url: str,
        client_ip: str,
    ) -> ReportResult:
        now = self._now()

        os.makedirs(self.reports_dir, exist_ok=True)
        with self._lock:
            self._prune_index(now)
            existing = self._recent_index.get(normalized_url)
            if existing:
                return ReportResult(
                    status="exists",
                    report_id=existing.report_id,
                    timestamp=existing.timestamp,
                    deduped=True,
                    message="This URL was already reported recently.",
                )

            report_id = str(uuid.uuid4())
            timestamp = now

            record = {
                "reportId": report_id,
                "timestamp": timestamp.isoformat(),
                "url": payload.url,
                "normalizedUrl": normalized_url,
                "reason": payload.reason,
                "notes": payload.notes,
                "clientIpHash": self._hash_ip(client_ip),
            }
            with open(self.report_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=True) + "\n")
            self._recent_index[normalized_url] = IndexEntry(
                report_id=report_id,
                timestamp=timestamp,
            )

            return ReportResult(
                status="ok",
                report_id=report_id,
                timestamp=timestamp,
                deduped=False,
            )
