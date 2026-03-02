from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone

from .models import ReportRequest


class JsonlReportStore:
    def __init__(self, reports_dir: str, salt: str) -> None:
        self.reports_dir = reports_dir
        self.salt = salt
        self._lock = threading.Lock()

    @property
    def report_file(self) -> str:
        return os.path.join(self.reports_dir, "reports.jsonl")

    def _hash_ip(self, ip: str) -> str:
        payload = f"{self.salt}:{ip}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def write_report(self, payload: ReportRequest, normalized_url: str, client_ip: str) -> tuple[str, datetime]:
        report_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)

        os.makedirs(self.reports_dir, exist_ok=True)

        record = {
            "reportId": report_id,
            "timestamp": timestamp.isoformat(),
            "url": payload.url,
            "normalizedUrl": normalized_url,
            "reason": payload.reason,
            "notes": payload.notes,
            "clientIpHash": self._hash_ip(client_ip),
        }

        with self._lock:
            with open(self.report_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=True) + "\n")

        return report_id, timestamp
