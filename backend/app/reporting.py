from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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


@dataclass
class StoredReport:
    report_id: str
    timestamp: datetime
    url: str
    normalized_url: str
    reason: str
    reporter: str
    user: str
    why_suspicious: str
    evidence: str | None
    suspicious_percent: int
    client_ip_hash: str

    def to_list_item(self) -> dict:
        return {
            "reportId": self.report_id,
            "timestamp": self.timestamp,
            "url": self.url,
            "normalizedUrl": self.normalized_url,
            "reason": self.reason,
            "reporter": self.reporter,
            "user": self.user,
            "whySuspicious": self.why_suspicious,
            "suspiciousPercent": self.suspicious_percent,
        }

    def to_detail(self) -> dict:
        data = self.to_list_item()
        data["evidence"] = self.evidence
        return data


class JsonlReportStore:
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
        self._reports: list[StoredReport] = []
        self._bootstrap_from_disk()

    @property
    def report_file(self) -> str:
        return os.path.join(self.reports_dir, "reports.jsonl")

    def _hash_ip(self, ip: str) -> str:
        payload = f"{self.salt}:{ip}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _to_utc(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _prune_index(self, now: datetime) -> None:
        cutoff = now.timestamp() - self.dedupe_seconds
        stale = [
            url
            for url, entry in self._recent_index.items()
            if entry.timestamp.timestamp() < cutoff
        ]
        for url in stale:
            self._recent_index.pop(url, None)

    def _parse_record(self, row: dict) -> StoredReport | None:
        report_id = str(row.get("reportId") or "").strip()
        timestamp_raw = str(row.get("timestamp") or "").strip()
        normalized_url = str(row.get("normalizedUrl") or "").strip()
        url = str(row.get("url") or "").strip()
        reason = str(row.get("reason") or "").strip()
        if not (report_id and timestamp_raw and normalized_url and url and reason):
            return None

        ts = self._to_utc(datetime.fromisoformat(timestamp_raw))
        return StoredReport(
            report_id=report_id,
            timestamp=ts,
            url=url,
            normalized_url=normalized_url,
            reason=reason,
            reporter=str(row.get("reporter") or "user").strip() or "user",
            user=str(row.get("user") or "anonymous").strip() or "anonymous",
            why_suspicious=(
                str(row.get("whySuspicious") or row.get("notes") or "").strip()
                or "No explanation provided."
            ),
            evidence=row.get("evidence"),
            suspicious_percent=max(0, min(100, int(row.get("suspiciousPercent") or 50))),
            client_ip_hash=str(row.get("clientIpHash") or "").strip(),
        )

    def _bootstrap_from_disk(self) -> None:
        path = self.report_file
        if not os.path.exists(path):
            return

        cutoff = self._now().timestamp() - self.dedupe_seconds
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                    report = self._parse_record(row)
                    if not report:
                        continue
                    self._reports.append(report)
                except Exception:
                    continue

        for report in reversed(self._reports):
            if report.timestamp.timestamp() < cutoff:
                continue
            if report.normalized_url in self._recent_index:
                continue
            self._recent_index[report.normalized_url] = IndexEntry(
                report_id=report.report_id,
                timestamp=report.timestamp,
            )

    def _write_record(self, record: dict) -> None:
        os.makedirs(self.reports_dir, exist_ok=True)
        with open(self.report_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")

    def write_report(
        self,
        payload: ReportRequest,
        normalized_url: str,
        client_ip: str,
        suspicious_percent: int,
    ) -> ReportResult:
        now = self._now()

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
            timestamp = self._to_utc(now)
            record = {
                "reportId": report_id,
                "timestamp": timestamp.isoformat(),
                "url": payload.url,
                "normalizedUrl": normalized_url,
                "reason": payload.reason,
                "whySuspicious": payload.whySuspicious,
                "evidence": payload.evidence,
                "suspiciousPercent": max(0, min(100, int(suspicious_percent))),
                "reporter": "user",
                "user": "anonymous",
                "clientIpHash": self._hash_ip(client_ip),
            }
            self._write_record(record)

            report = self._parse_record(record)
            if report is not None:
                self._reports.append(report)
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

    def _resolve_since_cutoff(self, since: str | None) -> datetime | None:
        if not since or since == "all":
            return None

        now = self._to_utc(self._now())
        lowered = since.lower()
        if lowered == "24h":
            return now - timedelta(hours=24)
        if lowered == "7d":
            return now - timedelta(days=7)

        parsed = datetime.fromisoformat(since)
        return self._to_utc(parsed)

    def list_reports(
        self,
        query: str | None,
        reason: str | None,
        user: str | None,
        since: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[dict], int, list[str]]:
        with self._lock:
            reports = list(reversed(self._reports))

        query_lower = (query or "").strip().lower()
        reason_filter = (reason or "").strip().lower()
        user_filter = (user or "").strip().lower()
        cutoff = self._resolve_since_cutoff(since)
        available_users = sorted(
            {report.user for report in reports if report.user},
            key=lambda item: item.lower(),
        )

        filtered: list[StoredReport] = []
        for report in reports:
            if reason_filter and report.reason.lower() != reason_filter:
                continue
            if user_filter and report.user.lower() != user_filter:
                continue
            if cutoff and report.timestamp < cutoff:
                continue
            if query_lower:
                haystack = f"{report.url} {report.normalized_url}".lower()
                if query_lower not in haystack:
                    continue
            filtered.append(report)

        # Extra safety for legacy data that may contain duplicates.
        deduped_items: list[StoredReport] = []
        seen_latest: dict[str, datetime] = {}
        for item in filtered:
            latest = seen_latest.get(item.normalized_url)
            if latest and (latest - item.timestamp).total_seconds() <= self.dedupe_seconds:
                continue
            seen_latest[item.normalized_url] = item.timestamp
            deduped_items.append(item)

        total = len(deduped_items)
        start = (page - 1) * page_size
        end = start + page_size
        page_items = [report.to_list_item() for report in deduped_items[start:end]]
        return page_items, total, available_users

    def get_report(self, report_id: str) -> dict | None:
        with self._lock:
            for report in reversed(self._reports):
                if report.report_id == report_id:
                    return report.to_detail()
        return None
