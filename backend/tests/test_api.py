from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def make_client(tmp_path: Path, dedupe_seconds: int = 86400, now_provider=None) -> TestClient:
    settings = Settings(
        cors_origins=["*"],
        rate_limit_requests=100,
        rate_limit_window_seconds=60,
        suspicious_tlds={"ru", "tk", "xyz", "top", "click", "zip"},
        reports_dir=str(tmp_path / "reports"),
        report_ip_hash_salt="test-salt",
        report_dedupe_seconds=dedupe_seconds,
    )
    app = create_app(settings, now_provider=now_provider)
    return TestClient(app)


def test_invalid_url_returns_400(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    response = client.post("/api/analyze", json={"url": "example.com/no-scheme"})

    assert response.status_code == 400
    payload = response.json()
    assert "detail" in payload


def test_safe_url_returns_low_and_signals(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    response = client.post("/api/analyze", json={"url": "https://google.com"})

    assert response.status_code == 200
    data = response.json()
    assert data["riskLabel"] == "low"
    assert data["riskScore"] <= 33
    assert isinstance(data["signals"], list)
    assert len(data["signals"]) >= 1


def test_suspicious_url_returns_high_with_multiple_signals(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    suspicious = "http://xn--googl-qmc.ru:8080/login/verify/account%252fsecure@update"
    response = client.post("/api/analyze", json={"url": suspicious})

    assert response.status_code == 200
    data = response.json()
    assert data["riskLabel"] == "high"
    assert data["riskScore"] >= 67
    assert len(data["signals"]) >= 3


def test_report_writes_jsonl(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    payload = {
        "url": "https://example.com/login",
        "reason": "phishing_or_scam",
        "whySuspicious": "Suspicious login form",
        "evidence": "Received from SMS",
    }
    response = client.post("/api/report", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["deduped"] is False
    assert "reportId" in body

    report_file = tmp_path / "reports" / "reports.jsonl"
    assert report_file.exists()

    lines = report_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["url"] == payload["url"]
    assert row["reason"] == payload["reason"]
    assert row["whySuspicious"] == payload["whySuspicious"]
    assert isinstance(row["suspiciousPercent"], int)
    assert row["clientIpHash"]


def test_duplicate_report_returns_exists(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    payload = {
        "url": "https://EXAMPLE.com/a/",
        "reason": "phishing_or_scam",
        "whySuspicious": "Looks like fake login page",
    }

    first = client.post("/api/report", json=payload)
    second = client.post(
        "/api/report",
        json={**payload, "url": "https://example.com/a#ignored"},
    )

    assert first.status_code == 200
    assert second.status_code == 200

    body1 = first.json()
    body2 = second.json()
    assert body1["status"] == "ok"
    assert body1["deduped"] is False
    assert body2["status"] == "exists"
    assert body2["deduped"] is True
    assert body2["reportId"] == body1["reportId"]
    assert body2["message"] == "This URL was already reported recently."

    report_file = tmp_path / "reports" / "reports.jsonl"
    lines = report_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1


def test_different_urls_create_separate_reports(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    first = client.post(
        "/api/report",
        json={
            "url": "https://example.com/a",
            "reason": "phishing_or_scam",
            "whySuspicious": "Potential fake sign-in form",
        },
    )
    second = client.post(
        "/api/report",
        json={
            "url": "https://example.com/b",
            "reason": "phishing_or_scam",
            "whySuspicious": "Requests credentials urgently",
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["status"] == "ok"
    assert second.json()["status"] == "ok"
    assert first.json()["reportId"] != second.json()["reportId"]

    report_file = tmp_path / "reports" / "reports.jsonl"
    lines = report_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_same_url_after_dedupe_window_creates_new_report(tmp_path: Path) -> None:
    now = datetime(2026, 3, 2, 0, 0, tzinfo=timezone.utc)

    clock = {"value": now}

    def now_provider() -> datetime:
        return clock["value"]

    client = make_client(tmp_path, dedupe_seconds=10, now_provider=now_provider)
    payload = {
        "url": "https://example.com/a",
        "reason": "phishing_or_scam",
        "whySuspicious": "Looks suspicious and urgent",
    }

    first = client.post("/api/report", json=payload)
    clock["value"] = clock["value"] + timedelta(seconds=11)
    second = client.post("/api/report", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["status"] == "ok"
    assert second.json()["status"] == "ok"
    assert second.json()["deduped"] is False
    assert second.json()["reportId"] != first.json()["reportId"]


def test_reports_endpoint_filters_and_paginates(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    rows = [
        {
            "url": "https://news.example.com/update",
            "reason": "other",
            "whySuspicious": "Unexpected update request",
        },
        {
            "url": "https://secure-bank-login.ru/verify/account",
            "reason": "phishing_or_scam",
            "whySuspicious": "Looks like fake bank portal",
        },
        {
            "url": "https://malware.bad.site/download",
            "reason": "malware",
            "whySuspicious": "Pushes unknown executable",
        },
    ]
    for row in rows:
        response = client.post("/api/report", json=row)
        assert response.status_code == 200

    by_reason = client.get("/api/reports?reason=malware&page=1&pageSize=25")
    assert by_reason.status_code == 200
    body = by_reason.json()
    assert body["total"] == 1
    assert body["items"][0]["reason"] == "malware"
    assert "suspiciousPercent" in body["items"][0]
    assert "whySuspicious" in body["items"][0]

    by_user = client.get("/api/reports?user=anonymous&page=1&pageSize=25")
    assert by_user.status_code == 200
    assert by_user.json()["total"] == 3

    by_query = client.get("/api/reports?query=secure-bank-login&page=1&pageSize=25")
    assert by_query.status_code == 200
    body = by_query.json()
    assert body["total"] == 1
    assert "secure-bank-login" in body["items"][0]["url"]

    paged = client.get("/api/reports?page=1&pageSize=2")
    assert paged.status_code == 200
    body = paged.json()
    assert body["page"] == 1
    assert body["pageSize"] == 2
    assert body["total"] == 3
    assert len(body["items"]) == 2

    paged_2 = client.get("/api/reports?page=2&pageSize=2")
    assert paged_2.status_code == 200
    assert len(paged_2.json()["items"]) == 1


def test_report_detail_endpoint_returns_full_report(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    created = client.post(
        "/api/report",
        json={
            "url": "https://example.com/abc",
            "reason": "phishing_or_scam",
            "whySuspicious": "full detail check",
            "evidence": "sms from unknown sender",
        },
    )
    report_id = created.json()["reportId"]

    detail = client.get(f"/api/reports/{report_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["reportId"] == report_id
    assert body["whySuspicious"] == "full detail check"
    assert body["evidence"] == "sms from unknown sender"
    assert isinstance(body["suspiciousPercent"], int)
    assert body["normalizedUrl"] == "https://example.com/abc"
