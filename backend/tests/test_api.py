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
        "notes": "Suspicious login form",
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
    assert row["clientIpHash"]


def test_duplicate_report_returns_exists(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    payload = {
        "url": "https://EXAMPLE.com/a/",
        "reason": "phishing_or_scam",
        "notes": "first",
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
        json={"url": "https://example.com/a", "reason": "phishing_or_scam"},
    )
    second = client.post(
        "/api/report",
        json={"url": "https://example.com/b", "reason": "phishing_or_scam"},
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
