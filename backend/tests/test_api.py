from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def make_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        cors_origins=["*"],
        rate_limit_requests=100,
        rate_limit_window_seconds=60,
        suspicious_tlds={"ru", "tk", "xyz", "top", "click", "zip"},
        reports_dir=str(tmp_path / "reports"),
        report_ip_hash_salt="test-salt",
    )
    app = create_app(settings)
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
    assert "reportId" in body

    report_file = tmp_path / "reports" / "reports.jsonl"
    assert report_file.exists()

    lines = report_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["url"] == payload["url"]
    assert row["reason"] == payload["reason"]
    assert row["clientIpHash"]
