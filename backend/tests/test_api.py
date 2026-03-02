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
        user_login_email="user@test.local",
        user_login_password="user12345",
        admin_login_email="admin@test.local",
        admin_login_password="admin12345",
        auth_token_ttl_minutes=720,
    )
    app = create_app(settings, now_provider=now_provider)
    return TestClient(app)


def login_headers(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    token = response.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_auth_login_and_me(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    bad = client.post(
        "/api/auth/login", json={"username": "user@test.local", "password": "wrong"}
    )
    assert bad.status_code == 401

    headers = login_headers(client, "user@test.local", "user12345")
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["role"] == "user"


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


def test_report_requires_auth(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    payload = {
        "url": "https://example.com/login",
        "reason": "phishing_or_scam",
        "whySuspicious": "Suspicious login form",
    }
    response = client.post("/api/report", json=payload)
    assert response.status_code == 401


def test_report_writes_jsonl(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    payload = {
        "url": "https://example.com/login",
        "reason": "phishing_or_scam",
        "whySuspicious": "Suspicious login form",
        "evidence": "Received from SMS",
    }
    response = client.post(
        "/api/report",
        json=payload,
        headers=login_headers(client, "user@test.local", "user12345"),
    )

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
    assert row["reporter"] == "user"
    assert row["user"] == "user@test.local"


def test_duplicate_report_creates_new_report_and_increases_total(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    headers = login_headers(client, "user@test.local", "user12345")
    payload = {
        "url": "https://EXAMPLE.com/a/",
        "reason": "phishing_or_scam",
        "whySuspicious": "Looks like fake login page",
    }

    first = client.post("/api/report", json=payload, headers=headers)
    second = client.post(
        "/api/report",
        json={**payload, "url": "https://example.com/a#ignored"},
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    body1 = first.json()
    body2 = second.json()
    assert body1["status"] == "ok"
    assert body2["status"] == "ok"
    assert body2["reportId"] != body1["reportId"]

    listed = client.get("/api/reports?page=1&pageSize=25")
    assert listed.status_code == 200
    listed_body = listed.json()
    assert listed_body["total"] == 2
    assert listed_body["items"][0]["frequency"] == 2


def test_same_url_after_time_window_still_creates_new_report(tmp_path: Path) -> None:
    now = datetime(2026, 3, 2, 0, 0, tzinfo=timezone.utc)
    clock = {"value": now}

    def now_provider() -> datetime:
        return clock["value"]

    client = make_client(tmp_path, dedupe_seconds=10, now_provider=now_provider)
    headers = login_headers(client, "user@test.local", "user12345")
    payload = {
        "url": "https://example.com/a",
        "reason": "phishing_or_scam",
        "whySuspicious": "Looks suspicious and urgent",
    }

    first = client.post("/api/report", json=payload, headers=headers)
    clock["value"] = clock["value"] + timedelta(seconds=11)
    second = client.post("/api/report", json=payload, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["status"] == "ok"
    assert second.json()["reportId"] != first.json()["reportId"]


def test_reports_endpoint_filters_and_paginates(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    headers = login_headers(client, "user@test.local", "user12345")

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
        response = client.post("/api/report", json=row, headers=headers)
        assert response.status_code == 200

    by_reason = client.get("/api/reports?reason=malware&page=1&pageSize=25")
    assert by_reason.status_code == 200
    assert by_reason.json()["total"] == 1

    paged = client.get("/api/reports?page=1&pageSize=2")
    assert paged.status_code == 200
    assert len(paged.json()["items"]) == 2


def test_admin_can_delete_report(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    user_headers = login_headers(client, "user@test.local", "user12345")
    admin_headers = login_headers(client, "admin@test.local", "admin12345")

    created = client.post(
        "/api/report",
        json={
            "url": "https://example.com/delete-me",
            "reason": "other",
            "whySuspicious": "Delete flow test",
        },
        headers=user_headers,
    )
    report_id = created.json()["reportId"]

    forbidden = client.delete(f"/api/reports/{report_id}", headers=user_headers)
    assert forbidden.status_code == 403

    deleted = client.delete(f"/api/reports/{report_id}", headers=admin_headers)
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"

    missing = client.get(f"/api/reports/{report_id}")
    assert missing.status_code == 404
