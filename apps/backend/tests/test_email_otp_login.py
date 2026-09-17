"""Email-OTP login — verifying the `email_login` purpose issues a real
session (cookies), unlike the informational purposes (email_verify,
sensitive_action, login_stepup) which only return {"verified": true}."""

import re
import uuid

import pytest
from sqlalchemy import select

from app.modules.identity.models.otp import OtpChallenge
from app.modules.identity.services.token_service import hash_opaque_token

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest.fixture(autouse=True)
def _bypass_rate_limit(monkeypatch):
    from app.core import rate_limit as rl

    async def no_limit(*_a, **_k):
        return None

    monkeypatch.setattr(rl, "_check", no_limit)


def _email() -> str:
    return f"email-otp-{uuid.uuid4().hex[:12]}@example.com"


async def _register(client, email: str) -> None:
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "first_name": "Email",
            "last_name": "Otp",
            "mobile": "9876500201",
            "state_code": "KARNATAKA",
            "city": "Bangalore",
            "password": "EmailOtpPass!42",
        },
    )
    assert resp.status_code == 201, resp.text


async def _capture_code(client, email: str, monkeypatch, purpose: str) -> str:
    captured: dict[str, str] = {}

    def capture_send(*, to, subject, body, kind):
        captured["body"] = body

    monkeypatch.setattr("app.modules.identity.services.otp_service._send", capture_send)

    resp = await client.post("/api/v1/auth/otp/request", json={"email": email, "purpose": purpose})
    assert resp.status_code == 200, resp.text
    match = re.search(r"\b(\d{6})\b", captured["body"])
    assert match
    return match.group(1)


async def test_email_otp_login_issues_session(client, db_session, monkeypatch):
    email = _email()
    await _register(client, email)
    await client.post("/api/v1/auth/logout")

    code = await _capture_code(client, email, monkeypatch, "email_login")

    resp = await client.post("/api/v1/auth/otp/verify", json={"email": email, "purpose": "email_login", "code": code})
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["email"] == email
    assert "access_token" in resp.cookies
    assert "refresh_token" in resp.cookies

    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["data"]["email"] == email


async def test_email_otp_login_wrong_code_no_session(client, db_session, monkeypatch):
    email = _email()
    await _register(client, email)
    await client.post("/api/v1/auth/logout")

    await _capture_code(client, email, monkeypatch, "email_login")

    resp = await client.post("/api/v1/auth/otp/verify", json={"email": email, "purpose": "email_login", "code": "000000"})
    assert resp.status_code == 400
    assert "access_token" not in resp.cookies


async def test_email_verify_purpose_still_returns_verified_flag_not_session(client, db_session, monkeypatch):
    """Non-login purposes must keep their old, non-session behavior."""
    email = _email()
    await _register(client, email)
    await client.post("/api/v1/auth/logout")

    code = await _capture_code(client, email, monkeypatch, "email_verify")

    resp = await client.post("/api/v1/auth/otp/verify", json={"email": email, "purpose": "email_verify", "code": code})
    assert resp.status_code == 200
    assert resp.json()["data"] == {"verified": True}
    assert "access_token" not in resp.cookies


async def test_email_otp_login_unknown_email_generic_error(client, db_session, monkeypatch):
    """An OTP challenge can exist for an email with no account (e.g. request
    raced with account deletion) — verify must fail generically, never 500,
    and never establish a session."""
    email = _email()
    captured: dict[str, str] = {}

    def capture_send(*, to, subject, body, kind):
        captured["body"] = body

    monkeypatch.setattr("app.modules.identity.services.otp_service._send", capture_send)
    from app.core import rate_limit as rl

    async def no_limit(*_a, **_k):
        return None

    monkeypatch.setattr(rl, "_check", no_limit)

    resp = await client.post("/api/v1/auth/otp/request", json={"email": email, "purpose": "email_login"})
    assert resp.status_code == 200
    match = re.search(r"\b(\d{6})\b", captured["body"])
    assert match
    code = match.group(1)

    verify = await client.post("/api/v1/auth/otp/verify", json={"email": email, "purpose": "email_login", "code": code})
    assert verify.status_code == 400
    assert "access_token" not in verify.cookies
