from __future__ import annotations

import logging

import pytest

from aioaquarea import AuthenticationError, AuthenticationErrorCodes, Client, core
from aioaquarea.auth import CCAppVersion, check_response
from aioaquarea.const import DEFAULT_X_APP_VERSION

from .conftest import (
    ACCESS_TOKEN,
    CLIENT_ID,
    NEW_ACCESS_TOKEN,
    NEW_REFRESH_TOKEN,
    PASSWORD,
    REFRESH_TOKEN,
    SECRETS,
    URL_ACC_LOGIN,
    URL_USERPASS,
    call_count,
    mock_password_flow,
    mock_refresh_flow,
)


async def test_password_login_success(client, mocked):
    mock_password_flow(mocked)
    await client.login()
    assert client.is_logged
    assert client._settings.access_token == ACCESS_TOKEN
    assert client._settings.refresh_token == REFRESH_TOKEN
    assert client._settings.clientId == CLIENT_ID
    assert client.token_expiration is not None


@pytest.mark.parametrize("status", [400, 401, 403])
async def test_wrong_password_maps_to_invalid_credentials(client, mocked, status):
    mock_password_flow(mocked, login_status=status)
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == AuthenticationErrorCodes.INVALID_USERNAME_OR_PASSWORD


async def test_other_login_status_stays_api_error(client, mocked):
    mock_password_flow(mocked, login_status=500, login_body={"x": 1})
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == AuthenticationErrorCodes.API_ERROR


async def test_mfa_redirect(client, mocked):
    mock_password_flow(mocked, mfa=True)
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == AuthenticationErrorCodes.MFA_REQUIRED


async def test_refresh_token_success_skips_password_flow(logged_client, mocked):
    client = logged_client
    seen = mock_refresh_flow(mocked)
    client._last_login = client._last_login.min  # allow a new login
    await client.login()
    assert seen["json"]["grant_type"] == "refresh_token"
    assert seen["json"]["refresh_token"] == REFRESH_TOKEN
    assert client._settings.access_token == NEW_ACCESS_TOKEN
    assert client._settings.refresh_token == NEW_REFRESH_TOKEN
    assert not any(URL_USERPASS in str(k[1]) for k in mocked.requests)


async def test_refresh_without_rotation_keeps_old_refresh_token(logged_client, mocked):
    mock_refresh_flow(mocked, rotate=False)
    logged_client._last_login = logged_client._last_login.min
    await logged_client.login()
    assert logged_client._settings.refresh_token == REFRESH_TOKEN
    assert logged_client._settings.access_token == NEW_ACCESS_TOKEN


@pytest.mark.parametrize("status", [400, 401, 403])
async def test_refresh_failure_falls_back_to_password_flow(logged_client, mocked, status):
    mock_refresh_flow(mocked, status=status)
    mock_password_flow(mocked)
    logged_client._last_login = logged_client._last_login.min
    await logged_client.login()
    assert any(URL_USERPASS in str(k[1]) for k in mocked.requests)
    assert logged_client._settings.access_token == ACCESS_TOKEN


async def test_refresh_server_error_does_not_start_password_flow(logged_client, mocked):
    mock_refresh_flow(mocked, status=503)
    logged_client._last_login = logged_client._last_login.min
    with pytest.raises(AuthenticationError) as exc:
        await logged_client.login()
    assert exc.value.error_code == AuthenticationErrorCodes.API_ERROR
    assert not any(URL_USERPASS in str(k[1]) for k in mocked.requests)


async def test_refresh_token_without_stored_token(client):
    with pytest.raises(AuthenticationError):
        await client._authenticator.refresh_token()


async def test_failure_cooldown_avoids_network(client, mocked):
    mock_password_flow(mocked, login_status=401)
    with pytest.raises(AuthenticationError) as first:
        await client.login()
    calls = call_count(mocked)
    assert calls > 0
    with pytest.raises(AuthenticationError) as second:
        await client.login()
    assert second.value is first.value
    assert call_count(mocked) == calls


async def test_cooldown_doubles_and_is_capped(client, mocked):
    for expected in (60, 120, 240):
        mock_password_flow(mocked, login_status=401)
        with pytest.raises(AuthenticationError):
            await client.login()
        remaining = client._login_retry_at - __import__("time").monotonic()
        assert expected - 2 < remaining <= expected
        client._login_retry_at = 0  # cooldown elapsed
    client._login_failures = 20
    mock_password_flow(mocked, login_status=401)
    with pytest.raises(AuthenticationError):
        await client.login()
    remaining = client._login_retry_at - __import__("time").monotonic()
    assert remaining <= core.LOGIN_COOLDOWN_MAX


async def test_success_resets_cooldown(client, mocked):
    mock_password_flow(mocked, login_status=401)
    with pytest.raises(AuthenticationError):
        await client.login()
    client._login_retry_at = 0
    mock_password_flow(mocked)
    await client.login()
    assert client._login_failures == 0
    assert client._login_failure is None


async def test_mfa_failure_is_cached(client, mocked):
    mock_password_flow(mocked, mfa=True)
    with pytest.raises(AuthenticationError):
        await client.login()
    calls = call_count(mocked)
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == AuthenticationErrorCodes.MFA_REQUIRED
    assert call_count(mocked) == calls


async def test_no_secrets_in_logs(client, mocked, caplog):
    caplog.set_level(logging.DEBUG)
    mock_password_flow(mocked)
    await client.login()
    mock_refresh_flow(mocked)
    client._last_login = client._last_login.min
    await client.login()
    mocked.get("https://accsmart.panasonic.com/device/group", payload={"groupList": []})
    await client._api_client.request("GET", external_url="https://accsmart.panasonic.com/device/group")
    assert caplog.records
    text = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    for secret in SECRETS:
        assert secret not in text, secret
    assert "<html" not in text


async def test_no_secrets_in_logs_on_failures(client, mocked, caplog):
    caplog.set_level(logging.DEBUG)
    mock_password_flow(mocked, login_status=401)
    with pytest.raises(AuthenticationError):
        await client.login()
    mock_password_flow(mocked, login_status=500, login_body={"echo": PASSWORD})
    client._login_retry_at = 0
    with pytest.raises(AuthenticationError):
        await client.login()
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert PASSWORD not in text


async def test_check_response_logs_only_metadata(mocked, session, caplog):
    mocked.get("https://example.com/x", status=500, body="BODY-WITH-SECRET")
    resp = await session.get("https://example.com/x")
    with pytest.raises(AuthenticationError):
        await check_response(resp, "step", 200)
    assert "BODY-WITH-SECRET" not in caplog.text
    assert "step" in caplog.text


async def test_app_version_refresh(monkeypatch, mocked):
    monkeypatch.undo()  # use the real refresh
    version = CCAppVersion()
    assert await version.get() == DEFAULT_X_APP_VERSION
    url = "https://apps.apple.com/de/app/panasonic-comfort-cloud/id1348640525"
    mocked.get(url, body="<p>Version 9.8.7</p>")
    await version.init()
    assert await version.get() == "9.8.7"
    mocked.get(url, body="nothing")
    await version.refresh()
    assert await version.get() == "9.8.7"
    mocked.get(url, status=500)
    await version.refresh()
    mocked.get(url, exception=OSError("boom"))
    await version.refresh()
    assert await version.get() == "9.8.7"


async def test_new_app_version_published_triggers_refresh(client, mocked, monkeypatch):
    refreshed = []

    async def fake_refresh(self):
        refreshed.append(1)

    monkeypatch.setattr(CCAppVersion, "refresh", fake_refresh)
    mock_password_flow(mocked)
    # first ACC login says the app version is outdated, the second one works
    mocked.post(URL_ACC_LOGIN, status=401, payload={"code": 4106}, repeat=False)
    await client.login()
    assert refreshed


async def test_client_without_credentials_is_rejected(session):
    with pytest.raises(ValueError):
        Client(session)


async def test_demo_environment_login(session, mocked):
    from aioaquarea import AquareaEnvironment

    c = Client(session, environment=AquareaEnvironment.DEMO)
    c._settings.access_token = "demo"
    mocked.get("https://accsmart.panasonic.com/", payload={})
    await c.login()
    assert c.token_expiration is not None


async def test_close_only_closes_owned_session(session):
    c = Client(session, USERNAME_, PASSWORD)
    await c.close()
    assert not session.closed
    own = Client(username=USERNAME_, password=PASSWORD)
    await own.close()
    assert own._sess.closed


USERNAME_ = "user@example.com"
