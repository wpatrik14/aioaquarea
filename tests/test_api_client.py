from __future__ import annotations

import json
import re

import pytest

from aioaquarea import ApiError, AuthenticationError, AuthenticationErrorCodes
from aioaquarea.api_client import AquareaAPIClient
from aioaquarea.auth import CCAppVersion, PanasonicRequestHeader, PanasonicSettings
from aioaquarea.const import AquareaEnvironment

from .conftest import ACCESS_TOKEN, CLIENT_ID

BASE = "https://accsmart.panasonic.com"


@pytest.fixture
def api(session):
    settings = PanasonicSettings()
    settings.access_token = ACCESS_TOKEN
    settings.clientId = CLIENT_ID
    return AquareaAPIClient(session, settings, CCAppVersion(), AquareaEnvironment.PRODUCTION)


async def test_headers_and_success(api, mocked):
    mocked.get(f"{BASE}/x", payload={"ok": 1})
    resp = await api.request("GET", "x")
    assert resp.status == 200
    assert await resp.json() == {"ok": 1}  # body still readable after release
    (call,) = next(iter(mocked.requests.values()))
    headers = call.kwargs["headers"]
    assert headers["x-user-authorization-v2"] == f"Bearer {ACCESS_TOKEN}"
    assert headers["x-client-id"] == CLIENT_ID
    assert re.fullmatch(r"[0-9a-f]{9}cfc[0-9a-f]{55}", headers["x-cfc-api-key"])
    assert headers["x-app-name"] == "Comfort Cloud"


async def test_custom_headers_and_external_url(api, mocked):
    mocked.get("https://other.example/y", payload={})
    await api.request("GET", external_url="https://other.example/y", headers={"x-test": "1"})
    mocked.get(f"{BASE}/rel", payload={})
    await api.request("GET", external_url="rel")
    calls = [c for v in mocked.requests.values() for c in v]
    assert calls[0].kwargs["headers"]["x-test"] == "1"


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_status_maps_to_token_expired(api, mocked, status):
    mocked.get(f"{BASE}/x", status=status, body="denied")
    with pytest.raises(AuthenticationError) as exc:
        await api.request("GET", "x")
    assert exc.value.error_code == AuthenticationErrorCodes.TOKEN_EXPIRED


@pytest.mark.parametrize("status", [400, 404, 500, 502])
async def test_non_2xx_raises_api_error(api, mocked, status):
    mocked.get(f"{BASE}/x", status=status, body="oops")
    with pytest.raises(ApiError) as exc:
        await api.request("GET", "x")
    assert not isinstance(exc.value, AuthenticationError)
    assert exc.value.error_code == f"HTTP_{status}"


async def test_non_2xx_not_raised_when_disabled(api, mocked):
    mocked.get(f"{BASE}/x", status=500, body="oops")
    resp = await api.request("GET", "x", throw_on_error=False)
    assert resp.status == 500


async def test_token_expiry_message_is_authentication_error(api, mocked):
    mocked.get(f"{BASE}/x", payload={"message": [{"errorCode": "1", "errorMessage": "Token expires"}]})
    with pytest.raises(AuthenticationError) as exc:
        await api.request("GET", "x")
    assert exc.value.error_code == AuthenticationErrorCodes.TOKEN_EXPIRED


async def test_json_error_on_http_200(api, mocked):
    mocked.get(f"{BASE}/x", payload={"message": [{"errorCode": "5000", "errorMessage": "bad"}]})
    with pytest.raises(ApiError) as exc:
        await api.request("GET", "x")
    assert exc.value.error_code == "5000"


async def test_known_auth_code_in_error(api, mocked):
    mocked.get(
        f"{BASE}/x",
        payload={"message": [{"errorCode": "1001-1401", "errorMessage": "nope"}]},
    )
    with pytest.raises(AuthenticationError) as exc:
        await api.request("GET", "x")
    assert exc.value.error_code == AuthenticationErrorCodes.INVALID_USERNAME_OR_PASSWORD


async def test_string_messages(api):
    errors = await api.look_for_errors({"message": "Token expires soon"})
    assert errors[0].error_code == AuthenticationErrorCodes.TOKEN_EXPIRED
    errors = await api.look_for_errors({"message": ["something"]})
    assert errors[0].error_code == "unknown_error_code"
    assert await api.look_for_errors([1, 2]) == []
    assert await api.look_for_errors({"message": [5]}) == []


async def test_token_updated_from_response(api, mocked):
    api.access_token = ACCESS_TOKEN
    mocked.get(
        f"{BASE}/x",
        payload={"accessToken": {"token": "newtok", "expires": "2030-01-01T00:00:00+0000"}},
    )
    await api.request("GET", "x")
    assert api.access_token == "newtok"
    assert api.token_expiration.year == 2030
    api.token_expiration = None
    assert api.token_expiration is None


async def test_non_json_response_is_returned(api, mocked):
    mocked.get(f"{BASE}/x", body="<html/>", content_type="text/html")
    resp = await api.request("GET", "x")
    assert await resp.text() == "<html/>"


async def test_missing_token_raises(session):
    from aioaquarea.auth import PanasonicRequestHeader

    with pytest.raises(AuthenticationError):
        await PanasonicRequestHeader.get(PanasonicSettings(), CCAppVersion())


def test_aqua_headers():
    h = PanasonicRequestHeader.get_aqua_headers(content_type="application/json")
    assert h["Accept"] == "application/json"
    assert h["content-type"] == "application/json"
    assert "text/html" in PanasonicRequestHeader.get_aqua_headers()["Accept"]
    assert PanasonicRequestHeader.get_aqua_headers(accept="x/y")["Accept"] == "x/y"


def test_api_key_is_deterministic():
    k1 = PanasonicRequestHeader._get_api_key("2025-01-01 10:00:00", "tok")
    assert k1 == PanasonicRequestHeader._get_api_key("2025-01-01 10:00:00", "tok")
    assert PanasonicRequestHeader._get_api_key("garbage", "tok") is None
    assert json.dumps(k1)
