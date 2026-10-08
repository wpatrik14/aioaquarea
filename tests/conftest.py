"""Shared fixtures and a fake Panasonic login flow."""

from __future__ import annotations

import json
import re
from pathlib import Path

import aiohttp
import pytest
from aioresponses import CallbackResult, aioresponses

from aioaquarea import Client
from aioaquarea.auth import CCAppVersion
from aioaquarea.const import BASE_PATH_ACC, BASE_PATH_AUTH, REDIRECT_URI

FIXTURES = Path(__file__).parent / "fixtures"

PASSWORD = "S3cret-P4ssw0rd!"
USERNAME = "user@example.com"
ACCESS_TOKEN = "ACCESS-TOKEN-VALUE-1234"
REFRESH_TOKEN = "REFRESH-TOKEN-VALUE-5678"
NEW_ACCESS_TOKEN = "NEW-ACCESS-TOKEN-4321"
NEW_REFRESH_TOKEN = "NEW-REFRESH-TOKEN-8765"
CSRF = "CSRF-COOKIE-VALUE"
AUTH_CODE = "AUTH-CODE-VALUE"
STATE = "STATE-VALUE-XYZ"
CLIENT_ID = "ACC-CLIENT-ID"
SECRETS = [
    PASSWORD,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    NEW_ACCESS_TOKEN,
    NEW_REFRESH_TOKEN,
    CSRF,
    AUTH_CODE,
    STATE,
    "SECRET-WRESULT-BLOB",
    "SECRET-WCTX-BLOB",
]

URL_AUTHORIZE = re.compile(rf"^{re.escape(BASE_PATH_AUTH)}/authorize\?.*")
URL_LOGIN_PAGE = f"{BASE_PATH_AUTH}/login?state={STATE}"
URL_USERPASS = f"{BASE_PATH_AUTH}/usernamepassword/login"
URL_CALLBACK = f"{BASE_PATH_AUTH}/login/callback"
URL_RESUME = f"{BASE_PATH_AUTH}/authorize/resume?state={STATE}"
URL_TOKEN = f"{BASE_PATH_AUTH}/oauth/token"
URL_ACC_LOGIN = f"{BASE_PATH_ACC}/auth/v2/login"


def load_fixture(name: str):
    text = (FIXTURES / name).read_text()
    return json.loads(text) if name.endswith(".json") else text


def token_body(access=ACCESS_TOKEN, refresh=REFRESH_TOKEN, expires_in=3600):
    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
        "scope": "openid offline_access",
    }


def mock_password_flow(
    m: aioresponses,
    *,
    login_status: int = 200,
    mfa: bool = False,
    login_body=None,
):
    """Register every request of a full password login."""
    m.get(
        URL_AUTHORIZE,
        status=302,
        headers={"Location": f"login?state={STATE}"},
    )
    m.get(
        URL_LOGIN_PAGE,
        status=200,
        headers={"Set-Cookie": f"_csrf={CSRF}; Path=/"},
        body="<html>login page</html>",
    )
    if login_status != 200:
        m.post(
            URL_USERPASS,
            status=login_status,
            payload=login_body
            or {
                "name": "ValidationError",
                "code": "invalid_user_password",
                "description": "Wrong email or password.",
            },
        )
        return
    m.post(URL_USERPASS, status=200, body=load_fixture("login_response.html"))
    m.post(URL_CALLBACK, status=302, headers={"Location": f"authorize/resume?state={STATE}"})
    if mfa:
        location = f"mf?state={STATE}"
    else:
        location = f"{REDIRECT_URI}?code={AUTH_CODE}&state={STATE}"
    m.get(URL_RESUME, status=302, headers={"Location": location})
    if not mfa:  # an MFA login gets its token only after complete_mfa
        m.post(URL_TOKEN, payload=token_body())
        m.post(URL_ACC_LOGIN, payload={"clientId": CLIENT_ID})


def mock_refresh_flow(m: aioresponses, *, status: int = 200, rotate: bool = True):
    seen: dict = {}

    def cb(url, **kwargs):
        seen["json"] = kwargs.get("json")
        if status != 200:
            return CallbackResult(status=status, payload={"error": "invalid_grant"})
        return CallbackResult(
            status=200,
            payload=token_body(
                NEW_ACCESS_TOKEN, NEW_REFRESH_TOKEN if rotate else None
            ),
        )

    m.post(URL_TOKEN, callback=cb)
    if status == 200:
        m.post(URL_ACC_LOGIN, payload={"clientId": CLIENT_ID})
    return seen


def call_count(m: aioresponses) -> int:
    return sum(len(v) for v in m.requests.values())


@pytest.fixture(autouse=True)
def no_app_store(monkeypatch):
    """Never contact the App Store."""

    async def fake_refresh(self):
        return None

    monkeypatch.setattr(CCAppVersion, "refresh", fake_refresh)


@pytest.fixture
def mocked():
    with aioresponses() as m:
        yield m


@pytest.fixture
async def session():
    async with aiohttp.ClientSession() as sess:
        yield sess


@pytest.fixture
async def client(session):
    return Client(session, USERNAME, PASSWORD)


@pytest.fixture
async def logged_client(client, mocked):
    """A client with a valid token whose HTTP traffic is mocked by `mocked`."""
    mock_password_flow(mocked)
    await client.login()
    mocked.requests.clear()
    return client
