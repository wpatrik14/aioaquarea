import asyncio
import contextlib

import pytest

from aioaquarea.auth import Authenticator, CCAppVersion, PanasonicSettings
from aioaquarea.const import BASE_PATH_AUTH, REDIRECT_URI, AquareaEnvironment
from aioaquarea.errors import AuthenticationError, AuthenticationErrorCodes
from aioaquarea.mfa import describe_response, find_code_form

GUARDIAN = """<html><head><title>Verify</title>
<script src="https://cdn.example.com/js/guardian-widget.js?v=SECRET1"></script>
<script>var cfg = {state: "SECRETSTATE"};</script></head>
<body><h1>Multi-factor authentication</h1><h2>Check your email</h2>
<div id="guardian-container"></div>
<form method="post" action="/mf/verify?state=SECRETSTATE">
<input type="hidden" name="state" value="SECRETSTATE">
<input type="text" name="ticket" value="user@example.com"></form></body></html>"""

PLAIN = """<html><head><title>Enter code</title></head><body>
<h1>Enter the code</h1>
<form method="POST" action="/mf/submit?state=SECRETSTATE">
<input type="hidden" name="state" value="SECRETSTATE">
<input type="hidden" name="_csrf" value="CSRFVALUE">
<input type="text" name="OtpCode">
<input type="submit" name="action" value="verify"></form>
<p>We sent an SMS.</p></body></html>"""


def test_describe_guardian_page():
    out = describe_response(200, None, "text/html", GUARDIAN)
    print(out)
    assert "title='Verify'" in out
    assert "Check your email" in out
    assert "/js/guardian-widget.js" in out
    assert "guardian=yes" in out and "email=yes" in out and "sms=no" in out
    assert "action=/mf/verify" in out
    assert "ticket:text" in out
    for secret in ("SECRET", "user@example.com", "?v=", "cdn.example.com"):
        assert secret not in out


def test_describe_plain_form():
    out = describe_response(200, None, "text/html", PLAIN)
    print(out)
    assert "state:hidden" in out and "OtpCode:text" in out
    assert "sms=yes" in out and "guardian=no" in out
    for secret in ("SECRETSTATE", "CSRFVALUE", "verify\""):
        assert secret not in out


def test_describe_redirect():
    out = describe_response(
        302, "https://authglb.digital.panasonic.com/u/mfa-otp-challenge?state=ABC&x=1"
    )
    assert "path=/u/mfa-otp-challenge" in out
    assert "ABC" not in out
    assert "query params: state, x" in out


def test_find_code_form_plain():
    form = find_code_form(PLAIN, BASE_PATH_AUTH + "/mf?state=x")
    assert form.action == BASE_PATH_AUTH + "/mf/submit?state=SECRETSTATE"
    assert form.code_field == "OtpCode"
    assert form.fields == {"state": "SECRETSTATE", "_csrf": "CSRFVALUE", "action": "verify"}


def test_find_code_form_guardian_none():
    assert find_code_form(GUARDIAN, BASE_PATH_AUTH + "/mf") is None


class FakeResponse:
    def __init__(self, status=200, body="", location=None):
        self.status = status
        self._body = body
        self.headers = {"Location": location} if location else {}
        self.content_type = "text/html"

    async def text(self):
        return self._body


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    @contextlib.asynccontextmanager
    async def _next(self, method, url, data):
        self.requests.append((method, url, data))
        yield self.responses.pop(0)

    def get(self, url, **kw):
        return self._next("get", url, None)

    def request(self, method, url, data=None, **kw):
        return self._next(method, url, data)


def make_auth(session):
    auth = Authenticator(
        session, PanasonicSettings(), CCAppVersion(), AquareaEnvironment.PRODUCTION, None
    )
    auth._mfa_url = BASE_PATH_AUTH + "/mf?state=x"
    auth._code_verifier = "verifier"
    return auth


def test_complete_mfa_success():
    session = FakeSession(
        [
            FakeResponse(200, PLAIN),
            FakeResponse(302, location="/authorize/resume?state=x"),
            FakeResponse(302, location=REDIRECT_URI + "?code=THECODE&state=x"),
        ]
    )
    auth = make_auth(session)
    calls = []

    async def fake_token(code, verifier):
        calls.append((code, verifier))

    async def fake_acc():
        calls.append("acc")

    auth._request_new_token = fake_token
    auth._retrieve_client_acc = fake_acc
    asyncio.run(auth.complete_mfa("123456"))
    assert calls == [("THECODE", "verifier"), "acc"]
    method, url, data = session.requests[1]
    assert method == "post" and data["OtpCode"] == "123456"
    assert data["state"] == "SECRETSTATE" and data["_csrf"] == "CSRFVALUE"


def test_complete_mfa_guardian_unsupported():
    auth = make_auth(FakeSession([FakeResponse(200, GUARDIAN)]))
    with pytest.raises(AuthenticationError) as exc:
        asyncio.run(auth.complete_mfa("123456"))
    assert exc.value.error_code == AuthenticationErrorCodes.MFA_REQUIRED
    assert "guardian widget" in exc.value.error_message


def test_complete_mfa_without_pending_login():
    auth = make_auth(FakeSession([]))
    auth._mfa_url = None
    with pytest.raises(AuthenticationError):
        asyncio.run(auth.complete_mfa("1"))
