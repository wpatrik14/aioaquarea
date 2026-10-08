"""Multi-factor authentication through Panasonic's Auth0 Guardian page."""

from __future__ import annotations

import base64
import json
import logging
import time

import pytest
from aioresponses import CallbackResult

from aioaquarea import (
    AuthenticationError,
    AuthenticationErrorCodes,
    Client,
    MfaChallenge,
    MfaRequiredError,
)
from aioaquarea.const import BASE_PATH_AUTH, REDIRECT_URI
from aioaquarea.mfa import mask_destination, normalize_factor
from aioaquarea.mfa_guardian import (
    host_allowed,
    jwt_expired,
    normalize_url,
    parse_guardian_page,
)

from .conftest import (
    AUTH_CODE,
    NEW_ACCESS_TOKEN,
    NEW_REFRESH_TOKEN,
    PASSWORD,
    REFRESH_TOKEN,
    SECRETS,
    STATE,
    URL_ACC_LOGIN,
    URL_RESUME,
    URL_TOKEN,
    URL_USERPASS,
    USERNAME,
    call_count,
    mock_password_flow,
    mock_refresh_flow,
    token_body,
)

Codes = AuthenticationErrorCodes


def b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def make_jwt(exp_offset: int = 300, **claims) -> str:
    payload = {"exp": int(time.time()) + exp_offset, **claims}
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(payload)}.c2lnbmF0dXJl"


REQUEST_TOKEN = make_jwt(txid="REQ-SECRET-TX")
TX_TOKEN = make_jwt(txid="TX-SECRET-ID")
SIGNATURE = "GUARDIAN-SIGNATURE-SECRET"
TRACKING_ID = "TRACKING-ID-SECRET"
MFA_CSRF = "MFA-CSRF-SECRET"
PHONE = "+36 30 123 4562"
CODE = "123456"
GUARDIAN_SECRETS = SECRETS + [REQUEST_TOKEN, TX_TOKEN, SIGNATURE, TRACKING_ID, MFA_CSRF]

MF_URL = f"{BASE_PATH_AUTH}/mf?state={STATE}"
SERVICE = "https://pdpauthglb-a1.panasonic.auth0.com"
START_FLOW = f"{SERVICE}/api/start-flow"
SEND_SMS = f"{SERVICE}/api/send-sms"
VERIFY_OTP = f"{SERVICE}/api/verify-otp"
RECOVER = f"{SERVICE}/api/recover-account"
TX_STATE = f"{SERVICE}/api/transaction-state"


SERVICE_JS = SERVICE.replace("/", "\\/")  # JSON-style escaped slashes


def guardian_page(request_token: str = REQUEST_TOKEN) -> str:
    """The /mf page shape seen in the field: an inline config object."""
    return f"""<!DOCTYPE html><html><head>
<title>Panasonic Digital Platform - MFA Standard</title>
<script src="/js/guardian-js/1.3.2/guardian-js.min.js"></script>
<script>
  var mfaConfig = {{
    globalTrackingId: "{TRACKING_ID}",
    postActionURL: "\\/mf?state={STATE}",
    requestToken: "{request_token}",
    serviceUrl: "{SERVICE_JS}",
    stateCheckingMechanism: "polling",
    _csrf: "{MFA_CSRF}"
  }};
</script>
<script src="/mfa/loader.js"></script>
</head><body></body></html>"""


def start_flow_body(types, phone=None, enrollment_tx=None):
    account = {"id": "dev_1", "status": "confirmed", "methods": types}
    if phone:
        account["phone_number"] = phone
    body = {
        "transaction_token": TX_TOKEN,
        "device_account": account,
        "available_authentication_methods": ["otp", "sms"],
    }
    if enrollment_tx:
        body["enrollment_tx_id"] = enrollment_tx
    return body


class Recorder:
    """Collects (url, headers, body) of the Guardian API calls."""

    def __init__(self):
        self.calls: list[tuple[str, dict, object]] = []

    def cb(self, payload=None, status=200):
        def callback(url, **kwargs):
            self.calls.append((str(url), kwargs.get("headers") or {}, kwargs.get("json")))
            if payload is None:
                return CallbackResult(status=status)
            return CallbackResult(status=status, payload=payload)

        return callback

    def paths(self) -> list[str]:
        return [c[0].removeprefix(SERVICE) for c in self.calls]


def mock_page(m, body: str | None = None, status: int = 200):
    m.get(MF_URL, status=status, body=body or guardian_page(), content_type="text/html")


def mock_post_back(
    m, seen: dict, *, location: str | None = None, status: int = 302, resume: bool = True
):
    def post_cb(url, **kwargs):
        seen["data"] = kwargs.get("data")
        headers = {"Location": location or f"/authorize/resume?state={STATE}"}
        return CallbackResult(status=status, headers=headers if location != "" else {})

    m.post(MF_URL, callback=post_cb)
    if resume:
        m.get(
            URL_RESUME,
            status=302,
            headers={"Location": f"{REDIRECT_URI}?code={AUTH_CODE}&state={STATE}"},
        )
        m.post(URL_TOKEN, payload=token_body())
        m.post(URL_ACC_LOGIN, payload={"clientId": "ACC-CLIENT-ID"})


def mock_guardian(m, rec: Recorder, factor: str, *, phone=PHONE, accepted=True):
    types = [factor]
    m.post(START_FLOW, callback=rec.cb(start_flow_body(types, phone if factor == "sms" else None), 201))
    if factor == "sms":
        m.post(SEND_SMS, callback=rec.cb(status=204))
    m.post(VERIFY_OTP, callback=rec.cb(status=204))
    m.post(
        TX_STATE,
        callback=rec.cb({"id": "tx", "state": "accepted", "token": SIGNATURE}),
    )


async def login_to_mfa(client, mocked, rec=None, factor="sms", page=None):
    """Run the password login up to the MFA challenge; return the error."""
    rec = rec or Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked, page)
    mock_guardian(mocked, rec, factor)
    with pytest.raises(MfaRequiredError) as exc:
        await client.login()
    return exc.value, rec


def no_secrets(text: str):
    for secret in GUARDIAN_SECRETS + [CODE, PHONE, "4562", "123 4562"]:
        assert secret not in text, secret


# --- challenge --------------------------------------------------------------


async def test_sms_challenge(client, mocked):
    err, rec = await login_to_mfa(client, mocked, factor="sms")
    assert isinstance(err, AuthenticationError)  # existing callers keep working
    assert err.error_code == Codes.MFA_REQUIRED
    assert err.challenge == MfaChallenge("sms", "***62", ("sms",), True)
    assert client.mfa_challenge == err.challenge
    assert not client.is_logged
    assert rec.paths() == ["/api/start-flow", "/api/send-sms"]
    start, send = rec.calls
    assert start[1]["Authorization"] == f"Bearer {REQUEST_TOKEN}"
    assert start[1]["x-global-tracking-id"] == TRACKING_ID
    assert start[2] == {"state_transport": "polling"}
    assert send[1]["Authorization"] == f"Bearer {TX_TOKEN}"
    no_secrets(str(err) + repr(err.challenge))


async def test_otp_challenge_sends_nothing(client, mocked):
    err, rec = await login_to_mfa(client, mocked, factor="otp")
    assert err.challenge == MfaChallenge("otp", None, ("otp",), False)
    assert rec.paths() == ["/api/start-flow"]


async def test_code_factor_preferred_over_push(client, mocked):
    rec = Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["push", "otp"]), 201))
    with pytest.raises(MfaRequiredError) as exc:
        await client.login()
    assert exc.value.challenge.factor == "otp"
    assert exc.value.challenge.available_factors == ("push", "otp")


async def test_mfa_send_code_disabled(session, mocked):
    client = Client(session, USERNAME, PASSWORD, mfa_send_code=False)
    err, rec = await login_to_mfa(client, mocked, factor="sms")
    assert err.challenge.factor == "sms" and not err.challenge.code_sent
    assert rec.paths() == ["/api/start-flow"]
    mocked.post(SEND_SMS, callback=rec.cb(status=204))
    challenge = await client.resend_mfa_code()
    assert challenge.code_sent
    assert rec.paths() == ["/api/start-flow", "/api/send-sms"]


# --- completing -------------------------------------------------------------


@pytest.mark.parametrize("factor", ["sms", "otp"])
async def test_complete_mfa(client, mocked, factor, caplog):
    caplog.set_level(logging.DEBUG)
    _, rec = await login_to_mfa(client, mocked, factor=factor)
    seen: dict = {}
    mock_post_back(mocked, seen)

    await client.complete_mfa("123 456")

    assert client.is_logged
    assert client.refresh_token == REFRESH_TOKEN
    assert client._settings.clientId == "ACC-CLIENT-ID"
    assert client.token_expiration is not None
    assert client.mfa_challenge is None
    verify, state = rec.calls[-2:]
    assert verify[1]["Authorization"] == f"Bearer {TX_TOKEN}"
    assert verify[2] == {"type": "manual_input", "code": CODE}
    assert state[1]["Authorization"] == f"Bearer {TX_TOKEN}"
    assert seen["data"] == {"signature": SIGNATURE, "_csrf": MFA_CSRF}
    token_call = [k for k in mocked.requests if URL_TOKEN in str(k[1])]
    assert token_call
    body = mocked.requests[token_call[0]][0].kwargs["json"]
    assert body["grant_type"] == "authorization_code" and body["code"] == AUTH_CODE
    no_secrets("\n".join(r.getMessage() for r in caplog.records))


async def test_complete_mfa_resets_login_cooldown(client, mocked):
    await login_to_mfa(client, mocked)
    assert client._login_failure is not None
    mock_post_back(mocked, {})
    await client.complete_mfa(CODE)
    assert client._login_failure is None and client._login_failures == 0
    assert client._login_retry_at == 0.0


async def test_recovery_code(client, mocked):
    _, rec = await login_to_mfa(client, mocked, factor="otp")
    mocked.post(RECOVER, callback=rec.cb(status=204))
    mock_post_back(mocked, {})
    await client.complete_mfa("a" * 24)
    assert client.is_logged
    assert rec.calls[1][0] == RECOVER and rec.calls[1][2] == {"recovery_code": "a" * 24}


async def test_signature_in_verify_response_skips_polling(client, mocked):
    rec = Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(VERIFY_OTP, callback=rec.cb({"token": SIGNATURE}, 200))
    with pytest.raises(MfaRequiredError):
        await client.login()
    mock_post_back(mocked, {})
    await client.complete_mfa(CODE)
    assert rec.paths() == ["/api/start-flow", "/api/verify-otp"]


async def test_transaction_state_polls_until_accepted(client, mocked):
    rec = Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(VERIFY_OTP, callback=rec.cb(status=204))
    mocked.post(TX_STATE, callback=rec.cb({"state": "pending"}))
    mocked.post(TX_STATE, callback=rec.cb(status=429))
    mocked.post(TX_STATE, callback=rec.cb({"state": "accepted", "token": SIGNATURE}))
    with pytest.raises(MfaRequiredError):
        await client.login()
    mock_post_back(mocked, {})
    await client.complete_mfa(CODE)
    assert rec.paths().count("/api/transaction-state") == 3


# --- failures ---------------------------------------------------------------


async def test_wrong_code_then_right_code(client, mocked):
    rec = Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(VERIFY_OTP, callback=rec.cb({"errorCode": "invalid_otp"}, 401))
    mocked.post(VERIFY_OTP, callback=rec.cb(status=204))
    mocked.post(TX_STATE, callback=rec.cb({"state": "accepted", "token": SIGNATURE}))
    with pytest.raises(MfaRequiredError):
        await client.login()

    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa("000000")
    assert exc.value.error_code == Codes.MFA_INVALID_CODE
    assert not client.is_logged
    assert client.mfa_challenge is not None  # the transaction is still usable

    mock_post_back(mocked, {})
    await client.complete_mfa(CODE)
    assert client.is_logged


@pytest.mark.parametrize("code", ["", "12345", "abcdef", "1234567", "12 34"])
async def test_malformed_code_is_rejected_locally(client, mocked, code):
    _, rec = await login_to_mfa(client, mocked, factor="otp")
    calls = len(rec.calls)
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(code)
    assert exc.value.error_code == Codes.MFA_INVALID_CODE
    assert len(rec.calls) == calls


async def test_rejected_transaction_is_invalid_code(client, mocked):
    rec = Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(VERIFY_OTP, callback=rec.cb(status=204))
    mocked.post(TX_STATE, callback=rec.cb({"state": "rejected"}))
    with pytest.raises(MfaRequiredError):
        await client.login()
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.MFA_INVALID_CODE


async def test_expired_transaction_needs_new_login(client, mocked):
    rec = Recorder()
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    client._authenticator.mfa_poll_interval = 0
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(
        VERIFY_OTP, callback=rec.cb({"message": "Transaction token expired"}, 401)
    )
    with pytest.raises(MfaRequiredError):
        await client.login()
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.MFA_EXPIRED
    assert client.mfa_challenge is None
    # no pending transaction any more
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.MFA_EXPIRED

    # and the next login starts over instead of replaying the cached error
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    with pytest.raises(MfaRequiredError):
        await client.login()


async def test_expired_transaction_token_detected_locally(client, mocked):
    rec = Recorder()
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    expired_tx = make_jwt(-10)
    body = start_flow_body(["otp"])
    body["transaction_token"] = expired_tx
    mocked.post(START_FLOW, callback=rec.cb(body, 201))
    with pytest.raises(MfaRequiredError):
        await client.login()
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.MFA_EXPIRED
    assert len(rec.calls) == 1  # no verify request


async def test_expired_request_token(client, mocked):
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked, guardian_page(make_jwt(-10)))
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert not isinstance(exc.value, MfaRequiredError)
    assert exc.value.error_code == Codes.MFA_EXPIRED


@pytest.mark.parametrize(
    ("status", "step"),
    [(500, "verify-otp"), (429, "verify-otp"), (404, "verify-otp")],
)
async def test_unexpected_verify_status(client, mocked, status, step):
    rec = Recorder()
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(VERIFY_OTP, callback=rec.cb({"errorCode": "boom", "echo": CODE}, status))
    with pytest.raises(MfaRequiredError):
        await client.login()
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.API_ERROR
    assert step in exc.value.error_message and str(status) in exc.value.error_message
    no_secrets(str(exc.value))


async def test_unexpected_transaction_state(client, mocked):
    rec = Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(VERIFY_OTP, callback=rec.cb(status=204))
    mocked.post(TX_STATE, callback=rec.cb({"x": 1}, 500))
    with pytest.raises(MfaRequiredError):
        await client.login()
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.API_ERROR
    assert "transaction-state" in exc.value.error_message


async def test_transaction_never_accepted(client, mocked):
    rec = Recorder()
    client._authenticator.mfa_poll_interval = 0
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"]), 201))
    mocked.post(VERIFY_OTP, callback=rec.cb(status=204))
    mocked.post(TX_STATE, callback=rec.cb({"state": "pending"}), repeat=True)
    with pytest.raises(MfaRequiredError):
        await client.login()
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.API_ERROR
    assert "transaction-state" in exc.value.error_message


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"location": ""}, "mfa-submit"),  # 302 without Location
        ({"status": 200, "location": ""}, "mfa-submit"),  # re-rendered page
        ({"location": f"{REDIRECT_URI}?error=access_denied"}, "authorization code"),
        ({"location": "https://evil.example.com/x"}, "another host"),
    ],
)
async def test_unexpected_submit_result(client, mocked, kwargs, message):
    await login_to_mfa(client, mocked, factor="otp")
    mock_post_back(mocked, {}, **kwargs)
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.API_ERROR
    assert message in exc.value.error_message
    assert client.mfa_challenge is None  # the signature is used up


async def test_submit_redirect_loop(client, mocked):
    await login_to_mfa(client, mocked, factor="otp")
    mock_post_back(mocked, {}, resume=False)
    mocked.get(
        URL_RESUME,
        status=302,
        headers={"Location": f"/authorize/resume?state={STATE}"},
        repeat=True,
    )
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.API_ERROR


async def test_token_exchange_failure_after_mfa(client, mocked):
    await login_to_mfa(client, mocked, factor="otp")
    mock_post_back(mocked, {}, resume=False)
    mocked.get(
        URL_RESUME,
        status=302,
        headers={"Location": f"{REDIRECT_URI}?code={AUTH_CODE}&state={STATE}"},
    )
    mocked.post(URL_TOKEN, status=403, body="SECRET-BODY")
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.API_ERROR
    assert "get_token" in exc.value.error_message and "SECRET-BODY" not in str(exc.value)
    assert not client.is_logged


async def test_complete_without_pending_login(client):
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa(CODE)
    assert exc.value.error_code == Codes.MFA_EXPIRED
    with pytest.raises(AuthenticationError) as exc:
        await client.resend_mfa_code()
    assert exc.value.error_code == Codes.MFA_EXPIRED


# --- resend -----------------------------------------------------------------


async def test_resend_sms(client, mocked):
    _, rec = await login_to_mfa(client, mocked, factor="sms")
    mocked.post(SEND_SMS, callback=rec.cb(status=204))
    challenge = await client.resend_mfa_code()
    assert challenge == MfaChallenge("sms", "***62", ("sms",), True)
    assert rec.paths().count("/api/send-sms") == 2


async def test_resend_failures(client, mocked):
    _, rec = await login_to_mfa(client, mocked, factor="sms")
    mocked.post(SEND_SMS, callback=rec.cb({"errorCode": "too_many_attempts"}, 429))
    with pytest.raises(AuthenticationError) as exc:
        await client.resend_mfa_code()
    assert exc.value.error_code == Codes.API_ERROR and "send-sms" in exc.value.error_message
    mocked.post(SEND_SMS, callback=rec.cb({"message": "token expired"}, 401))
    with pytest.raises(AuthenticationError) as exc:
        await client.resend_mfa_code()
    assert exc.value.error_code == Codes.MFA_EXPIRED
    assert client.mfa_challenge is None


async def test_resend_is_sms_only(client, mocked):
    await login_to_mfa(client, mocked, factor="otp")
    with pytest.raises(AuthenticationError) as exc:
        await client.resend_mfa_code()
    assert exc.value.error_code == Codes.MFA_REQUIRED


# --- unsupported pages keep the plain MFA_REQUIRED error --------------------


def assert_plain_mfa_required(exc):
    assert not isinstance(exc, MfaRequiredError)
    assert exc.error_code == Codes.MFA_REQUIRED


async def test_unsupported_factor_push(client, mocked):
    rec = Recorder()
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["push"]), 201))
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert_plain_mfa_required(exc.value)
    assert "push" in exc.value.error_message


async def test_account_without_enrolled_factor(client, mocked):
    rec = Recorder()
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body([], enrollment_tx="x"), 201))
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert_plain_mfa_required(exc.value)


async def test_start_flow_failure(client, mocked):
    rec = Recorder()
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)
    mocked.post(START_FLOW, callback=rec.cb({"errorCode": "boom"}, 500))
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == Codes.API_ERROR
    assert "start-flow" in exc.value.error_message


async def test_page_without_guardian(client, mocked):
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked, "<html><body>Enter your code</body></html>")
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert_plain_mfa_required(exc.value)


async def test_page_unreachable_or_unexpected_host(client, mocked):
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked, status=500)
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert_plain_mfa_required(exc.value)
    # Guardian service on a host that must never get the bearer token
    client._login_retry_at = 0
    mock_password_flow(mocked, mfa=True)
    page = guardian_page().replace(SERVICE_JS, "https:\\/\\/evil.example.com")
    mock_page(mocked, page)
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert_plain_mfa_required(exc.value)
    assert "unexpected host" in exc.value.error_message


async def test_page_redirects_are_followed_on_same_host_only(client, mocked):
    mock_password_flow(mocked, mfa=True)
    mocked.get(MF_URL, status=302, headers={"Location": "https://evil.example.com/mf"})
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert_plain_mfa_required(exc.value)

    client._login_retry_at = 0
    mock_password_flow(mocked, mfa=True)
    mocked.get(MF_URL, status=302, headers={"Location": f"/mf2?state={STATE}"})
    mocked.get(f"{BASE_PATH_AUTH}/mf2?state={STATE}", body=guardian_page())
    mocked.post(START_FLOW, callback=Recorder().cb(start_flow_body(["otp"]), 201))
    with pytest.raises(MfaRequiredError):
        await client.login()


async def test_service_unreachable(client, mocked):
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked)  # START_FLOW is not mocked: connection error
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert_plain_mfa_required(exc.value)


# --- refresh token (skips MFA on later logins) ------------------------------


async def test_mfa_login_keeps_no_stale_refresh_token(client, mocked):
    await login_to_mfa(client, mocked, factor="otp")
    client._settings.refresh_token = "STALE-REFRESH-TOKEN"
    mock_post_back(mocked, {}, resume=False)
    mocked.get(
        URL_RESUME,
        status=302,
        headers={"Location": f"{REDIRECT_URI}?code={AUTH_CODE}&state={STATE}"},
    )
    mocked.post(URL_TOKEN, payload=token_body(refresh=None))
    mocked.post(URL_ACC_LOGIN, payload={"clientId": "ACC-CLIENT-ID"})
    await client.complete_mfa(CODE)
    assert client.refresh_token is None


async def test_refresh_token_constructor_skips_password_and_mfa(session, mocked):
    client = Client(session, refresh_token=REFRESH_TOKEN)
    assert client.refresh_token == REFRESH_TOKEN
    seen = mock_refresh_flow(mocked)
    await client.login()
    assert client.is_logged
    assert client.refresh_token == NEW_REFRESH_TOKEN  # rotated
    assert seen["json"]["refresh_token"] == REFRESH_TOKEN
    assert "scope" not in seen["json"]  # not known for a stored token
    assert not any(URL_USERPASS in str(k[1]) for k in mocked.requests)


async def test_rejected_refresh_token_without_password(session, mocked):
    client = Client(session, refresh_token=REFRESH_TOKEN)
    mock_refresh_flow(mocked, status=400)
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == Codes.TOKEN_EXPIRED
    assert client.refresh_token is None


async def test_rejected_refresh_token_with_password_needs_mfa_again(session, mocked):
    client = Client(session, USERNAME, PASSWORD, refresh_token=REFRESH_TOKEN)
    mock_refresh_flow(mocked, status=400)
    err, _ = await login_to_mfa(client, mocked, factor="otp")
    assert err.challenge.factor == "otp"
    assert client.refresh_token is None


async def test_refresh_token_survives_mfa_login_and_reuse(client, mocked, session):
    await login_to_mfa(client, mocked, factor="otp")
    mock_post_back(mocked, {})
    await client.complete_mfa(CODE)
    stored = client.refresh_token
    assert stored == REFRESH_TOKEN

    again = Client(session, refresh_token=stored)
    seen = mock_refresh_flow(mocked)
    await again.login()
    assert seen["json"]["grant_type"] == "refresh_token"
    assert again._settings.access_token == NEW_ACCESS_TOKEN


async def test_unreachable_refresh_does_not_start_mfa(session, mocked):
    client = Client(session, USERNAME, PASSWORD, refresh_token=REFRESH_TOKEN)
    mock_refresh_flow(mocked, status=503)
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == Codes.API_ERROR
    assert call_count(mocked) == 1


# --- parsing & helpers ------------------------------------------------------


def test_parse_page_variants():
    page = f"""<script>window.cfg = {{ "requestToken": "{REQUEST_TOKEN}",
      "serviceUrl": "https:\\/\\/svc.example.panasonic.com\\/mfa",
      "postActionURL": "&#x2F;mf?state=abc&amp;x=1" }};</script>"""
    config = parse_guardian_page(page, f"{BASE_PATH_AUTH}/mf?state=abc")
    assert config.get("request_token") == REQUEST_TOKEN
    assert config.get("service_url") == "https://svc.example.panasonic.com/mfa"
    assert config.get("post_action") == f"{BASE_PATH_AUTH}/mf?state=abc&x=1"


def test_parse_page_jwt_fallback_and_placeholders():
    page = f"""<script>var a = {{ requestToken: "{{{{token}}}}", other: "{REQUEST_TOKEN}" }};</script>"""
    config = parse_guardian_page(page, f"{BASE_PATH_AUTH}/mf")
    assert config.get("request_token") == REQUEST_TOKEN
    assert config.get("service_url") is None


def test_helpers():
    assert normalize_url("\\/a\\/b", "https://h.example/x") == "https://h.example/a/b"
    assert normalize_url("  ", "https://h.example/x") == ""
    assert jwt_expired(make_jwt(-5)) is True and jwt_expired(make_jwt(50)) is False
    assert jwt_expired("not-a-jwt") is None and jwt_expired("a.!!!.c") is None
    assert mask_destination("+36 30 123 4562") == "***62"
    assert mask_destination("jane@example.com") == "***@***.com"
    assert mask_destination("---") == "***" and mask_destination(None) is None
    assert normalize_factor({"type": "TOTP"}) == "otp"
    assert normalize_factor("phone") == "sms"
    assert normalize_factor("recovery-code") is None and normalize_factor(3) is None
    assert normalize_factor("voice") == "voice" and normalize_factor("email") == "email"
    assert normalize_factor("weird") == "unknown"
    page = f"{BASE_PATH_AUTH}/mf"
    assert host_allowed(f"{BASE_PATH_AUTH}/x", page)
    assert host_allowed("https://x.panasonic.auth0.com", page)
    assert host_allowed("https://t.guardian.eu.auth0.com", page)
    assert not host_allowed("http://x.panasonic.auth0.com", page)
    assert not host_allowed("https://evil.example.com", page)
    assert not host_allowed("https://panasonic.auth0.com.evil.example.com", page)


def test_error_classes():
    err = MfaRequiredError(MfaChallenge("sms", "***62"))
    assert err.error_code == Codes.MFA_REQUIRED
    assert "sms" in str(err) and "***62" not in str(err)
