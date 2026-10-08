"""Auth0 classic Guardian MFA page (guardian-js protocol, polling transport)."""

from __future__ import annotations

import base64
import json
import logging
import time

import pytest
from aioresponses import CallbackResult

from aioaquarea.const import BASE_PATH_AUTH, REDIRECT_URI
from aioaquarea.errors import AuthenticationError, AuthenticationErrorCodes
from aioaquarea.mfa_guardian import (
    GuardianConfig,
    GuardianFlow,
    config_summary,
    enum_summary,
    host_allowed,
    jwt_expired,
    mask_destination,
    normalize_factor,
    normalize_url,
    parse_guardian_page,
)

from .conftest import (
    AUTH_CODE,
    SECRETS,
    STATE,
    URL_RESUME,
    mock_password_flow,
    token_body,
)


def b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def make_jwt(exp_offset: int = 300, **claims) -> str:
    header = b64({"alg": "HS256", "typ": "JWT"})
    payload = b64({"exp": int(time.time()) + exp_offset, **claims})
    return f"{header}.{payload}.c2lnbmF0dXJl"


REQUEST_TOKEN = make_jwt(txid="REQ-SECRET-TX")
TX_TOKEN = make_jwt(txid="TX-SECRET-ID")
SIGNATURE = "GUARDIAN-SIGNATURE-SECRET"
TRACKING_ID = "TRACKING-ID-SECRET"
MFA_CSRF = "MFA-CSRF-SECRET"
PHONE = "+36 30 123 4567"
EMAIL = "jane.doe@example.com"
GUARDIAN_SECRETS = [REQUEST_TOKEN, TX_TOKEN, SIGNATURE, TRACKING_ID, MFA_CSRF, PHONE, EMAIL]

MF_URL = f"{BASE_PATH_AUTH}/mf?state={STATE}"
LOADER_URL = f"{BASE_PATH_AUTH}/mfa/loader.js"
SERVICE = f"{BASE_PATH_AUTH}/appliance-mfa"
START_FLOW = f"{SERVICE}/api/start-flow"
SEND_SMS = f"{SERVICE}/api/send-sms"
VERIFY_OTP = f"{SERVICE}/api/verify-otp"
TX_STATE = f"{SERVICE}/api/transaction-state"
SERVICE_JS = SERVICE.replace("/", "\\/")  # JSON-style escaped slashes
MF_URL_JS = MF_URL.replace("/", "\\/")


def guardian_page(config: str | None = None) -> str:
    """The /mf page shape seen in the field, with an Auth0 classic inline config."""
    if config is None:
        config = f"""
    var mfaConfig = {{
      mfaServerUrl: "{SERVICE_JS}",
      requestToken: "{REQUEST_TOKEN}",
      postActionURL: "{MF_URL_JS}",
      globalTrackingId: "{TRACKING_ID}",
      userData: {{
        userId: "auth0|abc", email: "{EMAIL}", friendlyUserId: "{EMAIL}",
        tenant: "pdpauthglb-a1"
      }},
      _csrf: "{MFA_CSRF}",
      stateCheckingMechanism: "manual",
      allowRememberBrowser: false
    }};"""
    return f"""<!DOCTYPE html><html><head>
<title>Panasonic Digital Platform - MFA Standard</title>
<script src="/js/guardian-js/1.3.2/guardian-js.min.js"></script>
<script>{config}</script>
<script src="/mfa/loader.js"></script>
</head><body><div id="container"></div></body></html>"""


LOADER_JS = """(function(){var c=window.mfaConfig||{};
fetch("/mfa/api/info").then(function(){});
var g=auth0GuardianJS({serviceUrl:c.mfaServerUrl,requestToken:c.requestToken});
var s={state:"pending"};})();"""


def start_flow_body(types, phone=None, enrollment_tx=None):
    account = {"id": "dev_1", "methods": types, "available_authenticator_types": types}
    if phone:
        account["phone_number"] = phone
    body = {
        "transaction_token": TX_TOKEN,
        "device_account": account,
        "available_enrollment_methods": ["otp", "sms"],
        "available_authentication_methods": types,
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


def mock_page(m, page=None, loader=LOADER_JS):
    m.get(MF_URL, status=200, body=page or guardian_page(), content_type="text/html")
    if loader is not None:
        m.get(LOADER_URL, status=200, body=loader, content_type="application/javascript")


def mock_post_back(m, seen: dict):
    def post_cb(url, **kwargs):
        seen["data"] = kwargs.get("data")
        return CallbackResult(status=302, headers={"Location": f"/authorize/resume?state={STATE}"})

    m.post(MF_URL, callback=post_cb)
    m.get(
        URL_RESUME,
        status=302,
        headers={"Location": f"{REDIRECT_URI}?code={AUTH_CODE}&state={STATE}"},
    )


async def login_to_mfa(client, mocked, page=None, loader=LOADER_JS):
    mock_password_flow(mocked, mfa=True)
    mock_page(mocked, page, loader)
    client._authenticator.guardian_poll_interval = 0
    with pytest.raises(AuthenticationError) as exc:
        await client.login()
    assert exc.value.error_code == AuthenticationErrorCodes.MFA_REQUIRED


def assert_no_secrets(text: str):
    for secret in SECRETS + GUARDIAN_SECRETS + ["123456", "4567"]:
        assert secret not in text, secret


async def test_totp_success(client, mocked, caplog):
    caplog.set_level(logging.DEBUG)
    await login_to_mfa(client, mocked)
    description = client.mfa_description
    print(description)
    assert "request_token(inline)" in description
    assert "service_url(inline)" in description and "post_action(inline)" in description
    assert "expired=no" in description
    assert "/mfa/api/info" in description  # path literal from loader.js
    assert_no_secrets(description)

    rec = Recorder()
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["otp"])))
    mocked.post(VERIFY_OTP, callback=rec.cb(status=204))
    mocked.post(TX_STATE, callback=rec.cb({"id": "tx", "state": "accepted", "token": SIGNATURE}))
    seen: dict = {}
    mock_post_back(mocked, seen)

    challenge = await client.start_mfa()
    assert challenge.factor == "otp" and not challenge.code_sent
    await client.complete_mfa("123 456")

    assert client.is_logged
    assert client._settings.refresh_token == token_body()["refresh_token"]
    start, verify, state = rec.calls
    assert start[1]["Authorization"] == f"Bearer {REQUEST_TOKEN}"
    assert start[1]["x-global-tracking-id"] == TRACKING_ID
    assert start[2] == {"state_transport": "polling"}
    assert verify[1]["Authorization"] == f"Bearer {TX_TOKEN}"
    assert verify[2] == {"type": "manual_input", "code": "123456"}
    assert state[1]["Authorization"] == f"Bearer {TX_TOKEN}"
    assert seen["data"] == {"signature": SIGNATURE, "_csrf": MFA_CSRF}

    steps = [str(s) for s in client.mfa_steps]
    joined = "\n".join(steps)
    print(joined)
    assert "start-flow: status=200" in joined and "factor=otp" in joined
    assert "state=accepted" in joined and "token-exchange" in joined
    assert_no_secrets(joined)
    assert_no_secrets("\n".join(r.getMessage() for r in caplog.records))


async def test_sms_send_then_verify(client, mocked):
    await login_to_mfa(client, mocked)
    rec = Recorder()
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["sms"], phone=PHONE)))
    mocked.post(SEND_SMS, callback=rec.cb(status=204))
    mocked.post(VERIFY_OTP, callback=rec.cb({}))
    mocked.post(TX_STATE, callback=rec.cb({"state": "pending"}))
    mocked.post(TX_STATE, callback=rec.cb({"state": "accepted", "token": SIGNATURE}))
    seen: dict = {}
    mock_post_back(mocked, seen)

    challenge = await client.start_mfa()
    assert challenge.factor == "sms" and challenge.code_sent
    assert challenge.destination == "***67"
    assert [c[0].rsplit("/", 1)[1] for c in rec.calls] == ["start-flow", "send-sms"]
    await client.complete_mfa("654321")
    assert client.is_logged
    assert seen["data"]["signature"] == SIGNATURE


async def test_wrong_code_can_be_retried(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body(["otp"]))
    mocked.post(VERIFY_OTP, status=403, payload={"errorCode": "invalid_otp", "message": "x"})
    await client.start_mfa()
    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa("000000")
    assert exc.value.error_code == AuthenticationErrorCodes.MFA_REQUIRED
    assert "not accepted" in exc.value.error_message
    assert "invalid_otp" in exc.value.error_message

    with pytest.raises(AuthenticationError) as exc:
        await client.complete_mfa("12ab")
    assert "expected 6 digits" in exc.value.error_message

    mocked.post(VERIFY_OTP, status=200, payload={"signature": SIGNATURE})
    seen: dict = {}
    mock_post_back(mocked, seen)
    await client.complete_mfa("123456")
    assert client.is_logged


async def test_rejected_and_never_accepted(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body(["otp"]), repeat=True)
    mocked.post(VERIFY_OTP, status=204, repeat=True)
    mocked.post(TX_STATE, payload={"state": "rejected"})
    await client.start_mfa()
    with pytest.raises(AuthenticationError, match="rejected"):
        await client.complete_mfa("123456")
    mocked.post(TX_STATE, payload={"state": "pending"}, repeat=True)
    with pytest.raises(AuthenticationError, match="never became accepted"):
        await client.complete_mfa("123456")


async def test_totp_without_start_mfa_is_backwards_compatible(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body(["otp"]))
    mocked.post(VERIFY_OTP, status=204)
    mocked.post(TX_STATE, payload={"state": "accepted", "token": SIGNATURE})
    mock_post_back(mocked, {})
    await client.complete_mfa("123456")
    assert client.is_logged


async def test_sms_without_start_mfa_sends_code_first(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body(["sms"]))
    mocked.post(SEND_SMS, status=204)
    with pytest.raises(AuthenticationError, match="new SMS code was just sent"):
        await client.complete_mfa("123456")
    mocked.post(VERIFY_OTP, status=204)
    mocked.post(TX_STATE, payload={"state": "accepted", "token": SIGNATURE})
    mock_post_back(mocked, {})
    await client.complete_mfa("123456")
    assert client.is_logged


async def test_mfa_bypasses_and_resets_login_cooldown(client, mocked):
    await login_to_mfa(client, mocked)
    assert client._login_failure is not None
    mocked.post(START_FLOW, payload=start_flow_body(["otp"]))
    mocked.post(VERIFY_OTP, status=204)
    mocked.post(TX_STATE, payload={"state": "accepted", "token": SIGNATURE})
    mock_post_back(mocked, {})
    await client.complete_mfa("123456")
    assert client._login_failure is None
    assert client._login_failures == 0 and client._login_retry_at == 0


async def test_config_from_loader_js(client, mocked):
    page = guardian_page("var x = 1;")
    loader = (
        "window.__mfa = JSON.parse('"
        + json.dumps({"requestToken": REQUEST_TOKEN, "mfaServerUrl": SERVICE})
        + "'); var s = {state: \"pending\", postActionURL: \"/mf\"};"
    )
    await login_to_mfa(client, mocked, page, loader)
    assert "request_token(loader)" in client.mfa_description
    assert "state(" not in client.mfa_description
    rec = Recorder()
    mocked.post(START_FLOW, callback=rec.cb(start_flow_body(["totp"])))
    mocked.post(VERIFY_OTP, status=204)
    mocked.post(TX_STATE, payload={"state": "accepted", "token": SIGNATURE})
    seen: dict = {}
    mocked.post(
        f"{BASE_PATH_AUTH}/mf",
        callback=lambda url, **kw: (
            seen.update(data=kw.get("data"))
            or CallbackResult(
                status=302, headers={"Location": f"{REDIRECT_URI}?code={AUTH_CODE}"}
            )
        ),
    )
    assert (await client.start_mfa()).factor == "otp"
    await client.complete_mfa("123456")
    assert seen["data"] == {"signature": SIGNATURE}
    assert rec.calls[0][1]["Authorization"] == f"Bearer {REQUEST_TOKEN}"


async def test_missing_config_gives_clear_error(client, mocked):
    await login_to_mfa(client, mocked, guardian_page("var nothing = true;"), loader=None)
    assert "found=[]" in client.mfa_description
    with pytest.raises(AuthenticationError) as exc:
        await client.start_mfa()
    assert "guardian config without request token" in exc.value.error_message
    with pytest.raises(AuthenticationError, match="without request token"):
        await client.complete_mfa("123456")


REAL_SHAPE = {
    "available_authentication_methods": [{"name": "otp"}, "sms"],
    "available_enrollment_methods": [{"type": "otp"}, "sms"],
    "device_account": {
        "available_authenticator_types": ["otp"],
        "available_methods": ["otp"],
        "methods": ["otp"],
        "push_notifications": {"enabled": False},
        "status": "confirmed",
    },
    "feature_switches": {"mfa_app": True, "mfa_sms": False},
    "transaction_token": TX_TOKEN,
}


def real_shape(methods, **extra):
    body = json.loads(json.dumps(REAL_SHAPE))
    body["device_account"]["methods"] = methods
    body["device_account"].update(extra)
    return body


async def test_start_flow_201_totp(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, status=201, payload=real_shape(["otp"]))
    challenge = await client.start_mfa()
    assert challenge.factor == "otp" and not challenge.code_sent
    joined = "\n".join(str(s) for s in client.mfa_steps)
    assert "start-flow: status=201" in joined
    assert "device_account.methods=['otp']" in joined
    assert "device_account.status=confirmed" in joined
    assert "feature_switches={'mfa_app': True, 'mfa_sms': False}" in joined
    assert "available_authentication_methods=['otp', 'sms']" in joined
    assert "available_enrollment_methods=['otp', 'sms']" in joined


async def test_start_flow_201_sms_masks_phone(client, mocked):
    await login_to_mfa(client, mocked)
    rec = Recorder()
    mocked.post(
        START_FLOW,
        callback=rec.cb(real_shape(["sms"], phone_number=PHONE, status="<Weird Value>"), 201),
    )
    mocked.post(SEND_SMS, callback=rec.cb(status=202))
    challenge = await client.start_mfa()
    assert challenge.factor == "sms" and challenge.code_sent
    assert challenge.destination == "***67"
    assert [c[0].rsplit("/", 1)[1] for c in rec.calls] == ["start-flow", "send-sms"]
    joined = "\n".join(str(s) for s in client.mfa_steps)
    assert "device_account.status=<other>" in joined
    enums = next(str(x) for x in client.mfa_steps if x.name == "enums")
    assert "Weird" not in joined and PHONE not in joined and "phone" not in enums
    assert_no_secrets(joined)


def test_factor_detection_fallbacks():
    assert normalize_factor({"type": "TOTP"}) == "otp"
    assert normalize_factor({"nothing": 1}) is None
    assert normalize_factor("voice") == "voice"
    data = {
        "available_authentication_methods": "otp",
        "feature_switches": {"mfa_app": True, "x": "str", "BAD KEY": True},
    }
    out = enum_summary(data, {"available_methods": [{"name": "UPPER"}, 5, True]})
    assert "available_methods=['<other>', '<other>', True]" in out
    assert "available_authentication_methods=['otp']" in out
    assert "feature_switches={'mfa_app': True}" in out
    assert enum_summary({}, {}) == ""


async def test_available_methods_fallback_and_voice_unsupported(client, mocked):
    await login_to_mfa(client, mocked)
    body = real_shape([])
    body["device_account"]["available_methods"] = ["voice"]
    mocked.post(START_FLOW, status=201, payload=body)
    with pytest.raises(AuthenticationError, match="unsupported MFA factor: voice"):
        await client.start_mfa()


async def test_push_is_unsupported(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body(["push"]))
    with pytest.raises(AuthenticationError, match="unsupported MFA factor: push"):
        await client.start_mfa()


async def test_push_with_otp_prefers_otp(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body(["push", "otp"]))
    challenge = await client.start_mfa()
    assert challenge.factor == "otp" and challenge.available_factors == ["push", "otp"]


async def test_not_enrolled_is_unsupported(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body([], enrollment_tx="enr"))
    with pytest.raises(AuthenticationError, match="no MFA factor enrolled"):
        await client.start_mfa()


async def test_start_flow_error(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, status=401, payload={"errorCode": "invalid_token"})
    with pytest.raises(AuthenticationError, match=r"start-flow failed \(status 401\)"):
        await client.start_mfa()
    mocked.post(START_FLOW, status=200, payload={"nothing": 1})
    with pytest.raises(AuthenticationError, match="no transaction token"):
        await client.start_mfa()


async def test_foreign_post_action_refused(client, mocked):
    page = guardian_page(
        f'requestToken: "{REQUEST_TOKEN}", postActionURL: "https://evil.example.com/mf"'
    )
    await login_to_mfa(client, mocked, page, loader=None)
    mocked.post(START_FLOW, payload=start_flow_body(["otp"]))
    mocked.post(VERIFY_OTP, status=204)
    mocked.post(TX_STATE, payload={"state": "accepted", "token": SIGNATURE})
    await client.start_mfa()
    with pytest.raises(AuthenticationError, match="posts to another host"):
        await client.complete_mfa("123456")
    assert not any(url.host == "evil.example.com" for _, url in mocked.requests)


async def test_foreign_service_url_refused(client, mocked):
    page = guardian_page(
        f'requestToken: "{REQUEST_TOKEN}", mfaServerUrl: "https://evil.example.com/mfa"'
    )
    await login_to_mfa(client, mocked, page, loader=None)
    with pytest.raises(AuthenticationError, match="unexpected host"):
        await client.start_mfa()
    assert not any(url.host == "evil.example.com" for _, url in mocked.requests)


async def test_expired_request_token(client, mocked):
    page = guardian_page(f'requestToken: "{make_jwt(-10)}"')
    await login_to_mfa(client, mocked, page, loader=None)
    assert "expired=yes" in client.mfa_description
    with pytest.raises(AuthenticationError, match="expired"):
        await client.start_mfa()


async def test_post_back_without_redirect_fails(client, mocked):
    await login_to_mfa(client, mocked)
    mocked.post(START_FLOW, payload=start_flow_body(["otp"]))
    mocked.post(VERIFY_OTP, payload={"token": SIGNATURE})
    mocked.post(MF_URL, status=200, body="<html><title>Error</title></html>")
    await client.start_mfa()
    with pytest.raises(AuthenticationError, match="unexpected response"):
        await client.complete_mfa("123456")


async def test_start_mfa_without_pending_login(client):
    with pytest.raises(AuthenticationError, match="No pending MFA login"):
        await client.start_mfa()


async def test_verify_before_start(session):
    flow = GuardianFlow(session, GuardianConfig(page_url=MF_URL), user_agent="ua")
    with pytest.raises(AuthenticationError, match="call start_mfa first"):
        await flow.verify("123456")
    assert "fallback" in str(flow.steps[0])


async def test_loader_fetch_failure_is_noted(client, mocked):
    await login_to_mfa(client, mocked, guardian_page("var nothing = 1;"), loader=None)
    assert "/mfa/loader.js: failed" in client.mfa_description


def test_parse_data_attributes_atob_and_jwt_scan():
    blob = base64.b64encode(json.dumps({"postActionURL": "/mf/post"}).encode()).decode()
    html = f"""<html><body>
    <div id="mfa" data-mfa-server-url="https://pdp.guardian.eu.auth0.com"
         data-tenant="pdpauthglb-a1"></div>
    <script>var cfg = JSON.parse(atob("{blob}")); var t = "{REQUEST_TOKEN}";
    var tpl = {{ csrf: "{{{{ csrf }}}}" }};</script></body></html>"""
    config = parse_guardian_page(html, MF_URL)
    assert config.get("service_url") == "https://pdp.guardian.eu.auth0.com"
    assert config.get("post_action") == "https://authglb.digital.panasonic.com/mf/post"
    assert config.get("request_token") == REQUEST_TOKEN
    assert config.get("tenant") == "pdpauthglb-a1"
    assert config.get("csrf") is None  # template placeholder ignored
    assert config.sources["request_token"] == "inline-jwt"
    assert config.sources["post_action"] == "inline-b64"


def test_helpers():
    assert mask_destination(PHONE) == "***67"
    assert mask_destination("XXXXXXXX") == "***"
    assert mask_destination(EMAIL) == "***@***.com"
    assert mask_destination(None) is None
    assert normalize_factor("totp") == "otp"
    assert normalize_factor("guardian") == "push"
    assert normalize_factor("email") == "email"
    assert normalize_factor("recovery-code") is None
    assert normalize_factor("webauthn") == "unknown"
    assert normalize_factor(3) is None
    assert host_allowed("https://pdp.guardian.eu.auth0.com/", MF_URL)
    assert host_allowed("https://other.digital.panasonic.com/x", MF_URL)
    assert not host_allowed("http://authglb.digital.panasonic.com/x", MF_URL)
    assert not host_allowed("https://guardian.auth0.com.evil.com/", MF_URL)
    assert jwt_expired("not-a-jwt") is None
    assert jwt_expired(make_jwt(-5)) is True
    assert jwt_expired(f"a.{b64({'sub': 1})}.c") is None



@pytest.mark.parametrize(
    "url",
    [
        "https://panasonic.guardian.eu.auth0.com/",
        "https://panasonic.guardian.auth0.com/api/start-flow",
        "https://authglb.digital.panasonic.com/appliance-mfa",
        "https://x.panasonic.com",
    ],
)
def test_service_host_allowed(url):
    assert host_allowed(url, MF_URL)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.com/",
        "https://auth0.com.evil.com/",
        "https://guardian.auth0.com.evil/",
        "https://panasonic.guardian.eu.auth0.com.evil.com/",
        "http://panasonic.guardian.eu.auth0.com/",
        "https://evilpanasonic.com/",
        "https://guardian.auth0.com/",
    ],
)
def test_service_host_rejected(url):
    assert not host_allowed(url, MF_URL)


async def test_rejected_host_named_in_error(client, mocked):
    page = guardian_page(
        f'requestToken: "{REQUEST_TOKEN}", mfaServerUrl: "https://evil.example.com/mfa"'
    )
    await login_to_mfa(client, mocked, page, loader=None)
    with pytest.raises(AuthenticationError, match=r"unexpected host \(evil.example.com, service_url_form=absolute\)"):
        await client.start_mfa()


def _summary(extra, mechanism):
    config = GuardianConfig(page_url=MF_URL)
    config.merge_text(
        f'serviceUrl: "https://panasonic.guardian.eu.auth0.com/x/y?q=SECRET", '
        f'postActionURL: "/mf?state=SECRET", stateCheckingMechanism: "{mechanism}"{extra}',
        "inline",
    )
    return config_summary(config), config


def test_summary_service_host_and_post_path():
    text, _ = _summary("", "polling")
    assert "service_host=https://panasonic.guardian.eu.auth0.com post_action_path=/mf" in text
    assert "state_checking_mechanism=polling" in text
    assert "SECRET" not in text
    assert "websocket" not in text


def test_summary_mechanism_other_and_websocket():
    text, _ = _summary("", "manual")
    assert "state_checking_mechanism=other" in text
    assert "manual" not in text
    text, config = _summary("", "websocket")
    assert "state_checking_mechanism=websocket" in text
    assert "uses polling transport" in text
    flow = GuardianFlow(None, config, user_agent="ua")
    assert any("websocket" in step.note for step in flow.steps)


@pytest.mark.parametrize(
    ("raw", "form"),
    [
        (r"https:\/\/authglb.digital.panasonic.com\/appliance-mfa", "escaped"),
        (r"https:\u002F\u002Fauthglb.digital.panasonic.com\u002Fappliance-mfa", "escaped"),
        (r"https:\x2F\x2Fauthglb.digital.panasonic.com\x2Fappliance-mfa", "escaped"),
        ("https:&#x2F;&#x2F;authglb.digital.panasonic.com&#x2F;appliance-mfa", "escaped"),
        ("https://authglb.digital.panasonic.com/appliance-mfa?a=1&amp;b=2", "escaped"),
        ("/appliance-mfa", "relative"),
        ("//authglb.digital.panasonic.com/appliance-mfa", "protocol-relative"),
        ("https://authglb.digital.panasonic.com/appliance-mfa", "absolute"),
    ],
)
def test_service_url_forms_normalized(raw, form):
    config = GuardianConfig(page_url=MF_URL)
    config.merge_text(f'serviceUrl: "{raw}"', "inline")
    url = config.get("service_url")
    assert url is not None
    assert url.startswith("https://authglb.digital.panasonic.com/appliance-mfa")
    assert config.url_forms["service_url"] == form
    assert host_allowed(url, MF_URL)
    assert f"service_url_form={form}" in config_summary(config)


def test_attribute_url_normalized():
    config = parse_guardian_page(
        '<div data-service-url="/appliance-mfa" data-post-action="/mf?x=1"></div>', MF_URL
    )
    assert config.get("service_url") == "https://authglb.digital.panasonic.com/appliance-mfa"
    assert config.url_forms["service_url"] == "relative"


def test_empty_form_and_error_diagnostics():
    assert normalize_url("  ", MF_URL) == ("", "empty")
    config = GuardianConfig(page_url=MF_URL)
    flow = GuardianFlow(None, config, user_agent="ua")
    flow.service_url = "not a url"
    assert not host_allowed(flow.service_url, MF_URL)


def test_panasonic_auth0_private_cloud_host():
    assert host_allowed("https://pdpauthglb-a1.panasonic.auth0.com", MF_URL)
    for bad in (
        "https://panasonic.auth0.com.evil.com",
        "https://a.b.panasonic.auth0.com",
        "https://evil-panasonic.auth0.com",
        "http://pdpauthglb-a1.panasonic.auth0.com",
    ):
        assert not host_allowed(bad, MF_URL)
