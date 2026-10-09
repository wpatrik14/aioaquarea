"""Panasonic's Auth0 Guardian MFA page (``guardian-js``, polling transport).

Panasonic's ``/mf`` page holds an inline configuration object with a short lived
``requestToken`` (a JWT), the Guardian service URL and the URL the result is
posted back to. ``guardian-js`` then talks to the Guardian API:

* ``POST {serviceUrl}/api/start-flow`` (``Authorization: Bearer <requestToken>``,
  body ``{"state_transport": "polling"}``) returns a ``transaction_token`` and
  the enrolled ``device_account`` (factor types, phone number).
* ``POST {serviceUrl}/api/send-sms`` (``Bearer <transactionToken>``) texts the code.
* ``POST {serviceUrl}/api/verify-otp`` with ``{"type": "manual_input", "code": ...}``
  checks an SMS/TOTP code (``api/recover-account`` checks a recovery code).
* ``POST {serviceUrl}/api/transaction-state`` returns ``{"state": "accepted",
  "token": <signature>}`` once the code was accepted.
* The signature is posted as a form (``signature=...``) to the page's
  ``postActionURL``, which redirects back into the OAuth flow.

Tokens, codes and phone numbers are never logged or put into error messages:
errors name the step and the HTTP status only.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import html
import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from .errors import AuthenticationError, AuthenticationErrorCodes
from .mfa import (
    FACTOR_OTP,
    FACTOR_PUSH,
    FACTOR_SMS,
    FACTOR_UNKNOWN,
    MfaChallenge,
    mask_destination,
    normalize_factor,
)

_LOGGER = logging.getLogger(__name__)

# Normalized config key (lower case, letters and digits only) -> role.
KEY_ALIASES: dict[str, str] = {
    "requesttoken": "request_token",
    "mfarequesttoken": "request_token",
    "ticket": "ticket",
    "mfaserverurl": "service_url",
    "serviceurl": "service_url",
    "guardianserviceurl": "service_url",
    "guardianurl": "service_url",
    "mfaserviceurl": "service_url",
    "postactionurl": "post_action",
    "postaction": "post_action",
    "posturl": "post_action",
    "postactionuri": "post_action",
    "globaltrackingid": "global_tracking_id",
    "csrf": "csrf",
    "csrftoken": "csrf",
}
URL_ROLES = frozenset({"service_url", "post_action"})

_KV_RE = re.compile(
    r"""(?P<kq>["']?)(?P<key>[A-Za-z_$][\w$-]{0,60})(?P=kq)\s*[:=]\s*"""
    r"""(?:(?P<vq>["'`])(?P<val>(?:\\.|(?!(?P=vq)).){0,8000}?)(?P=vq))""",
    re.S,
)
_JWT_RE = re.compile(r"eyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]*")
_JS_ESCAPE_RE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|(.))", re.S)
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,40}$")
_SIX_DIGITS_RE = re.compile(r"\d{6}")
_RECOVERY_CODE_RE = re.compile(r"[A-Za-z0-9]{24}")


def _unsupported(reason: str) -> AuthenticationError:
    """The MFA page/factor is something this client cannot drive."""
    return AuthenticationError(
        AuthenticationErrorCodes.MFA_REQUIRED, f"unsupported MFA: {reason}"
    )


def _step_error(step: str, status: int | None = None, data: Any = None) -> AuthenticationError:
    """Unexpected answer in an MFA step: step name and status only, no values."""
    detail = f" (status {status})" if status is not None else ""
    if isinstance(data, dict):
        code = _get(data, "errorCode", "error_code", "error")
        if isinstance(code, str) and _ERROR_CODE_RE.match(code):
            detail += f" (errorCode={code})"
    return AuthenticationError(
        AuthenticationErrorCodes.API_ERROR, f"MFA step '{step}' failed{detail}"
    )


def _expired() -> AuthenticationError:
    return AuthenticationError(
        AuthenticationErrorCodes.MFA_EXPIRED, "MFA request expired; log in again"
    )


def _invalid_code(reason: str = "MFA code not accepted") -> AuthenticationError:
    return AuthenticationError(AuthenticationErrorCodes.MFA_INVALID_CODE, reason)


def _get(data: dict, *names: str) -> Any:
    """Read a key in snake_case or camelCase."""
    for name in names:
        if name in data:
            return data[name]
    return None


def is_success(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def _js_unescape(value: str) -> str:
    def repl(m: re.Match) -> str:
        code = m.group(1) or m.group(2)
        return chr(int(code, 16)) if code else m.group(3)

    return _JS_ESCAPE_RE.sub(repl, value)


def normalize_url(raw: str, page_url: str) -> str:
    """Decode JS/HTML escapes (``\\/``, ``&amp;``) and resolve against the page."""
    value = raw.strip()
    for _ in range(2):  # allow double-encoded values
        decoded = html.unescape(_js_unescape(value)).strip()
        if decoded == value:
            break
        value = decoded
    return urllib.parse.urljoin(page_url, value) if value else ""


def _jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, binascii.Error):
        return None
    return payload if isinstance(payload, dict) else None


def jwt_expired(token: str) -> bool | None:
    """True/False from the JWT's ``exp`` claim, None if it cannot be read."""
    payload = _jwt_payload(token)
    if not payload or not isinstance(payload.get("exp"), int | float):
        return None
    return payload["exp"] <= time.time()


def _plausible(role: str, value: str) -> bool:
    """Reject template placeholders and values of the wrong shape."""
    if not value or "{{" in value or value in ("null", "undefined"):
        return False
    if role == "request_token":
        return value.count(".") == 2 and " " not in value
    if role == "service_url":
        return value.startswith("https://")
    if role == "post_action":
        return value.startswith(("https://", "/"))
    return True


@dataclass
class GuardianConfig:
    """Configuration of a Guardian MFA page. Values are secret: never log them."""

    page_url: str
    values: dict[str, str] = field(default_factory=dict)  # role -> value

    def get(self, role: str) -> str | None:
        return self.values.get(role)


def parse_guardian_page(body: str, page_url: str) -> GuardianConfig:
    """Read the configuration from the inline scripts of the ``/mf`` page."""
    config = GuardianConfig(page_url=page_url)
    soup = BeautifulSoup(body or "", "html.parser")
    inline = [s.get_text() for s in soup.find_all("script") if not s.get("src")]
    for text in inline:
        for match in _KV_RE.finditer(text):
            role = KEY_ALIASES.get(re.sub(r"[^a-z0-9]", "", match.group("key").lower()))
            if role is None or role in config.values:
                continue
            raw = match.group("val")
            if role in URL_ROLES:
                value = normalize_url(raw, page_url)
            else:
                try:
                    value = json.loads(f'"{raw}"')
                except ValueError:
                    value = raw.replace("\\/", "/")
                value = html.unescape(value).strip()
            if _plausible(role, value):
                config.values[role] = value
    if "request_token" not in config.values:
        # Fallback: an unnamed JWT in the page is probably the request token.
        for text in inline:
            match = _JWT_RE.search(text)
            if match:
                config.values["request_token"] = match.group(0)
                break
    return config


def host_allowed(url: str, page_url: str) -> bool:
    """Guardian API calls carry a bearer token: only trusted hosts."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https":
        return False
    if host == urllib.parse.urlparse(page_url).hostname:
        return True
    if host.endswith(".panasonic.com"):
        return True
    return bool(
        re.fullmatch(r"[a-z0-9-]+\.guardian(\.[a-z0-9-]+)?\.auth0\.com", host)
        or re.fullmatch(r"[a-z0-9-]+\.panasonic\.auth0\.com", host)
    )


class GuardianFlow:
    """Drives the Guardian API the way guardian-js does with polling transport."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        config: GuardianConfig,
        *,
        user_agent: str,
        poll_interval: float = 2.0,
        poll_attempts: int = 10,
    ):
        self._sess = session
        self.config = config
        self._user_agent = user_agent
        self.poll_interval = poll_interval
        self._poll_attempts = poll_attempts
        self.challenge: MfaChallenge | None = None
        self._tx_token: str | None = None

        service = config.get("service_url")
        if not service:
            # Auth0 custom domains serve the Guardian API under /appliance-mfa.
            page = urllib.parse.urlparse(config.page_url)
            service = f"{page.scheme}://{page.netloc}/appliance-mfa"
        self.service_url = service.rstrip("/")

    async def _api(self, path: str, token: str, body: dict | None) -> tuple[int, Any]:
        url = f"{self.service_url}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": self._user_agent,
        }
        tracking = self.config.get("global_tracking_id")
        if tracking:
            headers["x-global-tracking-id"] = tracking
        async with self._sess.post(
            url, json=body, headers=headers, allow_redirects=False
        ) as response:
            status = response.status
            try:
                data = await response.json(content_type=None)
            except (ValueError, aiohttp.ContentTypeError):
                data = None
        _LOGGER.debug("MFA step %s: status %s", path.strip("/").removeprefix("api/"), status)
        return status, data

    async def start(self, *, send_code: bool = True) -> MfaChallenge:
        """``start-flow``, pick the factor and (for SMS) text the code."""
        if not host_allowed(self.service_url, self.config.page_url):
            raise _unsupported("Guardian service on an unexpected host")
        request_token = self.config.get("request_token")
        if not request_token:
            if self.config.get("ticket"):
                raise _unsupported("enrollment ticket instead of request token")
            raise _unsupported("guardian config without request token")
        if jwt_expired(request_token):
            raise _expired()

        status, data = await self._api(
            "api/start-flow", request_token, {"state_transport": "polling"}
        )
        if not is_success(status) or not isinstance(data, dict):
            raise _step_error("start-flow", status, data)
        tx_token = _get(data, "transaction_token", "transactionToken")
        if not isinstance(tx_token, str) or not tx_token:
            raise _step_error("start-flow", status)
        self._tx_token = tx_token

        if _get(data, "enrollment_tx_id", "enrollmentTxId"):
            raise _unsupported("the account has no MFA factor enrolled yet")

        account = _get(data, "device_account", "deviceAccount") or {}
        if not isinstance(account, dict):
            account = {}
        raw = (
            _get(account, "methods")
            or _get(account, "available_methods", "availableMethods")
            or _get(data, "available_authentication_methods", "availableAuthenticationMethods")
            or []
        )
        factors: list[str] = []
        for item in raw if isinstance(raw, list) else []:
            factor = normalize_factor(item)
            if factor and factor not in factors:
                factors.append(factor)
        # Like guardian-js take the first type, but prefer a code factor to push.
        codeable = [f for f in factors if f in (FACTOR_OTP, FACTOR_SMS)]
        factor = codeable[0] if codeable else (factors[0] if factors else FACTOR_UNKNOWN)
        if factor == FACTOR_PUSH:
            raise _unsupported("push notification (Guardian app) factor")
        if factor not in (FACTOR_OTP, FACTOR_SMS):
            raise _unsupported(f"factor {factor}")
        destination = mask_destination(_get(account, "phone_number", "phoneNumber"))
        challenge = MfaChallenge(factor, destination, tuple(factors), False)
        self.challenge = challenge
        if factor == FACTOR_SMS and send_code:
            await self.resend()
        return self.challenge

    async def resend(self) -> None:
        """Text the SMS code (again)."""
        if not self._tx_token or self.challenge is None:
            raise _expired()
        if self.challenge.factor != FACTOR_SMS:
            raise _unsupported("only SMS codes can be sent again")
        status, data = await self._api("api/send-sms", self._tx_token, None)
        if status == 401 and self._looks_expired(data):
            raise _expired()
        if not is_success(status):
            raise _step_error("send-sms", status, data)
        self.challenge = MfaChallenge(
            self.challenge.factor,
            self.challenge.destination,
            self.challenge.available_factors,
            True,
        )

    @staticmethod
    def _looks_expired(data: Any) -> bool:
        try:
            return "expir" in json.dumps(data).lower()
        except (TypeError, ValueError):
            return False

    async def verify(self, code: str) -> str:
        """Verify the code and return the signature to post back to the page."""
        if not self._tx_token:
            raise _expired()
        if jwt_expired(self._tx_token):
            raise _expired()
        code = (code or "").strip().replace(" ", "")
        if _SIX_DIGITS_RE.fullmatch(code):
            step, body = "verify-otp", {"type": "manual_input", "code": code}
        elif _RECOVERY_CODE_RE.fullmatch(code):
            step, body = "recover-account", {"recovery_code": code}
        else:
            raise _invalid_code("MFA code not accepted: expected 6 digits")
        status, data = await self._api(f"api/{step}", self._tx_token, body)
        if not is_success(status):
            if self._looks_expired(data):
                raise _expired()
            if status in (400, 401, 403, 422):
                raise _invalid_code()
            raise _step_error(step, status, data)

        signature = _get(data, "signature", "token") if isinstance(data, dict) else None
        for attempt in range(self._poll_attempts):
            if isinstance(signature, str) and signature:
                return signature
            if attempt:
                await asyncio.sleep(self.poll_interval)
            status, data = await self._api("api/transaction-state", self._tx_token, None)
            if status == 429:
                continue
            if not is_success(status) or not isinstance(data, dict):
                if status == 401 and self._looks_expired(data):
                    raise _expired()
                raise _step_error("transaction-state", status, data)
            state = data.get("state")
            if state == "rejected":
                raise _invalid_code()
            if state == "accepted":
                signature = _get(data, "token", "signature")
        if isinstance(signature, str) and signature:
            return signature
        raise _step_error("transaction-state")

    def result_form(self, signature: str) -> tuple[str, dict[str, str]]:
        """URL and fields for posting the signature back (guardian formPostHelper)."""
        action = self.config.get("post_action") or self.config.page_url
        action = urllib.parse.urljoin(self.config.page_url, action)
        page_host = urllib.parse.urlparse(self.config.page_url).netloc
        if urllib.parse.urlparse(action).netloc != page_host:
            raise _unsupported("result posts to another host")
        fields = {"signature": signature}
        if self.config.get("csrf"):
            fields["_csrf"] = self.config.get("csrf")  # type: ignore[assignment]
        return action, fields
