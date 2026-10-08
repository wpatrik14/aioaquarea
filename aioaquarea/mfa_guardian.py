"""EXPERIMENTAL support for Auth0's classic Guardian MFA page.

Panasonic's ``/mf`` page loads ``guardian-js`` and a small loader script. The
page (or the loader) holds a configuration object with a short lived
``requestToken`` (a JWT), the Guardian service URL and the URL the result is
posted back to. ``guardian-js`` then talks to the Guardian API:

* ``POST {serviceUrl}/api/start-flow`` (``Authorization: Bearer <requestToken>``,
  body ``{"state_transport": "polling"}``) returns a ``transaction_token`` and
  the enrolled ``device_account`` (factor types, masked phone number).
* ``POST {serviceUrl}/api/send-sms`` (``Bearer <transactionToken>``) sends the
  SMS code.
* ``POST {serviceUrl}/api/verify-otp`` with ``{"type": "manual_input",
  "code": "123456"}`` checks an SMS/TOTP code (``api/recover-account`` with
  ``{"recovery_code": ...}`` checks a recovery code).
* ``POST {serviceUrl}/api/transaction-state`` returns ``{"state": "accepted",
  "token": <signature>}`` once the code was accepted.
* The signature is posted as a regular form (``signature=...``) to the page's
  ``postActionURL``, which redirects back into the OAuth flow.

Nothing in here logs values: diagnostics contain step names, HTTP statuses,
JSON key names and which configuration keys were found.
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

# A child of "aioaquarea.mfa" so the probe's log filter lets it through.
_LOGGER = logging.getLogger("aioaquarea.mfa.guardian")

FACTOR_SMS = "sms"
FACTOR_OTP = "otp"
FACTOR_PUSH = "push"
FACTOR_EMAIL = "email"
FACTOR_UNKNOWN = "unknown"

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
    "state": "state",
    "tenant": "tenant",
    "allowrememberbrowser": "allow_remember_browser",
    "statecheckingmechanism": "state_checking_mechanism",
}

_KV_RE = re.compile(
    r"""(?P<kq>["']?)(?P<key>[A-Za-z_$][\w$-]{0,60})(?P=kq)\s*[:=]\s*"""
    r"""(?:(?P<vq>["'`])(?P<val>(?:\\.|(?!(?P=vq)).){0,8000}?)(?P=vq)"""
    r"""|(?P<lit>true|false)\b)""",
    re.S,
)
_JWT_RE = re.compile(r"eyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]*")
_ATOB_RE = re.compile(r"""atob\(\s*["']([A-Za-z0-9+/=_-]{16,})["']\s*\)""")
_PATH_LITERAL_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{1,80})(?:[?#][^"'`]*)?["'`]""")
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,40}$")
_LOADER_HINTS = (
    "requestToken",
    "postActionURL",
    "mfaServerUrl",
    "serviceUrl",
    "guardian",
    "auth0GuardianJS",
    "formPostHelper",
    "fetch(",
    "XMLHttpRequest",
    "start-flow",
    "verify-otp",
)


def normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _unescape(value: str) -> str:
    try:
        value = json.loads(f'"{value}"')
    except ValueError:
        value = value.replace("\\/", "/")
    return html.unescape(value)


def _decode_jwt_payload(token: str) -> dict | None:
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
    payload = _decode_jwt_payload(token)
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


# A static loader script may contain unrelated literals such as state: "pending".
LOADER_ROLES = frozenset(
    {"request_token", "service_url", "post_action", "global_tracking_id", "tenant"}
)


@dataclass
class GuardianConfig:
    """Configuration of a Guardian MFA page. Values are secret: never log them."""

    page_url: str
    values: dict[str, str] = field(default_factory=dict)  # role -> value
    sources: dict[str, str] = field(default_factory=dict)  # role -> where found
    seen_keys: set[str] = field(default_factory=set)  # all key names seen
    inline_scripts: int = 0
    loader_notes: list[str] = field(default_factory=list)

    def get(self, role: str) -> str | None:
        return self.values.get(role)

    def found(self) -> list[str]:
        """Sanitized ``role(source)`` list, no values."""
        return [f"{role}({self.sources[role]})" for role in sorted(self.values)]

    def merge_text(self, text: str, source: str, roles: frozenset[str] | None = None) -> None:
        """Extract ``key: "value"`` pairs from script/JSON text.

        ``roles`` limits which roles may be taken from this source.
        """
        for match in _KV_RE.finditer(text or ""):
            key = match.group("key")
            self.seen_keys.add(key)
            role = KEY_ALIASES.get(normalize_key(key))
            if role is None or role in self.values or (roles and role not in roles):
                continue
            if match.group("lit") is not None:
                value = match.group("lit")
            else:
                value = _unescape(match.group("val")).strip()
            # Skip template placeholders and empty values.
            if not _plausible(role, value):
                continue
            self.values[role] = value
            self.sources[role] = source
        for blob in _ATOB_RE.findall(text or ""):
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode()
            except (ValueError, binascii.Error, UnicodeDecodeError):
                continue
            self.merge_text(decoded, source + "-b64", roles)

    def merge_attributes(self, soup: BeautifulSoup) -> None:
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if not attr.startswith("data-") or not isinstance(value, str):
                    continue
                self.seen_keys.add(attr)
                role = KEY_ALIASES.get(normalize_key(attr[5:]))
                if role and role not in self.values and _plausible(role, value.strip()):
                    self.values[role] = value.strip()
                    self.sources[role] = "attr"

    def scan_jwt(self, text: str, source: str) -> None:
        """Fallback: an unnamed JWT in the page is probably the request token."""
        if "request_token" in self.values:
            return
        match = _JWT_RE.search(text or "")
        if match:
            self.values["request_token"] = match.group(0)
            self.sources["request_token"] = source + "-jwt"


def parse_guardian_page(body: str, page_url: str) -> GuardianConfig:
    """Parse inline scripts and data attributes of the ``/mf`` page."""
    config = GuardianConfig(page_url=page_url)
    soup = BeautifulSoup(body or "", "html.parser")
    inline = [s.get_text() for s in soup.find_all("script") if not s.get("src")]
    config.inline_scripts = len(inline)
    for text in inline:
        config.merge_text(text, "inline")
    config.merge_attributes(soup)
    for text in inline:
        config.scan_jwt(text, "inline")
    return config


def loader_script_urls(body: str, page_url: str) -> list[str]:
    """Same-host scripts other than the guardian-js library (e.g. /mfa/loader.js)."""
    soup = BeautifulSoup(body or "", "html.parser")
    host = urllib.parse.urlparse(page_url).netloc
    urls = []
    for script in soup.find_all("script", src=True):
        url = urllib.parse.urljoin(page_url, script["src"])
        path = urllib.parse.urlparse(url).path
        if urllib.parse.urlparse(url).netloc != host or "guardian-js" in path:
            continue
        urls.append(url)
    return urls


def describe_loader(status: int, text: str) -> str:
    """Sanitized description of a loader script: size, hints and path literals."""
    hints = [h for h in _LOADER_HINTS if h in (text or "")]
    paths = sorted(set(_PATH_LITERAL_RE.findall(text or "")))[:20]
    return f"status={status} bytes={len(text or '')} mentions={hints} paths={paths}"


def merge_loader(config: GuardianConfig, path: str, status: int, text: str) -> None:
    config.loader_notes.append(f"{path}: {describe_loader(status, text)}")
    if status == 200:
        config.merge_text(text, "loader", LOADER_ROLES)
        config.scan_jwt(text, "loader")


def config_summary(config: GuardianConfig) -> str:
    """Sanitized multi-line summary of what was found (key names only)."""
    interesting = sorted(k for k in config.seen_keys if len(k) <= 40)[:60]
    lines = [
        f"guardian config: inline_scripts={config.inline_scripts} found={config.found()}",
        f"  key names seen: {interesting}",
    ]
    token = config.get("request_token")
    if token:
        expired = jwt_expired(token)
        lines.append(
            "  request_token: jwt="
            + ("yes" if _decode_jwt_payload(token) else "no")
            + " expired="
            + ("unknown" if expired is None else ("yes" if expired else "no"))
        )
    lines.extend(f"  loader {note}" for note in config.loader_notes)
    return "\n".join(lines)


@dataclass
class MfaStep:
    """One sanitized step of the MFA flow: no values, only names and statuses."""

    name: str
    status: int | None = None
    keys: list[str] = field(default_factory=list)
    note: str = ""

    def __str__(self) -> str:
        text = self.name
        if self.status is not None:
            text += f": status={self.status}"
        if self.keys:
            text += f" keys={self.keys}"
        if self.note:
            text += f" ({self.note})"
        return text


@dataclass
class MfaChallenge:
    """What the user has to do to finish the login."""

    factor: str  # "sms", "otp", "push", "email" or "unknown"
    destination: str | None = None  # masked, e.g. "***67"; never the raw value
    available_factors: list[str] = field(default_factory=list)
    code_sent: bool = False


def mask_destination(value: Any) -> str | None:
    """Mask a phone number/e-mail so that at most two trailing digits remain."""
    if not isinstance(value, str) or not value:
        return None
    if "@" in value:
        domain = value.rsplit("@", 1)[1]
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        return "***@***" + (f".{tld}" if tld.isalpha() and len(tld) <= 6 else "")
    digits = [c for c in value if c.isdigit()]
    return "***" + "".join(digits[-2:]) if digits else "***"


def json_keys(data: Any) -> list[str]:
    """Top-level keys, plus one level of nested keys as ``parent.child``."""
    if not isinstance(data, dict):
        return []
    keys = []
    for key, value in data.items():
        keys.append(str(key))
        if isinstance(value, dict):
            keys.extend(f"{key}.{child}" for child in value)
    return sorted(keys)


def normalize_factor(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    name = name.lower()
    if name in ("otp", "totp", "guardian-otp", "google-authenticator"):
        return FACTOR_OTP
    if name in ("sms", "phone", "voice"):
        return FACTOR_SMS
    if name in ("push", "guardian", "push-notification"):
        return FACTOR_PUSH
    if name == "email":
        return FACTOR_EMAIL
    if name in ("recovery-code", "recovery_code"):
        return None
    return FACTOR_UNKNOWN


def _get(data: dict, *names: str) -> Any:
    """Read a key in snake_case or camelCase."""
    for name in names:
        if name in data:
            return data[name]
    return None


def _mfa_error(message: str) -> AuthenticationError:
    return AuthenticationError(AuthenticationErrorCodes.MFA_REQUIRED, message)


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
    return bool(re.fullmatch(r"[a-z0-9-]+\.guardian(\.[a-z0-9-]+)?\.auth0\.com", host))


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
        self._poll_interval = poll_interval
        self._poll_attempts = poll_attempts
        self.steps: list[MfaStep] = []
        self.challenge: MfaChallenge | None = None
        self._tx_token: str | None = None

        page = urllib.parse.urlparse(config.page_url)
        service = config.get("service_url")
        if not service:
            # Auth0 custom domains serve the Guardian API under /appliance-mfa.
            service = f"{page.scheme}://{page.netloc}/appliance-mfa"
            self.steps.append(MfaStep("config", note="service_url=fallback /appliance-mfa"))
        self.service_url = service.rstrip("/")

    def _step(self, name, status=None, keys=None, note="") -> None:
        step = MfaStep(name, status, keys or [], note)
        self.steps.append(step)
        _LOGGER.debug("guardian step %s", step)

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
        self._step(path.strip("/").removeprefix("api/"), status, json_keys(data))
        return status, data

    @staticmethod
    def _error_detail(data: Any) -> str:
        if isinstance(data, dict):
            code = _get(data, "errorCode", "error_code", "error")
            if isinstance(code, str) and _ERROR_CODE_RE.match(code):
                return f" (errorCode={code})"
        return ""

    async def start(self) -> MfaChallenge:
        """``start-flow``, pick the factor and send the SMS if it is an SMS factor."""
        if not host_allowed(self.service_url, self.config.page_url):
            raise _mfa_error("unsupported MFA page: Guardian service on an unexpected host")
        request_token = self.config.get("request_token")
        if not request_token:
            if self.config.get("ticket"):
                raise _mfa_error("unsupported MFA page: enrollment ticket instead of request token")
            raise _mfa_error("unsupported MFA page: guardian config without request token")
        if jwt_expired(request_token):
            raise _mfa_error("MFA request expired; log in again")

        status, data = await self._api(
            "api/start-flow", request_token, {"state_transport": "polling"}
        )
        if status != 200 or not isinstance(data, dict):
            raise _mfa_error(
                f"MFA start-flow failed (status {status}){self._error_detail(data)}"
            )
        tx_token = _get(data, "transaction_token", "transactionToken")
        if not isinstance(tx_token, str) or not tx_token:
            raise _mfa_error("MFA start-flow returned no transaction token")
        self._tx_token = tx_token

        if _get(data, "enrollment_tx_id", "enrollmentTxId"):
            raise _mfa_error("unsupported MFA: the account has no MFA factor enrolled yet")

        account = _get(data, "device_account", "deviceAccount") or {}
        if not isinstance(account, dict):
            account = {}
        raw = (
            _get(account, "available_authenticator_types", "availableAuthenticatorTypes")
            or _get(account, "methods")
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
        destination = mask_destination(_get(account, "phone_number", "phoneNumber"))
        self.challenge = MfaChallenge(factor, destination, factors)
        self._step("factor", note=f"factor={factor} available={factors}")

        if factor == FACTOR_SMS:
            status, data = await self._api("api/send-sms", tx_token, None)
            if status not in (200, 201, 202, 204):
                raise _mfa_error(
                    f"MFA send-sms failed (status {status}){self._error_detail(data)}"
                )
            self.challenge.code_sent = True
        elif factor == FACTOR_PUSH:
            raise _mfa_error("unsupported MFA factor: push notification (Guardian app)")
        elif factor not in (FACTOR_OTP, FACTOR_SMS):
            raise _mfa_error(f"unsupported MFA factor: {factor}")
        return self.challenge

    async def verify(self, code: str) -> str:
        """Verify the code and return the signature to post back to the page."""
        if not self._tx_token:
            raise _mfa_error("No pending MFA login; call start_mfa first")
        code = (code or "").strip().replace(" ", "")
        if re.fullmatch(r"\d{6}", code):
            path, body = "api/verify-otp", {"type": "manual_input", "code": code}
        elif re.fullmatch(r"[A-Za-z0-9]{24}", code):
            path, body = "api/recover-account", {"recovery_code": code}
        else:
            raise _mfa_error(
                "MFA code not accepted: expected 6 digits (or a 24 character recovery code)"
            )
        status, data = await self._api(path, self._tx_token, body)
        if status == 401 and isinstance(data, dict) and "expired" in json.dumps(data).lower():
            raise _mfa_error("MFA request expired; log in again")
        if status >= 400:
            raise _mfa_error(
                f"MFA code not accepted (status {status}){self._error_detail(data)}"
            )
        signature = None
        if isinstance(data, dict):
            signature = _get(data, "signature", "token")
        for attempt in range(self._poll_attempts):
            if isinstance(signature, str) and signature:
                return signature
            if attempt:
                await asyncio.sleep(self._poll_interval)
            status, data = await self._api("api/transaction-state", self._tx_token, None)
            if status == 429:
                continue
            if status != 200 or not isinstance(data, dict):
                raise _mfa_error(
                    f"MFA transaction-state failed (status {status}){self._error_detail(data)}"
                )
            state = data.get("state")
            self.steps[-1].note = f"state={state if isinstance(state, str) else '?'}"
            if state == "rejected":
                raise _mfa_error("MFA code not accepted: transaction rejected")
            if state == "accepted":
                signature = _get(data, "token", "signature")
        if isinstance(signature, str) and signature:
            return signature
        raise _mfa_error("MFA code not accepted: transaction never became accepted")

    def result_form(self, signature: str) -> tuple[str, dict[str, str]]:
        """URL and fields for posting the signature back (guardian formPostHelper)."""
        action = self.config.get("post_action") or self.config.page_url
        action = urllib.parse.urljoin(self.config.page_url, action)
        page_host = urllib.parse.urlparse(self.config.page_url).netloc
        if urllib.parse.urlparse(action).netloc != page_host:
            raise _mfa_error("unsupported MFA page: result posts to another host")
        fields = {"signature": signature}
        if self.config.get("csrf"):
            fields["_csrf"] = self.config.get("csrf")
        if self.config.get("state") and "state=" not in action:
            fields["state"] = self.config.get("state")
        if self.config.get("allow_remember_browser") == "true":
            fields["rememberBrowser"] = "false"
        self._step(
            "post-result",
            note=f"fields={sorted(fields)} post_action="
            + ("config" if self.config.get("post_action") else "page"),
        )
        return action, fields
