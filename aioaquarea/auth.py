import base64
import datetime as dt
import hashlib
import json
import logging
import re
import secrets
import string
import time
import urllib.parse
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import aiohttp
from bs4 import BeautifulSoup

from .const import (
    APP_CLIENT_ID,
    APP_STORE_LOOKUP_URL,
    APP_VERSION_PROBE_TIMEOUT,
    AUTH_0_CLIENT,
    AUTH_API_USER_AGENT,
    AUTH_BROWSER_USER_AGENT,
    BASE_PATH_ACC,
    BASE_PATH_AUTH,
    DEFAULT_X_APP_VERSION,
    FALLBACK_X_APP_VERSIONS,
    GATE_CODE_VERSION_ACCEPTED,
    GATE_CODE_VERSION_REJECTED,
    GOOGLE_PLAY_APP_URL,
    REDIRECT_URI,
    AquareaEnvironment,
)
from .errors import (
    AppVersionRejectedError,
    AuthenticationError,
    AuthenticationErrorCodes,
    MfaRequiredError,
)
from .mfa import MfaChallenge
from .mfa_guardian import GuardianFlow, parse_guardian_page

_LOGGER = logging.getLogger(__name__)

MAX_REDIRECTS = 5


class PanasonicSettings:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.expires_at = None
        self.scope = None
        self.clientId = None
        self.username = None
        self.password = None

    def set_token(self, access_token, refresh_token, expires_at, scope):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.scope = scope


class GateOutcome(StrEnum):
    """What the login gate said about one ``x-app-version``."""

    ACCEPTED = "accepted"  # gate answered "token expires" (4100): version is fine
    REJECTED = "rejected"  # gate answered "new version published" (4106)
    UNEXPECTED = "unexpected"  # an answer, but neither of the two known ones
    UNREACHABLE = "unreachable"  # no answer (network error, timeout)


@dataclass(frozen=True)
class VersionProbe:
    """The result of probing the gate with one candidate version."""

    version: str
    source: str  # google_play / app_store / last_known_good / built_in
    outcome: GateOutcome
    status: int | None = None
    code: str | None = None


_VERSION_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){2}")
_SAFE_CODE_RE = re.compile(r"[A-Za-z0-9_-]{1,40}")


def _is_version(value: object) -> bool:
    return isinstance(value, str) and _VERSION_RE.fullmatch(value) is not None


def _gate_code(body: object) -> str | None:
    code = body.get("code") if isinstance(body, dict) else None
    if isinstance(code, bool) or not isinstance(code, (str, int)):
        return None
    return str(code) if _SAFE_CODE_RE.fullmatch(str(code)) else None


async def probe_gate(session: aiohttp.ClientSession, version: str, source: str) -> VersionProbe:
    """Ask the login gate whether it accepts ``version``; needs no credentials.

    The gate checks ``x-app-version`` before the token, so a dummy token is
    enough: an accepted version is answered with 401 / code 4100 ("token
    expires"), a rejected one with 401 / code 4106. Nothing is logged in and
    nothing is changed on the server.
    """
    settings = PanasonicSettings()
    settings.access_token = "aioaquarea-gate-probe"  # not a credential
    headers = await PanasonicRequestHeader.get(
        settings, None, include_client_id=False, version=version
    )
    try:
        async with session.post(
            f"{BASE_PATH_ACC}/auth/v2/login", headers=headers, json={"language": 0}
        ) as response:
            status = response.status
            try:
                code = _gate_code(await response.json(content_type=None))
            except (aiohttp.ClientError, ValueError):
                code = None
    except (aiohttp.ClientError, TimeoutError, OSError) as err:
        _LOGGER.warning("App version gate probe for %s failed (%s)", version, type(err).__name__)
        return VersionProbe(version, source, GateOutcome.UNREACHABLE)
    outcome = GateOutcome.UNEXPECTED
    if status == 401 and code == str(GATE_CODE_VERSION_ACCEPTED):
        outcome = GateOutcome.ACCEPTED
    elif status == 401 and code == str(GATE_CODE_VERSION_REJECTED):
        outcome = GateOutcome.REJECTED
    return VersionProbe(version, source, outcome, status, code)


class CCAppVersion:
    """The ``x-app-version`` header value, kept working on its own.

    Panasonic rejects app versions it considers outdated (or unknown) with
    401 / code 4106 on ``/auth/v2/login``, and the version in the app stores is
    not always the one it accepts. So the version is never trusted blindly:
    ``refresh`` builds a candidate list (Google Play, App Store, the last
    version that worked, built-in constants), probes the gate with a dummy token
    and adopts the first candidate the gate accepts. The accepted version is
    cached for the lifetime of the process.
    """

    # The last version the gate accepted, shared by all clients of the process.
    _process_good: ClassVar[str | None] = None

    def __init__(self):
        self.version = CCAppVersion._process_good or DEFAULT_X_APP_VERSION
        # True once the gate accepted ``version`` (it is not just the default).
        self._verified = CCAppVersion._process_good is not None
        # Every probe of the latest ``refresh``, for diagnostics and the canary.
        self.last_probes: list[VersionProbe] = []

    async def init(self):
        """Pick a version the gate accepts, unless one is already verified.

        Raises ``AppVersionRejectedError`` when the gate rejects every
        candidate, before any credentials are sent anywhere.
        """
        if not self._verified:
            await self.refresh()

    async def refresh(self):
        """Probe the gate and adopt the first candidate version it accepts.

        One probe sequence per call, with short timeouts. The current version is
        only replaced by a version the gate accepted. If the gate cannot be
        asked (unreachable, or an unknown answer) the current version is kept.
        Raises ``AppVersionRejectedError`` when every candidate is rejected.
        """
        self.last_probes = []
        timeout = aiohttp.ClientTimeout(total=APP_VERSION_PROBE_TIMEOUT)
        async with aiohttp.ClientSession(
            timeout=timeout, cookie_jar=aiohttp.DummyCookieJar()
        ) as session:
            async for source, version in self._candidates(session):
                probe = await probe_gate(session, version, source)
                self.last_probes.append(probe)
                if probe.outcome is GateOutcome.ACCEPTED:
                    _LOGGER.debug("App version %s (%s) accepted", version, source)
                    self.version = version
                    self._verified = True
                    CCAppVersion._process_good = version
                    return
                if probe.outcome is not GateOutcome.REJECTED:
                    # The gate itself is not answering as expected: say nothing
                    # about the candidates, and do not keep hammering it.
                    _LOGGER.warning(
                        "App version gate answered %s (status %s, code %s); "
                        "keeping app version %s",
                        probe.outcome.value,
                        probe.status,
                        probe.code,
                        self.version,
                    )
                    return
                _LOGGER.info("App version %s (%s) rejected by Panasonic", version, source)
        # Every candidate was rejected: nothing that was cached is good anymore.
        self._verified = False
        CCAppVersion._process_good = None
        raise AppVersionRejectedError([probe.version for probe in self.last_probes])

    async def _candidates(
        self, session: aiohttp.ClientSession
    ) -> AsyncIterator[tuple[str, str]]:
        """Yield (source, version) in probe order, skipping duplicates.

        The app stores are only read when the candidates before them were not
        accepted, and a failing store is skipped.
        """
        seen: set[str] = set()

        def fresh(version: str | None) -> bool:
            if version is None or version in seen:
                return False
            seen.add(version)
            return True

        version = await self._google_play_version(session)
        if version is not None and fresh(version):
            yield "google_play", version
        version = await self._app_store_version(session)
        if version is not None and fresh(version):
            yield "app_store", version
        last_good = self.version if self._verified else None
        if last_good is not None and fresh(last_good):
            yield "last_known_good", last_good
        for version in (*FALLBACK_X_APP_VERSIONS, DEFAULT_X_APP_VERSION):
            if fresh(version):
                yield "built_in", version

    @staticmethod
    async def _google_play_version(session: aiohttp.ClientSession) -> str | None:
        # The API client identifies as Android, so this is the matching version.
        try:
            async with session.get(GOOGLE_PLAY_APP_URL) as response:
                if response.status != 200:
                    _LOGGER.warning("Google Play page answered %s", response.status)
                    return None
                match = re.search(r'\[\[\["(\d+\.\d+\.\d+)"\]\]', await response.text())
        except (aiohttp.ClientError, TimeoutError, OSError, ValueError) as err:
            _LOGGER.warning("Could not read the Google Play page (%s)", type(err).__name__)
            return None
        if match is None or not _is_version(match.group(1)):
            _LOGGER.warning("Could not parse the app version from the Google Play page")
            return None
        return match.group(1)

    @staticmethod
    async def _app_store_version(session: aiohttp.ClientSession) -> str | None:
        try:
            async with session.get(APP_STORE_LOOKUP_URL) as response:
                if response.status != 200:
                    _LOGGER.warning("App Store lookup answered %s", response.status)
                    return None
                data = json.loads(await response.text())
            version = data["results"][0]["version"]
        except (aiohttp.ClientError, TimeoutError, OSError, ValueError, LookupError, TypeError) as err:
            _LOGGER.warning("Could not read the App Store version (%s)", type(err).__name__)
            return None
        return version if _is_version(version) else None

    async def get(self):
        return self.version


class PanasonicRequestHeader:
    @staticmethod
    async def get(
        settings: PanasonicSettings,
        app_version: CCAppVersion | None,
        include_client_id=True,
        version: str | None = None,
    ):
        if settings.access_token is None:
            raise AuthenticationError(
                AuthenticationErrorCodes.API_ERROR,
                "Access token is missing from settings.",
            )

        # NOTE: this is the *local* time, but _get_api_key() interprets it as
        # UTC. TODO: verify against upstream pcomfortcloud before changing.
        now = dt.datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        api_key = PanasonicRequestHeader._get_api_key(timestamp, settings.access_token)
        headers = {
            "accept": "application/json; charset=utf-8",
            "content-type": "application/json",
            "user-agent": "G-RAC",
            "x-app-name": "Comfort Cloud",
            "x-app-timestamp": timestamp,
            "x-app-type": "1",
            # ``version`` pins a specific value (used to probe the gate)
            "x-app-version": version or await (app_version or CCAppVersion()).get(),
            "x-cfc-api-key": api_key,
            "x-user-authorization-v2": "Bearer " + settings.access_token,
        }
        if include_client_id and settings.clientId:
            headers["x-client-id"] = settings.clientId
        return headers

    @staticmethod
    def get_aqua_headers(
        content_type: str = "application/x-www-form-urlencoded",
        referer: str = "https://aquarea-smart.panasonic.com/",
        user_agent: str = AUTH_BROWSER_USER_AGENT,
        accept: str | None = None,
    ):
        if accept is None:
            if content_type == "application/json":
                accept = "application/json"
            else:
                accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"

        headers = {
            "Cache-Control": "max-age=0",
            "Accept": accept,
            "Accept-Encoding": "deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": user_agent,
            "content-type": content_type,
            "referer": referer,
        }
        return headers

    @staticmethod
    def _get_api_key(timestamp, token):
        try:
            date = dt.datetime.strptime(
                timestamp, "%Y-%m-%d %H:%M:%S"
            )  # Use dt for datetime
            # Local time formatted by the caller, treated as UTC here (see above).
            timestamp_ms = str(
                int(date.replace(tzinfo=dt.timezone.utc).timestamp() * 1000)
            )  # Use dt for datetime

            components = [
                "Comfort Cloud".encode("utf-8"),
                "521325fb2dd486bf4831b47644317fca".encode("utf-8"),
                timestamp_ms.encode("utf-8"),
                "Bearer ".encode("utf-8"),
                token.encode("utf-8"),
            ]

            input_buffer = b"".join(components)
            hash_obj = hashlib.sha256()
            hash_obj.update(input_buffer)
            hash_str = hash_obj.hexdigest()

            result = hash_str[:9] + "cfc" + hash_str[9:]
            return result
        except Exception:
            _LOGGER.error("Failed to generate API key")


# Helper functions from the provided code
def generate_random_string(length: int) -> str:
    return "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(length)
    )


def get_querystring_parameter_from_header_entry_url(
    response: aiohttp.ClientResponse, header_entry, querystring_parameter
):
    header_entry_value = response.headers[header_entry]
    parsed_url = urllib.parse.urlparse(header_entry_value)
    params = urllib.parse.parse_qs(parsed_url.query)
    return params.get(querystring_parameter, [None])[0]


class RefreshTokenRejected(AuthenticationError):
    """The refresh token was rejected (4xx); a full login is needed."""


def _safe_path(location: str) -> str:
    """Return only the path of a URL, never its query string."""
    return urllib.parse.urlparse(location).path


async def check_response(
    response: aiohttp.ClientResponse, step_name: str, expected_status: int
):
    """Raise if the response status is not the expected one.

    Only the step name, status, content type and a safe API error code are
    logged: response bodies can contain credentials, tokens or session data.
    """
    if response.status != expected_status:
        try:
            error_body = await response.json(content_type=None)
        except (aiohttp.ClientError, ValueError):
            error_body = None
        error_code = error_body.get("code") if isinstance(error_body, dict) else None
        if (
            not isinstance(error_code, (str, int))
            or isinstance(error_code, bool)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(error_code))
        ):
            error_code = None
        _LOGGER.error(
            "Error in %s: expected status %s, got %s (content-type: %s, api code: %s)",
            step_name,
            expected_status,
            response.status,
            response.headers.get("Content-Type", "unknown"),
            error_code or "unknown",
        )
        response.release()
        raise AuthenticationError(
            AuthenticationErrorCodes.API_ERROR,
            f"Error in {step_name}: Unexpected status code {response.status}",
        )


def raise_missing_code(location: str):
    """Raise when the login did not end with an authorization code.

    Panasonic sends accounts with multi-factor authentication to an ``/mf``
    challenge page instead. Requesting a token without a code would only fail
    with a 400, and retrying repeats a password login that Panasonic reports to
    the user by email each time. ``Authenticator`` handles supported MFA pages
    before getting here; this is the fallback for unsupported ones.
    """
    path = _safe_path(location)
    if path.lstrip("/").startswith("mf"):
        raise AuthenticationError(
            AuthenticationErrorCodes.MFA_REQUIRED,
            "The Panasonic ID requires multi-factor authentication, "
            "but this MFA page is not supported",
        )
    raise AuthenticationError(
        AuthenticationErrorCodes.API_ERROR,
        f"Login did not return an authorization code (redirected to {path})",
    )


async def has_new_version_been_published(response: aiohttp.ClientResponse) -> bool:
    if response.status == 401:
        try:
            response_json = await response.json()
            return response_json["code"] == 4106
        except (aiohttp.ContentTypeError, ValueError, KeyError, TypeError):
            return False
    return False


class Authenticator:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        settings: PanasonicSettings,
        app_version: CCAppVersion,
        environment: AquareaEnvironment,
        logger: logging.Logger,
        *,
        mfa_send_code: bool = True,
    ):
        self._sess = session
        self._settings = settings
        self._app_version = app_version
        self._environment = environment
        self._logger = logger
        self._mfa_send_code = mfa_send_code
        self.mfa_poll_interval = 2.0
        # The login state needed to finish a login that stopped at the MFA page.
        self._code_verifier: str | None = None
        self._mfa_flow: GuardianFlow | None = None

    @property
    def mfa_challenge(self) -> MfaChallenge | None:
        """The pending MFA challenge, if a login is waiting for a code."""
        flow = self._mfa_flow
        return flow.challenge if flow is not None else None

    async def authenticate(self, username: str, password: str):
        self._sess.cookie_jar.clear_domain("authglb.digital.panasonic.com")
        self._mfa_flow = None
        # generate initial state and code_challenge
        code_verifier = generate_random_string(43)
        self._code_verifier = code_verifier

        code_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode("utf-8")).digest()
            )
            .split("=".encode("utf-8"))[0]
            .decode("utf-8")
        )

        authorization_response = await self._authorize(code_challenge)
        authorization_redirect = authorization_response.headers["Location"]

        # check if the user can skip the authentication workflows - in that case,
        # the location is directly pointing to the redirect url with the "code"
        # query parameter included
        if authorization_redirect.startswith(REDIRECT_URI):
            code = get_querystring_parameter_from_header_entry_url(
                authorization_response, "Location", "code"
            )
            if code is None:
                await self._missing_code(authorization_redirect)
        else:
            code = await self._login(authorization_response, username, password)

        await self._request_new_token(code, code_verifier)
        await self._retrieve_client_acc()

    async def refresh_token(self):
        """Get a new access token using the stored refresh token.

        Raises RefreshTokenRejected on a 4xx answer (the caller should fall back
        to a full login) and AuthenticationError(API_ERROR) otherwise.
        """
        refresh_token = self._settings.refresh_token
        if not refresh_token:
            raise RefreshTokenRejected(
                AuthenticationErrorCodes.TOKEN_EXPIRED, "No refresh token available"
            )
        self._logger.debug("Refreshing token")
        # do before, so that timestamp is older rather than newer
        now = dt.datetime.now()
        unix_time_token_received = time.mktime(now.timetuple())

        response = await self._sess.post(
            f"{BASE_PATH_AUTH}/oauth/token",
            headers={
                "Auth0-Client": AUTH_0_CLIENT,
                "user-agent": AUTH_API_USER_AGENT,
            },
            json={
                # unknown (omitted) when only a stored refresh token was supplied
                **({"scope": self._settings.scope} if self._settings.scope else {}),
                "client_id": APP_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            allow_redirects=False,
        )
        if 400 <= response.status < 500:
            _LOGGER.debug("refresh_token rejected with status %s", response.status)
            response.release()
            raise RefreshTokenRejected(
                AuthenticationErrorCodes.TOKEN_EXPIRED,
                f"Refresh token rejected (status {response.status})",
            )
        await check_response(response, "refresh_token", 200)
        token_response = json.loads(await response.text())
        self._set_token(token_response, unix_time_token_received)
        await self._retrieve_client_acc()

    async def _authorize(self, challenge) -> aiohttp.ClientResponse:
        # --------------------------------------------------------------------
        # AUTHORIZE
        # --------------------------------------------------------------------
        state = generate_random_string(20)
        self._logger.debug("Requesting authorization")

        response = await self._sess.get(
            f"{BASE_PATH_AUTH}/authorize",
            headers={
                "user-agent": AUTH_API_USER_AGENT,
            },
            params={
                "scope": "openid offline_access comfortcloud.control a2w.control",
                "audience": f"https://digital.panasonic.com/{APP_CLIENT_ID}/api/v1/",
                "protocol": "oauth2",
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "auth0Client": AUTH_0_CLIENT,
                "client_id": APP_CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "state": state,
            },
            allow_redirects=False,
        )
        if await has_new_version_been_published(response):
            await self._app_version.refresh()
        await check_response(response, "authorize", 302)
        return response

    async def _login(
        self, authorization_response: aiohttp.ClientResponse, username, password
    ):
        state = get_querystring_parameter_from_header_entry_url(
            authorization_response, "Location", "state"
        )
        location = authorization_response.headers["Location"]
        self._logger.debug(
            "Following authorization redirect to %s", _safe_path(location)
        )
        response = await self._sess.get(
            f"{BASE_PATH_AUTH}/{location}", allow_redirects=False
        )
        await check_response(response, "authorize_redirect", 200)

        # get the "_csrf" cookie
        csrf_cookie = response.cookies["_csrf"]

        # -------------------------------------------------------------------
        # LOGIN
        # -------------------------------------------------------------------
        self._logger.debug("Authenticating with username and password")
        response = await self._sess.post(
            f"{BASE_PATH_AUTH}/usernamepassword/login",
            headers={
                "Auth0-Client": AUTH_0_CLIENT,
                "user-agent": AUTH_API_USER_AGENT,
            },
            json={
                "client_id": APP_CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "tenant": "pdpauthglb-a1",
                "response_type": "code",
                "scope": "openid offline_access comfortcloud.control a2w.control",
                "audience": f"https://digital.panasonic.com/{APP_CLIENT_ID}/api/v1/",
                "_csrf": csrf_cookie,
                "state": state,
                "_intstate": "deprecated",
                "username": username,
                "password": password,
                "lang": "en",
                "connection": "PanasonicID-Authentication",
            },
            allow_redirects=False,
        )
        if response.status in (400, 401, 403):
            # Auth0 answers a rejected username/password (and blocked users)
            # with 401 {"code": "invalid_user_password"} (ASSUMED: 400/403 for
            # other rejections). The body is deliberately not logged.
            self._logger.error("Login rejected by Panasonic (status %s)", response.status)
            response.release()
            raise AuthenticationError(
                AuthenticationErrorCodes.INVALID_USERNAME_OR_PASSWORD,
                f"Username or password rejected (status {response.status})",
            )
        await check_response(response, "login", 200)

        # -------------------------------------------------------------------
        # CALLBACK
        # -------------------------------------------------------------------

        # get wa, wresult, wctx from body
        response_text = await response.text()
        self._logger.debug("Received login response (%d bytes)", len(response_text))
        soup = BeautifulSoup(response_text, "html.parser")
        input_lines = soup.find_all("input", {"type": "hidden"})
        parameters = dict()
        for input_line in input_lines:
            parameters[input_line.get("name")] = input_line.get("value")

        self._logger.debug("Posting login callback (%d fields)", len(parameters))
        response = await self._sess.post(
            url=f"{BASE_PATH_AUTH}/login/callback",
            data=parameters,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": AUTH_BROWSER_USER_AGENT,
            },
            allow_redirects=False,
        )
        await check_response(response, "login_callback", 302)

        # ------------------------------------------------------------------
        # FOLLOW REDIRECT
        # ------------------------------------------------------------------

        location = response.headers["Location"]
        self._logger.debug("Callback redirect to %s", _safe_path(location))

        response = await self._sess.get(
            f"{BASE_PATH_AUTH}/{location}", allow_redirects=False
        )
        await check_response(response, "login_redirect", 302)
        location = response.headers["Location"]
        self._logger.debug("Login redirect to %s", _safe_path(location))

        code = get_querystring_parameter_from_header_entry_url(
            response, "Location", "code"
        )
        if code is None:
            await self._missing_code(location)
        return code

    async def _missing_code(self, location: str):
        """Start MFA if ``location`` is the MFA page, else raise like ``raise_missing_code``."""
        if _safe_path(location).lstrip("/").startswith("mf"):
            await self._start_mfa(urllib.parse.urljoin(BASE_PATH_AUTH + "/", location))
        raise_missing_code(location)

    async def _fetch_mfa_page(self, url: str) -> tuple[str, str]:
        """GET the MFA page following same-host redirects; return (final url, body)."""
        auth_host = urllib.parse.urlparse(BASE_PATH_AUTH).netloc
        for _ in range(MAX_REDIRECTS + 1):
            async with self._sess.get(
                url,
                headers={"User-Agent": AUTH_BROWSER_USER_AGENT},
                allow_redirects=False,
            ) as response:
                location = response.headers.get("Location")
                if response.status == 200:
                    return url, await response.text()
            if not location:
                break
            url = urllib.parse.urljoin(url, location)
            if urllib.parse.urlparse(url).netloc != auth_host:
                break  # never follow (or send cookies) to another host
        return url, ""

    async def _start_mfa(self, mfa_url: str) -> None:
        """Start the MFA challenge and raise ``MfaRequiredError`` for it.

        Raises a plain ``MFA_REQUIRED`` error when the page or factor is not
        supported (or cannot be loaded), like before MFA was supported.
        """
        try:
            page_url, body = await self._fetch_mfa_page(mfa_url)
        except (aiohttp.ClientError, TimeoutError) as err:
            raise AuthenticationError(
                AuthenticationErrorCodes.MFA_REQUIRED,
                f"The MFA page could not be loaded ({type(err).__name__})",
            ) from None
        if "guardian" not in body.lower():
            return  # not a Guardian page: caller raises the generic MFA error
        config = parse_guardian_page(body, page_url)
        flow = GuardianFlow(
            self._sess,
            config,
            user_agent=AUTH_BROWSER_USER_AGENT,
            poll_interval=self.mfa_poll_interval,
        )
        try:
            challenge = await flow.start(send_code=self._mfa_send_code)
        except (aiohttp.ClientError, TimeoutError) as err:
            raise AuthenticationError(
                AuthenticationErrorCodes.MFA_REQUIRED,
                f"The MFA service could not be reached ({type(err).__name__})",
            ) from None
        self._mfa_flow = flow
        self._logger.debug(
            "MFA required: factor %s, code sent: %s", challenge.factor, challenge.code_sent
        )
        raise MfaRequiredError(challenge)

    def _pending_flow(self) -> GuardianFlow:
        if self._mfa_flow is None or self._code_verifier is None:
            raise AuthenticationError(
                AuthenticationErrorCodes.MFA_EXPIRED,
                "No pending MFA login; log in again",
            )
        return self._mfa_flow

    async def resend_mfa_code(self) -> MfaChallenge:
        """Text the SMS code again (SMS factor only)."""
        flow = self._pending_flow()
        try:
            await flow.resend()
        except AuthenticationError as err:
            if err.error_code == AuthenticationErrorCodes.MFA_EXPIRED:
                self._mfa_flow = None
            raise
        assert flow.challenge is not None
        return flow.challenge

    async def complete_mfa(self, code: str):
        """Finish a login that raised ``MfaRequiredError`` with the MFA ``code``.

        A wrong code raises ``MFA_INVALID_CODE`` and can be retried; an expired
        MFA transaction raises ``MFA_EXPIRED`` and needs a new login.
        """
        flow = self._pending_flow()
        try:
            signature = await flow.verify(code)
            url, data = flow.result_form(signature)
            auth_code = await self._submit_mfa_result(url, data)
        except AuthenticationError as err:
            if err.error_code != AuthenticationErrorCodes.MFA_INVALID_CODE:
                self._mfa_flow = None  # the transaction cannot be reused
            raise
        code_verifier = self._code_verifier
        self._mfa_flow = None
        self._code_verifier = None
        await self._request_new_token(auth_code, code_verifier)
        await self._retrieve_client_acc()
        self._logger.debug(
            "MFA login completed (refresh token received: %s)",
            "yes" if self._settings.refresh_token else "no",
        )

    async def _submit_mfa_result(self, url: str, data: dict) -> str:
        """POST the MFA result and follow same-host redirects to the auth code."""
        auth_host = urllib.parse.urlparse(BASE_PATH_AUTH).netloc
        method = "post"
        for hop in range(MAX_REDIRECTS + 3):
            step = "mfa-submit" if hop == 0 else f"mfa-redirect-{hop}"
            if urllib.parse.urlparse(url).netloc != auth_host:
                raise AuthenticationError(
                    AuthenticationErrorCodes.API_ERROR,
                    f"MFA step '{step}' redirected to another host",
                )
            async with self._sess.request(
                method,
                url,
                data=data if method == "post" else None,
                headers={"User-Agent": AUTH_BROWSER_USER_AGENT},
                allow_redirects=False,
            ) as response:
                location = response.headers.get("Location")
                status = response.status
            if location is None:
                raise AuthenticationError(
                    AuthenticationErrorCodes.API_ERROR,
                    f"MFA step '{step}' failed (status {status})",
                )
            if location.startswith(REDIRECT_URI):
                auth_code = urllib.parse.parse_qs(
                    urllib.parse.urlparse(location).query
                ).get("code", [None])[0]
                if auth_code is None:
                    raise AuthenticationError(
                        AuthenticationErrorCodes.API_ERROR,
                        f"MFA step '{step}' returned no authorization code",
                    )
                return auth_code
            url, method, data = urllib.parse.urljoin(url, location), "get", None
        raise AuthenticationError(
            AuthenticationErrorCodes.API_ERROR, "MFA step 'mfa-redirect' too many redirects"
        )

    async def _request_new_token(self, code, code_verifier):
        self._logger.debug("Requesting a new token")
        # do before, so that timestamp is older rather than newer
        now = dt.datetime.now()
        unix_time_token_received = time.mktime(now.timetuple())

        response = await self._sess.post(
            f"{BASE_PATH_AUTH}/oauth/token",
            headers={
                "Auth0-Client": AUTH_0_CLIENT,
                "user-agent": AUTH_API_USER_AGENT,
            },
            json={
                "scope": "openid",
                "client_id": APP_CLIENT_ID,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": code_verifier,
            },
            allow_redirects=False,
        )
        await check_response(response, "get_token", 200)

        token_response = json.loads(await response.text())
        # A fresh login never inherits an older (possibly revoked) refresh token.
        self._set_token(token_response, unix_time_token_received, keep_refresh_token=False)

    def _set_token(
        self, token_response, unix_time_token_received, keep_refresh_token=True
    ):
        # A refresh response may omit the refresh token/scope (no rotation):
        # keep the stored ones then.
        self._settings.set_token(
            token_response["access_token"],
            token_response.get("refresh_token")
            or (self._settings.refresh_token if keep_refresh_token else None),
            unix_time_token_received + token_response["expires_in"],
            token_response.get("scope") or self._settings.scope,
        )

    async def _retrieve_client_acc(self):
        # ------------------------------------------------------------------
        # RETRIEVE ACC_CLIENT_ID
        # ------------------------------------------------------------------
        headers = await PanasonicRequestHeader.get(
            self._settings, self._app_version, include_client_id=False
        )

        response = await self._sess.post(
            f"{BASE_PATH_ACC}/auth/v2/login", headers=headers, json={"language": 0}
        )
        if await has_new_version_been_published(response):
            # Panasonic stopped accepting the version we announce. Probe once for
            # one it accepts (raises AppVersionRejectedError when there is none),
            # retry once, and report a second rejection as what it is.
            self._logger.info("Panasonic rejected the app version, probing for a new one")
            response.release()
            await self._app_version.refresh()
            response = await self._sess.post(
                f"{BASE_PATH_ACC}/auth/v2/login",
                headers=await PanasonicRequestHeader.get(
                    self._settings, self._app_version, include_client_id=False
                ),
                json={"language": 0},
            )
            if await has_new_version_been_published(response):
                response.release()
                raise AppVersionRejectedError([await self._app_version.get()])

        await check_response(response, "get_acc_client_id", 200)

        json_body = json.loads(await response.text())
        self._settings.clientId = json_body["clientId"]
        return
