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

import aiohttp
from bs4 import BeautifulSoup

from .const import (
    APP_CLIENT_ID,
    AUTH_0_CLIENT,
    AUTH_API_USER_AGENT,
    AUTH_BROWSER_USER_AGENT,
    BASE_PATH_ACC,
    BASE_PATH_AUTH,
    DEFAULT_X_APP_VERSION,
    REDIRECT_URI,
    AquareaEnvironment,
)
from .errors import AuthenticationError, AuthenticationErrorCodes
from .mfa import (
    MAX_REDIRECTS,
    MfaForm,
    describe_response,
    find_code_form,
    unsupported_reason,
)

_LOGGER = logging.getLogger(__name__)
_MFA_LOGGER = logging.getLogger("aioaquarea.mfa")


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


class CCAppVersion:
    def __init__(self):
        self.version = DEFAULT_X_APP_VERSION  # Default version

    async def init(self):
        # Try to fetch version on initialization
        await self.refresh()

    async def refresh(self):
        # Fetch the latest app version from App Store
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://apps.apple.com/de/app/panasonic-comfort-cloud/id1348640525"
                ) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        # Look for version pattern in the HTML
                        version_match = re.search(
                            r"Version\s+(\d+\.\d+\.\d+)", html_content
                        )
                        if version_match:
                            new_version = version_match.group(1)
                            _LOGGER.debug(f"Found new app version: {new_version}")
                            self.version = new_version
                        else:
                            _LOGGER.warning(
                                f"Could not parse version from App Store page, keeping current version: {self.version}"
                            )
                    else:
                        _LOGGER.error(
                            f"Failed to fetch App Store page: {response.status}, keeping current version: {self.version}"
                        )
        except Exception as e:
            _LOGGER.error(
                f"Error fetching app version: {e}, keeping current version: {self.version}"
            )

    async def get(self):
        return self.version


class PanasonicRequestHeader:
    @staticmethod
    async def get(
        settings: PanasonicSettings, app_version: CCAppVersion, include_client_id=True
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
            "x-app-version": await app_version.get(),
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

    Only the step name, status and content type are logged: bodies can contain
    credentials, tokens or session data.
    """
    if response.status != expected_status:
        _LOGGER.error(
            "Error in %s: expected status %s, got %s (content-type: %s)",
            step_name,
            expected_status,
            response.status,
            response.headers.get("Content-Type", "unknown"),
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
    the user by email each time.
    """
    path = _safe_path(location)
    if path.lstrip("/").startswith("mf"):
        raise AuthenticationError(
            AuthenticationErrorCodes.MFA_REQUIRED,
            "The Panasonic ID requires multi-factor authentication, which is not supported yet",
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
    ):
        self._sess = session
        self._settings = settings
        self._app_version = app_version
        self._environment = environment
        self._logger = logger
        self._code_verifier: str | None = None
        self._mfa_url: str | None = None
        # In-memory only, never logged: the MFA page captured during login, so
        # complete_mfa need not re-fetch it (a re-fetch may send a new code).
        self._mfa_form: MfaForm | None = None
        self._mfa_reason: str | None = None
        self._mfa_captured = False
        self.mfa_description: str | None = None

    async def authenticate(self, username: str, password: str):
        self._sess.cookie_jar.clear_domain("authglb.digital.panasonic.com")
        self._mfa_url = None
        self._mfa_form = None
        self._mfa_reason = None
        self._mfa_captured = False
        self.mfa_description = None
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
                "scope": self._settings.scope,
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
        """Remember the MFA page (if any), then raise like ``raise_missing_code``."""
        path = urllib.parse.urlparse(location).path
        stripped = path.lstrip("/")
        if stripped.startswith("mf") or stripped.startswith("u/mfa-"):
            self._mfa_url = urllib.parse.urljoin(BASE_PATH_AUTH + "/", location)
            try:
                self.mfa_description = await self._describe_mfa_page()
            except Exception as err:  # diagnostics must never change the error
                _MFA_LOGGER.debug("Could not describe MFA page: %s", type(err).__name__)
        raise_missing_code(location)

    async def _fetch_hops(self, url: str):
        """GET ``url`` following redirects manually; return one tuple per hop."""
        hops = []
        for _ in range(MAX_REDIRECTS + 1):
            async with self._sess.get(
                url,
                headers={"User-Agent": AUTH_BROWSER_USER_AGENT},
                allow_redirects=False,
            ) as response:
                body = await response.text() if response.status == 200 else ""
                location = response.headers.get("Location")
                hops.append(
                    (url, response.status, location, response.content_type, body)
                )
            if not location or location.startswith(REDIRECT_URI):
                break
            url = urllib.parse.urljoin(url, location)
            if (
                urllib.parse.urlparse(url).netloc
                != urllib.parse.urlparse(BASE_PATH_AUTH).netloc
            ):
                break  # never follow (or send cookies) to another host
        return hops

    def _capture_mfa_page(self, hops) -> None:
        page_url, status, _, _, body = hops[-1]
        self._mfa_form = find_code_form(body, page_url) if status == 200 else None
        self._mfa_reason = unsupported_reason(body)
        self._mfa_captured = True

    async def _describe_mfa_page(self) -> str:
        hops = await self._fetch_hops(self._mfa_url)
        self._capture_mfa_page(hops)
        parts = []
        for n, (_, status, location, ctype, body) in enumerate(hops, 1):
            text = describe_response(status, location, ctype, body)
            parts.append(f"hop {n}: " + text.replace("\n", "\n  "))
        description = "\n".join(parts)
        _MFA_LOGGER.debug("MFA page structure (sanitized):\n%s", description)
        return description

    async def complete_mfa(self, code: str):
        """EXPERIMENTAL: finish a login that stopped at Panasonic's MFA page.

        Must be called after ``authenticate`` raised ``MFA_REQUIRED``. Only
        plain HTML forms with a code-like input are supported; anything else
        (for example a Guardian widget) raises ``MFA_REQUIRED`` with a short
        sanitized reason. The behaviour may change or be removed.
        """
        if not self._mfa_url or not self._code_verifier:
            raise AuthenticationError(
                AuthenticationErrorCodes.MFA_REQUIRED,
                "No pending MFA login; call authenticate first",
            )
        if not self._mfa_captured:
            # Nothing captured during login: fetch once as a fallback.
            self._capture_mfa_page(await self._fetch_hops(self._mfa_url))
        form = self._mfa_form
        if form is None:
            raise AuthenticationError(
                AuthenticationErrorCodes.MFA_REQUIRED,
                self._mfa_reason or "unsupported MFA page",
            )
        if (
            urllib.parse.urlparse(form.action).netloc
            != urllib.parse.urlparse(BASE_PATH_AUTH).netloc
        ):
            raise AuthenticationError(
                AuthenticationErrorCodes.MFA_REQUIRED,
                "unsupported MFA page: form posts to another host",
            )

        data = dict(form.fields)
        data[form.code_field] = code
        url, method = form.action, "post"
        for _ in range(MAX_REDIRECTS + 3):
            async with self._sess.request(
                method,
                url,
                data=data if method == "post" else None,
                headers={"User-Agent": AUTH_BROWSER_USER_AGENT},
                allow_redirects=False,
            ) as response:
                location = response.headers.get("Location")
                status = response.status
                resp_body = await response.text() if status == 200 else ""
                ctype = response.content_type
            if location is None:
                _MFA_LOGGER.debug(
                    "MFA submit ended without redirect:\n%s",
                    describe_response(status, None, ctype, resp_body),
                )
                raise AuthenticationError(
                    AuthenticationErrorCodes.MFA_REQUIRED,
                    f"MFA code not accepted or unexpected response (status {status})",
                )
            if location.startswith(REDIRECT_URI):
                auth_code = urllib.parse.parse_qs(
                    urllib.parse.urlparse(location).query
                ).get("code", [None])[0]
                if auth_code is None:
                    raise AuthenticationError(
                        AuthenticationErrorCodes.MFA_REQUIRED,
                        "MFA redirect did not contain an authorization code",
                    )
                break
            url, method, data = urllib.parse.urljoin(url, location), "get", None
        else:
            raise AuthenticationError(
                AuthenticationErrorCodes.MFA_REQUIRED,
                "too many redirects after MFA code",
            )

        await self._request_new_token(auth_code, self._code_verifier)
        await self._retrieve_client_acc()
        self._mfa_url = None
        self._mfa_form = None
        self._mfa_reason = None
        self._mfa_captured = False
        self._code_verifier = None

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
        self._set_token(token_response, unix_time_token_received)

    def _set_token(self, token_response, unix_time_token_received):
        # A refresh response may omit the refresh token/scope (no rotation):
        # keep the stored ones then.
        self._settings.set_token(
            token_response["access_token"],
            token_response.get("refresh_token") or self._settings.refresh_token,
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
            self._logger.info("New version of acc client id has been published")
            await self._app_version.refresh()
            response = await self._sess.post(
                f"{BASE_PATH_ACC}/auth/v2/login",
                headers=await PanasonicRequestHeader.get(
                    self._settings, self._app_version, include_client_id=False
                ),
                json={"language": 0},
            )

        await check_response(response, "get_acc_client_id", 200)

        json_body = json.loads(await response.text())
        self._settings.clientId = json_body["clientId"]
        return
