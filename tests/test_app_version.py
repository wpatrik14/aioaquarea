"""The app version is probed against the login gate, never trusted blindly."""

from __future__ import annotations

import pytest
from aioresponses import CallbackResult

from aioaquarea import AppVersionRejectedError, AuthenticationError, AuthenticationErrorCodes
from aioaquarea.auth import CCAppVersion, GateOutcome
from aioaquarea.const import (
    APP_STORE_LOOKUP_URL,
    DEFAULT_X_APP_VERSION,
    GOOGLE_PLAY_APP_URL,
)

from .conftest import (
    ACCESS_TOKEN,
    CLIENT_ID,
    URL_ACC_LOGIN,
    mock_password_flow,
)


@pytest.fixture(autouse=True)
def no_app_store(monkeypatch):
    """Override the global stub: these tests exercise the real probing."""
    monkeypatch.setattr(CCAppVersion, "_process_good", None)


def play_page(version: str) -> str:
    return f'<script>[[["{version}"]],[[[35]],[[[29,"10"]]]]]</script>'


def mock_stores(m, *, play: str | None = None, store: str | None = None):
    """Google Play and the App Store; ``None`` makes a store fail."""
    if play is None:
        m.get(GOOGLE_PLAY_APP_URL, status=500, repeat=True)
    else:
        m.get(GOOGLE_PLAY_APP_URL, body=play_page(play), repeat=True)
    if store is None:
        m.get(APP_STORE_LOOKUP_URL, exception=OSError("down"), repeat=True)
    else:
        m.get(APP_STORE_LOOKUP_URL, payload={"results": [{"version": store}]}, repeat=True)


def mock_gate(m, accepted: set[str], *, real_accepted: set[str] | None = None) -> list[dict]:
    """The gate: 4100 for accepted versions, 4106 for the others.

    A request with the real access token is a login (answered with the client id
    when its version is in ``real_accepted``); everything else is a probe.
    """
    requests: list[dict] = []

    def cb(url, **kwargs):
        headers = kwargs["headers"]
        version = headers["x-app-version"]
        real = headers["x-user-authorization-v2"] == f"Bearer {ACCESS_TOKEN}"
        requests.append({"version": version, "real": real, "headers": headers})
        if real and version in (real_accepted if real_accepted is not None else accepted):
            return CallbackResult(status=200, payload={"clientId": CLIENT_ID})
        code = 4100 if version in accepted and not real else 4106
        return CallbackResult(status=401, payload={"code": code, "message": "x"})

    m.post(URL_ACC_LOGIN, callback=cb, repeat=True)
    return requests


def probed(requests: list[dict]) -> list[str]:
    return [r["version"] for r in requests if not r["real"]]


def requested_urls(m) -> list[str]:
    return [str(url) for _, url in m.requests]


async def test_play_version_accepted(mocked):
    mock_stores(mocked, play="5.1.0", store="9.9.9")
    gate = mock_gate(mocked, {"5.1.0"})
    version = CCAppVersion()
    await version.init()

    assert await version.get() == "5.1.0"
    assert probed(gate) == ["5.1.0"]  # one probe, the App Store was not needed
    assert not any("itunes" in u for u in requested_urls(mocked))
    assert version.last_probes[0].source == "google_play"
    assert version.last_probes[0].outcome is GateOutcome.ACCEPTED
    # cached for the process: a new object starts verified, and init() is offline
    mocked.requests.clear()
    other = CCAppVersion()
    await other.init()
    assert await other.get() == "5.1.0"
    assert not mocked.requests


async def test_probe_sends_no_credentials(mocked):
    mock_stores(mocked, play="5.1.0")
    gate = mock_gate(mocked, {"5.1.0"})
    await CCAppVersion().init()

    headers = gate[0]["headers"]
    assert headers["x-user-authorization-v2"] == "Bearer aioaquarea-gate-probe"
    assert "x-client-id" not in headers


@pytest.mark.parametrize(
    ("store", "accepted", "expected", "sequence"),
    [
        # Play and the App Store agree on a rejected version: constants win
        ("5.1.1", {"5.1.0", "4.4.0"}, "5.1.0", ["5.1.1", "5.1.0"]),
        # the App Store knows a better version than Play
        ("5.2.0", {"5.2.0"}, "5.2.0", ["5.1.1", "5.2.0"]),
        # only the oldest constant is still accepted
        ("5.1.1", {"4.4.0"}, "4.4.0", ["5.1.1", "5.1.0", "4.4.0"]),
    ],
)
async def test_rejected_play_version_falls_back(mocked, store, accepted, expected, sequence):
    mock_stores(mocked, play="5.1.1", store=store)
    gate = mock_gate(mocked, accepted)
    version = CCAppVersion()
    await version.init()

    assert await version.get() == expected
    assert probed(gate) == sequence  # no version is probed twice


async def test_rejected_version_is_never_adopted(mocked):
    mock_stores(mocked, play="5.1.1")
    mock_gate(mocked, set())
    version = CCAppVersion()
    seen = []
    with pytest.raises(AppVersionRejectedError):
        await version.refresh()
    seen.append(await version.get())
    assert seen == [DEFAULT_X_APP_VERSION]


async def test_scrape_failure_falls_through_to_constants(mocked):
    mock_stores(mocked)  # both stores fail
    gate = mock_gate(mocked, {"5.1.0", "4.4.0"})
    version = CCAppVersion()
    await version.init()

    assert await version.get() == "5.1.0"
    assert probed(gate) == ["5.1.0"]
    assert version.last_probes[0].source == "built_in"


@pytest.mark.parametrize("junk", ["not a version", "5.1.0; DROP", "5.1", ""])
async def test_garbage_store_versions_are_ignored(mocked, junk):
    mocked.get(GOOGLE_PLAY_APP_URL, body="no version in here", repeat=True)
    mocked.get(APP_STORE_LOOKUP_URL, payload={"results": [{"version": junk}]}, repeat=True)
    gate = mock_gate(mocked, {"5.1.0"})
    await CCAppVersion().init()
    assert probed(gate) == ["5.1.0"]


async def test_all_candidates_rejected_raises_clear_error(mocked):
    mock_stores(mocked, play="5.1.1", store="5.2.0")
    gate = mock_gate(mocked, set())
    version = CCAppVersion()
    with pytest.raises(AppVersionRejectedError) as exc:
        await version.init()

    assert isinstance(exc.value, AuthenticationError)  # callers of the old error still work
    assert exc.value.error_code == AuthenticationErrorCodes.APP_VERSION_REJECTED
    assert "rejected the app version" in str(exc.value)
    assert "credentials were not checked" in str(exc.value)
    assert exc.value.versions_tried == ("5.1.1", "5.2.0", "5.1.0", "4.4.0")
    assert probed(gate) == list(exc.value.versions_tried)
    assert await version.get() == DEFAULT_X_APP_VERSION  # unchanged
    assert CCAppVersion._process_good is None


async def test_rejection_does_not_reach_the_credentials(client, mocked):
    mock_stores(mocked, play="5.1.1")
    mock_gate(mocked, set())
    with pytest.raises(AppVersionRejectedError):
        await client.login()
    # nothing but the stores and the gate was contacted: no password login
    assert all("authglb" not in url for url in requested_urls(mocked))


@pytest.mark.parametrize("status", [500, 200])
async def test_unclear_gate_keeps_current_version_and_stops(mocked, status):
    mock_stores(mocked, play="5.1.0")
    mocked.post(URL_ACC_LOGIN, status=status, payload={"code": 1}, repeat=True)
    version = CCAppVersion()
    await version.init()

    assert await version.get() == DEFAULT_X_APP_VERSION
    assert len(version.last_probes) == 1  # does not hammer a gate that is unwell
    assert version.last_probes[0].outcome is GateOutcome.UNEXPECTED
    assert CCAppVersion._process_good is None
    assert not version._verified  # the next login tries again


async def test_unreachable_gate_keeps_current_version(mocked):
    mock_stores(mocked, play="5.1.0")
    mocked.post(URL_ACC_LOGIN, exception=OSError("down"), repeat=True)
    version = CCAppVersion()
    await version.init()
    assert await version.get() == DEFAULT_X_APP_VERSION
    assert version.last_probes[0].outcome is GateOutcome.UNREACHABLE


async def test_login_reprobes_once_on_4106(client, mocked):
    # 5.1.0 worked, then Panasonic moved on to 5.2.0 (what Google Play shows)
    client._app_version.version = "5.1.0"
    client._app_version._verified = True
    mock_stores(mocked, play="5.2.0")
    gate = mock_gate(mocked, {"5.2.0"})
    mock_password_flow(mocked)

    await client.login()

    assert [(r["version"], r["real"]) for r in gate] == [
        ("5.1.0", True),  # real login: rejected
        ("5.2.0", False),  # one probe
        ("5.2.0", True),  # retried once, accepted
    ]
    assert await client._app_version.get() == "5.2.0"
    assert sum("play.google.com" in u for u in requested_urls(mocked)) == 1
    assert client._settings.clientId == CLIENT_ID


async def test_login_reprobe_is_bounded(client, mocked):
    # the probe is happy with 5.1.0, but the real login keeps getting 4106
    client._app_version.version = "5.1.0"
    client._app_version._verified = True
    mock_stores(mocked, play="5.1.0")
    gate = mock_gate(mocked, {"5.1.0"}, real_accepted=set())
    mock_password_flow(mocked)

    with pytest.raises(AppVersionRejectedError):
        await client.login()

    assert [r["real"] for r in gate] == [True, False, True]  # no loop
    assert sum("play.google.com" in u for u in requested_urls(mocked)) == 1


async def test_login_reprobe_with_everything_rejected(client, mocked):
    client._app_version.version = "5.1.0"
    client._app_version._verified = True
    mock_stores(mocked, play="5.1.1")
    gate = mock_gate(mocked, set())
    mock_password_flow(mocked)

    with pytest.raises(AppVersionRejectedError):
        await client.login()

    assert [r["real"] for r in gate] == [True, False, False, False]  # 3 candidates, one sequence
