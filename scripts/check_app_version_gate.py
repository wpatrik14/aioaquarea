"""Canary: does the Panasonic login gate still accept an app version we can send?

Runs the library's own version selection (``CCAppVersion.refresh``): candidates
from Google Play, the App Store and the built-in constants are probed against
``POST /auth/v2/login`` with a dummy token. The gate checks the app version
before the token, so no account, password or token is involved, and nothing is
logged in or changed.

Exit codes:
  0  a candidate version is accepted
  1  every candidate is rejected (code 4106): the library needs a new version
  2  the gate answered something unexpected: its behaviour changed
  3  the gate could not be reached (probably transient)

``--report FILE`` writes a Markdown summary for a GitHub issue when the exit
code is 1 or 2. Only versions, HTTP statuses and numeric gate codes are printed.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from aioaquarea.auth import CCAppVersion, GateOutcome, VersionProbe
from aioaquarea.errors import AppVersionRejectedError

EXIT_OK, EXIT_REJECTED, EXIT_UNEXPECTED, EXIT_UNREACHABLE = 0, 1, 2, 3


def table(probes: list[VersionProbe]) -> str:
    rows = ["| Version | Source | Gate answer | HTTP status | Gate code |", "|---|---|---|---|---|"]
    for probe in probes:
        rows.append(
            f"| `{probe.version}` | {probe.source} | {probe.outcome.value} "
            f"| {probe.status or '-'} | {probe.code or '-'} |"
        )
    return "\n".join(rows)


async def run() -> tuple[int, str, list[VersionProbe]]:
    version = CCAppVersion()
    try:
        await version.refresh()
    except AppVersionRejectedError:
        return EXIT_REJECTED, "Every candidate app version was rejected (code 4106).", version.last_probes
    last = version.last_probes[-1]
    if last.outcome is GateOutcome.ACCEPTED:
        return EXIT_OK, f"App version {last.version} ({last.source}) is accepted.", version.last_probes
    if last.outcome is GateOutcome.UNEXPECTED:
        return (
            EXIT_UNEXPECTED,
            f"The gate answered with HTTP {last.status} / code {last.code}, "
            "neither 4100 (accepted) nor 4106 (rejected).",
            version.last_probes,
        )
    return EXIT_UNREACHABLE, "The Panasonic gate could not be reached.", version.last_probes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=Path, help="write a Markdown summary here on failure")
    args = parser.parse_args()

    code, summary, probes = asyncio.run(run())
    text = f"{summary}\n\n{table(probes)}\n"
    print(text)
    if args.report and code in (EXIT_REJECTED, EXIT_UNEXPECTED):
        args.report.write_text(
            "The scheduled canary (`scripts/check_app_version_gate.py`, no credentials "
            "involved) found a problem with the app version the library announces to "
            f"Panasonic.\n\n{text}\n"
            "Users see login failures (HTTP 401, code 4106) until the library is "
            "updated. Candidates come from Google Play, the App Store and the built-in "
            "constants in `aioaquarea/const.py`; probe the gate with a dummy token to "
            "find a version it accepts.\n"
        )
    return code


if __name__ == "__main__":
    sys.exit(main())
