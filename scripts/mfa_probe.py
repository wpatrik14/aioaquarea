#!/usr/bin/env python3
"""Experimental probe for Panasonic MFA logins (aioaquarea-ng).

Run it locally. It asks for your Panasonic ID and password (never as command
line arguments), logs in, and if Panasonic asks for MFA it prints a sanitized
description of the MFA page and optionally tries to submit the code you type.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys

import aiohttp

from aioaquarea import AquareaEnvironment, Client
from aioaquarea.errors import AuthenticationError, AuthenticationErrorCodes

WARNING = """\
This is an experimental probe. It runs on your computer and sends your
credentials only to Panasonic (authglb.digital.panasonic.com and the Aquarea
API). The output is designed to be safe to paste into the GitHub issue: it
contains page structure only, no passwords, cookies, tokens, state values,
e-mail addresses or input values. Please look it over before pasting anyway.
"""


def setup_logging() -> None:
    # Only the MFA structure logger is enabled at DEBUG. The rest of the
    # library's debug output includes tokens and page contents, so it stays off.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
    root = logging.getLogger("aioaquarea")
    root.setLevel(logging.WARNING)
    root.addHandler(handler)
    logging.getLogger("aioaquarea.mfa").setLevel(logging.DEBUG)


async def run() -> int:
    print(WARNING)
    username = input("Panasonic ID (e-mail): ").strip()
    password = getpass.getpass("Password: ")
    async with aiohttp.ClientSession() as session:
        client = Client(
            username=username,
            password=password,
            session=session,
            environment=AquareaEnvironment.PRODUCTION,
        )
        try:
            await client.login()
        except AuthenticationError as err:
            if err.error_code != AuthenticationErrorCodes.MFA_REQUIRED:
                print(f"Login failed: {err.error_code}")
                return 1
            print("\nLogin stopped at the MFA step.")
            print("---- sanitized MFA page structure (safe to paste) ----")
            print(client.mfa_description or "(could not be fetched)")
            print("---- end ----\n")
        else:
            print("Login succeeded without MFA.")
            return 0

        code = input(
            "Enter the MFA code Panasonic sent you (or leave empty to stop): "
        ).strip()
        if not code:
            return 0
        try:
            await client.complete_mfa(code)
        except AuthenticationError as err:
            print(f"MFA completion failed: {err.error_code} - {err.error_message}")
            return 1
        devices = await client.get_devices()
        print(f"MFA login succeeded. Devices found: {len(devices)}")
        return 0


def main() -> None:
    argparse.ArgumentParser(
        description="Probe Panasonic MFA login. Credentials are prompted for, "
        "never passed as arguments."
    ).parse_args()
    setup_logging()
    sys.exit(asyncio.run(run()))


if __name__ == "__main__":
    main()
