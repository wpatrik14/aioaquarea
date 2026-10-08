#!/usr/bin/env python3
"""Experimental probe for Panasonic MFA logins (aioaquarea-ng).

Run it locally. It asks for your Panasonic ID and password (never as command
line arguments), logs in, and if Panasonic asks for MFA it prints a sanitized
description of the MFA page, starts the MFA challenge (for SMS this sends the
code), asks for the code and tries to finish the login, printing every step.
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
from aioaquarea.mfa import redact_text

WARNING = """\
This is an experimental probe. It runs on your computer and sends your
credentials only to Panasonic (authglb.digital.panasonic.com and the Aquarea
API). The output is designed to be safe to paste into the GitHub issue: it
contains page structure, configuration key names, HTTP statuses and JSON key
names only: no passwords, cookies, tokens, state values, e-mail addresses,
phone numbers, codes or input values (page texts are redacted and truncated).
Please look it over before pasting anyway.
"""


class _OnlyMfaFilter(logging.Filter):
    """Let only the sanitized ``aioaquarea.mfa`` (and child) records through."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.name == "aioaquarea.mfa" or record.name.startswith("aioaquarea.mfa.")


def setup_logging() -> None:
    # The library logs full response bodies (auth.py check_response logs at
    # ERROR) and tokens at DEBUG. Silence all of it except aioaquarea.mfa, whose
    # output is sanitized. A filtered root handler also stops logging's
    # "last resort" stderr handler from printing anything else.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
    handler.addFilter(_OnlyMfaFilter())
    logging.getLogger().addHandler(handler)
    logging.getLogger("aioaquarea").setLevel(logging.CRITICAL + 1)
    # INFO, not DEBUG: the steps are printed below; DEBUG would repeat them.
    logging.getLogger("aioaquarea.mfa").setLevel(logging.INFO)


# Messages raised by aioaquarea.mfa / complete_mfa itself are fixed strings and
# safe to print. Any other message may contain response text, so it is dropped.
_SAFE_PREFIXES = (
    "unsupported MFA",
    "MFA code not accepted",
    "MFA redirect did not",
    "MFA request expired",
    "MFA start-flow",
    "MFA send-sms failed",
    "MFA transaction-state failed",
    "No pending MFA login",
    "too many redirects after MFA",
)


def safe_error(err: BaseException) -> str:
    """Describe an exception without ever including response content."""
    code = getattr(err, "error_code", None)
    parts = [type(err).__name__]
    if code is not None:
        parts.append(f"error_code={code}")
    message = getattr(err, "error_message", None)
    if isinstance(message, str) and message.startswith(_SAFE_PREFIXES):
        # Fixed library strings (plus status codes and Guardian error codes).
        parts.append(f"message={message}")
    elif isinstance(message, str):
        parts.append(f"message={redact_text(message)[:30]}")
    return " ".join(parts)


def print_steps(client: Client) -> None:
    steps = client.mfa_steps
    if not steps:
        return
    print("---- sanitized MFA steps (safe to paste) ----")
    for n, step in enumerate(steps, 1):
        print(f"{n:2}. {step}")
    print("---- end ----")


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
                print(f"Login failed: {safe_error(err)}")
                return 1
            print("\nLogin stopped at the MFA step.")
            print("---- sanitized MFA page structure (safe to paste) ----")
            print(client.mfa_description or "(could not be fetched)")
            print("---- end ----\n")
        else:
            print("Login succeeded without MFA.")
            return 0

        try:
            challenge = await client.start_mfa()
        except AuthenticationError as err:
            print(f"Starting MFA failed: {safe_error(err)}")
            print_steps(client)
            return 1
        print(
            f"MFA factor: {challenge.factor} (available: {challenge.available_factors}); "
            f"code sent: {'yes' if challenge.code_sent else 'no'}; "
            f"destination: {challenge.destination or 'n/a'}"
        )
        print_steps(client)
        hint = {
            "sms": "the SMS code",
            "otp": "the 6-digit code from your authenticator app",
        }.get(challenge.factor, "the MFA code")

        while True:
            code = input(f"\nEnter {hint} (or leave empty to stop): ").strip()
            if not code:
                return 0
            try:
                await client.complete_mfa(code)
            except AuthenticationError as err:
                print(f"MFA completion failed: {safe_error(err)}")
                print_steps(client)
                if "not accepted" in str(getattr(err, "error_message", "")):
                    continue  # wrong or expired code: let the user try again
                return 1
            break
        print_steps(client)
        devices = await client.get_devices()
        print(f"MFA login succeeded. Devices found: {len(devices)}")
        return 0


def main() -> None:
    argparse.ArgumentParser(
        description="Probe Panasonic MFA login. Credentials are prompted for, "
        "never passed as arguments."
    ).parse_args()
    setup_logging()
    try:
        code = asyncio.run(run())
    except KeyboardInterrupt:
        code = 130
    except Exception as err:  # never print a traceback: it may hold response text
        print(f"Probe failed: {safe_error(err)}")
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
