# aioaquarea-ng

[![PyPI](https://img.shields.io/pypi/v/aioaquarea-ng)](https://pypi.org/project/aioaquarea-ng/)

Asynchronous Python library for Panasonic Aquarea heat pumps, through the Panasonic Aquarea Smart Cloud API. It powers the [home-assistant-aquarea](https://github.com/wpatrik14/home-assistant-aquarea) integration.

This is the maintained fork of [cjaliaga/aioaquarea](https://github.com/cjaliaga/aioaquarea), originally written by Carlos J. Aliaga. Upstream has had no merges or releases since May 2026, and Panasonic has started enforcing multi-factor authentication on logins ([cjaliaga/aioaquarea#92](https://github.com/cjaliaga/aioaquarea/issues/92)), so development continues here. The package name changed; the import name did not.

## Installation

```bash
pip install aioaquarea-ng
```

```python
import aioaquarea  # same import name as the original package
```

Don't install it next to the original `aioaquarea` package: both provide the `aioaquarea` module.

## Status

- **Multi-factor authentication:** accounts that get Panasonic's MFA challenge fail with `AuthenticationError` code `MFA_REQUIRED` instead of a confusing token error. Completing the challenge is in progress ([#7](https://github.com/wpatrik14/aioaquarea/pull/7)).
- **Water pressure:** `Device.water_pressure` (bar), when the unit reports it.

Bug reports and pull requests are welcome in this repository.

## Requirements

This library requires:

- Python >= 3.9
- asyncio
- aiohttp

## Usage
The library supports the production environment of the Panasonic Aquarea Smart Cloud API and also the Demo environment. One of the main usages of this library is to integrate the Panasonic Aquarea Smart Cloud API with Home Assistant via [home-assistant-aquarea](https://github.com/wpatrik14/home-assistant-aquarea)

Here is a simple example of how to use the library via getting a device object to interact with it:

```python
from aioaquarea import (
    Client,
    AquareaEnvironment,
    UpdateOperationMode
)

import aiohttp
import asyncio
import logging
from datetime import timedelta

async def main():
    async with aiohttp.ClientSession() as session:
        client = Client(
            username="USERNAME",
            password="PASSWORD",
            session=session,
            device_direct=True,
            refresh_login=True,
            environment=AquareaEnvironment.PRODUCTION,
        )

        # The library is designed to retrieve a device object and interact with it:
        devices = await client.get_devices(include_long_id=True)

        # Picking the first device associated with the account:
        device_info = devices[0]

        device = await client.get_device(
            device_info=device_info, consumption_refresh_interval=timedelta(minutes=1)
        )

        # Or the device can also be retrieved by its long id if we know it:
        device = await client.get_device(
            device_id="LONG ID", consumption_refresh_interval=timedelta(minutes=1)
        )

        # Then we can interact with the device:
        await device.set_mode(UpdateOperationMode.HEAT)

        # The device can automatically refresh its data:
        await device.refresh_data()
```

## Acknowledgements

The original library is by [Carlos J. Aliaga](https://github.com/cjaliaga) ([cjaliaga/aioaquarea](https://github.com/cjaliaga/aioaquarea)), MIT licensed.


Big thanks to [ronhks](https://github.com/ronhks) for his awesome work on the [Panasonic Aquarea Smart Cloud integration with MQTT](https://github.com/ronhks/panasonic-aquarea-smart-cloud-mqtt).

## Testing MFA login

Panasonic now asks some accounts for multi-factor authentication (MFA). Support is
experimental. Panasonic's MFA page is Auth0's classic *Guardian* page; the library now
drives the Guardian API directly for authenticator app (TOTP) and SMS codes. Push
notifications and e-mail codes are not supported yet.

```python
from aioaquarea import AuthenticationError, AuthenticationErrorCodes

try:
    await client.login()
except AuthenticationError as err:
    if err.error_code != AuthenticationErrorCodes.MFA_REQUIRED:
        raise
    challenge = await client.start_mfa()  # sends the SMS for an SMS factor
    print(challenge.factor, challenge.destination)  # e.g. "sms", "***67" (masked)
    await client.complete_mfa(input("Code: "))  # raises MFA_REQUIRED on a wrong code
```

The probe script below helps test this against a real account. It runs on your own
computer, asks for your Panasonic ID and password (the password is never a command
line argument), and sends them only to Panasonic. If MFA is required it prints a
sanitized description of the MFA page, starts the challenge (for SMS this sends the
code), asks for the code and prints every step of the login. The output contains page
structure, configuration key names, HTTP statuses and JSON key names only (no cookies,
tokens, state values, e-mail addresses, phone numbers or codes), but look it over before
pasting it into an issue.

```bash
pip install --force-reinstall "git+https://github.com/wpatrik14/aioaquarea@mfa-probe"
curl -O https://raw.githubusercontent.com/wpatrik14/aioaquarea/mfa-probe/scripts/mfa_probe.py
python mfa_probe.py
```

(Or clone the repository and run `python scripts/mfa_probe.py` after installing.) The
script imports the installed `aioaquarea` package, so the `pip install` step is required.
