"""Types and helpers for Panasonic's multi-factor authentication (MFA) step."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FACTOR_SMS = "sms"
FACTOR_OTP = "otp"
FACTOR_PUSH = "push"
FACTOR_EMAIL = "email"
FACTOR_VOICE = "voice"
FACTOR_UNKNOWN = "unknown"


@dataclass(frozen=True)
class MfaChallenge:
    """What the user has to do to finish a login that needs MFA.

    ``factor`` is ``"sms"`` (a code is texted to the phone) or ``"otp"`` (the
    code comes from an authenticator app). ``destination`` is masked, for
    example ``"***62"``; the full phone number is never exposed.
    """

    factor: str
    destination: str | None = None
    available_factors: tuple[str, ...] = field(default_factory=tuple)
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


def normalize_factor(name: Any) -> str | None:
    """Map a Guardian method name (string or ``{"name"/"type"/"method": ...}``)."""
    if isinstance(name, dict):
        name = next(
            (name[k] for k in ("name", "type", "method") if isinstance(name.get(k), str)),
            None,
        )
    if not isinstance(name, str):
        return None
    name = name.lower()
    if name in ("otp", "totp", "guardian-otp", "google-authenticator"):
        return FACTOR_OTP
    if name in ("sms", "phone"):
        return FACTOR_SMS
    if name == "voice":
        return FACTOR_VOICE  # needs a different endpoint: unsupported
    if name in ("push", "guardian", "push-notification"):
        return FACTOR_PUSH
    if name == "email":
        return FACTOR_EMAIL
    if name in ("recovery-code", "recovery_code"):
        return None
    return FACTOR_UNKNOWN
