"""Errors for aioaquarea."""

from __future__ import annotations

from enum import StrEnum

from .mfa import MfaChallenge


class ClientError(Exception):
    """Base exception for all client errors"""


class RequestFailedError(ClientError):
    """Exception raised when request to the server fails"""

    def __init__(self, response: str | object):
        self.response = response
        super().__init__()

    def __str__(self):
        if isinstance(self.response, str):
            return self.response
        return f"Invalid response: {self.response.status} - {self.response.reason}"


class ApiError(ClientError):
    """API error"""

    def __init__(self, error_code, error_message):
        super().__init__()
        self.error_code = error_code
        self.error_message = error_message

    def __str__(self) -> str:
        return f"API error: {self.error_code} - {self.error_message}"


class AuthenticationError(ApiError):
    """Authentication error"""

    def __str__(self) -> str:
        return f"Authentication error: {self.error_code} - {self.error_message}"


class MfaRequiredError(AuthenticationError):
    """The login needs a multi-factor code: pass it to ``Client.complete_mfa``.

    Subclass of ``AuthenticationError`` with ``error_code`` ``MFA_REQUIRED``, so
    callers that only know the plain error keep working.
    """

    def __init__(self, challenge: MfaChallenge):
        super().__init__(
            AuthenticationErrorCodes.MFA_REQUIRED,
            f"Multi-factor authentication required ({challenge.factor})",
        )
        self.challenge = challenge


class InvalidData(ClientError):
    """Invalid data"""

    def __init__(self, data):
        self.data = data
        super().__init__()

    def __str__(self):
        return f"Invalid data from server: {self.data!r}"


class AuthenticationErrorCodes(StrEnum):
    """Authentication error codes"""

    SESSION_CLOSED = "1001-0001"
    INVALID_USERNAME_OR_PASSWORD = "1001-1401"
    INVALID_CREDENTIALS = "1000-1401"
    API_ERROR = "API_ERROR"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"  # Added for token expiration
    MFA_REQUIRED = "MFA_REQUIRED"
    MFA_INVALID_CODE = "MFA_INVALID_CODE"  # wrong code: may be retried
    MFA_EXPIRED = "MFA_EXPIRED"  # MFA transaction expired: log in again


class DataNotAvailableError(Exception):
    """Exception raised when data is not available"""
