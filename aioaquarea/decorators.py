import functools
import logging
from typing import TYPE_CHECKING  # Re-add TYPE_CHECKING

from .errors import (  # Added ApiError
    ApiError,
    AuthenticationError,
    AuthenticationErrorCodes,
)

if TYPE_CHECKING:  # Re-add TYPE_CHECKING block
    from .core import AquareaClient

_LOGGER = logging.getLogger(__name__)


def auth_required(fn):
    """Decorator to require authentication and to refresh login if it's able to.

    A call can pass ``retry_login=False`` (the wrapped method must accept it)
    to get the first authentication failure raised instead of logging in and
    repeating the request; and to get one raised when not logged in at all.
    """

    @functools.wraps(fn)
    async def _wrap(
        client: "AquareaClient", *args, **kwargs
    ):  # Use string literal for type hint
        retry_login = kwargs.get("retry_login", True)
        if client.is_logged is False and not retry_login:
            raise AuthenticationError(
                AuthenticationErrorCodes.TOKEN_EXPIRED, "Not logged in"
            )
        if client.is_logged is False:
            client.logger.warning(f"{client}: User is not logged or session is too old")
            await client.login()

        try:
            response = await fn(client, *args, **kwargs)
        except (
            AuthenticationError,
            ApiError,
        ) as exception:  # Catch both AuthenticationError and ApiError
            client.logger.warning(
                f"{client}: API Error: {getattr(exception, 'error_code', 'N/A')} - {getattr(exception, 'error_message', str(exception))}."
            )

            # If the error is invalid credentials, always raise.
            if (
                isinstance(exception, AuthenticationError)
                and exception.error_code
                == AuthenticationErrorCodes.INVALID_USERNAME_OR_PASSWORD
            ):
                raise

            # If refresh is not enabled, or the caller does not want it, raise.
            if not client.is_refresh_login_enabled or not retry_login:
                raise

            # If it's an ApiError with "Missing Authentication Token" or AuthenticationError with TOKEN_EXPIRED, try to re-login.
            if (
                isinstance(exception, ApiError)
                and "Missing Authentication Token" in str(exception)
            ) or (
                isinstance(exception, AuthenticationError)
                and exception.error_code == AuthenticationErrorCodes.TOKEN_EXPIRED
            ):
                client.logger.warning(
                    f"{client}: Token expired or missing. Trying to login again."
                )
                await client.login()
                response = await fn(client, *args, **kwargs)
            else:
                # For any other unhandled AuthenticationError or ApiError, re-raise.
                raise

        return response

    return _wrap
