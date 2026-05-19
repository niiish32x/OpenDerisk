"""Base class for OAuth2/OIDC providers."""

import base64
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT payload without signature verification.

    Returns the claims dict, or None if the token is malformed.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        # Pad to multiple of 4 for base64 decoding
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        logger.warning("Failed to decode JWT payload", exc_info=True)
        return None


class BaseOAuthProvider(ABC):
    """Abstract base for an OAuth2/OIDC provider."""

    @abstractmethod
    def get_authorization_url(
        self,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        state: str,
    ) -> Optional[str]:
        """Build the authorization URL the user should be redirected to."""

    @abstractmethod
    async def exchange_code_for_token(
        self,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        code: str,
    ) -> Optional[Dict[str, Any]]:
        """Exchange an authorization code for tokens.

        Returns a dict with at least ``access_token``, and optionally
        ``id_token`` and ``refresh_token``.
        """

    @abstractmethod
    async def fetch_userinfo(
        self,
        provider_config: Dict[str, Any],
        token_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Fetch / decode the authenticated user's profile.

        *token_data* is the dict returned by :meth:`exchange_code_for_token`.
        Returns a dict with keys: id, login, username, name, email,
        avatar_url, avatar, picture.
        """
