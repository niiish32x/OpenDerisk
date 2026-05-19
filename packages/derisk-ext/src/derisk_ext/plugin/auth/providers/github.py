"""GitHub OAuth2 provider."""

import logging
from typing import Any, Dict, Optional

import httpx

from derisk_ext.plugin.auth.providers.base import BaseOAuthProvider

logger = logging.getLogger(__name__)

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"


class GitHubProvider(BaseOAuthProvider):
    """GitHub OAuth2 provider."""

    def get_authorization_url(
        self,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        state: str,
    ) -> Optional[str]:
        client_id = provider_config.get("client_id", "")
        scope = provider_config.get("scope", "read:user user:email")
        if not client_id:
            return None
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
        }
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{GITHUB_AUTH_URL}?{qs}"

    async def exchange_code_for_token(
        self,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        code: str,
    ) -> Optional[Dict[str, Any]]:
        data = {
            "client_id": provider_config.get("client_id", ""),
            "client_secret": provider_config.get("client_secret", ""),
            "code": code,
            "redirect_uri": redirect_uri,
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    GITHUB_TOKEN_URL,
                    data=data,
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            logger.exception("GitHub token exchange failed")
            return None

    async def fetch_userinfo(
        self,
        provider_config: Dict[str, Any],
        token_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        access_token = token_data.get("access_token")
        if not access_token:
            return None
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    GITHUB_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                resp.raise_for_status()
                data = resp.json()
                return {
                    "id": str(data.get("id", "")),
                    "login": data.get("login", ""),
                    "nickname": data.get("login", ""),
                    "username": data.get("username", data.get("name", "")),
                    "name": data.get("name", ""),
                    "email": data.get("email", ""),
                    "avatar_url": data.get("avatar_url", ""),
                    "avatar": data.get("avatar_url", ""),
                    "picture": data.get("avatar_url", ""),
                }
        except Exception:
            logger.exception("GitHub userinfo fetch failed")
            return None
