"""OAuth2 flow service — thin dispatcher that delegates to typed providers."""

import logging
from typing import Any, Dict, Optional

import httpx

from derisk_ext.plugin.auth.providers import GitHubProvider, MoziProvider
from derisk_ext.plugin.auth.providers.base import BaseOAuthProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider registry — add new OAuth2 / OIDC providers here.
# ---------------------------------------------------------------------------
_PROVIDERS: Dict[str, BaseOAuthProvider] = {
    "alibaba-inc": MoziProvider(),
    "github": GitHubProvider(),
}


class OAuth2Service:
    """OAuth2 flow service."""

    def _get_provider(
        self, provider_config: Dict[str, Any]
    ) -> Optional[BaseOAuthProvider]:
        return _PROVIDERS.get(provider_config.get("type", ""))

    # ---- public API -------------------------------------------------------

    def get_authorization_url(
        self,
        provider_id: str,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        state: str,
    ) -> Optional[str]:
        provider = self._get_provider(provider_config)
        if provider:
            return provider.get_authorization_url(
                provider_config, redirect_uri, state
            )

        # Generic / custom provider (config-driven)
        if provider_config.get("type") == "custom":
            auth_url = provider_config.get("authorization_url", "")
            client_id = provider_config.get("client_id", "")
            if not auth_url or not client_id:
                return None
            scope = provider_config.get("scope", "")
            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "response_type": "code",
            }
            if scope:
                params["scope"] = scope
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            sep = "&" if "?" in auth_url else "?"
            return f"{auth_url}{sep}{qs}"

        return None

    async def exchange_code_for_token(
        self,
        provider_id: str,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        code: str,
    ) -> Optional[Dict[str, Any]]:
        provider = self._get_provider(provider_config)
        if provider:
            return await provider.exchange_code_for_token(
                provider_config, redirect_uri, code
            )

        # Generic / custom provider
        if provider_config.get("type") == "custom":
            token_url = provider_config.get("token_url", "")
            if not token_url:
                return None
            data = {
                "client_id": provider_config.get("client_id", ""),
                "client_secret": provider_config.get("client_secret", ""),
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        token_url,
                        data=data,
                        headers={"Accept": "application/json"},
                    )
                    resp.raise_for_status()
                    return resp.json()
            except Exception:
                logger.exception("Token exchange failed")
                return None

        return None

    async def fetch_userinfo(
        self,
        provider_id: str,
        provider_config: Dict[str, Any],
        access_token: str,
        id_token: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        token_data: Dict[str, Any] = {"access_token": access_token}
        if id_token:
            token_data["id_token"] = id_token

        provider = self._get_provider(provider_config)
        if provider:
            return await provider.fetch_userinfo(provider_config, token_data)

        # Generic / custom provider
        if provider_config.get("type") == "custom":
            userinfo_url = provider_config.get("userinfo_url", "")
            if not userinfo_url:
                return None
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        userinfo_url,
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    raw_id = (
                        data.get("sub")
                        or data.get("id")
                        or data.get("uid")
                        or data.get("userId")
                        or ""
                    )
                    return {
                        "id": str(raw_id) if raw_id else "",
                        "login": data.get("login", data.get("account", "")),
                        "nickname": data.get("nickname", data.get("nickNameCn", "")),
                        "username": data.get("username", data.get("name", "")),
                        "name": data.get("name", data.get("realName", "")),
                        "email": (
                            data.get("email")
                            or data.get("mail")
                            or ""
                        ),
                        "avatar_url": data.get("avatar_url", data.get("avatar", "")),
                        "avatar": data.get("avatar", ""),
                        "picture": data.get("picture", ""),
                    }
            except Exception:
                logger.exception("Userinfo fetch failed")
                return None

        return None
