"""Pluggable OAuth2/OIDC providers."""

from derisk_ext.plugin.auth.providers.base import BaseOAuthProvider, decode_jwt_payload
from derisk_ext.plugin.auth.providers.github import GitHubProvider
from derisk_ext.plugin.auth.providers.mozi import MoziProvider

__all__ = [
    "BaseOAuthProvider",
    "decode_jwt_payload",
    "GitHubProvider",
    "MoziProvider",
]
