"""Auth plugin for OpenDerisk.

Provides JWT token management, OAuth2 integration, user management, and RBAC.
"""

from derisk_ext.plugin.auth.jwt import create_token, verify_token, decode_token
from derisk_ext.plugin.auth.catalog import FeaturePluginManifest, list_manifests, get_manifest, merge_catalog_with_state

__all__ = [
    "create_token",
    "verify_token",
    "decode_token",
    "FeaturePluginManifest",
    "list_manifests",
    "get_manifest",
    "merge_catalog_with_state",
]
