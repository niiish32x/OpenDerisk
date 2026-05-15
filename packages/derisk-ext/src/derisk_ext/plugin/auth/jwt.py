"""Standard JWT token management for OpenDerisk.

Replaces the legacy HMAC-based session token (derisk-app/auth/session.py)
with standard JWT (RS256) supporting dual identity (sub + act) and
self-contained RBAC claims.
"""

import logging
import os
import time
from typing import Any, Dict, Optional

import jwt as pyjwt  # PyJWT library

logger = logging.getLogger(__name__)

# --- Configuration ---

DEFAULT_EXPIRE_SECONDS = 7 * 24 * 3600  # 7 days
ISSUER = "derisk"

# Key paths
JWT_KEY_DIR = os.path.expanduser("~/.derisk/jwt")


def _get_private_key() -> str:
    """Load or generate RSA private key."""
    env_key = os.environ.get("OAUTH2_JWT_PRIVATE_KEY", "")
    if env_key:
        return env_key

    key_path = os.path.join(JWT_KEY_DIR, "private.pem")
    if os.path.exists(key_path):
        with open(key_path, "r") as f:
            return f.read()

    # Auto-generate key pair
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    os.makedirs(JWT_KEY_DIR, exist_ok=True)
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    with open(key_path, "w") as f:
        f.write(private_pem)
    with open(os.path.join(JWT_KEY_DIR, "public.pem"), "w") as f:
        f.write(public_pem)

    logger.info("Auto-generated JWT RSA key pair in %s", JWT_KEY_DIR)
    return private_pem


def _get_public_key() -> str:
    """Load or derive RSA public key."""
    env_key = os.environ.get("OAUTH2_JWT_PUBLIC_KEY", "")
    if env_key:
        return env_key

    pub_path = os.path.join(JWT_KEY_DIR, "public.pem")
    if os.path.exists(pub_path):
        with open(pub_path, "r") as f:
            return f.read()

    # Derive from private key
    private_pem = _get_private_key()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    key = serialization.load_pem_private_key(
        private_pem.encode(), password=None, backend=default_backend()
    )
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _get_expire_seconds() -> int:
    """Get configured token expiry in seconds."""
    val = os.environ.get("OAUTH2_JWT_EXPIRE_SECONDS", "")
    if val:
        try:
            return int(val)
        except ValueError:
            pass
    return DEFAULT_EXPIRE_SECONDS


# --- Public API ---

def create_token(
    user: Dict[str, Any],
    agent: Optional[Dict[str, Any]] = None,
    rbac: Optional[Dict[str, Any]] = None,
    audience: Optional[list] = None,
) -> str:
    """Create a signed JWT token.

    Args:
        user: User identity dict with keys: id, name, email, avatar_url
        agent: Optional agent identity dict: agent_name, app_id, agent_role
        rbac: Optional RBAC dict: role, roles, permissions
        audience: Optional audience list (defaults to ["derisk-api"])

    Returns:
        Signed JWT string.
    """
    now = int(time.time())
    expire = _get_expire_seconds()

    claims: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": str(user.get("id", "")),
        "name": user.get("name", user.get("login", "")),
        "email": user.get("email", ""),
        "avatar_url": user.get("avatar_url", user.get("avatar", "")),
        "iat": now,
        "exp": now + expire,
        "aud": audience or ["derisk-api"],
    }

    if agent:
        claims["act"] = {
            "agent_name": agent.get("agent_name", ""),
            "app_id": agent.get("app_id", ""),
            "agent_role": agent.get("agent_role", ""),
        }

    if rbac:
        claims["rbac"] = {
            "role": rbac.get("role", "normal"),
            "roles": rbac.get("roles", []),
            "permissions": rbac.get("permissions", {}),
        }

    private_key = _get_private_key()
    return pyjwt.encode(claims, private_key, algorithm="RS256")


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT token. Raises on invalid/expired token.

    Returns:
        The decoded claims dict.
    """
    public_key = _get_public_key()
    try:
        claims = pyjwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="derisk-api",
            issuer=ISSUER,
        )
        return claims
    except pyjwt.ExpiredSignatureError:
        raise JWTError("Token expired")
    except pyjwt.InvalidAudienceError:
        raise JWTError("Invalid audience")
    except pyjwt.InvalidIssuerError:
        raise JWTError("Invalid issuer")
    except pyjwt.InvalidTokenError as e:
        raise JWTError(f"Invalid token: {e}")


def decode_token(token: str) -> Dict[str, Any]:
    """Decode JWT claims without verification (for reading identity info).

    Use this only for extracting non-security-critical info (e.g., name for
    display). Never use this for authorization decisions.
    """
    try:
        return pyjwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        logger.debug("Failed to decode token: %s", e)
        return {}


class JWTError(Exception):
    """JWT verification failure."""
    pass
