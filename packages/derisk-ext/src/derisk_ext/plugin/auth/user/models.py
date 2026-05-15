"""User entity ORM model."""

from datetime import datetime
from typing import Any, Dict

from sqlalchemy import Column, DateTime, Integer, String

from derisk.storage.metadata import Model


class UserEntity(Model):
    """User entity matching the user table schema."""

    __tablename__ = "user"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=True)
    fullname = Column(String(50), nullable=True)
    oauth_provider = Column(String(64), nullable=True, comment="OAuth2 provider")
    oauth_id = Column(String(255), nullable=True, comment="OAuth provider user ID")
    email = Column(String(255), nullable=True, comment="User email")
    avatar = Column(String(512), nullable=True, comment="Avatar URL")
    password_hash = Column(String(255), nullable=True, comment="Bcrypt password hash for local login")
    role = Column(
        String(20), nullable=True, default="normal", comment="User role: normal/admin"
    )
    is_active = Column(
        Integer, nullable=False, default=1, comment="1=active, 0=disabled"
    )
    gmt_create = Column(DateTime, default=datetime.utcnow, nullable=False)
    gmt_modify = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


def user_to_dict(user: UserEntity) -> Dict[str, Any]:
    """Convert UserEntity to plain dict (safe to use after session close)."""
    return {
        "id": user.id,
        "name": user.name or "",
        "fullname": user.fullname or "",
        "email": user.email or "",
        "avatar": user.avatar or "",
        "oauth_provider": user.oauth_provider or "",
        "oauth_id": user.oauth_id or "",
        "role": user.role or "normal",
        "is_active": user.is_active if user.is_active is not None else 1,
        "gmt_create": user.gmt_create.isoformat() if user.gmt_create else None,
        "gmt_modify": user.gmt_modify.isoformat() if user.gmt_modify else None,
    }
