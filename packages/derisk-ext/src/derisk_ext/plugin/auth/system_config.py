"""System configuration storage (model + DAO) for feature plugin state."""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text

from derisk.storage.metadata import Model
from derisk.storage.metadata.db_manager import db

logger = logging.getLogger(__name__)


class SystemConfigEntity(Model):
    """系统配置表 - 用于存储功能插件等系统配置状态"""

    __tablename__ = "system_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String(128), unique=True, nullable=False, comment="配置键名")
    config_value = Column(Text, nullable=True, comment="配置值（JSON 格式）")
    config_type = Column(String(32), default="feature_plugin", comment="配置类型")
    description = Column(String(512), nullable=True, comment="配置描述")
    gmt_create = Column(DateTime, default=datetime.utcnow, nullable=False)
    gmt_modify = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class SystemConfigDao:
    """系统配置数据访问层"""

    def get_config(
        self, config_key: str, config_type: str = "feature_plugin"
    ) -> Optional[Dict[str, Any]]:
        with db.session(commit=False) as s:
            config = (
                s.query(SystemConfigEntity)
                .filter(
                    SystemConfigEntity.config_key == config_key,
                    SystemConfigEntity.config_type == config_type,
                )
                .first()
            )
            if config and config.config_value:
                try:
                    return json.loads(config.config_value)
                except (json.JSONDecodeError, TypeError):
                    return None
            return None

    def set_config(
        self,
        config_key: str,
        config_value: Dict[str, Any],
        config_type: str = "feature_plugin",
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        with db.session() as s:
            config = (
                s.query(SystemConfigEntity)
                .filter(
                    SystemConfigEntity.config_key == config_key,
                    SystemConfigEntity.config_type == config_type,
                )
                .first()
            )
            value_json = json.dumps(config_value, ensure_ascii=False)
            if config:
                config.config_value = value_json
                if description:
                    config.description = description
                s.flush()
                s.refresh(config)
            else:
                config = SystemConfigEntity(
                    config_key=config_key,
                    config_value=value_json,
                    config_type=config_type,
                    description=description,
                )
                s.add(config)
                s.flush()
                s.refresh(config)
            return {
                "id": config.id,
                "config_key": config.config_key,
                "config_value": json.loads(config.config_value) if config.config_value else {},
                "config_type": config.config_type,
            }

    def delete_config(self, config_key: str, config_type: str = "feature_plugin") -> bool:
        with db.session() as s:
            config = (
                s.query(SystemConfigEntity)
                .filter(
                    SystemConfigEntity.config_key == config_key,
                    SystemConfigEntity.config_type == config_type,
                )
                .first()
            )
            if config:
                s.delete(config)
                return True
            return False

    def get_all_configs(
        self, config_type: str = "feature_plugin"
    ) -> Dict[str, Dict[str, Any]]:
        with db.session(commit=False) as s:
            configs = (
                s.query(SystemConfigEntity)
                .filter(SystemConfigEntity.config_type == config_type)
                .all()
            )
            result = {}
            for config in configs:
                if config.config_value:
                    try:
                        result[config.config_key] = json.loads(config.config_value)
                    except (json.JSONDecodeError, TypeError):
                        result[config.config_key] = {}
                else:
                    result[config.config_key] = {}
            return result
