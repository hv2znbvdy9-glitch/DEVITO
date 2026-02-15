"""Configuration management for AVA."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from pathlib import Path


@dataclass
class AppConfig:
    """Application configuration."""

    app_name: str = "AVA"
    version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"
    app_dir: Path = field(default_factory=lambda: Path.home() / ".ava")
    config_file: Optional[Path] = None
    features: Dict[str, bool] = field(
        default_factory=lambda: {
            "logging": True,
            "monitoring": True,
            "validation": True,
        }
    )

    def __post_init__(self) -> None:
        """Initialize app directory after dataclass creation."""
        self.app_dir.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "app_name": self.app_name,
            "version": self.version,
            "debug": self.debug,
            "log_level": self.log_level,
            "features": self.features,
        }

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Create config from environment variables."""
        import os

        return cls(
            debug=os.getenv("AVA_DEBUG", "false").lower() == "true",
            log_level=os.getenv("AVA_LOG_LEVEL", "INFO"),
        )


# Global config instance
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Get or create the global config."""
    global _config
    if _config is None:
        _config = AppConfig.from_env()
    return _config


def set_config(config: AppConfig) -> None:
    """Set the global config."""
    global _config
    _config = config
