"""Logging configuration for AVA."""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional


class LoggerConfig:
    """Configure logging for the AVA project."""

    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

    _instance: Optional[logging.Logger] = None

    @classmethod
    def setup(
        cls,
        name: str = "ava",
        level: int = INFO,
        log_file: Optional[Path] = None,
    ) -> logging.Logger:
        """Set up and return a configured logger."""
        logger = logging.getLogger(name)
        logger.setLevel(level)

        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File Handler
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10485760, backupCount=5
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        cls._instance = logger
        return logger

    @classmethod
    def get_logger(cls) -> logging.Logger:
        """Get the configured logger instance."""
        if cls._instance is None:
            cls.setup()
        assert cls._instance is not None
        return cls._instance


# Default logger
logger = logging.getLogger("ava")
