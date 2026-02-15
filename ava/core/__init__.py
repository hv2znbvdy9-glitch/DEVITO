"""Package initialization."""

from ava.core.logging import logger  # noqa: F401
from ava.config.settings import get_config, set_config, AppConfig  # noqa: F401
from ava.core.engine import Engine  # noqa: F401

__version__ = "0.1.0"
__author__ = "Developer"

# Initialize default logger
logger.debug("AVA package initialized")
