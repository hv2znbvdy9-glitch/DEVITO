"""Main module for AVA package."""

import asyncio
import uvicorn
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    """Main entry point - start FastAPI server."""
    logger.info("🌟 AVA Wellbeing System - Starting...")
    uvicorn.run(
        app="ava.server:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=False
    )


if __name__ == "__main__":
    main()
