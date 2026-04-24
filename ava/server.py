"""Integrated AVA 2.0 Server with all capabilities."""

import asyncio
from typing import Optional
import uvicorn
from ava.api.server import app
from ava.cloud.manager import LocalCloudSync
from ava.sync.manager import SyncQueue
from ava.tasks.scheduler import TaskScheduler
from ava.db.pool import DatabasePool
from ava.core.logging import logger, LoggerConfig


class AVA20Server:
    """Integrated AVA 2.0 server with cloud, sync, and task capabilities."""

    def __init__(self):
        """Initialize AVA 2.0 server."""
        self.db_pool: Optional[DatabasePool] = None
        self.sync_queue: Optional[SyncQueue] = None
        self.task_scheduler: Optional[TaskScheduler] = None
        self.cloud_sync: Optional[LocalCloudSync] = None

    def setup(self) -> None:
        """Setup all components."""
        LoggerConfig.setup("ava-server", level=LoggerConfig.INFO)

        logger.info("🚀 Initializing AVA 2.0 Server Components...")

        # Initialize Database
        self.db_pool = DatabasePool("sqlite:///ava.db")
        self.db_pool.initialize()

        # Initialize Sync Queue
        self.sync_queue = SyncQueue()

        # Initialize Task Scheduler
        self.task_scheduler = TaskScheduler()

        # Initialize Cloud Sync
        self.cloud_sync = LocalCloudSync("/data/local")

        logger.info("✅ All components initialized successfully!")

    async def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the AVA 2.0 server."""
        logger.info(f"🌐 Starting AVA 2.0 API Server on {host}:{port}")

        # Start background sync
        sync_task = asyncio.create_task(self.cloud_sync.start_continuous_sync(interval_seconds=300))

        # Run uvicorn server
        config = uvicorn.Config(app, host=host, port=port, log_level="info", access_log=True)
        server = uvicorn.Server(config)

        try:
            await server.serve()
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")
        finally:
            sync_task.cancel()


async def main():
    """Main entry point."""
    server = AVA20Server()
    server.setup()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
