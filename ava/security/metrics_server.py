"""
AVA Adaptive Security - Prometheus Metrics HTTP Server
=======================================================
Stellt Metriken via HTTP für Prometheus Scraping bereit
"""

import asyncio
import logging
from aiohttp import web
from typing import Optional

from .metrics import get_metrics, update_all_metrics, PROMETHEUS_AVAILABLE

logger = logging.getLogger(__name__)


class MetricsServer:
    """HTTP Server für Prometheus Metrics"""

    def __init__(self, host: str = "0.0.0.0", port: int = 9090):
        if not PROMETHEUS_AVAILABLE:
            raise ImportError("prometheus_client not installed")

        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None

        # Setup routes
        self.app.router.add_get("/metrics", self.metrics_handler)
        self.app.router.add_get("/health", self.health_handler)

        logger.info(f"Metrics server configured on {host}:{port}")

    async def metrics_handler(self, request: web.Request) -> web.Response:
        """Serve Prometheus metrics"""
        try:
            # Update all metrics before serving
            update_all_metrics()

            metrics = get_metrics()
            data = metrics.get_metrics()

            return web.Response(body=data, content_type="text/plain; version=0.0.4")
        except Exception as e:
            logger.error(f"Error serving metrics: {e}")
            return web.Response(text=f"Error: {e}", status=500)

    async def health_handler(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.Response(text="OK", status=200)

    async def start(self):
        """Start metrics server"""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()

        logger.info(f"✅ Metrics server started on http://{self.host}:{self.port}")
        logger.info(f"   Metrics: http://{self.host}:{self.port}/metrics")
        logger.info(f"   Health:  http://{self.host}:{self.port}/health")

    async def stop(self):
        """Stop metrics server"""
        if self.runner:
            await self.runner.cleanup()
            logger.info("Metrics server stopped")

    async def run_forever(self):
        """Run server forever"""
        await self.start()

        try:
            # Keep running
            while True:
                await asyncio.sleep(3600)
        except KeyboardInterrupt:
            logger.info("Shutting down metrics server...")
        finally:
            await self.stop()


async def run_metrics_server(host: str = "0.0.0.0", port: int = 9090):
    """Convenience function to run metrics server"""
    server = MetricsServer(host=host, port=port)
    await server.run_forever()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if not PROMETHEUS_AVAILABLE:
        print("❌ prometheus_client not installed")
        print("Install: pip install prometheus-client aiohttp")
    else:
        print("🚀 Starting Prometheus Metrics Server...")
        print("Press CTRL+C to stop\n")

        asyncio.run(run_metrics_server())
