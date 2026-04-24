"""
AVA Adaptive Security Orchestrator
===================================
Zentrale Steuerung für ALLE Sicherheitssysteme:
- Adaptive Network IDS
- Cookie Security Scanner
- Distributed Security Mesh
- Universal Interface Protection

SELBST-LERNEND • ADAPTIV • DISTRIBUTED • UNIVERSAL
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, Optional

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .adaptive_ids import get_adaptive_ids
from .cookie_scanner import get_cookie_scanner
from .distributed_mesh import get_security_mesh, NodeType, mesh_heartbeat
from .universal_protection import get_universal_protection

logger = logging.getLogger(__name__)


class AdaptiveSecurityOrchestrator:
    """Zentrale Orchestrierung aller adaptiven Sicherheitssysteme"""

    def __init__(self):
        # Initialisiere alle Subsysteme
        self.adaptive_ids = get_adaptive_ids()
        self.cookie_scanner = get_cookie_scanner()
        self.security_mesh = get_security_mesh(NodeType.LOCAL)
        self.universal_protection = get_universal_protection()

        # Status
        self.is_running = False
        self.start_time: Optional[datetime] = None

        # Rich Console
        if RICH_AVAILABLE:
            self.console = Console()

        logger.info("🚀 Adaptive Security Orchestrator initialized")

    def get_global_security_score(self) -> float:
        """
        Berechne globalen Security-Score (0-100)
        Basiert auf allen Subsystemen
        """
        scores = []

        # 1. Adaptive IDS Score
        ids_stats = self.adaptive_ids.get_statistics()
        if ids_stats["total_scans"] > 0:
            threat_ratio = ids_stats["threats_detected"] / ids_stats["total_scans"]
            ids_score = max(0, 100 - (threat_ratio * 100))
            scores.append(ids_score)
        else:
            scores.append(100)  # Keine Scans = perfekter Score

        # 2. Cookie Scanner Score
        cookie_stats = self.cookie_scanner.get_statistics()
        if cookie_stats["total_cookies_scanned"] > 0:
            threat_ratio = (
                cookie_stats["total_threats_found"] / cookie_stats["total_cookies_scanned"]
            )
            cookie_score = max(0, 100 - (threat_ratio * 100))
            scores.append(cookie_score)
        else:
            scores.append(100)

        # 3. Mesh Health Score
        mesh_stats = self.security_mesh.get_mesh_statistics()
        if mesh_stats["total_nodes"] > 0:
            health_ratio = mesh_stats["healthy_nodes"] / mesh_stats["total_nodes"]
            mesh_score = health_ratio * 100
            scores.append(mesh_score)
        else:
            scores.append(100)

        # 4. Protection Score
        protection_stats = self.universal_protection.get_statistics()
        if protection_stats["total_requests"] > 0:
            block_ratio = protection_stats["total_blocked"] / protection_stats["total_requests"]
            # Moderates Blocking ist gut (nicht zu hoch, nicht zu niedrig)
            if block_ratio < 0.1:  # < 10%
                protection_score = 100 - (block_ratio * 50)
            else:  # Zu viele Blocks = viele Angriffe
                protection_score = max(0, 100 - (block_ratio * 200))
            scores.append(protection_score)
        else:
            scores.append(100)

        # Gewichteter Durchschnitt
        return sum(scores) / len(scores) if scores else 50.0

    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Hole umfassende Statistiken von allen Systemen"""
        return {
            "orchestrator": {
                "is_running": self.is_running,
                "uptime_seconds": (
                    (datetime.utcnow() - self.start_time).seconds if self.start_time else 0
                ),
                "global_security_score": self.get_global_security_score(),
            },
            "adaptive_ids": self.adaptive_ids.get_statistics(),
            "cookie_scanner": self.cookie_scanner.get_statistics(),
            "security_mesh": self.security_mesh.get_mesh_statistics(),
            "universal_protection": self.universal_protection.get_statistics(),
        }

    def generate_master_report(self) -> str:
        """Generiere Master-Report über alle Systeme"""
        stats = self.get_comprehensive_statistics()

        report = f"""
╔════════════════════════════════════════════════════════════════════════════════╗
║                   AVA ADAPTIVE SECURITY PLATFORM v4.0                          ║
║                  SELBST-LERNEND • ADAPTIV • DISTRIBUTED                        ║
╚════════════════════════════════════════════════════════════════════════════════╝

🎯 GLOBAL SECURITY SCORE: {stats['orchestrator']['global_security_score']:.1f}/100

⏱️ SYSTEM STATUS:
  Running:               {'✅ YES' if stats['orchestrator']['is_running'] else '❌ NO'}
  Uptime:                {stats['orchestrator']['uptime_seconds']:,} seconds

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️ ADAPTIVE NETWORK IDS:
  Total Scans:           {stats['adaptive_ids']['total_scans']:,}
  Threats Detected:      {stats['adaptive_ids']['threats_detected']:,}
  Threats Blocked:       {stats['adaptive_ids']['threats_blocked']:,}
  Patterns Learned:      {stats['adaptive_ids']['patterns_learned']:,}
  Unique Fingerprints:   {stats['adaptive_ids']['unique_fingerprints']:,}
  Blacklisted IPs:       {stats['adaptive_ids']['blacklisted_ips']:,}
  Blacklisted MACs:      {stats['adaptive_ids']['blacklisted_macs']:,}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🍪 COOKIE SECURITY SCANNER:
  Cookies Scanned:       {stats['cookie_scanner']['total_cookies_scanned']:,}
  Threats Found:         {stats['cookie_scanner']['total_threats_found']:,}
  Learned Patterns:      {stats['cookie_scanner']['learned_patterns_count']:,}
  Blacklisted Names:     {stats['cookie_scanner']['blacklisted_names_count']:,}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌐 DISTRIBUTED SECURITY MESH:
  Total Nodes:           {stats['security_mesh']['total_nodes']:,}
  Healthy Nodes:         {stats['security_mesh']['healthy_nodes']:,}
  Total Events:          {stats['security_mesh']['total_events']:,}
  Active Policies:       {stats['security_mesh']['total_policies']:,}
  Shared Blacklist IPs:  {stats['security_mesh']['shared_blacklist_ips']:,}
  Shared Blacklist MACs: {stats['security_mesh']['shared_blacklist_macs']:,}
  Threat Signatures:     {stats['security_mesh']['shared_threat_signatures']:,}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚡ UNIVERSAL INTERFACE PROTECTION:
  Total Requests:        {stats['universal_protection']['total_requests']:,}
  Blocked Requests:      {stats['universal_protection']['total_blocked']:,}
  Threats Detected:      {stats['universal_protection']['total_threats']:,}
  
  Protected Interfaces:"""

        for interface, pstats in stats["universal_protection"]["protectors"].items():
            report += f"\n    • {interface.upper():15s} Processed: {pstats['requests_processed']:6,}  Blocked: {pstats['requests_blocked']:6,}"

        report += "\n\n╚════════════════════════════════════════════════════════════════════════════════╝\n"

        return report

    def create_dashboard_layout(self) -> Layout:
        """Erstelle Rich Dashboard Layout"""
        if not RICH_AVAILABLE:
            raise ImportError("Rich library not available")

        layout = Layout()

        # 2x2 Grid
        layout.split_column(
            Layout(name="header", size=3), Layout(name="main"), Layout(name="footer", size=3)
        )

        layout["main"].split_row(Layout(name="left"), Layout(name="right"))

        layout["left"].split_column(Layout(name="ids"), Layout(name="cookies"))

        layout["right"].split_column(Layout(name="mesh"), Layout(name="protection"))

        return layout

    def render_dashboard(self, layout: Layout):
        """Rendere Dashboard-Inhalte"""
        if not RICH_AVAILABLE:
            return

        stats = self.get_comprehensive_statistics()
        score = stats["orchestrator"]["global_security_score"]

        # Header
        header_text = Text()
        header_text.append("AVA ADAPTIVE SECURITY PLATFORM v4.0\n", style="bold magenta")

        # Score-basierte Farbe
        if score >= 90:
            score_style = "bold green"
        elif score >= 70:
            score_style = "bold yellow"
        elif score >= 50:
            score_style = "bold orange1"
        else:
            score_style = "bold red"

        header_text.append("Security Score: ", style="white")
        header_text.append(f"{score:.1f}/100", style=score_style)

        layout["header"].update(Panel(header_text, border_style="magenta"))

        # Adaptive IDS
        ids_table = Table(title="🛡️ Adaptive Network IDS", border_style="cyan")
        ids_table.add_column("Metric", style="cyan")
        ids_table.add_column("Value", justify="right", style="white")

        ids_stats = stats["adaptive_ids"]
        ids_table.add_row("Total Scans", f"{ids_stats['total_scans']:,}")
        ids_table.add_row("Threats Detected", f"{ids_stats['threats_detected']:,}")
        ids_table.add_row("Threats Blocked", f"{ids_stats['threats_blocked']:,}")
        ids_table.add_row("Patterns Learned", f"{ids_stats['patterns_learned']:,}")
        ids_table.add_row("Blacklisted IPs", f"{ids_stats['blacklisted_ips']:,}")

        layout["ids"].update(Panel(ids_table, border_style="cyan"))

        # Cookie Scanner
        cookie_table = Table(title="🍪 Cookie Scanner", border_style="green")
        cookie_table.add_column("Metric", style="green")
        cookie_table.add_column("Value", justify="right", style="white")

        cookie_stats = stats["cookie_scanner"]
        cookie_table.add_row("Cookies Scanned", f"{cookie_stats['total_cookies_scanned']:,}")
        cookie_table.add_row("Threats Found", f"{cookie_stats['total_threats_found']:,}")
        cookie_table.add_row("Learned Patterns", f"{cookie_stats['learned_patterns_count']:,}")

        layout["cookies"].update(Panel(cookie_table, border_style="green"))

        # Security Mesh
        mesh_table = Table(title="🌐 Security Mesh", border_style="blue")
        mesh_table.add_column("Metric", style="blue")
        mesh_table.add_column("Value", justify="right", style="white")

        mesh_stats = stats["security_mesh"]
        mesh_table.add_row("Total Nodes", f"{mesh_stats['total_nodes']:,}")
        mesh_table.add_row("Healthy Nodes", f"{mesh_stats['healthy_nodes']:,}")
        mesh_table.add_row("Total Events", f"{mesh_stats['total_events']:,}")
        mesh_table.add_row("Shared IPs", f"{mesh_stats['shared_blacklist_ips']:,}")

        layout["mesh"].update(Panel(mesh_table, border_style="blue"))

        # Universal Protection
        prot_table = Table(title="⚡ Interface Protection", border_style="yellow")
        prot_table.add_column("Metric", style="yellow")
        prot_table.add_column("Value", justify="right", style="white")

        prot_stats = stats["universal_protection"]
        prot_table.add_row("Total Requests", f"{prot_stats['total_requests']:,}")
        prot_table.add_row("Blocked", f"{prot_stats['total_blocked']:,}")
        prot_table.add_row("Threats", f"{prot_stats['total_threats']:,}")

        layout["protection"].update(Panel(prot_table, border_style="yellow"))

        # Footer
        uptime = stats["orchestrator"]["uptime_seconds"]
        footer_text = Text()
        footer_text.append(f"Uptime: {uptime:,}s  ", style="dim")
        footer_text.append("• Status: ", style="dim")
        footer_text.append("OPERATIONAL", style="bold green" if self.is_running else "bold red")
        footer_text.append("  • Press CTRL+C to exit", style="dim")

        layout["footer"].update(Panel(footer_text, border_style="dim"))

    async def run_dashboard(self, refresh_interval: int = 2):
        """Starte Live-Dashboard"""
        if not RICH_AVAILABLE:
            logger.error("Rich library not available for dashboard")
            return

        self.is_running = True
        self.start_time = datetime.utcnow()

        layout = self.create_dashboard_layout()

        with Live(layout, console=self.console, refresh_per_second=1):
            logger.info("🎨 Dashboard started")

            try:
                while True:
                    self.render_dashboard(layout)
                    await asyncio.sleep(refresh_interval)

            except KeyboardInterrupt:
                logger.info("⏹️ Dashboard stopped by user")
            finally:
                self.is_running = False

    async def start_monitoring(self):
        """Starte alle Monitoring-Tasks"""
        self.is_running = True
        self.start_time = datetime.utcnow()

        logger.info("🚀 Starting adaptive security monitoring...")

        # Starte Mesh Heartbeat
        heartbeat_task = asyncio.create_task(mesh_heartbeat(self.security_mesh, interval=30))

        try:
            # Hauptloop
            while True:
                # Periodisches Speichern
                self.adaptive_ids.save_state()
                self.cookie_scanner.save_state()
                self.security_mesh.save_state()

                await asyncio.sleep(60)

        except KeyboardInterrupt:
            logger.info("⏹️ Monitoring stopped by user")
        finally:
            heartbeat_task.cancel()
            self.is_running = False

            # Finales Speichern
            self.adaptive_ids.save_state()
            self.cookie_scanner.save_state()
            self.security_mesh.save_state()


# Global Orchestrator
_orchestrator: Optional[AdaptiveSecurityOrchestrator] = None


def get_orchestrator() -> AdaptiveSecurityOrchestrator:
    """Hole oder erstelle globalen Orchestrator"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AdaptiveSecurityOrchestrator()
    return _orchestrator


async def run_adaptive_security_dashboard():
    """Convenience-Funktion für Dashboard"""
    orchestrator = get_orchestrator()
    await orchestrator.run_dashboard()


async def run_adaptive_security_monitoring():
    """Convenience-Funktion für Headless Monitoring"""
    orchestrator = get_orchestrator()
    await orchestrator.start_monitoring()


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    orchestrator = get_orchestrator()

    if len(sys.argv) > 1 and sys.argv[1] == "dashboard":
        # Dashboard-Modus
        asyncio.run(run_adaptive_security_dashboard())
    else:
        # Report-Modus
        print(orchestrator.generate_master_report())
