"""
AVA Security Orchestration, Automation and Response (SOAR)
===========================================================
Unified security operations dashboard and orchestration platform.

Features:
- Centralized security monitoring
- Cross-system correlation
- Automated response orchestration
- Real-time threat dashboard
- Security metrics & KPIs
- Compliance reporting
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich import box

# Import AVA security modules
try:
    from .threat_intelligence import get_threat_intelligence
    from .zero_trust import ZeroTrustEngine
    from .incident_response import get_incident_response_system
    from .network_defense import get_defense_engine
except ImportError:
    # Fallback for standalone execution
    pass

logger = logging.getLogger(__name__)


class SecurityOrchestrator:
    """Main security orchestration engine"""

    def __init__(self):
        self.console = Console()
        self.running = False

        # Initialize security components
        try:
            self.threat_intel = get_threat_intelligence()
            self.zero_trust = ZeroTrustEngine()
            self.incident_response = get_incident_response_system()
            self.network_defense = get_defense_engine()
        except Exception as e:
            logger.warning(f"Some security modules not available: {e}")
            self.threat_intel = None
            self.zero_trust = None
            self.incident_response = None
            self.network_defense = None

        self.metrics = {
            "uptime_start": datetime.utcnow(),
            "total_threats_detected": 0,
            "total_incidents": 0,
            "total_blocked_ips": 0,
            "total_access_requests": 0,
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        uptime = datetime.utcnow() - self.metrics["uptime_start"]

        status = {
            "uptime_seconds": int(uptime.total_seconds()),
            "timestamp": datetime.utcnow().isoformat(),
            "components": {},
        }

        # Threat Intelligence status
        if self.threat_intel:
            ti_report = self.threat_intel.generate_threat_report()
            status["components"]["threat_intelligence"] = {
                "status": "operational",
                "total_events": ti_report["total_events"],
                "ioc_database_size": ti_report["ioc_database_size"],
            }
        else:
            status["components"]["threat_intelligence"] = {"status": "unavailable"}

        # Zero Trust status
        if self.zero_trust:
            zt_stats = self.zero_trust.get_access_statistics()
            status["components"]["zero_trust"] = {
                "status": "operational",
                "total_requests": zt_stats["total_requests"],
                "grant_rate": f"{zt_stats['grant_rate']:.1f}%",
                "total_users": zt_stats["total_users"],
            }
        else:
            status["components"]["zero_trust"] = {"status": "unavailable"}

        # Incident Response status
        if self.incident_response:
            ir_stats = self.incident_response.get_statistics()
            status["components"]["incident_response"] = {
                "status": "operational",
                "total_incidents": ir_stats["total_incidents"],
                "total_playbooks": ir_stats["total_playbooks"],
            }
        else:
            status["components"]["incident_response"] = {"status": "unavailable"}

        # Network Defense status
        if self.network_defense:
            nd_stats = self.network_defense.get_statistics()
            status["components"]["network_defense"] = {
                "status": "operational",
                "packets_inspected": nd_stats["total_packets_inspected"],
                "packets_blocked": nd_stats["packets_blocked"],
                "blocked_ips": nd_stats["blocked_ips"],
                "total_alerts": nd_stats["total_alerts"],
            }
        else:
            status["components"]["network_defense"] = {"status": "unavailable"}

        return status

    def get_security_score(self) -> int:
        """Calculate overall security posture score (0-100)"""
        score = 100

        if self.threat_intel:
            ti_report = self.threat_intel.generate_threat_report()
            critical_events = ti_report["events_by_level"].get("CRITICAL", 0)
            score -= min(critical_events * 5, 30)  # Max -30 for critical events

        if self.zero_trust:
            zt_stats = self.zero_trust.get_access_statistics()
            if zt_stats["grant_rate"] < 50:
                score -= 10  # Many denied access attempts

        if self.incident_response:
            ir_stats = self.incident_response.get_statistics()
            open_incidents = sum(
                count
                for status, count in ir_stats["by_status"].items()
                if status not in ["resolved", "closed"]
            )
            score -= min(open_incidents * 3, 20)  # Max -20 for open incidents

        if self.network_defense:
            nd_stats = self.network_defense.get_statistics()
            if nd_stats["blocked_ips"] > 10:
                score -= 10  # High number of blocked IPs

        return max(0, min(100, score))

    def create_dashboard_layout(self) -> Layout:
        """Create dashboard layout"""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3), Layout(name="body"), Layout(name="footer", size=3)
        )

        layout["body"].split_row(Layout(name="left"), Layout(name="right"))

        layout["left"].split_column(Layout(name="threats"), Layout(name="network"))

        layout["right"].split_column(Layout(name="incidents"), Layout(name="access"))

        return layout

    def create_header(self) -> Panel:
        """Create dashboard header"""
        score = self.get_security_score()

        if score >= 90:
            score_color = "green"
            status_emoji = "🟢"
        elif score >= 70:
            score_color = "yellow"
            status_emoji = "🟡"
        else:
            score_color = "red"
            status_emoji = "🔴"

        uptime = datetime.utcnow() - self.metrics["uptime_start"]
        uptime_str = str(uptime).split(".")[0]  # Remove microseconds

        header_text = f"""
[bold cyan]AVA Security Operations Center (SOC)[/bold cyan]  
{status_emoji} Security Score: [{score_color}]{score}/100[/{score_color}] | Uptime: {uptime_str} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """.strip()

        return Panel(header_text, box=box.DOUBLE)

    def create_threats_panel(self) -> Panel:
        """Create threat intelligence panel"""
        if not self.threat_intel:
            return Panel("[red]Threat Intelligence: Unavailable[/red]", title="🎯 Threats")

        ti_report = self.threat_intel.generate_threat_report()

        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        table.add_column("Level", style="cyan")
        table.add_column("Count", justify="right")

        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = ti_report["events_by_level"].get(level, 0)
            if count > 0:
                table.add_row(level, str(count))

        return Panel(table, title="🎯 Threat Intelligence", border_style="cyan")

    def create_network_panel(self) -> Panel:
        """Create network defense panel"""
        if not self.network_defense:
            return Panel("[red]Network Defense: Unavailable[/red]", title="🛡️ Network")

        nd_stats = self.network_defense.get_statistics()

        content = f"""
[cyan]Packets Inspected:[/cyan] {nd_stats['total_packets_inspected']:,}
[yellow]Packets Blocked:[/yellow] {nd_stats['packets_blocked']:,}
[red]Blocked IPs:[/red] {nd_stats['blocked_ips']}
[orange1]Active Alerts:[/orange1] {nd_stats['total_alerts']}
        """.strip()

        return Panel(content, title="🛡️ Network Defense", border_style="green")

    def create_incidents_panel(self) -> Panel:
        """Create incident response panel"""
        if not self.incident_response:
            return Panel("[red]Incident Response: Unavailable[/red]", title="🚨 Incidents")

        ir_stats = self.incident_response.get_statistics()

        table = Table(show_header=True, header_style="bold red", box=box.SIMPLE)
        table.add_column("Status", style="cyan")
        table.add_column("Count", justify="right")

        for status, count in ir_stats["by_status"].items():
            table.add_row(status.title(), str(count))

        return Panel(table, title="🚨 Incident Response", border_style="red")

    def create_access_panel(self) -> Panel:
        """Create access control panel"""
        if not self.zero_trust:
            return Panel("[red]Zero Trust: Unavailable[/red]", title="🔐 Access")

        zt_stats = self.zero_trust.get_access_statistics()

        content = f"""
[cyan]Total Requests:[/cyan] {zt_stats['total_requests']:,}
[green]Granted:[/green] {zt_stats['granted']:,} ({zt_stats['grant_rate']:.1f}%)
[red]Denied:[/red] {zt_stats['denied']:,}
[yellow]Active Users:[/yellow] {zt_stats['total_users']}
[blue]Registered Devices:[/blue] {zt_stats['total_devices']}
        """.strip()

        return Panel(content, title="🔐 Zero Trust Access", border_style="blue")

    def create_footer(self) -> Panel:
        """Create dashboard footer"""
        footer_text = "[dim]Press Ctrl+C to exit | AVA Security Platform v3.0[/dim]"
        return Panel(footer_text, box=box.SIMPLE)

    def render_dashboard(self, layout: Layout):
        """Render dashboard content"""
        layout["header"].update(self.create_header())
        layout["threats"].update(self.create_threats_panel())
        layout["network"].update(self.create_network_panel())
        layout["incidents"].update(self.create_incidents_panel())
        layout["access"].update(self.create_access_panel())
        layout["footer"].update(self.create_footer())

    async def run_dashboard(self, refresh_interval: float = 2.0):
        """Run live dashboard"""
        self.running = True
        layout = self.create_dashboard_layout()

        try:
            with Live(layout, console=self.console, refresh_per_second=4, screen=True):
                while self.running:
                    self.render_dashboard(layout)
                    await asyncio.sleep(refresh_interval)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Dashboard stopped[/yellow]")
            self.running = False

    def print_status_report(self):
        """Print status report to console"""
        self.console.print("\n[bold cyan]═══════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]  AVA Security Operations Center - Status  [/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════════[/bold cyan]\n")

        status = self.get_system_status()
        score = self.get_security_score()

        # Overall status
        if score >= 90:
            score_emoji = "🟢"
            rating = "[green]EXCELLENT[/green]"
        elif score >= 70:
            score_emoji = "🟡"
            rating = "[yellow]GOOD[/yellow]"
        else:
            score_emoji = "🔴"
            rating = "[red]NEEDS ATTENTION[/red]"

        self.console.print(f"{score_emoji} [bold]Security Posture:[/bold] {rating} ({score}/100)\n")

        # Component status
        self.console.print("[bold]Component Status:[/bold]")
        for component, info in status["components"].items():
            status_icon = "✅" if info["status"] == "operational" else "❌"
            self.console.print(
                f"  {status_icon} {component.replace('_', ' ').title()}: {info['status']}"
            )

        self.console.print()

        # Detailed stats
        if self.threat_intel:
            ti_report = self.threat_intel.generate_threat_report()
            self.console.print("[bold]🎯 Threat Intelligence:[/bold]")
            self.console.print(f"  Total Events: {ti_report['total_events']}")
            self.console.print(f"  IOC Database Size: {ti_report['ioc_database_size']}")
            self.console.print(
                f"  MITRE Techniques Detected: {len(ti_report['detected_mitre_techniques'])}\n"
            )

        if self.network_defense:
            nd_stats = self.network_defense.get_statistics()
            self.console.print("[bold]🛡️ Network Defense:[/bold]")
            self.console.print(f"  Packets Inspected: {nd_stats['total_packets_inspected']:,}")
            self.console.print(f"  Packets Blocked: {nd_stats['packets_blocked']:,}")
            self.console.print(f"  Blocked IPs: {nd_stats['blocked_ips']}\n")

        if self.incident_response:
            ir_stats = self.incident_response.get_statistics()
            self.console.print("[bold]🚨 Incident Response:[/bold]")
            self.console.print(f"  Total Incidents: {ir_stats['total_incidents']}")
            self.console.print(f"  Active Playbooks: {ir_stats['total_playbooks']}\n")

        if self.zero_trust:
            zt_stats = self.zero_trust.get_access_statistics()
            self.console.print("[bold]🔐 Zero Trust:[/bold]")
            self.console.print(f"  Access Requests: {zt_stats['total_requests']}")
            self.console.print(f"  Grant Rate: {zt_stats['grant_rate']:.1f}%")
            self.console.print(f"  Active Users: {zt_stats['total_users']}\n")

        self.console.print("[bold cyan]═══════════════════════════════════════════[/bold cyan]\n")


# Global orchestrator instance
_orchestrator: Optional[SecurityOrchestrator] = None


def get_orchestrator() -> SecurityOrchestrator:
    """Get or create global orchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SecurityOrchestrator()
    return _orchestrator


async def main():
    """Main entry point"""
    import sys

    orchestrator = get_orchestrator()

    if len(sys.argv) > 1 and sys.argv[1] == "dashboard":
        # Run live dashboard
        await orchestrator.run_dashboard()
    else:
        # Print status report
        orchestrator.print_status_report()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)  # Reduce noise in dashboard

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
