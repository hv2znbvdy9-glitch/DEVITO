"""
AVA Windows Security Lab Integration
=====================================
Integriert das PowerShell Ethical/Blue Team Lab in AVA

Bietet Python-Wrapper für Windows Security Analysis
"""

import asyncio
import json
import logging
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class WindowsSecurityAnalysis:
    """Windows Security Analysis Ergebnis"""

    timestamp: datetime
    analysis_type: str
    findings: Dict[str, Any]
    risk_score: int  # 0-100
    recommendations: List[str]


class WindowsSecurityLab:
    """Windows Security Lab - Python Wrapper"""

    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.lab_script_path = Path(__file__).parent / "windows_ethical_lab.ps1"

        if not self.is_windows:
            logger.warning("Not running on Windows - Lab features limited")

    async def run_powershell_analysis(self, analysis_type: str) -> WindowsSecurityAnalysis:
        """Führe PowerShell Security-Analyse durch"""
        if not self.is_windows:
            return WindowsSecurityAnalysis(
                timestamp=datetime.utcnow(),
                analysis_type=analysis_type,
                findings={"error": "Not running on Windows"},
                risk_score=0,
                recommendations=[],
            )

        # PowerShell Command basierend auf Analyse-Typ
        commands = {
            "system_profiling": """
                $info = Get-ComputerInfo | Select OsName, OsVersion, CsProcessors, CsTotalPhysicalMemory
                $info | ConvertTo-Json
            """,
            "identity_analysis": """
                $users = Get-LocalUser | Select Name, Enabled, LastLogon
                $admins = Get-LocalGroupMember Administrators | Select Name
                @{
                    users = $users
                    admins = $admins
                } | ConvertTo-Json
            """,
            "network_behavior": """
                $conns = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | 
                    Select State, LocalAddress, LocalPort, RemoteAddress, RemotePort -First 20
                $conns | ConvertTo-Json
            """,
            "process_analysis": """
                $procs = Get-Process | Sort CPU -Descending | Select -First 20 Name, Id, CPU, Path
                $procs | ConvertTo-Json
            """,
            "security_controls": """
                try {
                    $defender = Get-MpComputerStatus | 
                        Select AntivirusEnabled, RealTimeProtectionEnabled, TamperProtection
                    $firewall = Get-NetFirewallProfile | 
                        Select Name, Enabled, DefaultInboundAction
                    @{
                        defender = $defender
                        firewall = $firewall
                    } | ConvertTo-Json
                } catch {
                    @{error = $_.Exception.Message} | ConvertTo-Json
                }
            """,
            "log_analysis": """
                try {
                    $events = Get-EventLog Security -Newest 10 | 
                        Select TimeGenerated, EventID, EntryType, Message
                    $events | ConvertTo-Json
                } catch {
                    @{error = $_.Exception.Message} | ConvertTo-Json
                }
            """,
        }

        if analysis_type not in commands:
            raise ValueError(f"Unknown analysis type: {analysis_type}")

        try:
            # Führe PowerShell Command aus
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", commands[analysis_type]],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0 and result.stdout:
                findings = json.loads(result.stdout)
            else:
                findings = {"error": result.stderr or "Unknown error"}

            # Berechne Risk Score
            risk_score = self._calculate_risk_score(analysis_type, findings)

            # Generiere Empfehlungen
            recommendations = self._generate_recommendations(analysis_type, findings)

            return WindowsSecurityAnalysis(
                timestamp=datetime.utcnow(),
                analysis_type=analysis_type,
                findings=findings,
                risk_score=risk_score,
                recommendations=recommendations,
            )

        except subprocess.TimeoutExpired:
            logger.error(f"PowerShell analysis timed out: {analysis_type}")
            return WindowsSecurityAnalysis(
                timestamp=datetime.utcnow(),
                analysis_type=analysis_type,
                findings={"error": "Analysis timed out"},
                risk_score=50,
                recommendations=["Retry analysis", "Check system performance"],
            )
        except Exception as e:
            logger.error(f"PowerShell analysis failed: {e}")
            return WindowsSecurityAnalysis(
                timestamp=datetime.utcnow(),
                analysis_type=analysis_type,
                findings={"error": str(e)},
                risk_score=0,
                recommendations=[],
            )

    def _calculate_risk_score(self, analysis_type: str, findings: Dict) -> int:
        """Berechne Risk Score basierend auf Findings"""
        if "error" in findings:
            return 50  # Unbekannt

        risk = 0

        if analysis_type == "security_controls":
            defender = findings.get("defender", {})

            # Hohe Risks
            if not defender.get("AntivirusEnabled", True):
                risk += 40
            if not defender.get("RealTimeProtectionEnabled", True):
                risk += 30
            if not defender.get("TamperProtection", True):
                risk += 20

            firewall = findings.get("firewall", [])
            for fw in firewall:
                if not fw.get("Enabled", True):
                    risk += 30

        elif analysis_type == "identity_analysis":
            users = findings.get("users", [])
            enabled_users = [u for u in users if u.get("Enabled", False)]

            # Viele aktive Benutzer = höheres Risiko
            if len(enabled_users) > 10:
                risk += 20

            admins = findings.get("admins", [])
            if len(admins) > 3:
                risk += 15

        elif analysis_type == "network_behavior":
            conns = findings if isinstance(findings, list) else []

            # Viele externe Verbindungen
            if len(conns) > 50:
                risk += 25

        return min(risk, 100)

    def _generate_recommendations(self, analysis_type: str, findings: Dict) -> List[str]:
        """Generiere Empfehlungen"""
        recommendations = []

        if "error" in findings:
            recommendations.append("Fix errors before proceeding with analysis")
            return recommendations

        if analysis_type == "security_controls":
            defender = findings.get("defender", {})

            if not defender.get("AntivirusEnabled", True):
                recommendations.append("❗ Enable Windows Defender Antivirus")
            if not defender.get("RealTimeProtectionEnabled", True):
                recommendations.append("❗ Enable Real-Time Protection")
            if not defender.get("TamperProtection", True):
                recommendations.append("⚠️ Enable Tamper Protection")

            firewall = findings.get("firewall", [])
            for fw in firewall:
                if not fw.get("Enabled", True):
                    recommendations.append(
                        f"❗ Enable Firewall for {fw.get('Name', 'unknown')} profile"
                    )

        elif analysis_type == "identity_analysis":
            admins = findings.get("admins", [])
            if len(admins) > 3:
                recommendations.append(
                    "⚠️ Review administrator accounts - too many admins detected"
                )

            users = findings.get("users", [])
            never_logged_in = [u for u in users if not u.get("LastLogon")]
            if never_logged_in:
                recommendations.append(f"Consider removing {len(never_logged_in)} unused accounts")

        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")

        return recommendations

    async def comprehensive_scan(self) -> Dict[str, WindowsSecurityAnalysis]:
        """Führe umfassenden Security Scan durch"""
        logger.info("Starting comprehensive Windows security scan...")

        analyses = {}
        analysis_types = [
            "system_profiling",
            "identity_analysis",
            "network_behavior",
            "process_analysis",
            "security_controls",
            "log_analysis",
        ]

        for analysis_type in analysis_types:
            logger.info(f"Running {analysis_type}...")
            analysis = await self.run_powershell_analysis(analysis_type)
            analyses[analysis_type] = analysis

        return analyses

    def generate_report(self, analyses: Dict[str, WindowsSecurityAnalysis]) -> str:
        """Generiere Security Report"""
        report = """
╔════════════════════════════════════════════════════════════╗
║         AVA Windows Security Lab - Report                  ║
╚════════════════════════════════════════════════════════════╝
"""

        total_risk = 0
        total_recommendations = []

        for analysis_type, analysis in analyses.items():
            report += f"\n{'='*60}\n"
            report += f"{analysis_type.upper().replace('_', ' ')}\n"
            report += f"{'='*60}\n"
            report += f"Timestamp: {analysis.timestamp.isoformat()}\n"
            report += f"Risk Score: {analysis.risk_score}/100\n"

            if analysis.recommendations:
                report += "\nRecommendations:\n"
                for rec in analysis.recommendations:
                    report += f"  • {rec}\n"

            total_risk += analysis.risk_score
            total_recommendations.extend(analysis.recommendations)

        # Overall Score
        avg_risk = total_risk / len(analyses) if analyses else 0
        security_score = 100 - avg_risk

        report += f"\n{'='*60}\n"
        report += "OVERALL ASSESSMENT\n"
        report += f"{'='*60}\n"
        report += f"Security Score: {security_score:.1f}/100\n"
        report += f"Average Risk: {avg_risk:.1f}/100\n"
        report += f"Total Recommendations: {len(set(total_recommendations))}\n"

        if security_score >= 80:
            report += "\n✅ Security posture: GOOD\n"
        elif security_score >= 60:
            report += "\n⚠️ Security posture: MODERATE - Improvements needed\n"
        else:
            report += "\n❌ Security posture: POOR - Immediate action required\n"

        report += "\n╚════════════════════════════════════════════════════════════╝\n"

        return report


# Global instance
_lab: Optional[WindowsSecurityLab] = None


def get_windows_lab() -> WindowsSecurityLab:
    """Get or create global lab instance"""
    global _lab
    if _lab is None:
        _lab = WindowsSecurityLab()
    return _lab


async def run_windows_security_scan():
    """Convenience function to run full scan"""
    lab = get_windows_lab()
    analyses = await lab.comprehensive_scan()
    report = lab.generate_report(analyses)
    print(report)
    return analyses


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if platform.system() != "Windows":
        print("⚠️ This module is designed for Windows systems")
        print("Running in compatibility mode with limited features")

    print("\n🔍 AVA Windows Security Lab - Starting scan...\n")

    asyncio.run(run_windows_security_scan())
