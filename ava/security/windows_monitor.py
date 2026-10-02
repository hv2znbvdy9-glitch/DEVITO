"""
AVA Windows Security Monitor - Python Implementation
Cross-platform security monitoring with Windows-specific features
"""

import subprocess
import json
import logging
import platform
from typing import Dict, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class WindowsSecurityMonitor:
    """Windows-specific security monitoring."""

    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.blocked_processes = [
            "mstsc",
            "rdpclip",
            "teamviewer",
            "anydesk",
            "rustdesk",
            "vnc",
            "scrcpy",
            "msra",
            "quickassist",
            "mirror",
            "chrome_remote_desktop",
        ]

    def check_blocked_processes(self) -> List[Dict]:
        """Check for blocked remote access processes."""
        if not self.is_windows:
            logger.warning("Not running on Windows - skipping process check")
            return []

        alerts = []
        try:
            # Use PowerShell to get process list
            cmd = [
                "powershell",
                "-Command",
                "Get-Process | Select-Object Name, Id, Path | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                processes = json.loads(result.stdout)
                if not isinstance(processes, list):
                    processes = [processes]

                for proc in processes:
                    proc_name = proc.get("Name", "").lower()
                    for blocked in self.blocked_processes:
                        if blocked in proc_name:
                            alerts.append(
                                {
                                    "type": "blocked_process",
                                    "name": proc.get("Name"),
                                    "pid": proc.get("Id"),
                                    "path": proc.get("Path"),
                                    "timestamp": datetime.now().isoformat(),
                                }
                            )
                            logger.warning(
                                f"Blocked process detected: {proc.get('Name')} [PID: {proc.get('Id')}]"
                            )

        except Exception as e:
            logger.error(f"Error checking processes: {e}")

        return alerts

    def get_security_status(self) -> Dict:
        """Get Windows security status."""
        if not self.is_windows:
            return {"platform": platform.system(), "windows_features": False}

        status = {
            "platform": "Windows",
            "timestamp": datetime.now().isoformat(),
            "defender_enabled": False,
            "firewall_enabled": False,
            "rdp_enabled": True,  # Assume enabled until checked
        }

        try:
            # Windows Defender status
            cmd = [
                "powershell",
                "-Command",
                "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                defender_status = json.loads(result.stdout)
                status["defender_enabled"] = defender_status.get("RealTimeProtectionEnabled", False)

        except Exception as e:
            logger.error(f"Error checking Windows Defender: {e}")

        try:
            # Firewall status
            cmd = [
                "powershell",
                "-Command",
                "Get-NetFirewallProfile -Profile Domain | Select-Object Enabled | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                firewall_status = json.loads(result.stdout)
                status["firewall_enabled"] = firewall_status.get("Enabled", False)

        except Exception as e:
            logger.error(f"Error checking Firewall: {e}")

        return status

    def _run_defense_script(self, action: str, output_dir: str = "") -> str:
        """Helper to run the AVA-01610-1 Port 445 defense script."""
        if not self.is_windows:
            logger.warning("Not running on Windows")
            return ""

        script_path = Path(__file__).resolve().parents[2] / "scripts" / "windows" / "ava_01610_1_reversible_445_defense.ps1"
        if not script_path.exists():
            logger.error(f"Defense script not found at {script_path}")
            return ""

        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script_path),
            "-Action", action
        ]
        if output_dir:
            cmd.extend(["-OutputDirectory", output_dir])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"Error running defense script for action {action}: {result.stderr}")
                return ""
        except Exception as e:
            logger.error(f"Exception running defense script: {e}")
            return ""

    def audit_port_445(self, output_dir: str = "") -> str:
        """Audit Port 445 status."""
        return self._run_defense_script("Audit", output_dir)

    def enforce_port_445(self, output_dir: str = "") -> str:
        """Enforce local firewall Port 445 blocking."""
        return self._run_defense_script("Enforce", output_dir)

    def rollback_port_445(self, output_dir: str = "") -> str:
        """Rollback local firewall Port 445 blocking."""
        return self._run_defense_script("Rollback", output_dir)

    def verify_port_445_chain(self, output_dir: str = "") -> str:
        """Verify Port 445 immutable chain integrity."""
        return self._run_defense_script("VerifyChain", output_dir)

    def disable_rdp(self) -> bool:
        """Disable RDP access (requires admin)."""
        if not self.is_windows:
            logger.warning("Not running on Windows")
            return False

        try:
            cmd = [
                "powershell",
                "-Command",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
                "-Name fDenyTSConnections -Value 1",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logger.info("RDP disabled successfully")
                return True
            else:
                logger.error(f"Failed to disable RDP: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error disabling RDP: {e}")
            return False

    def kill_blocked_process(self, pid: int) -> bool:
        """Kill a blocked process by PID."""
        if not self.is_windows:
            return False

        try:
            cmd = ["taskkill", "/F", "/PID", str(pid)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logger.info(f"Killed process PID {pid}")
                return True
            else:
                logger.error(f"Failed to kill PID {pid}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error killing process: {e}")
            return False

    def export_evidence(self, output_dir: Path) -> Dict:
        """Export security evidence to directory."""
        output_dir.mkdir(parents=True, exist_ok=True)

        evidence = {
            "timestamp": datetime.now().isoformat(),
            "platform": platform.system(),
            "files": [],
        }

        if not self.is_windows:
            return evidence

        try:
            # Export process list
            cmd = [
                "powershell",
                "-Command",
                "Get-Process | Select-Object Name, Id, Path, StartTime | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                process_file = output_dir / "processes.json"
                process_file.write_text(result.stdout, encoding="utf-8")
                evidence["files"].append(str(process_file))

        except Exception as e:
            logger.error(f"Error exporting evidence: {e}")

        return evidence


# Cross-platform security utilities
class SecurityMonitor:
    """Cross-platform security monitoring."""

    def __init__(self):
        self.platform = platform.system()
        self.windows_monitor = WindowsSecurityMonitor() if self.platform == "Windows" else None

    def run_security_scan(self) -> Dict:
        """Run comprehensive security scan."""
        scan_results = {
            "timestamp": datetime.now().isoformat(),
            "platform": self.platform,
            "alerts": [],
            "status": {},
        }

        if self.platform == "Windows" and self.windows_monitor:
            # Windows-specific checks
            scan_results["alerts"] = self.windows_monitor.check_blocked_processes()
            scan_results["status"] = self.windows_monitor.get_security_status()
        else:
            # Unix-like systems
            scan_results["status"] = self._get_unix_security_status()

        return scan_results

    def _get_unix_security_status(self) -> Dict:
        """Get security status for Unix-like systems."""
        status = {"platform": self.platform, "timestamp": datetime.now().isoformat()}

        try:
            # Check if firewall is active (ufw/iptables)
            result = subprocess.run(["which", "ufw"], capture_output=True, timeout=5)
            if result.returncode == 0:
                ufw_status = subprocess.run(
                    ["sudo", "ufw", "status"], capture_output=True, text=True, timeout=5
                )
                status["firewall"] = "active" in ufw_status.stdout.lower()

        except Exception as e:
            logger.debug(f"Firewall check not available: {e}")

        return status


if __name__ == "__main__":
    # Demo
    logging.basicConfig(level=logging.INFO)

    monitor = SecurityMonitor()
    results = monitor.run_security_scan()

    print(json.dumps(results, indent=2))
