"""Real system and network state collection utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Optional, Sequence, Tuple

import psutil

KNOWN_SAFE_IPS = {
    "8.8.8.8": "Google DNS",
    "1.1.1.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
}

KNOWN_SAFE_PROCESSES = [
    "explorer.exe",
    "svchost.exe",
    "chrome.exe",
    "code.exe",
    "powershell.exe",
    "system",
]

STATE_NAMES = {
    -3: "FAIL",
    -2: "CRITICAL",
    -1: "WATCH",
    0: "NEUTRAL",
    1: "STABLE",
    2: "STRONG",
    3: "OPTIMAL",
}

Alert = Tuple[str, str]
SuspiciousProcess = Tuple[str, str]


@dataclass(frozen=True)
class RealStateReport:
    """Combined snapshot of a single system and network sample."""

    score: int
    state: str
    cpu: float
    ram: float
    alerts: List[Alert]


def clamp(value: int) -> int:
    """Clamp the score to the supported range."""
    return max(-3, min(3, value))


def collect_system() -> Tuple[float, float, List[str], List[SuspiciousProcess]]:
    """Collect CPU, RAM, process names, and suspicious temp executions."""
    cpu = float(psutil.cpu_percent())
    ram = float(psutil.virtual_memory().percent)
    processes: List[str] = []
    suspicious: List[SuspiciousProcess] = []
    safe_processes = {name.lower() for name in KNOWN_SAFE_PROCESSES}

    for process in psutil.process_iter(["name", "exe"]):
        try:
            name = process.info.get("name") or "<unknown>"
            exe = process.info.get("exe") or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue

        processes.append(name)

        if exe and "temp" in exe.lower() and name.lower() not in safe_processes:
            suspicious.append((name, exe))

    return cpu, ram, processes, suspicious


def collect_network() -> Tuple[Sequence[Any], List[str]]:
    """Collect network connections and the distinct remote IPs in use."""
    connections = psutil.net_connections()
    remote_ips = set()

    for connection in connections:
        raddr = getattr(connection, "raddr", None)
        ip = getattr(raddr, "ip", None)
        if ip:
            remote_ips.add(ip)

    return connections, sorted(remote_ips)


def analyze_system(
    cpu: float,
    ram: float,
    processes: Sequence[str],
    suspicious: Sequence[SuspiciousProcess],
) -> Tuple[int, List[Alert]]:
    """Calculate the system score and generated alerts."""
    score = 2
    alerts: List[Alert] = []

    if cpu > 85:
        score -= 1
        alerts.append(("WATCH", "High CPU: {0}%".format(cpu)))

    if ram > 85:
        score -= 1
        alerts.append(("WATCH", "High RAM: {0}%".format(ram)))

    if len(processes) > 180:
        score -= 1
        alerts.append(("WATCH", "High process count"))

    for name, _exe in suspicious:
        score -= 2
        alerts.append(("CRITICAL", "Temp execution: {0}".format(name)))

    return clamp(score), alerts


def analyze_network(connections: Sequence[Any], remote_ips: Sequence[str]) -> Tuple[int, List[Alert]]:
    """Calculate the network score and generated alerts."""
    score = 2
    alerts: List[Alert] = []

    for ip in remote_ips:
        if ip in KNOWN_SAFE_IPS:
            alerts.append(("INFO", "Safe: {0} ({1})".format(ip, KNOWN_SAFE_IPS[ip])))
        else:
            score -= 1
            alerts.append(("WATCH", "Unknown IP: {0}".format(ip)))

    if len(connections) > 80:
        score -= 1
        alerts.append(("WATCH", "Many connections: {0}".format(len(connections))))

    return clamp(score), alerts


def build_report(
    *,
    cpu: Optional[float] = None,
    ram: Optional[float] = None,
    processes: Optional[Sequence[str]] = None,
    suspicious: Optional[Sequence[SuspiciousProcess]] = None,
    connections: Optional[Sequence[Any]] = None,
    remote_ips: Optional[Sequence[str]] = None,
) -> RealStateReport:
    """Build a single combined state report from live or injected data."""
    if cpu is None or ram is None or processes is None or suspicious is None:
        cpu, ram, processes, suspicious = collect_system()

    if connections is None or remote_ips is None:
        connections, remote_ips = collect_network()

    system_score, system_alerts = analyze_system(cpu, ram, processes, suspicious)
    network_score, network_alerts = analyze_network(connections, remote_ips)
    final_score = clamp(round((system_score + network_score) / 2))

    return RealStateReport(
        score=final_score,
        state=STATE_NAMES[final_score],
        cpu=cpu,
        ram=ram,
        alerts=system_alerts + network_alerts,
    )


def render(report: RealStateReport, now: Optional[datetime] = None) -> str:
    """Render a human-readable report."""
    lines = [
        "",
        "=" * 60,
        "AVA v2 - REAL STATE ENGINE",
        "=" * 60,
        "TIME       : {0}".format(now or datetime.now()),
        "CPU        : {0}%".format(report.cpu),
        "RAM        : {0}%".format(report.ram),
        "SCORE      : {0}".format(report.score),
        "STATE      : {0}".format(report.state),
        "",
        "ALERTS:",
    ]

    for severity, message in report.alerts[:10]:
        lines.append("[{0}] {1}".format(severity, message))

    return "\n".join(lines)
