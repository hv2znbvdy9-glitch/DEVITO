"""Tests for real system and network state collection."""

from datetime import datetime
from types import SimpleNamespace

import ava.monitoring.real_state as real_state


class FakeProcess:
    """Simple psutil process stub."""

    def __init__(self, name, exe):
        self.info = {"name": name, "exe": exe}


def test_collect_system_flags_non_safe_temp_process(monkeypatch) -> None:
    """collect_system returns suspicious temp executions."""
    fake_psutil = SimpleNamespace(
        cpu_percent=lambda: 12.5,
        virtual_memory=lambda: SimpleNamespace(percent=48.0),
        process_iter=lambda attrs: [
            FakeProcess("code.exe", r"C:\Users\dev\AppData\Local\Temp\code.exe"),
            FakeProcess("malware.exe", r"C:\Temp\malware.exe"),
            FakeProcess("svc.exe", r"C:\Windows\svc.exe"),
        ],
        NoSuchProcess=RuntimeError,
        AccessDenied=PermissionError,
        ZombieProcess=RuntimeError,
    )

    monkeypatch.setattr(real_state, "psutil", fake_psutil)

    cpu, ram, processes, suspicious = real_state.collect_system()

    assert cpu == 12.5
    assert ram == 48.0
    assert processes == ["code.exe", "malware.exe", "svc.exe"]
    assert suspicious == [("malware.exe", r"C:\Temp\malware.exe")]


def test_collect_network_deduplicates_remote_ips(monkeypatch) -> None:
    """collect_network returns unique remote IPs only."""
    connections = [
        SimpleNamespace(raddr=SimpleNamespace(ip="8.8.8.8")),
        SimpleNamespace(raddr=SimpleNamespace(ip="10.0.0.2")),
        SimpleNamespace(raddr=SimpleNamespace(ip="10.0.0.2")),
        SimpleNamespace(raddr=()),
    ]

    monkeypatch.setattr(real_state.psutil, "net_connections", lambda: connections)

    collected_connections, remote_ips = real_state.collect_network()

    assert collected_connections == connections
    assert remote_ips == ["10.0.0.2", "8.8.8.8"]


def test_build_report_combines_system_and_network_alerts() -> None:
    """build_report combines system and network analysis into one state."""
    report = real_state.build_report(
        cpu=90.0,
        ram=20.0,
        processes=["proc-{0}".format(index) for index in range(181)],
        suspicious=[("bad.exe", r"C:\Temp\bad.exe")],
        connections=[object()] * 81,
        remote_ips=["8.8.8.8", "10.0.0.9"],
    )

    assert report.score == -1
    assert report.state == "WATCH"
    assert ("WATCH", "High CPU: 90.0%") in report.alerts
    assert ("CRITICAL", "Temp execution: bad.exe") in report.alerts
    assert ("INFO", "Safe: 8.8.8.8 (Google DNS)") in report.alerts
    assert ("WATCH", "Unknown IP: 10.0.0.9") in report.alerts
    assert ("WATCH", "Many connections: 81") in report.alerts


def test_render_outputs_report_summary() -> None:
    """render returns a formatted report string."""
    report = real_state.RealStateReport(
        score=2,
        state="STRONG",
        cpu=11.0,
        ram=22.0,
        alerts=[("INFO", "Safe: 8.8.8.8 (Google DNS)")],
    )

    rendered = real_state.render(report, now=datetime(2024, 1, 2, 3, 4, 5))

    assert "AVA v2 - REAL STATE ENGINE" in rendered
    assert "TIME       : 2024-01-02 03:04:05" in rendered
    assert "STATE      : STRONG" in rendered
    assert "[INFO] Safe: 8.8.8.8 (Google DNS)" in rendered
