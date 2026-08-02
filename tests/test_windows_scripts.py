from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "windows" / "ava_security_framework.ps1"


def test_ava_security_framework_is_read_only_by_default():
    content = SCRIPT_PATH.read_text(encoding="utf-8")

    forbidden_patterns = [
        "Stop-Process",
        "Set-ItemProperty",
        "Disable-NetFirewallRule",
        "Register-ScheduledTask",
        "New-ScheduledTaskAction",
        "New-ScheduledTaskTrigger",
        "reg add",
        "Remove-Item $LOCKFILE",
    ]

    for pattern in forbidden_patterns:
        assert pattern not in content, f"found forbidden pattern {pattern}"

    assert "ReadOnly" in content
    assert "No system changes were performed" in content
