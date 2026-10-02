from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "windows" / "ava_security_framework.ps1"
DEFENSE_SCRIPT_PATH = REPO_ROOT / "scripts" / "windows" / "ava_01610_1_reversible_445_defense.ps1"


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


def test_ava_01610_1_reversible_445_defense_script_integrity():
    assert DEFENSE_SCRIPT_PATH.exists(), f"Defense script not found at {DEFENSE_SCRIPT_PATH}"
    content = DEFENSE_SCRIPT_PATH.read_text(encoding="utf-8")

    # Verify the marker and main concepts
    assert "AVA 01610 1" in content or "AVA 01610-1" in content
    assert "Audit" in content
    assert "Enforce" in content
    assert "Rollback" in content
    assert "VerifyChain" in content

    # Verify steps implementation
    # Step 1: TCP Port 445 monitoring and LanmanServer
    assert "Get-NetTCPConnection" in content
    assert "LanmanServer" in content
    assert "Get-SmbServerConfiguration" in content

    # Step 2: Context validation (Domain vs Private vs Public)
    assert "Get-NetConnectionProfile" in content
    assert "Get-NetFirewallProfile" in content
    assert "Evaluate-DefensePolicy" in content

    # Step 3: Local defense rule creation
    assert "New-NetFirewallRule" in content
    assert "AVA-01610 Block SMB Inbound" in content

    # Step 4: Reversible Rollback
    assert "Remove-NetFirewallRule" in content

    # Step 5: Ledger / Cryptographic Chaining
    assert "Get-AVAStringHash" in content
    assert "chain.jsonl" in content
    assert "PreviousHash" in content
    assert "SHA256" in content or "SHA-256" in content or "sha256" in content


def test_windows_security_monitor_port_445_actions():
    from unittest.mock import patch, MagicMock
    from ava.security.windows_monitor import WindowsSecurityMonitor

    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run") as mock_run:
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "Audit Results"
        mock_run.return_value = mock_process
        
        monitor = WindowsSecurityMonitor()
        assert monitor.is_windows is True
        
        # Test Audit
        res = monitor.audit_port_445()
        assert res == "Audit Results"
        mock_run.assert_called_with(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(DEFENSE_SCRIPT_PATH),
                "-Action", "Audit"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Test Enforce
        monitor.enforce_port_445(output_dir="C:\\temp")
        mock_run.assert_called_with(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(DEFENSE_SCRIPT_PATH),
                "-Action", "Enforce",
                "-OutputDirectory", "C:\\temp"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Test Rollback
        monitor.rollback_port_445()
        mock_run.assert_called_with(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(DEFENSE_SCRIPT_PATH),
                "-Action", "Rollback"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Test VerifyChain
        monitor.verify_port_445_chain()
        mock_run.assert_called_with(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(DEFENSE_SCRIPT_PATH),
                "-Action", "VerifyChain"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

