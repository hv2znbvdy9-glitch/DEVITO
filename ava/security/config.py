# AVA Security Configuration

# Blocked processes (remote access tools)
BLOCKED_PROCESSES = [
    "mstsc",
    "rdpclip",
    "teamviewer",
    "anydesk",
    "rustdesk",
    "vnc",
    "tightvnc",
    "ultravnc",
    "realvnc",
    "scrcpy",
    "msra",
    "quickassist",
    "mirror",
    "chrome_remote_desktop",
    "ammyy",
    "supremo",
    "logmein",
    "gotomypc",
    "screenconnect",
]

# Critical ports to monitor
CRITICAL_PORTS = [
    3389,  # RDP
    445,  # SMB
    135,  # RPC
    139,  # NetBIOS
    5900,  # VNC
    5901,  # VNC
    22,  # SSH (if unexpected)
]

# Security scan intervals (seconds)
SCAN_INTERVAL = 300  # 5 minutes

# Log settings
LOG_MAX_SIZE_MB = 5
LOG_RETENTION_DAYS = 30

# Evidence collection
EVIDENCE_DIR = "/var/log/ava/evidence"  # Linux
EVIDENCE_DIR_WINDOWS = "C:\\ProgramData\\AVA\\Evidence"  # Windows

# MITRE ATT&CK Detection Rules
DETECTION_RULES = {
    "T1110": {"name": "Brute Force", "event_id": 4625, "threshold": 5, "severity": "MEDIUM"},
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "event_id": 4688,
        "match": ["powershell", "cmd.exe", "wscript"],
        "threshold": 1,
        "severity": "HIGH",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "event_id": 4697,
        "threshold": 1,
        "severity": "HIGH",
    },
    "T1078": {"name": "Valid Accounts", "event_id": 4672, "threshold": 3, "severity": "CRITICAL"},
}

# Alert thresholds
ALERT_THRESHOLDS = {
    "failed_logins": 5,
    "process_start_rate": 50,  # per minute
    "network_connections": 100,
}

# Windows Defender monitoring
DEFENDER_CHECK_ENABLED = True

# Firewall monitoring
FIREWALL_CHECK_ENABLED = True

# RDP auto-disable
RDP_AUTO_DISABLE = True
