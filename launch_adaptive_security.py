#!/usr/bin/env python3
"""
AVA Adaptive Security Platform Launcher
========================================
Starte das selbst-lernende, adaptive Sicherheitssystem

Usage:
    python launch_adaptive_security.py [command]
    
Commands:
    status      - Zeige System-Status (default)
    dashboard   - Starte Live-Dashboard
    monitor     - Starte Headless-Monitoring
    scan        - Führe manuelle Scans durch
    report      - Generiere umfassenden Report
    demo        - Demonstrationsmodus
    help        - Zeige Hilfe
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from ava.security.adaptive_ids import get_adaptive_ids, continuous_network_monitoring
from ava.security.cookie_scanner import get_cookie_scanner, Cookie
from ava.security.distributed_mesh import get_security_mesh, NodeType, SecurityNode, SecurityPolicy
from ava.security.universal_protection import get_universal_protection, InterfaceRequest
from ava.security.adaptive_orchestrator import (
    get_orchestrator,
    run_adaptive_security_dashboard,
    run_adaptive_security_monitoring
)

logger = logging.getLogger(__name__)


def print_banner():
    """Zeige Banner"""
    banner = """
╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║       █████╗ ██╗   ██╗ █████╗     █████╗ ██████╗  █████╗ ██████╗ ████████╗   ║
║      ██╔══██╗██║   ██║██╔══██╗   ██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝   ║
║      ███████║██║   ██║███████║   ███████║██║  ██║███████║██████╔╝   ██║      ║
║      ██╔══██║╚██╗ ██╔╝██╔══██║   ██╔══██║██║  ██║██╔══██║██╔═══╝    ██║      ║
║      ██║  ██║ ╚████╔╝ ██║  ██║   ██║  ██║██████╔╝██║  ██║██║        ██║      ║
║      ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝      ║
║                                                                                ║
║               ADAPTIVE SECURITY PLATFORM v4.0 - SELF-LEARNING                 ║
║         ONLINE • OFFLINE • LOCAL • DISTRIBUTED • CLOUD • UNIVERSAL            ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def show_status():
    """Zeige Status"""
    print_banner()
    
    orchestrator = get_orchestrator()
    
    print(orchestrator.generate_master_report())
    
    print("\n✅ All systems operational!")
    print("\nNext steps:")
    print("  • python launch_adaptive_security.py dashboard  - Live dashboard")
    print("  • python launch_adaptive_security.py monitor    - Start monitoring")
    print("  • python launch_adaptive_security.py demo       - Run demo")


async def run_dashboard():
    """Starte Dashboard"""
    print_banner()
    print("🎨 Starting live dashboard...\n")
    print("Press CTRL+C to exit\n")
    
    await run_adaptive_security_dashboard()


async def run_monitoring():
    """Starte Monitoring"""
    print_banner()
    print("🔄 Starting adaptive security monitoring...\n")
    print("Press CTRL+C to stop\n")
    
    await run_adaptive_security_monitoring()


async def run_scan():
    """Führe manuelle Scans durch"""
    print_banner()
    print("🔍 Running manual security scans...\n")
    
    anids = get_adaptive_ids()
    cookie_scanner = get_cookie_scanner()
    protection = get_universal_protection()
    
    print("1️⃣ Network Scan: Checking known hosts...")
    
    # Simuliere Netzwerk-Scans
    test_ips = [
        ("192.168.1.100", "00:11:22:33:44:55", "benign"),
        ("198.51.100.50", "DE:AD:BE:EF:00:00", "malicious"),
        ("10.0.0.5", None, "suspicious")
    ]
    
    for ip, mac, label in test_ips:
        allowed, reason, threat = await anids.scan_address(ip, mac)
        icon = "✅" if allowed else "🚫"
        print(f"  {icon} {ip:20s} [{label:10s}] - {reason}")
        
    print("\n2️⃣ Cookie Scan: Analyzing cookies...")
    
    # Teste Cookies
    test_cookies = [
        Cookie(name="session", value="abc123", secure=True, http_only=True),
        Cookie(name="_ga", value="GA1.2.1234567890.1234567890"),
        Cookie(name="xss_test", value="<script>alert('XSS')</script>"),
    ]
    
    for cookie in test_cookies:
        threats = cookie_scanner.scan_cookie(cookie)
        if threats:
            print(f"  ⚠️ {cookie.name:15s} - {len(threats)} threat(s) detected")
            for threat in threats:
                print(f"      → {threat.threat_type.value}: {threat.description}")
        else:
            print(f"  ✅ {cookie.name:15s} - Clean")
            
    print("\n3️⃣ Interface Protection: Testing requests...")
    
    # Teste Requests
    test_requests = [
        InterfaceRequest(
            interface_type="http",
            method="GET",
            path="/api/users",
            source_ip="192.168.1.100"
        ),
        InterfaceRequest(
            interface_type="http",
            method="POST",
            path="/submit",
            body=b"<script>alert('XSS')</script>",
            source_ip="198.51.100.50"
        ),
    ]
    
    for request in test_requests:
        response = await protection.protect_request(request)
        icon = "✅" if response.action.value == "allow" else "🚫"
        print(f"  {icon} {request.interface_type.upper():10s} {request.method or 'N/A':6s} - {response.action.value}")
        
    print("\n✅ Scan complete!\n")
    
    # Zeige zusammengefassten Report
    orchestrator = get_orchestrator()
    print(orchestrator.generate_master_report())


def generate_report():
    """Generiere umfassenden Report"""
    print_banner()
    
    orchestrator = get_orchestrator()
    print(orchestrator.generate_master_report())
    
    print("\n" + "="*80)
    print("DETAILED SUBSYSTEM REPORTS")
    print("="*80 + "\n")
    
    # Adaptive IDS Report
    anids = get_adaptive_ids()
    print(anids.generate_report())
    
    # Cookie Scanner Report
    cookie_scanner = get_cookie_scanner()
    print(cookie_scanner.generate_report())
    
    # Security Mesh Report
    mesh = get_security_mesh()
    print(mesh.generate_mesh_report())
    
    # Protection Report
    protection = get_universal_protection()
    print(protection.generate_report())


async def run_demo():
    """Demonstrationsmodus"""
    print_banner()
    print("🎭 DEMO MODE - Demonstrating adaptive security capabilities\n")
    
    anids = get_adaptive_ids()
    cookie_scanner = get_cookie_scanner()
    mesh = get_security_mesh()
    protection = get_universal_protection()
    
    print("="*80)
    print("DEMO 1: Adaptive Network Intrusion Detection")
    print("="*80 + "\n")
    
    # Normale IP
    print("Testing normal IP address...")
    allowed, reason, threat = await anids.scan_address(
        ip="192.168.1.100",
        mac="00:11:22:33:44:55",
        ports=[80, 443]
    )
    print(f"Result: {'ALLOWED' if allowed else 'BLOCKED'} - {reason}\n")
    
    # Suspicious MAC
    print("Testing suspicious MAC address (NULL MAC)...")
    allowed, reason, threat = await anids.scan_address(
        ip="192.168.1.101",
        mac="00:00:00:00:00:00",
        ports=[22, 23]
    )
    print(f"Result: {'ALLOWED' if allowed else 'BLOCKED'} - {reason}\n")
    
    # Port Scan Simulation
    print("Simulating port scan (30 ports)...")
    attacker_ip = "203.0.113.50"
    for port in range(1, 31):
        await anids.scan_address(ip=attacker_ip, ports=[port])
    allowed, reason, threat = await anids.scan_address(ip=attacker_ip)
    print(f"Result: {'ALLOWED' if allowed else 'BLOCKED'} - {reason}\n")
    
    print("\n" + "="*80)
    print("DEMO 2: Cookie Security Scanner")
    print("="*80 + "\n")
    
    # XSS Cookie
    print("Testing XSS payload in cookie...")
    xss_cookie = Cookie(name="user_input", value="<script>alert('XSS')</script>")
    threats = cookie_scanner.scan_cookie(xss_cookie)
    print(f"Threats detected: {len(threats)}")
    for threat in threats:
        print(f"  • {threat.threat_type.value} (Severity: {threat.severity}/10)")
    print()
    
    # Tracking Cookie
    print("Testing tracking cookie...")
    tracking_cookie = Cookie(name="_ga", value="GA1.2.123456789.987654321")
    threats = cookie_scanner.scan_cookie(tracking_cookie)
    print(f"Threats detected: {len(threats)}")
    for threat in threats:
        print(f"  • {threat.threat_type.value} (Severity: {threat.severity}/10)")
    print()
    
    print("\n" + "="*80)
    print("DEMO 3: Distributed Security Mesh")
    print("="*80 + "\n")
    
    # Registriere Knoten
    print("Registering edge node...")
    edge_node = SecurityNode(
        node_id="edge_demo_001",
        node_type=NodeType.EDGE,
        hostname="edge-server-demo",
        ip_address="10.0.1.100"
    )
    mesh.register_node(edge_node)
    print(f"✅ Node registered: {edge_node.node_id}\n")
    
    # Teile Bedrohungsinformation
    print("Sharing threat intelligence...")
    mesh.share_blacklist_ip("198.51.100.50", "DDoS attack detected in demo")
    mesh.share_threat_signature("demo_attack_pattern", 8)
    print("✅ Threat intelligence shared across mesh\n")
    
    print("\n" + "="*80)
    print("DEMO 4: Universal Interface Protection")
    print("="*80 + "\n")
    
    # HTTP Request
    print("Testing normal HTTP request...")
    http_request = InterfaceRequest(
        interface_type="http",
        source_ip="192.168.1.100",
        method="GET",
        path="/api/users"
    )
    response = await protection.protect_request(http_request)
    print(f"Action: {response.action.value.upper()} - {response.reason}\n")
    
    # SQL Injection
    print("Testing SQL injection attack...")
    sql_request = InterfaceRequest(
        interface_type="http",
        source_ip="198.51.100.99",
        method="GET",
        path="/users?id=1' OR '1'='1"
    )
    response = await protection.protect_request(sql_request)
    print(f"Action: {response.action.value.upper()} - {response.reason}")
    print(f"Threat Score: {response.threat_score:.1f}/100\n")
    
    # WebSocket Flooding
    print("Simulating WebSocket message flooding (150 messages)...")
    flood_ip = "203.0.113.100"
    for i in range(150):
        ws_request = InterfaceRequest(
            interface_type="websocket",
            source_ip=flood_ip,
            body=b"flood"
        )
        await protection.protect_request(ws_request)
    print("✅ Flooding detected and mitigated\n")
    
    print("\n" + "="*80)
    print("DEMO COMPLETE - Final Statistics")
    print("="*80 + "\n")
    
    orchestrator = get_orchestrator()
    print(orchestrator.generate_master_report())


def show_help():
    """Zeige Hilfe"""
    print(__doc__)
    
    print("\nDetailed Command Information:")
    print("\n  status")
    print("    Shows current status of all security subsystems")
    print("    - Adaptive Network IDS statistics")
    print("    - Cookie Security Scanner statistics")
    print("    - Distributed Security Mesh status")
    print("    - Universal Interface Protection metrics")
    print("    - Global security score (0-100)")
    
    print("\n  dashboard")
    print("    Starts a live, auto-refreshing terminal dashboard")
    print("    - Real-time statistics from all subsystems")
    print("    - Visual representation with colors and tables")
    print("    - Updates every 2 seconds")
    print("    - Press CTRL+C to exit")
    
    print("\n  monitor")
    print("    Starts headless monitoring mode (no UI)")
    print("    - Continuous background monitoring")
    print("    - Periodic state saving")
    print("    - Mesh heartbeat")
    print("    - Logs to console")
    
    print("\n  scan")
    print("    Performs manual security scans")
    print("    - Network address scanning")
    print("    - Cookie security analysis")
    print("    - Interface protection testing")
    print("    - Generates report after completion")
    
    print("\n  report")
    print("    Generates comprehensive security report")
    print("    - Master report with all subsystems")
    print("    - Detailed per-subsystem reports")
    print("    - Statistics and metrics")
    
    print("\n  demo")
    print("    Runs demonstration mode")
    print("    - Shows all security features in action")
    print("    - Simulates various attacks")
    print("    - Demonstrates self-learning capabilities")
    
    print("\n  help")
    print("    Shows this help message")
    
    print("\n\nExamples:")
    print("  python launch_adaptive_security.py")
    print("  python launch_adaptive_security.py dashboard")
    print("  python launch_adaptive_security.py scan")
    print("  python launch_adaptive_security.py demo")


def main():
    """Hauptfunktion"""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse command
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    
    if command == "status":
        show_status()
        
    elif command == "dashboard":
        asyncio.run(run_dashboard())
        
    elif command == "monitor":
        asyncio.run(run_monitoring())
        
    elif command == "scan":
        asyncio.run(run_scan())
        
    elif command == "report":
        generate_report()
        
    elif command == "demo":
        asyncio.run(run_demo())
        
    elif command == "help":
        show_help()
        
    else:
        print(f"Unknown command: {command}")
        print("Run 'python launch_adaptive_security.py help' for usage information")
        sys.exit(1)


if __name__ == "__main__":
    main()
