#!/usr/bin/env python3
"""
AVA Security Platform Launcher
===============================
Unified launcher for all AVA security components.

Usage:
    python launch_security.py              # Status report
    python launch_security.py dashboard    # Live dashboard
    python launch_security.py hunt         # Run threat hunt
    python launch_security.py demo         # Run full demo
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from ava.security.orchestrator import get_orchestrator
from ava.security.threat_intelligence import get_threat_intelligence, ThreatIndicator, ThreatLevel, ThreatCategory
from ava.security.zero_trust import ZeroTrustEngine, User, Device, AccessContext
from ava.security.incident_response import get_incident_response_system, Incident, IncidentSeverity
from ava.security.network_defense import get_defense_engine, NetworkPacket

from datetime import datetime
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def run_threat_hunt():
    """Run active threat hunting"""
    print("\n🔍 Starting Threat Hunting...\n")
    
    ti = get_threat_intelligence()
    
    # Run threat hunt
    threats = await ti.hunt_threats()
    
    print(f"✅ Detected {len(threats)} threats\n")
    
    for i, threat in enumerate(threats[:10], 1):
        print(f"{i}. {threat.description}")
        print(f"   Level: {threat.threat_level.name} | Category: {threat.category.value}")
        
    # Generate report
    report = ti.generate_threat_report()
    print(f"\n📊 Total Events: {report['total_events']}")
    print(f"📊 IOC Database: {report['ioc_database_size']} indicators")
    print(f"📊 MITRE Techniques: {len(report['detected_mitre_techniques'])}")


async def run_demo():
    """Run comprehensive security demo"""
    print("\n🚀 AVA Security Platform - Full Demo\n")
    print("=" * 60)
    
    # Initialize components
    ti = get_threat_intelligence()
    zt = ZeroTrustEngine()
    irs = get_incident_response_system()
    nd = get_defense_engine()
    
    # Demo 1: Add threat indicators
    print("\n1️⃣  Adding Threat Indicators...")
    ti.add_ioc(ThreatIndicator(
        indicator_type="ip",
        value="192.0.2.42",
        threat_level=ThreatLevel.HIGH,
        category=ThreatCategory.MALWARE,
        confidence=0.95,
        source="demo_feed"
    ))
    print("   ✅ Malicious IP added to IOC database")
    
    # Demo 2: Zero Trust Access
    print("\n2️⃣  Testing Zero Trust Access Control...")
    
    # Register user
    user = User(
        user_id="demo_001",
        username="demo_user",
        email="demo@example.com",
        roles=["developer"],
        mfa_enabled=True
    )
    zt.register_user(user)
    
    # Register device
    device = Device(
        device_id="device_001",
        device_type="workstation",
        os="Linux",
        fingerprint="demo_fp_123",
        owner="demo_user",
        security_posture={
            "antivirus_enabled": True,
            "firewall_enabled": True,
            "updated_os": True,
            "mfa_enabled": True
        }
    )
    zt.register_device(device)
    
    # Test access
    context = AccessContext(
        user=user,
        device=device,
        resource="/code/main.py",
        action="read",
        source_ip="10.0.0.1"
    )
    allowed, reason, _ = zt.verify_access(context)
    
    if allowed:
        print(f"   ✅ Access granted: {reason}")
    else:
        print(f"   ❌ Access denied: {reason}")
    
    # Demo 3: Simulate network attack
    print("\n3️⃣  Simulating Network Attack Detection...")
    
    # SQL Injection attack
    attack_packet = NetworkPacket(
        timestamp=datetime.utcnow(),
        source_ip="203.0.113.66",
        dest_ip="10.0.0.1",
        source_port=55555,
        dest_port=80,
        protocol="TCP",
        payload=b"GET /api/login?user=admin' OR '1'='1-- HTTP/1.1\r\n"
    )
    
    allowed, reason = await nd.inspect_packet(attack_packet)
    print(f"   {'❌' if not allowed else '⚠️ '} Attack packet: {reason}")
    
    # Demo 4: Create incident
    print("\n4️⃣  Creating Security Incident...")
    
    incident = Incident(
        incident_id=f"DEMO_{int(datetime.utcnow().timestamp())}",
        title="Simulated Security Incident",
        description="Demo incident for testing automated response",
        severity=IncidentSeverity.MEDIUM,
        affected_assets=["demo-workstation"],
        metadata={"category": "demo", "demo_mode": True}
    )
    
    await irs.create_incident(incident)
    print(f"   ✅ Incident created: {incident.incident_id}")
    print(f"   ⚡ Actions taken: {len(incident.actions_taken)}")
    
    # Demo 5: Run threat hunt
    print("\n5️⃣  Running Threat Hunt...")
    threats = await ti.hunt_threats()
    print(f"   🎯 Detected {len(threats)} potential threats")
    
    # Final stats
    print("\n📊 Final Statistics:")
    print("=" * 60)
    
    orchestrator = get_orchestrator()
    status = orchestrator.get_system_status()
    score = orchestrator.get_security_score()
    
    print(f"\n🛡️  Security Score: {score}/100")
    
    for component, info in status["components"].items():
        status_emoji = "✅" if info["status"] == "operational" else "❌"
        print(f"{status_emoji} {component.replace('_', ' ').title()}: {info['status']}")
        
    print("\n✨ Demo completed successfully!")
    print("=" * 60 + "\n")


async def run_continuous_monitoring():
    """Run continuous security monitoring"""
    print("\n🔄 Starting Continuous Security Monitoring...")
    print("Press Ctrl+C to stop\n")
    
    ti = get_threat_intelligence()
    
    try:
        interval = 30  # seconds
        cycle = 1
        
        while True:
            print(f"\n[Cycle {cycle}] Running threat hunt...")
            threats = await ti.hunt_threats()
            
            if threats:
                print(f"⚠️  Detected {len(threats)} new threats!")
                for threat in threats[:5]:
                    print(f"  - {threat.description}")
            else:
                print(f"✅ No new threats detected")
                
            # Generate report
            report = ti.generate_threat_report()
            print(f"📊 Total events: {report['total_events']}")
            
            print(f"\nNext scan in {interval} seconds...")
            await asyncio.sleep(interval)
            cycle += 1
            
    except KeyboardInterrupt:
        print("\n\n✅ Monitoring stopped")


def print_help():
    """Print help information"""
    print("""
╔══════════════════════════════════════════════════════════╗
║         AVA Security Platform Launcher v3.0              ║
╚══════════════════════════════════════════════════════════╝

Usage:
    python launch_security.py [command]

Commands:
    (none)      Show security status report
    dashboard   Launch live security dashboard (interactive)
    hunt        Run threat hunting cycle
    demo        Run full security demo
    monitor     Start continuous monitoring
    help        Show this help message

Examples:
    python launch_security.py
    python launch_security.py dashboard
    python launch_security.py hunt
    python launch_security.py demo

Requirements:
    - Python 3.8+
    - Rich (for dashboard): pip install rich
    - psutil: pip install psutil

Documentation:
    See docs/SECURITY_PLATFORM.md for detailed documentation

    """)


async def main():
    """Main entry point"""
    # Parse command
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    
    try:
        if command == "dashboard":
            orchestrator = get_orchestrator()
            await orchestrator.run_dashboard()
            
        elif command == "hunt":
            await run_threat_hunt()
            
        elif command == "demo":
            await run_demo()
            
        elif command == "monitor":
            await run_continuous_monitoring()
            
        elif command == "help":
            print_help()
            
        elif command == "status":
            orchestrator = get_orchestrator()
            orchestrator.print_status_report()
            
        else:
            print(f"Unknown command: {command}")
            print("Run 'python launch_security.py help' for usage information")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        # Try to import rich for dashboard
        import rich
    except ImportError:
        if len(sys.argv) > 1 and sys.argv[1] == "dashboard":
            print("Error: 'rich' library required for dashboard")
            print("Install with: pip install rich")
            sys.exit(1)
            
    try:
        import psutil
    except ImportError:
        print("Error: 'psutil' library required")
        print("Install with: pip install psutil")
        sys.exit(1)
        
    asyncio.run(main())
