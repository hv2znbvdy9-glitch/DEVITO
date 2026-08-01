"""Tests for the aggressive defense module and human-in-the-loop approvals."""

from ava.security.aggressive_defense import (
    AggressiveDefenseMode,
    AutomatedThreatResponse,
    ZeroTrustFirewall,
    get_aggressive_defense,
    get_automated_response,
)


class TestAggressiveDefenseMode:
    """Tests for the aggressive defense evaluator."""

    def test_evaluate_clean_traffic(self):
        defense = AggressiveDefenseMode()
        result = defense.evaluate_threat("192.168.1.1", 0.0, "unknown")
        assert result["action"] == "ALLOW"

    def test_evaluate_suspicious_traffic(self):
        defense = AggressiveDefenseMode()
        result = defense.evaluate_threat("192.168.1.2", 7.0, "port_scan")
        assert result["action"] == "BLOCK"

    def test_evaluate_threat_triggers_destroy(self):
        defense = AggressiveDefenseMode()
        result = defense.evaluate_threat("192.168.1.3", 50.0, "sql_injection")
        assert result["action"] == "DESTROY"
        assert "192.168.1.3" in defense.blacklisted_ips

    def test_honeypot_response_contains_trap_flag(self):
        defense = AggressiveDefenseMode()
        response = defense.create_honeypot_response("xss")
        assert response["trap"] is True


class TestZeroTrustFirewall:
    """Tests for the zero-trust firewall."""

    def test_default_deny(self):
        firewall = ZeroTrustFirewall()
        assert firewall.check_access("10.0.0.1") is False

    def test_whitelist_allows(self):
        firewall = ZeroTrustFirewall()
        firewall.add_to_whitelist("10.0.0.2")
        assert firewall.check_access("10.0.0.2") is True


class TestAutomatedThreatResponse:
    """Tests for the human-in-the-loop approval flow."""

    def test_respond_without_approval_queues_destroy(self):
        defense = AggressiveDefenseMode()
        response_system = AutomatedThreatResponse(defense)
        result = response_system.respond({"action": "DESTROY", "ip": "10.0.0.5"})
        assert result["status"] == "PENDING_APPROVAL"
        assert "approval_id" in result

    def test_approve_queued_destroy(self):
        defense = AggressiveDefenseMode()
        response_system = AutomatedThreatResponse(defense)
        pending = response_system.respond({"action": "DESTROY", "ip": "10.0.0.6"})
        approved = response_system.approve_action(pending["approval_id"])
        assert approved["status"] == "DESTROYED"
        assert "10.0.0.6" in defense.blacklisted_ips

    def test_block_action_does_not_require_approval(self):
        defense = AggressiveDefenseMode()
        response_system = AutomatedThreatResponse(defense)
        result = response_system.respond({"action": "BLOCK", "ip": "10.0.0.7"})
        assert result["status"] == "BLOCKED"

    def test_approve_unknown_id(self):
        defense = AggressiveDefenseMode()
        response_system = AutomatedThreatResponse(defense)
        result = response_system.approve_action("nonexistent")
        assert result["status"] == "ERROR"


class TestSingletons:
    """Tests for global module instances."""

    def test_get_aggressive_defense_singleton(self):
        a = get_aggressive_defense()
        b = get_aggressive_defense()
        assert a is b

    def test_get_automated_response_singleton(self):
        a = get_automated_response()
        b = get_automated_response()
        assert a is b
