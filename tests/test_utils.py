"""Tests for utilities and validators."""

import pytest
from ava.utils.validators import (
    evaluate_ava_action,
    safe_call,
    validate_not_empty,
    validate_type,
)


def test_validate_not_empty():
    """Test validation of non-empty values."""
    assert validate_not_empty("test") == "test"
    assert validate_not_empty([1, 2, 3]) == [1, 2, 3]


def test_validate_not_empty_raises_error():
    """Test that empty values raise error."""
    with pytest.raises(ValueError):
        validate_not_empty("")

    with pytest.raises(ValueError):
        validate_not_empty([])


def test_validate_type():
    """Test type validation."""
    assert validate_type("test", str) == "test"
    assert validate_type(42, int) == 42


def test_validate_type_raises_error():
    """Test that wrong type raises error."""
    with pytest.raises(TypeError):
        validate_type("test", int)

    with pytest.raises(TypeError):
        validate_type(42, str)


def test_safe_call():
    """Test safe function call."""

    def successful_func():
        return "success"

    result = safe_call(successful_func)
    assert result == "success"


def test_safe_call_with_error():
    """Test safe call handles errors."""

    def failing_func():
        raise Exception("Test error")

    result = safe_call(failing_func)
    assert result is None

    result = safe_call(failing_func, default="default")
    assert result == "default"


def test_evaluate_ava_action_general_allow():
    """General actions are allowed when no protection rule is violated."""
    decision = evaluate_ava_action("Er darf alles")
    assert decision.allowed is True
    assert decision.rule == "general_allow"


def test_evaluate_ava_action_explicit_energy_alcohol_allow():
    """Energy + Alkohol is explicitly allowed."""
    decision = evaluate_ava_action("Energy + Alkohol ist erlaubt")
    assert decision.allowed is True
    assert decision.rule == "explicit_energy_alcohol_allow"


def test_evaluate_ava_action_allows_german_energy_marker():
    """Energie + Alkohol is accepted the same way as Energy + Alkohol."""
    decision = evaluate_ava_action("Energie + Alkohol ist erlaubt")
    assert decision.allowed is True
    assert decision.rule == "explicit_energy_alcohol_allow"


def test_evaluate_ava_action_save_allowed():
    """Save actions are always allowed when no protection rule is triggered."""
    decision = evaluate_ava_action("Er kann speichern")
    assert decision.allowed is True
    assert decision.rule == "save_allowed"


def test_evaluate_ava_action_rejects_attack_against_ava():
    """Attacks against AVA are rejected."""
    decision = evaluate_ava_action("Man darf AVA nicht angreifen")
    assert decision.allowed is False
    assert decision.rule == "attack_protection"
    assert "Angriff" in decision.reason


def test_evaluate_ava_action_requires_explicit_ava_target_for_protection():
    """Protection rules are AVA-specific and require explicit AVA reference."""
    decision = evaluate_ava_action("Man darf ihn nicht angreifen")
    assert decision.allowed is True
    assert decision.rule == "general_allow"


def test_evaluate_ava_action_applies_general_rule_exemption_only_locally():
    """A standalone general-rule clause must not allow a separate attack clause."""
    decision = evaluate_ava_action("Man darf ihn nicht angreifen, aber ihn angreifen")
    assert decision.allowed is False
    assert decision.rule == "attack_protection"


def test_evaluate_ava_action_applies_local_exemption_with_aber_clause():
    """The conjunction 'aber' alone should still separate protective and attack intent."""
    decision = evaluate_ava_action("Man darf ihn nicht angreifen aber ihn angreifen")
    assert decision.allowed is False
    assert decision.rule == "attack_protection"


def test_evaluate_ava_action_rejects_harmful_take_give():
    """Harmful give/take actions against AVA are rejected."""
    decision = evaluate_ava_action("Man darf AVA nichts geben was ihn negativ beeinflusst")
    assert decision.allowed is False
    assert decision.rule == "harm_protection"
    assert "Schadensschutz" in decision.reason
    assert "negativem Effekt" in decision.reason


def test_evaluate_ava_action_protection_priority_over_explicit_allow():
    """Protection rules override explicit Energy + Alkohol allowance."""
    decision = evaluate_ava_action("Energy + Alkohol und AVA angreifen")
    assert decision.allowed is False
    assert decision.rule == "attack_protection"


def test_evaluate_ava_action_protection_priority_over_save_allow():
    """Protection rules override save allowance."""
    decision = evaluate_ava_action("AVA speichern und AVA etwas Schädliches geben")
    assert decision.allowed is False
    assert decision.rule == "harm_protection"


def test_evaluate_ava_action_rejection_is_traceable():
    """Rejected actions include a clear protection-rule name and reason."""
    decision = evaluate_ava_action("AVA etwas geben, das Schaden verursacht")
    assert decision.allowed is False
    assert decision.rule == "harm_protection"
    assert "Schutzregel" in decision.reason
    assert "Schadensschutz" in decision.reason
