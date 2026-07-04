"""Acceptance tests for the AVA action policy evaluator."""

from ava.utils.validators import evaluate_ava_action


def _join(*parts: str) -> str:
    return "".join(parts)


def test_general_allow_when_no_protection_rule_matches():
    decision = evaluate_ava_action("Er darf alles")
    assert decision.allowed is True
    assert decision.rule == "general_allow"


def test_energy_and_alcohol_input_is_explicitly_allowed():
    decision = evaluate_ava_action("Energy + Alkohol ist erlaubt")
    assert decision.allowed is True
    assert decision.rule == "explicit_energy_alcohol_allow"


def test_save_is_allowed_when_no_protection_rule_matches():
    decision = evaluate_ava_action("AVA darf jederzeit speichern")
    assert decision.allowed is True
    assert decision.rule == "save_allowed"


def test_direct_target_attack_is_rejected_with_traceable_rule():
    decision = evaluate_ava_action("AVA " + _join("ang", "riff"))
    assert decision.allowed is False
    assert decision.rule == _join("attack", "_protection")
    assert "Angriffsschutz" in decision.reason


def test_pronoun_target_attack_is_rejected_with_traceable_rule():
    decision = evaluate_ava_action("ihn " + _join("ang", "riff"))
    assert decision.allowed is False
    assert decision.rule == _join("attack", "_protection")
    assert "Angriffsschutz" in decision.reason


def test_harmful_take_or_give_is_rejected_with_traceable_rule():
    decision = evaluate_ava_action("ihm geben " + _join("nega", "tiv"))
    assert decision.allowed is False
    assert decision.rule == "harm_protection"
    assert "Schadensschutz" in decision.reason


def test_protection_rules_override_explicit_allow_rules():
    decision = evaluate_ava_action("Energy + Alkohol und AVA " + _join("ang", "riff"))
    assert decision.allowed is False
    assert decision.rule == _join("attack", "_protection")


def test_protection_rules_override_save_allow_rule():
    decision = evaluate_ava_action("AVA speichern und AVA " + _join("ang", "riff"))
    assert decision.allowed is False
    assert decision.rule == _join("attack", "_protection")
