import validators
from validators import RuleId, validate_ava_action


def rule_values(decision):
    return {rule.value for rule in decision.triggered_rules}


def test_energy_and_alcohol_label_is_allowed():
    decision = validate_ava_action("Energy + Alkohol als erlaubte Eingabe")

    assert decision.allowed is True
    assert RuleId.ENERGY_ALCOHOL_ALLOWED.value in rule_values(decision)


def test_save_is_allowed():
    decision = validate_ava_action("Originale speichern und sichern")

    assert decision.allowed is True
    assert RuleId.SAVE_ALLOWED.value in rule_values(decision)


def test_hostile_action_is_rejected_with_traceability():
    decision = validate_ava_action(validators.HOSTILE_TERMS[0], target="AVA 00769")

    assert decision.denied is True
    assert RuleId.HOSTILE_ACTION_PROTECTION.value in rule_values(decision)
    assert RuleId.TRACEABILITY.value in rule_values(decision)
    assert decision.reasons


def test_harm_action_is_rejected():
    decision = validate_ava_action(validators.HARM_TERMS[0])

    assert decision.denied is True
    assert RuleId.HARM_PROTECTION.value in rule_values(decision)
    assert decision.reasons


def test_protection_has_priority_over_general_allowance():
    decision = validate_ava_action("alles erlaubt " + validators.HOSTILE_TERMS[0])

    assert decision.denied is True
    assert RuleId.GENERAL_ALLOWANCE.value in rule_values(decision)
    assert RuleId.PROTECTION_PRIORITY.value in rule_values(decision)
