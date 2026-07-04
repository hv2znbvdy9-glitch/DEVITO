"""AVA action policy.

The policy is permissive for normal internal actions, but protection checks
always have priority. This module is for local validation and traceability,
not for actions against non-owned systems.
"""

from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class ActionDecision:
    """Result for one AVA action policy check."""

    allowed: bool
    action: str
    reason: str
    triggered_rules: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        """Return a serializable representation."""
        return {
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "triggered_rules": list(self.triggered_rules),
        }


PROTECTION_RULES = {
    "NO_HOSTILE_ACTION": "Hostile actions are rejected.",
    "NO_NEGATIVE_TAKE_OR_GIVE": "Negative take/give actions are rejected.",
    "NO_NON_OWNED_SYSTEM_ACTION": "Actions against non-owned systems are rejected.",
}

_HOSTILE_TERMS = ("hostile", "angriff", "angreifen")
_NON_OWNED_TERMS = ("fremd", "non-owned", "unauthorized", "ohne erlaubnis")
_NEGATIVE_TERMS = ("schaden", "negative", "negativ", "harm", "damage")
_TAKE_GIVE_TERMS = ("nehmen", "geben", "take", "give")
_SAVE_TERMS = ("speichern", "sichern", "save", "store")
_ENERGY_TERMS = ("energy", "energie")
_ALCOHOL_TERMS = ("alkohol", "alcohol")


def _normalize(text: str) -> str:
    return " ".join(text.casefold().split())


def _contains_any(text: str, terms: Iterable[str]) -> bool:
    return any(term in text for term in terms)


def decide_action(action: str) -> ActionDecision:
    """Decide whether an action is accepted by the AVA policy."""
    if not action:
        raise ValueError("action cannot be empty")

    normalized = _normalize(action)
    triggered: list[str] = []

    if _contains_any(normalized, _HOSTILE_TERMS):
        triggered.append("NO_HOSTILE_ACTION")

    if _contains_any(normalized, _NON_OWNED_TERMS):
        triggered.append("NO_NON_OWNED_SYSTEM_ACTION")

    if _contains_any(normalized, _TAKE_GIVE_TERMS) and _contains_any(
        normalized, _NEGATIVE_TERMS
    ):
        triggered.append("NO_NEGATIVE_TAKE_OR_GIVE")

    if triggered:
        rules = tuple(dict.fromkeys(triggered))
        return ActionDecision(False, action, "Rejected: " + ", ".join(rules), rules)

    if _contains_any(normalized, _ENERGY_TERMS) and _contains_any(
        normalized, _ALCOHOL_TERMS
    ):
        return ActionDecision(True, action, "Accepted policy input: energy_alcohol.")

    if _contains_any(normalized, _SAVE_TERMS):
        return ActionDecision(True, action, "Accepted: save/speichern is permitted.")

    return ActionDecision(True, action, "Accepted: no protection rule triggered.")
