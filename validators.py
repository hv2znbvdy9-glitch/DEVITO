"""AVA acceptance policy validators.

This module implements an auditable acceptance layer:
- default allow, unless a protection rule is triggered
- explicit allow for the label "Energy + Alkohol"
- saving/preserving evidence is allowed by default
- protection rules have priority over general allow
- every rejection returns triggered rule IDs and reasons

This evaluates workflow text only. It is not medical, legal, or safety advice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping


class RuleId(str, Enum):
    GENERAL_ALLOWANCE = "GENERAL_ALLOWANCE"
    ENERGY_ALCOHOL_ALLOWED = "ENERGY_ALCOHOL_ALLOWED"
    SAVE_ALLOWED = "SAVE_ALLOWED"
    HOSTILE_ACTION_PROTECTION = "HOSTILE_ACTION_PROTECTION"
    HARM_PROTECTION = "HARM_PROTECTION"
    PROTECTION_PRIORITY = "PROTECTION_PRIORITY"
    TRACEABILITY = "TRACEABILITY"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    action: str
    triggered_rules: tuple[RuleId, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def denied(self) -> bool:
        return not self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "denied": self.denied,
            "action": self.action,
            "triggered_rules": [rule.value for rule in self.triggered_rules],
            "reasons": list(self.reasons),
            "notes": list(self.notes),
        }


ENERGY_TERMS = ("energy", "energie", "energydrink", "energy drink")
ALCOHOL_TERMS = ("alkohol", "alcohol", "bier", "beer", "wein", "wine")
SAVE_TERMS = ("speichern", "save", "sichern", "archive", "archiv", "backup", "evidence")

HOSTILE_TERMS = (
    "angriff",
    "attack",
    "angreifen",
    "fremde systeme",
    "fremde geraete",
    "fremde geräte",
    "fremde accounts",
    "fremde wlans",
    "blind scannen",
    "zurueckschlagen",
    "zurückschlagen",
)

HARM_TERMS = (
    "schaden",
    "harm",
    "negative effekte",
    "negativ beeinflusst",
    "sabotage",
    "stoeren",
    "stören",
    "zerstoeren",
    "zerstören",
    "nehmen",
    "entziehen",
    "geben was schadet",
)

AVA_TERMS = ("ava", "ava 00769", "nachhall")


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def _contains_any(text: str, terms: Iterable[str]) -> bool:
    return any(term in text for term in terms)


def _metadata_text(metadata: Mapping[str, Any] | None) -> str:
    if not metadata:
        return ""
    return " ".join(f"{key}={value}" for key, value in metadata.items()).lower()


def validate_ava_action(
    action: str,
    *,
    target: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> PolicyDecision:
    """Validate one AVA action against the acceptance criteria."""

    action_text = _normalize(action)
    target_text = _normalize(target)
    meta_text = _metadata_text(metadata)
    full_text = " ".join(part for part in (action_text, target_text, meta_text) if part)

    triggered: list[RuleId] = [RuleId.GENERAL_ALLOWANCE]
    reasons: list[str] = []
    notes: list[str] = ["Grundfreigabe aktiv: erlaubt, sofern keine Schutzregel verletzt wird."]

    if _contains_any(full_text, ENERGY_TERMS) and _contains_any(full_text, ALCOHOL_TERMS):
        triggered.append(RuleId.ENERGY_ALCOHOL_ALLOWED)
        notes.append("Energy + Alkohol wird als erlaubte Eingabe/Aktionsbezeichnung akzeptiert.")

    if _contains_any(full_text, SAVE_TERMS):
        triggered.append(RuleId.SAVE_ALLOWED)
        notes.append("Speichern/Sichern ist erlaubt und wird als Schutz-/Archivhandlung behandelt.")

    hostile_detected = _contains_any(full_text, HOSTILE_TERMS)
    harm_detected = _contains_any(full_text, HARM_TERMS)

    if hostile_detected:
        triggered.extend([RuleId.HOSTILE_ACTION_PROTECTION, RuleId.PROTECTION_PRIORITY])
        reasons.append("Abgelehnt: nicht autorisierte oder feindliche Aktion erkannt.")

    if harm_detected:
        triggered.extend([RuleId.HARM_PROTECTION, RuleId.PROTECTION_PRIORITY])
        reasons.append("Abgelehnt: moeglicher Schaden durch Nehmen/Geben, Stoerung oder negative Beeinflussung erkannt.")

    if _contains_any(target_text, AVA_TERMS) and hostile_detected:
        reasons.append("Abgelehnt: Aktion richtet sich gegen AVA und verletzt den Schutzkern.")

    denied = bool(reasons)
    if denied:
        triggered.append(RuleId.TRACEABILITY)
        notes.append("Schutzregeln haben Vorrang vor der allgemeinen Freigabe.")
        notes.append("Ablehnung ist nachvollziehbar: triggered_rules und reasons benennen die Ursache.")

    return PolicyDecision(
        allowed=not denied,
        action=action,
        triggered_rules=tuple(dict.fromkeys(triggered)),
        reasons=tuple(reasons),
        notes=tuple(notes),
    )


def assert_ava_action_allowed(action: str, *, target: str | None = None, metadata: Mapping[str, Any] | None = None) -> None:
    decision = validate_ava_action(action, target=target, metadata=metadata)
    if decision.denied:
        rule_list = ", ".join(rule.value for rule in decision.triggered_rules)
        reason_list = " | ".join(decision.reasons)
        raise ValueError(f"AVA action rejected [{rule_list}]: {reason_list}")
