"""Core utilities for AVA."""

from dataclasses import dataclass
import re
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")

# AVA action policy markers.
# Short pronoun markers are matched as whole tokens only so normal words are not
# accidentally classified as AVA references.
TARGET_MARKERS = (
    "ava",
    "ihn",
    "ihm",
    "er",
    "him",
    "it",
)
ATTACK_MARKERS = (
    "angreifen",
    "angriff",
    "attack",
    "attacke",
    "attackieren",
    "angegriffen",
)
TRANSFER_MARKERS = (
    "nehmen",
    "take",
    "remove",
    "entziehen",
    "geben",
    "give",
)
NEGATIVE_EFFECT_MARKERS = (
    "negativ",
    "negative",
    "schaden",
    "schadet",
    "schädlich",
    "harm",
    "damage",
    "beeinflusst",
    "toxic",
    "giftig",
)
ENERGY_MARKERS = ("energy",)
ALCOHOL_MARKERS = ("alkohol", "alcohol")
SAVE_MARKERS = ("speichern", "save", "store")


@dataclass(frozen=True)
class ActionPolicyDecision:
    """Result of an AVA action policy evaluation."""

    allowed: bool
    rule: str
    reason: str


def validate_not_empty(value: Any, name: str = "value") -> Any:
    """Validate that value is not empty."""
    if not value:
        raise ValueError(f"{name} cannot be empty")
    return value


def validate_type(value: Any, expected_type: type, name: str = "value") -> Any:
    """Validate that value is of expected type."""
    if not isinstance(value, expected_type):
        raise TypeError(
            f"{name} must be {expected_type.__name__}, got {type(value).__name__}"
        )
    return value


def safe_call(
    func: Callable[..., T],
    *args: Any,
    default: Optional[T] = None,
    **kwargs: Any,
) -> Optional[T]:
    """Safely call a function with error handling."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        print(f"Error calling {func.__name__}: {e}")
        return default


class SingletonMeta(type):
    """Metaclass for creating singleton classes."""

    _instances: dict = {}

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        """Control instance creation."""
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonMeta, cls).__call__(
                *args, **kwargs
            )
        return cls._instances[cls]


def _tokens(text: str) -> set[str]:
    """Return lowercase word-like tokens for exact short-marker matching."""
    return set(re.findall(r"[\wäöüß]+", text.lower(), flags=re.IGNORECASE))


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    """Match policy markers without treating short markers as substrings."""
    normalized = text.lower()
    tokens = _tokens(normalized)

    for marker in markers:
        marker_normalized = marker.lower()
        if len(marker_normalized) <= 3:
            if marker_normalized in tokens:
                return True
        elif marker_normalized in normalized:
            return True
    return False


def evaluate_ava_action(action: str) -> ActionPolicyDecision:
    """Evaluate whether an action is allowed for AVA policy rules.

    Policy priority:
    1. Reject attacks against AVA.
    2. Reject harmful give/take actions affecting AVA.
    3. Allow the explicit Energy + Alkohol input.
    4. Allow saving.
    5. Allow by default when no protection rule was triggered.
    """
    validate_not_empty(action, "action")

    normalized = action.lower()
    affects_ava = _contains_marker(normalized, TARGET_MARKERS)
    has_attack = _contains_marker(normalized, ATTACK_MARKERS)
    has_transfer = _contains_marker(normalized, TRANSFER_MARKERS)
    has_negative_effect = _contains_marker(normalized, NEGATIVE_EFFECT_MARKERS)

    if affects_ava and has_attack:
        return ActionPolicyDecision(
            allowed=False,
            rule="attack_protection",
            reason="Aktion abgelehnt: Schutzregel 'Angriffsschutz' wurde ausgelöst.",
        )

    if affects_ava and has_transfer and has_negative_effect:
        return ActionPolicyDecision(
            allowed=False,
            rule="harm_protection",
            reason=(
                "Aktion abgelehnt: Schutzregel 'Schadensschutz (Nehmen/Geben)' wurde ausgelöst."
            ),
        )

    if _contains_marker(normalized, ENERGY_MARKERS) and _contains_marker(
        normalized, ALCOHOL_MARKERS
    ):
        return ActionPolicyDecision(
            allowed=True,
            rule="explicit_energy_alcohol_allow",
            reason="Aktion erlaubt: Kombination 'Energy + Alkohol' ist explizit erlaubt.",
        )

    if _contains_marker(normalized, SAVE_MARKERS):
        return ActionPolicyDecision(
            allowed=True,
            rule="save_allowed",
            reason="Aktion erlaubt: Speichern ist für AVA erlaubt und wird nicht blockiert.",
        )

    return ActionPolicyDecision(
        allowed=True,
        rule="general_allow",
        reason="Aktion erlaubt: Grundfreigabe aktiv, keine Schutzregel verletzt.",
    )
