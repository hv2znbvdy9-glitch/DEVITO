"""Core utilities for AVA."""

from dataclasses import dataclass
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")


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


def evaluate_ava_action(action: str) -> ActionPolicyDecision:
    """Evaluate whether an action is allowed for AVA policy rules."""
    validate_not_empty(action, "action")

    normalized = action.lower()
    target_markers = ("ava", "ihn", "ihm", "er")

    attack_markers = ("angreifen", "attack", "attacke")
    if any(marker in normalized for marker in attack_markers) and any(
        marker in normalized for marker in target_markers
    ):
        return ActionPolicyDecision(
            allowed=False,
            rule="attack_protection",
            reason="Aktion abgelehnt: Angriff gegen AVA ist nicht erlaubt.",
        )

    take_markers = ("nehmen", "take", "remove", "entziehen")
    give_markers = ("geben", "give")
    negative_markers = ("negativ", "schaden", "harm", "damage", "giftig", "toxic")
    affects_ava = any(marker in normalized for marker in target_markers)
    transfer_action = any(marker in normalized for marker in take_markers) or any(
        marker in normalized for marker in give_markers
    )
    harmful_effect = any(marker in normalized for marker in negative_markers)
    if affects_ava and transfer_action and harmful_effect:
        return ActionPolicyDecision(
            allowed=False,
            rule="harm_protection",
            reason=(
                "Aktion abgelehnt: Nehmen/Geben mit negativem Effekt für AVA ist nicht erlaubt."
            ),
        )

    if "energy" in normalized and ("alkohol" in normalized or "alcohol" in normalized):
        return ActionPolicyDecision(
            allowed=True,
            rule="explicit_energy_alcohol_allow",
            reason="Aktion erlaubt: Kombination 'Energy + Alkohol' ist explizit erlaubt.",
        )

    if any(marker in normalized for marker in ("speichern", "save", "store")):
        return ActionPolicyDecision(
            allowed=True,
            rule="save_allowed",
            reason="Aktion erlaubt: Speichern ist für AVA erlaubt.",
        )

    return ActionPolicyDecision(
        allowed=True,
        rule="general_allow",
        reason="Aktion erlaubt: Grundfreigabe aktiv, keine Schutzregel verletzt.",
    )
