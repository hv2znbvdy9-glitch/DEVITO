"""Core utilities for AVA."""

from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")


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
