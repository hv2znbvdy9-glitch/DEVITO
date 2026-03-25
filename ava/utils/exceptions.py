"""Exception classes for AVA."""


class AVAException(Exception):
    """Base exception for AVA."""

    pass


class ConfigError(AVAException):
    """Configuration error."""

    pass


class ValidationError(AVAException):
    """Validation error."""

    pass


class CLIError(AVAException):
    """CLI error."""

    pass
