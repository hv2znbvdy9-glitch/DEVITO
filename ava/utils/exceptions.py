"""Exception classes for AVA."""


class AVAException(Exception):
    """Base exception for AVA."""


class ConfigError(AVAException):
    """Configuration error."""


class ValidationError(AVAException):
    """Validation error."""


class CLIError(AVAException):
    """CLI error."""
