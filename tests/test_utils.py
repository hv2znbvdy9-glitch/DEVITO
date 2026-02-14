"""Tests for utilities and validators."""

import pytest
from ava.utils.validators import validate_not_empty, validate_type, safe_call


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
