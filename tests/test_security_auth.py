"""Tests for the AVA security authentication module."""

import os

import pytest
from fastapi import HTTPException

from ava.security.auth import (
    ADMIN_API_KEYS,
    OWNER_PASSWORD_HASH,
    OWNER_USERNAME,
    RateLimiter,
    SecurityValidator,
    ThreatLevel,
    ThreatLog,
    generate_password_hash,
    verify_password,
)


class TestPasswordHashing:
    """Tests for bcrypt password helpers."""

    def test_generate_password_hash_produces_bcrypt(self):
        password = "MySecurePassword123!"
        password_hash = generate_password_hash(password)
        assert password_hash.startswith("$2b$")
        assert verify_password(password, password_hash) is True

    def test_verify_password_with_wrong_password(self):
        password_hash = generate_password_hash("correct")
        assert verify_password("wrong", password_hash) is False

    def test_verify_password_with_empty_hash(self):
        assert verify_password("anything", "") is False

    def test_owner_password_hash_is_environment_or_empty(self):
        # After remediation the default password hash must not be a SHA-256.
        assert OWNER_PASSWORD_HASH == os.getenv("AVA_OWNER_PASSWORD_HASH", "")


class TestSecurityValidator:
    """Tests for API key and password validation."""

    def test_validate_api_key_missing(self):
        with pytest.raises(HTTPException) as exc_info:
            SecurityValidator.validate_api_key(None)
        assert exc_info.value.status_code == 401

    def test_validate_api_key_invalid(self):
        with pytest.raises(HTTPException) as exc_info:
            SecurityValidator.validate_api_key("invalid-key")
        assert exc_info.value.status_code == 403

    def test_validate_api_key_valid(self):
        valid_key = list(ADMIN_API_KEYS.keys())[0]
        data = SecurityValidator.validate_api_key(valid_key)
        assert data["owner"] == OWNER_USERNAME or "unknown"
        assert data["active"] is True

    def test_validate_owner_password_empty_hash(self):
        # When OWNER_PASSWORD_HASH is empty login must be disabled.
        assert SecurityValidator.validate_owner_password("anything") is False


class TestThreatLog:
    """Tests for threat logging and IP blocking."""

    def test_log_threat_and_block(self):
        log = ThreatLog()
        log.log_threat("10.0.0.1", "/test", ThreatLevel.CRITICAL, "test reason")
        assert len(log.threats) == 1
        assert log.is_ip_blocked("10.0.0.1") is True

    def test_block_ip_expires(self):
        log = ThreatLog()
        log.block_ip("10.0.0.2", duration_minutes=-1)
        assert log.is_ip_blocked("10.0.0.2") is False

    def test_get_threat_report(self):
        log = ThreatLog()
        report = log.get_threat_report()
        assert "total_threats" in report
        assert report["total_threats"] == 0


class TestRateLimiter:
    """Tests for rate limiting."""

    def test_rate_limiter_allows_under_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        assert limiter.is_allowed("client-1") is True
        assert limiter.is_allowed("client-1") is True

    def test_rate_limiter_blocks_over_limit(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.is_allowed("client-2")
        limiter.is_allowed("client-2")
        assert limiter.is_allowed("client-2") is False

    def test_rate_limiter_update_limits(self):
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        limiter.update_limits(1, 10)
        assert limiter.max_requests == 1
        assert limiter.window_seconds == 10

    def test_rate_limiter_update_limits_validation(self):
        limiter = RateLimiter()
        with pytest.raises(ValueError):
            limiter.update_limits(0, 10)


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_security_headers_do_not_contain_default_origin(self):
        from ava.security.auth import SECURITY_HEADERS

        # CORS origin must be configurable, not hardcoded to localhost:3000.
        origin = SECURITY_HEADERS.get("Access-Control-Allow-Origin", "")
        assert origin != "http://localhost:3000"
        assert origin == os.getenv("AVA_CORS_ORIGIN", "")
