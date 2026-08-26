"""
test_masking.py — Tests for field-level PII auto-masking and GDPR redaction.
"""

from src.masking import mask_string, mask_pii, mask_sensitive


def test_mask_string_partial():
    """Test partial masking on emails, IPs, and strings."""
    assert mask_string("alex.developer@example.com", strategy="partial") == "a***r@example.com"
    assert mask_string("192.168.1.100", strategy="partial") == "192.168.***.***"
    assert mask_string("supersecretpassword", strategy="partial") == "su***************rd"


def test_mask_string_full():
    """Test full redaction."""
    assert mask_string("secret_token_123", strategy="full") == "[REDACTED]"
    assert mask_string("alex@gmail.com", strategy="full") == "[REDACTED]"


def test_mask_string_hash():
    """Test SHA-256 pseudonymization hash."""
    hashed = mask_string("user_secret_data", strategy="hash")
    assert hashed.startswith("hash:")
    assert len(hashed) == 17  # 'hash:' + 12 hex chars


def test_mask_pii_auto_detect():
    """Test recursive auto-detection of sensitive keys in nested dicts."""
    user_data = {
        "user_id": 101,
        "username": "AlexDev",
        "email": "alex.dev@gmail.com",
        "ip_address": "10.0.0.42",
        "nested": {
            "password": "Password123!",
            "token": "tok_xyz_secret",
            "score": 500
        },
        "tags": ["builder", "vip"]
    }

    sanitized = mask_pii(user_data, strategy="partial", auto_detect=True)

    # Public fields must stay untouched
    assert sanitized["user_id"] == 101
    assert sanitized["username"] == "AlexDev"
    assert sanitized["tags"] == ["builder", "vip"]
    assert sanitized["nested"]["score"] == 500

    # Sensitive fields must be masked
    assert sanitized["email"] == "a***v@gmail.com"
    assert sanitized["ip_address"] == "10.0.***.***"
    assert sanitized["nested"]["password"] != "Password123!"
    assert sanitized["nested"]["token"] != "tok_xyz_secret"


def test_mask_sensitive_decorator():
    """Test @mask_sensitive decorator on functions."""
    @mask_sensitive(fields={"api_key", "secret_value"}, strategy="full")
    def get_api_credentials():
        return {
            "service": "Stripe",
            "api_key": "sk_live_123456789",
            "secret_value": "sec_abc"
        }

    res = get_api_credentials()
    assert res["service"] == "Stripe"
    assert res["api_key"] == "[REDACTED]"
    assert res["secret_value"] == "[REDACTED]"
