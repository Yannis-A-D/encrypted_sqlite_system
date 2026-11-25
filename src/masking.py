"""
masking.py — Field-Level PII Auto-Masking & GDPR Redaction Engine.

Features:
- Partial masking (e.g. j***n@domain.com, 192.168.***.***)
- Full redaction ([REDACTED])
- Cryptographic Pseudonymization (Keyed HMAC-SHA256 using HKDF domain separation,
  protecting emails, IPs, and phone numbers against rainbow-table reversal)
- Auto-detection of common sensitive fields (email, ip, password, token, phone, etc.)
- Function / Export decorator @mask_sensitive
"""

import os
import re
import hmac
import hashlib
import functools
from typing import Any, Callable
from collections.abc import Mapping, Sequence
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_SENSITIVE_KEYS = {
    "email", "mail", "ip", "ip_address", "ipv4", "ipv6",
    "password", "pass", "pwd", "token", "secret", "api_key",
    "phone", "phone_number", "mobile", "ssn", "credit_card",
    "card_number", "cvv", "real_name", "first_name", "last_name",
    "address", "street", "postal_code", "zip_code"
}

_FALLBACK_HMAC_KEY = os.urandom(32)


def _get_pseudonymization_key() -> bytes:
    """Derive a domain-separated 32-byte HMAC key from the master key via HKDF."""
    try:
        from .database import _get_raw_key_material
        raw_key = _get_raw_key_material()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"sqlite-gdpr-masking-salt-v1",
            info=b"sqlite-gdpr-pseudonymization",
        ).derive(raw_key)
    except Exception:
        return _FALLBACK_HMAC_KEY


def mask_string(val: str, strategy: str = "partial", secret_key: bytes | None = None) -> str:
    """Apply masking strategy to a string value."""
    if not val:
        return val

    if strategy == "full":
        return "[REDACTED]"

    if strategy == "hash":
        key = secret_key if secret_key is not None else _get_pseudonymization_key()
        digest = hmac.new(key, val.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        return f"hash:{digest}"

    # Partial Masking
    # 1. Email Masking (j***e@domain.com)
    if "@" in val and "." in val:
        parts = val.split("@", 1)
        name, domain = parts[0], parts[1]
        if len(name) <= 2:
            masked_name = name[0] + "***"
        else:
            masked_name = name[0] + "***" + name[-1]
        return f"{masked_name}@{domain}"

    # 2. IPv4 Masking (192.168.***.***)
    ipv4_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    ip_match = re.match(ipv4_pattern, val)
    if ip_match:
        return f"{ip_match.group(1)}.{ip_match.group(2)}.***.***"

    # 3. Generic String Masking
    if len(val) <= 4:
        return "****"
    return val[:2] + "*" * (len(val) - 4) + val[-2:]


def mask_pii(
    data: Any,
    fields: set[str] | list[str] | None = None,
    strategy: str = "partial",
    auto_detect: bool = True,
    secret_key: bytes | None = None,
) -> Any:
    """
    Recursively traverse and redact sensitive fields from dictionaries and lists.

    Arguments:
        data: Python dictionary, list, or primitive.
        fields: Specific field names to mask (case-insensitive).
        strategy: 'partial', 'full', or 'hash'.
        auto_detect: Whether to automatically mask common sensitive keys.
        secret_key: Optional explicit HMAC key for 'hash' pseudonymization.
    """
    target_fields = set(f.lower() for f in fields) if fields else set()
    if auto_detect:
        target_fields.update(DEFAULT_SENSITIVE_KEYS)

    hmac_key = (secret_key or _get_pseudonymization_key()) if strategy == "hash" else None

    def _traverse(obj: Any) -> Any:
        if isinstance(obj, Mapping):
            result = {}
            for k, v in obj.items():
                k_lower = str(k).lower()
                if k_lower in target_fields:
                    if isinstance(v, str):
                        result[k] = mask_string(v, strategy=strategy, secret_key=hmac_key)
                    elif isinstance(v, (int, float)):
                        if strategy == "hash" and hmac_key is not None:
                            digest = hmac.new(hmac_key, str(v).encode("utf-8"), hashlib.sha256).hexdigest()[:12]
                            result[k] = f"hash:{digest}"
                        else:
                            result[k] = "[REDACTED]" if strategy == "full" else "***"
                    else:
                        result[k] = "[REDACTED]"
                else:
                    result[k] = _traverse(v)
            return result

        elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
            return [_traverse(item) for item in obj]

        return obj

    return _traverse(data)


def mask_sensitive(
    fields: set[str] | list[str] | None = None,
    strategy: str = "partial",
    auto_detect: bool = True
):
    """
    Decorator to automatically sanitize return values of functions returning JSON/dicts.
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            raw_result = func(*args, **kwargs)
            return mask_pii(raw_result, fields=fields, strategy=strategy, auto_detect=auto_detect)
        return wrapper
    return decorator
