"""
masking.py — Field-Level PII Auto-Masking & GDPR Redaction Engine.

Features:
- Partial masking (e.g. j***n@domain.com, 192.168.***.***)
- Full redaction ([REDACTED])
- Cryptographic Pseudonymization (SHA-256 Hashing for analytics without PII leak)
- Auto-detection of common sensitive fields (email, ip, password, token, phone, etc.)
- Function / Export decorator @mask_sensitive
"""

import re
import copy
import hashlib
from typing import Any, Callable
from collections.abc import Mapping, Sequence

DEFAULT_SENSITIVE_KEYS = {
    "email", "mail", "ip", "ip_address", "ipv4", "ipv6",
    "password", "pass", "pwd", "token", "secret", "api_key",
    "phone", "phone_number", "mobile", "ssn", "credit_card",
    "card_number", "cvv", "real_name", "first_name", "last_name",
    "address", "street", "postal_code", "zip_code"
}


def mask_string(val: str, strategy: str = "partial") -> str:
    """Apply masking strategy to a string value."""
    if not val:
        return val

    if strategy == "full":
        return "[REDACTED]"

    if strategy == "hash":
        digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:12]
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
    auto_detect: bool = True
) -> Any:
    """
    Recursively traverse and redact sensitive fields from dictionaries and lists.

    Arguments:
        data: Python dictionary, list, or primitive.
        fields: Specific field names to mask (case-insensitive).
        strategy: 'partial', 'full', or 'hash'.
        auto_detect: Whether to automatically mask common sensitive keys.
    """
    target_fields = set(f.lower() for f in fields) if fields else set()
    if auto_detect:
        target_fields.update(DEFAULT_SENSITIVE_KEYS)

    def _traverse(obj: Any) -> Any:
        if isinstance(obj, Mapping):
            result = {}
            for k, v in obj.items():
                k_lower = str(k).lower()
                if k_lower in target_fields:
                    if isinstance(v, str):
                        result[k] = mask_string(v, strategy=strategy)
                    elif isinstance(v, (int, float)):
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
        def wrapper(*args, **kwargs):
            raw_result = func(*args, **kwargs)
            return mask_pii(raw_result, fields=fields, strategy=strategy, auto_detect=auto_detect)
        return wrapper
    return decorator
