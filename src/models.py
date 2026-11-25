"""
models.py — Strongly-Typed Result Models with Backward-Compatible Mapping Access.

Provides frozen dataclasses for telemetry, integrity audits, and key rotation results
so callers enjoy full IDE autocomplete and static type checking while remaining 100%
compatible with legacy dict-style `.get()` and `[]` indexing.
"""

from dataclasses import dataclass, field, asdict
from typing import Any


class _DictCompatMixin:
    """Allows frozen dataclasses to support dict-style indexing, `.get()`, and `in` checks."""

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and hasattr(self, key)

    def keys(self):
        return asdict(self).keys()  # type: ignore[arg-type]

    def items(self):
        return asdict(self).items()  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[arg-type]


@dataclass(frozen=True)
class IntegrityReport(_DictCompatMixin):
    """Structured result of a cryptographic database integrity audit."""
    status: str
    total_records: int
    valid_records: int
    corrupted_records: int
    corrupted_keys: list[dict[str, str]] = field(default_factory=list)
    message: str = ""


@dataclass(frozen=True)
class RotationReport(_DictCompatMixin):
    """Structured result of a key rotation operation (O(1) KEK wrap or O(N) deep DEK re-key)."""
    status: str
    mode: str  # "kek_envelope_o1" or "deep_dek_rekey"
    rotated_count: int
    failed_count: int = 0
    failed_keys: list[str] = field(default_factory=list)
    message: str = ""


@dataclass(frozen=True)
class EngineStats(_DictCompatMixin):
    """Structured telemetry snapshot for an EncryptedSQLite engine instance."""
    db_path: str
    algorithm: str
    encrypt_keys: bool
    envelope_enabled: bool
    key_slots: int
    l1_items_cached: int
    hits: int
    misses: int
    writes: int
    hit_ratio_percent: float
    stored_documents: int
