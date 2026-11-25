"""
collection.py — Strongly-Typed, Namespaced Document Collections for EncryptedSQLite.

Provides a clean MongoDB/Firestore-like collection interface backed by EncryptedSQLite:
- Automatic key prefix namespacing (`{collection}:{doc_id}`)
- Optional schema validation & hydration for Python `@dataclass`, Pydantic models, or dicts
- Scoped blind indexing (`find_by`), wildcard search, OCC versioned writes, and async wrappers
"""

import asyncio
from dataclasses import is_dataclass, asdict
from typing import Any, Callable, Generic, TypeVar

T = TypeVar("T")


def _serialize_doc(doc: Any) -> Any:
    """Convert dataclass or Pydantic model into a JSON-serializable dict."""
    if is_dataclass(doc) and not isinstance(doc, type):
        return asdict(doc)
    if hasattr(doc, "model_dump") and callable(doc.model_dump):
        return doc.model_dump()
    if hasattr(doc, "dict") and callable(doc.dict):
        return doc.dict()
    return doc


def _hydrate_doc(raw: Any, schema: type[T] | None) -> Any:
    """Hydrate a stored dict back into the configured dataclass or Pydantic schema."""
    if schema is None or raw is None:
        return raw
    if isinstance(raw, schema):
        return raw
    if hasattr(schema, "model_validate") and callable(schema.model_validate):
        return schema.model_validate(raw)
    if is_dataclass(schema) and isinstance(raw, dict):
        return schema(**raw)
    if isinstance(raw, dict):
        return schema(**raw)
    return raw


class Collection(Generic[T]):
    """Typed, namespaced document collection backed by an EncryptedSQLite engine."""

    def __init__(
        self,
        engine: Any,
        name: str,
        schema: type[T] | None = None,
        indexes: list[str] | set[str] | None = None,
    ):
        clean_name = name.strip().strip(":")
        if not clean_name:
            raise ValueError("Collection name must be non-empty.")
        self._engine = engine
        self.name = clean_name
        self._prefix = f"{clean_name}:"
        self.schema = schema

        if indexes:
            existing = set(self._engine._indexed_fields)
            existing.update(str(f).strip() for f in indexes if str(f).strip())
            self._engine.set_indexed_fields(existing)

    def _full_key(self, doc_id: str) -> str:
        return f"{self._prefix}{doc_id}"

    def _strip_prefix(self, full_key: str) -> str:
        if full_key.startswith(self._prefix):
            return full_key[len(self._prefix):]
        return full_key

    def put(self, doc_id: str, doc: T, ttl: float | None = None, db_ttl: float | None = None) -> None:
        """Store or update a document in this collection."""
        payload = _serialize_doc(doc)
        self._engine.set(self._full_key(doc_id), payload, ttl=ttl, db_ttl=db_ttl)

    def get(self, doc_id: str, default: Any = None) -> T | Any:
        """Retrieve and hydrate a document by ID."""
        raw = self._engine.get(self._full_key(doc_id), default=None)
        if raw is None:
            return default
        return _hydrate_doc(raw, self.schema)

    def get_versioned(self, doc_id: str, default: Any = None) -> tuple[T | Any, int]:
        """Retrieve a hydrated document alongside its OCC version number."""
        raw, ver = self._engine.get_versioned(self._full_key(doc_id), default=None)
        if raw is None:
            return default, 0
        return _hydrate_doc(raw, self.schema), ver

    def put_versioned(self, doc_id: str, doc: T, expected_version: int, ttl: float | None = None) -> int:
        """Conditionally store a document only if its current version matches expected_version."""
        payload = _serialize_doc(doc)
        return self._engine.set_versioned(self._full_key(doc_id), payload, expected_version=expected_version, ttl=ttl)

    def delete(self, doc_id: str) -> bool:
        """Delete a document from this collection."""
        return self._engine.delete(self._full_key(doc_id))

    def mput(self, mapping: dict[str, T], ttl: float | None = None, db_ttl: float | None = None) -> None:
        """Atomically batch-store multiple documents in this collection."""
        prefixed = {self._full_key(k): _serialize_doc(v) for k, v in mapping.items()}
        self._engine.mset(prefixed, ttl=ttl, db_ttl=db_ttl)

    def mget(self, doc_ids: list[str]) -> dict[str, T]:
        """Batch-retrieve and hydrate multiple documents by ID."""
        raw_map = self._engine.mget([self._full_key(i) for i in doc_ids])
        return {self._strip_prefix(k): _hydrate_doc(v, self.schema) for k, v in raw_map.items()}

    def ids(self, pattern: str = "*", limit: int | None = None) -> list[str]:
        """List document IDs in this collection matching an optional glob pattern."""
        full_keys = self._engine.search(pattern=f"{self._prefix}{pattern}", limit=limit)
        return [self._strip_prefix(k) for k in full_keys]

    def all(self, limit: int | None = None) -> list[T]:
        """Return all hydrated documents in this collection."""
        doc_ids = self.ids(limit=limit)
        if not doc_ids:
            return []
        docs = self.mget(doc_ids)
        return [docs[i] for i in doc_ids if i in docs]

    def find(self, predicate: Callable[[T], bool], limit: int | None = None) -> list[T]:
        """Filter hydrated documents in this collection using a Python predicate."""
        matches: list[T] = []
        for doc in self.all():
            try:
                if predicate(doc):
                    matches.append(doc)
                    if limit is not None and len(matches) >= limit:
                        break
            except Exception:
                continue
        return matches

    def find_by(self, field_name: str, value: Any) -> dict[str, T]:
        """Fast O(1) blind-index lookup scoped strictly to this collection."""
        raw_hits = self._engine.find_by_index(field_name, value)
        return {
            self._strip_prefix(k): _hydrate_doc(v, self.schema)
            for k, v in raw_hits.items()
            if k.startswith(self._prefix)
        }

    def count(self) -> int:
        """Count active non-expired documents in this collection."""
        return self._engine.count(pattern=f"{self._prefix}*")

    # Async convenience wrappers
    async def aget(self, doc_id: str, default: Any = None) -> T | Any:
        return await asyncio.to_thread(self.get, doc_id, default)

    async def aput(self, doc_id: str, doc: T, ttl: float | None = None, db_ttl: float | None = None) -> None:
        await asyncio.to_thread(self.put, doc_id, doc, ttl, db_ttl)

    async def adelete(self, doc_id: str) -> bool:
        return await asyncio.to_thread(self.delete, doc_id)

    async def afind_by(self, field_name: str, value: Any) -> dict[str, T]:
        return await asyncio.to_thread(self.find_by, field_name, value)
