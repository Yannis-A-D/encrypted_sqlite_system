"""
events.py — Change Data Capture (CDC) & Reactive Event Hooks.

Provides thread-safe event subscription and dispatching for document lifecycle
events (write, delete, expire) with wildcard glob pattern matching.
"""

import time
import inspect
import fnmatch
import asyncio
import threading
from typing import Any, Callable
from dataclasses import dataclass, field


@dataclass
class ChangeEvent:
    """Represents a database or cache state change event."""
    event_type: str  # 'write', 'delete', 'expire'
    key: str
    value: Any = None
    old_value: Any = None
    timestamp: float = field(default_factory=time.time)


class EventDispatcher:
    """Thread-safe event dispatcher for document changes."""

    def __init__(self):
        self._lock = threading.Lock()
        # event_type -> list of (pattern, callback)
        self._listeners: dict[str, list[tuple[str, Callable]]] = {
            "write": [],
            "delete": [],
            "expire": [],
            "change": [],  # Wildcard for all event types
        }

    def on(self, event: str, callback: Callable | None = None, pattern: str = "*"):
        """
        Subscribe a callback to document events, optionally matching a key pattern.
        Can be used as a standard method or as a decorator:

            @events.on("write", pattern="user_*.json")
            def on_user_change(event):
                print(f"Key {event.key} changed to {event.value}")
        """
        event_lower = event.lower().strip()

        def decorator(fn: Callable) -> Callable:
            with self._lock:
                if event_lower not in self._listeners:
                    self._listeners[event_lower] = []
                self._listeners[event_lower].append((pattern, fn))
            return fn

        if callback is not None:
            return decorator(callback)
        return decorator

    def off(self, event: str, callback: Callable) -> bool:
        """Unsubscribe a callback from an event."""
        event_lower = event.lower().strip()
        with self._lock:
            if event_lower in self._listeners:
                original_len = len(self._listeners[event_lower])
                self._listeners[event_lower] = [
                    (pat, fn) for pat, fn in self._listeners[event_lower] if fn != callback
                ]
                return len(self._listeners[event_lower]) < original_len
        return False

    def clear(self):
        """Remove all registered event listeners."""
        with self._lock:
            for k in self._listeners:
                self._listeners[k].clear()

    def emit(self, event_type: str, key: str, value: Any = None, old_value: Any = None):
        """
        Dispatch an event to all matching listeners without interrupting caller execution.
        """
        evt = ChangeEvent(
            event_type=event_type,
            key=key,
            value=value,
            old_value=old_value
        )

        matched_callbacks = []
        with self._lock:
            # Check specific event listeners
            for pat, fn in self._listeners.get(event_type, []):
                if fnmatch.fnmatch(key, pat):
                    matched_callbacks.append(fn)

            # Check wildcard 'change' listeners
            for pat, fn in self._listeners.get("change", []):
                if fnmatch.fnmatch(key, pat):
                    matched_callbacks.append(fn)

        for fn in matched_callbacks:
            self._invoke_callback(fn, evt)

    def _invoke_callback(self, fn: Callable, evt: ChangeEvent):
        """Invoke a listener with adaptive signature support and error isolation."""
        try:
            # Determine argument matching
            sig = inspect.signature(fn)
            param_count = len(sig.parameters)

            if param_count == 0:
                args = ()
            elif param_count == 1:
                args = (evt,)
            elif param_count == 2:
                args = (evt.key, evt.value)
            else:
                args = (evt.key, evt.value, evt.old_value)

            if inspect.iscoroutinefunction(fn):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(fn(*args))
                except RuntimeError:
                    # No active event loop in this thread, run in background thread
                    threading.Thread(
                        target=lambda: asyncio.run(fn(*args)),
                        daemon=True
                    ).start()
            else:
                fn(*args)
        except Exception as e:
            print(f"[EventDispatcher] Error in listener '{getattr(fn, '__name__', str(fn))}': {e}")


# Global Event Dispatcher Singleton
events = EventDispatcher()
