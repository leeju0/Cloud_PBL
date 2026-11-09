from __future__ import annotations

from copy import deepcopy
import re
from typing import Any


_SENSITIVE_KEY_PARTS = (
    "authorization",
    "password",
    "secret",
    "token",
    "credential",
    "privatekey",
)
_BODY_KEYS = {"requestobject", "responseobject", "requestbody", "responsebody", "body"}
_INLINE_CREDENTIAL_PATTERNS = (
    re.compile(r"(Authorization\s*:\s*Bearer\s+)[^\s,;]+", re.IGNORECASE),
    re.compile(r"((?:token|password|secret)\s*[=:]\s*)[^\s,;]+", re.IGNORECASE),
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("_", "").replace("-", "")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact(value: Any, key: str | None = None) -> Any:
    if key is not None and key.lower().replace("_", "").replace("-", "") in _BODY_KEYS:
        return None
    if key is not None and _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for child_key, child_value in value.items():
            redacted = _redact(child_value, str(child_key))
            if redacted is not None:
                result[child_key] = redacted
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern in _INLINE_CREDENTIAL_PATTERNS:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        return redacted
    return deepcopy(value)


def redact_for_llm(event_or_window: dict[str, Any]) -> dict[str, Any]:
    """Return a copy safe for model input, excluding raw request/response bodies."""

    result = _redact(event_or_window)
    return result if isinstance(result, dict) else {}
