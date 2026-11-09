from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import AuditEvent


@dataclass(frozen=True)
class ParseStats:
    total_lines: int = 0
    parsed_events: int = 0
    malformed_lines: int = 0
    incomplete_events: int = 0


def _iter_lines(lines: Iterable[str] | str | Path) -> Iterable[str]:
    if isinstance(lines, Path):
        return lines.read_text(encoding="utf-8").splitlines()
    if isinstance(lines, str):
        path = Path(lines)
        if path.exists() and path.is_file():
            return path.read_text(encoding="utf-8").splitlines()
        return lines.splitlines()
    return lines


def parse_audit_jsonl(lines: Iterable[str] | str | Path) -> tuple[list[AuditEvent], ParseStats]:
    events: list[AuditEvent] = []
    total = malformed = incomplete = 0
    for line_number, line in enumerate(_iter_lines(lines), start=1):
        total += 1
        if not line.strip():
            malformed += 1
            continue
        try:
            raw = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            malformed += 1
            continue
        if not isinstance(raw, dict):
            malformed += 1
            continue
        event = AuditEvent.from_dict(raw, line_number=line_number)
        events.append(event)
        if event.parse_errors:
            incomplete += 1
    return events, ParseStats(
        total_lines=total,
        parsed_events=len(events),
        malformed_lines=malformed,
        incomplete_events=incomplete,
    )
