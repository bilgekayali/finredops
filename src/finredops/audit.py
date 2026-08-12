"""Append-only, hash-chained audit events."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import (
    canonical_json,
    ensure_aware,
    freeze_value,
    parse_datetime,
    sha256_digest,
    to_primitive,
)


GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEvent:
    sequence: int
    timestamp: datetime
    actor_id: str
    event_type: str
    engagement_id: str
    payload: Mapping[str, Any]
    previous_hash: str
    event_hash: str

    def hash_payload(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "actor_id": self.actor_id,
            "event_type": self.event_type,
            "engagement_id": self.engagement_id,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }


class AuditChain:
    def __init__(self, events: Iterable[AuditEvent] = ()) -> None:
        self._events = list(events)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def append(
        self,
        *,
        timestamp: datetime,
        actor_id: str,
        event_type: str,
        engagement_id: str,
        payload: Mapping[str, Any],
    ) -> AuditEvent:
        timestamp = ensure_aware(timestamp)
        if self._events and timestamp < self._events[-1].timestamp:
            raise ValueError("Audit events must be appended in chronological order.")
        sequence = len(self._events) + 1
        previous_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        unsigned = {
            "sequence": sequence,
            "timestamp": timestamp,
            "actor_id": actor_id,
            "event_type": event_type,
            "engagement_id": engagement_id,
            "payload": freeze_value(payload),
            "previous_hash": previous_hash,
        }
        event = AuditEvent(
            **unsigned,
            event_hash=sha256_digest(unsigned),
        )
        self._events.append(event)
        return event

    def verify(self) -> tuple[bool, tuple[str, ...]]:
        errors: list[str] = []
        previous_hash = GENESIS_HASH
        for expected_sequence, event in enumerate(self._events, start=1):
            if event.sequence != expected_sequence:
                errors.append(f"Event {expected_sequence}: invalid sequence {event.sequence}.")
            if event.previous_hash != previous_hash:
                errors.append(f"Event {expected_sequence}: previous hash mismatch.")
            expected_hash = sha256_digest(event.hash_payload())
            if event.event_hash != expected_hash:
                errors.append(f"Event {expected_sequence}: event hash mismatch.")
            previous_hash = event.event_hash
        return not errors, tuple(errors)

    def to_jsonl(self) -> str:
        return "".join(canonical_json(event) + "\n" for event in self._events)

    def write(self, path: Path) -> None:
        path.write_text(self.to_jsonl(), encoding="utf-8")

    @classmethod
    def read(cls, path: Path) -> "AuditChain":
        events: list[AuditEvent] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                event = AuditEvent(
                    sequence=int(raw["sequence"]),
                    timestamp=parse_datetime(raw["timestamp"]),
                    actor_id=str(raw["actor_id"]),
                    event_type=str(raw["event_type"]),
                    engagement_id=str(raw["engagement_id"]),
                    payload=freeze_value(raw["payload"]),
                    previous_hash=str(raw["previous_hash"]),
                    event_hash=str(raw["event_hash"]),
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid audit event on line {line_number}: {exc}") from exc
            events.append(event)
        return cls(events)

    def as_list(self) -> list[dict[str, Any]]:
        return [to_primitive(event) for event in self._events]
