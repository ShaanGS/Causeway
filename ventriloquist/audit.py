"""Append-only, hash-chained audit log.

Every write, every retrieval, every decision, and every quarantine release is a link in a
SHA-256 chain. Altering or removing any past entry breaks every hash after it, so the log
can be proven intact rather than merely trusted. This is also the event source the console
renders -- the UI is a projection of this log and nothing else.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

GENESIS = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEvent:
    seq: int
    kind: str
    day: int
    payload: dict
    prev_hash: str
    hash: str

    def to_dict(self) -> dict:
        return {"seq": self.seq, "kind": self.kind, "day": self.day,
                "payload": self.payload, "prev_hash": self.prev_hash, "hash": self.hash}


def _digest(seq: int, kind: str, day: int, payload: dict, prev_hash: str) -> str:
    body = json.dumps(
        {"seq": seq, "kind": kind, "day": day, "payload": payload, "prev": prev_hash},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class AuditLog:
    """In-process chain with optional JSONL persistence and a live subscriber hook."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else None
        self._events: list[AuditEvent] = []
        self._subscribers: list[Callable[[AuditEvent], None]] = []
        #: Tail of a JSONL file that could not be parsed -- a run killed mid-write leaves
        #: a partial last line. Kept rather than discarded, because "the log is truncated"
        #: and "the log is intact" are different answers and verify() must not conflate
        #: them.
        self.truncated_after: int | None = None
        if self.path and self.path.exists():
            self._load()

    def _load(self) -> None:
        """Rebuild the chain from disk so verify() spans every session, not just this one.

        Without this an audit log is only ever checked against the events one process
        happened to see, which is the opposite of what a tamper-evident log is for -- the
        interesting question is always whether yesterday's entries are still what they
        were.
        """
        assert self.path is not None
        with self.path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    self._events.append(AuditEvent(
                        seq=d["seq"], kind=d["kind"], day=d["day"], payload=d["payload"],
                        prev_hash=d["prev_hash"], hash=d["hash"],
                    ))
                except (json.JSONDecodeError, KeyError, TypeError):
                    # Stop at the first unreadable line rather than skipping it: the
                    # chain is an ordered structure and a hole in the middle of it would
                    # verify as tampering, which would be the wrong diagnosis.
                    self.truncated_after = self._events[-1].seq if self._events else -1
                    break

    # -- writing -----------------------------------------------------------------

    def append(self, kind: str, payload: dict, *, day: int = 0) -> AuditEvent:
        prev = self._events[-1].hash if self._events else GENESIS
        seq = len(self._events)
        event = AuditEvent(
            seq=seq, kind=kind, day=day, payload=payload, prev_hash=prev,
            hash=_digest(seq, kind, day, payload, prev),
        )
        self._events.append(event)
        if self.path:
            with self.path.open("a") as fh:
                fh.write(json.dumps(event.to_dict(), separators=(",", ":")) + "\n")
        for fn in list(self._subscribers):
            try:
                fn(event)
            except Exception:  # a broken subscriber must never break enforcement
                pass
        return event

    def subscribe(self, fn: Callable[[AuditEvent], None]) -> Callable[[], None]:
        self._subscribers.append(fn)
        return lambda: self._subscribers.remove(fn)

    # -- reading -----------------------------------------------------------------

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    @property
    def head(self) -> str:
        return self._events[-1].hash if self._events else GENESIS

    def by_kind(self, kind: str) -> list[AuditEvent]:
        return [e for e in self._events if e.kind == kind]

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(self._events)

    # -- integrity ---------------------------------------------------------------

    def verify(self) -> tuple[bool, int | None]:
        """Recompute the whole chain. Returns (intact, first_bad_seq)."""
        prev = GENESIS
        for event in self._events:
            expected = _digest(event.seq, event.kind, event.day, event.payload, prev)
            if event.prev_hash != prev or event.hash != expected:
                return False, event.seq
            prev = event.hash
        return True, None
