"""Memory storage. A protocol plus two implementations, so the backing store is swappable.

The gateway never touches a concrete store type. Putting a vector database behind this
protocol is a new class, not a change to the enforcement path.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .provenance import (
    Origin,
    OriginKind,
    ProvenanceRecord,
    TrustLevel,
)

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


@dataclass(slots=True)
class MemoryItem:
    id: str
    content: str
    provenance: ProvenanceRecord
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"id": self.id, "content": self.content, "tags": list(self.tags),
                "provenance": self.provenance.to_dict()}


@runtime_checkable
class MemoryStore(Protocol):
    def put(self, item: MemoryItem) -> None: ...
    def get(self, memory_id: str) -> MemoryItem | None: ...
    def search(self, query: str, *, limit: int = 5) -> list[MemoryItem]: ...
    def all(self) -> list[MemoryItem]: ...
    def delete(self, memory_id: str) -> bool: ...


class InMemoryStore:
    """Default store. Deliberately simple -- relevance is not the thing under test here."""

    def __init__(self) -> None:
        self._items: dict[str, MemoryItem] = {}

    def put(self, item: MemoryItem) -> None:
        self._items[item.id] = item

    def get(self, memory_id: str) -> MemoryItem | None:
        return self._items.get(memory_id)

    def search(self, query: str, *, limit: int = 5) -> list[MemoryItem]:
        q = _tokens(query)
        if not q:
            return []
        scored: list[tuple[float, MemoryItem]] = []
        for item in self._items.values():
            body = _tokens(item.content) | _tokens(" ".join(item.tags))
            overlap = len(q & body)
            if overlap:
                scored.append((overlap / len(q), item))
        scored.sort(key=lambda pair: (-pair[0], pair[1].id))
        return [item for _, item in scored[:limit]]

    def all(self) -> list[MemoryItem]:
        return list(self._items.values())

    def delete(self, memory_id: str) -> bool:
        return self._items.pop(memory_id, None) is not None

    def __len__(self) -> int:
        return len(self._items)


class SqliteStore:
    """Durable store. Same protocol, so the gateway cannot tell the difference."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS memories ("
            " id TEXT PRIMARY KEY, content TEXT NOT NULL,"
            " tags TEXT NOT NULL, provenance TEXT NOT NULL)"
        )
        self.conn.commit()

    def put(self, item: MemoryItem) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO memories VALUES (?,?,?,?)",
            (item.id, item.content, json.dumps(list(item.tags)),
             _encode_provenance(item.provenance)),
        )
        self.conn.commit()

    def _row(self, row: tuple) -> MemoryItem:
        return MemoryItem(id=row[0], content=row[1], tags=tuple(json.loads(row[2])),
                          provenance=_decode_provenance(row[3]))

    def get(self, memory_id: str) -> MemoryItem | None:
        cur = self.conn.execute("SELECT * FROM memories WHERE id=?", (memory_id,))
        row = cur.fetchone()
        return self._row(row) if row else None

    def all(self) -> list[MemoryItem]:
        return [self._row(r) for r in self.conn.execute("SELECT * FROM memories")]

    def search(self, query: str, *, limit: int = 5) -> list[MemoryItem]:
        q = _tokens(query)
        if not q:
            return []
        scored = []
        for item in self.all():
            overlap = len(q & (_tokens(item.content) | _tokens(" ".join(item.tags))))
            if overlap:
                scored.append((overlap / len(q), item))
        scored.sort(key=lambda pair: (-pair[0], pair[1].id))
        return [item for _, item in scored[:limit]]

    def delete(self, memory_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM memories WHERE id=?", (memory_id,))
        self.conn.commit()
        return cur.rowcount > 0


def _encode_provenance(p: ProvenanceRecord) -> str:
    return json.dumps({
        "origins": [{"kind": o.kind.name, "locator": o.locator,
                     "trust": o.trust.name, "label": o.label} for o in p.origins],
        "effective_trust": p.effective_trust.name,
        "derived_from": list(p.derived_from),
        "written_by": p.written_by.name,
        "session_id": p.session_id, "turn_id": p.turn_id,
        "written_at_day": p.written_at_day, "content_sha256": p.content_sha256,
        "claimed_trust": p.claimed_trust.name if p.claimed_trust else None,
    })


def _decode_provenance(blob: str) -> ProvenanceRecord:
    d = json.loads(blob)
    origins = frozenset(
        Origin(OriginKind[o["kind"]], o["locator"], TrustLevel[o["trust"]], o["label"])
        for o in d["origins"]
    )
    return ProvenanceRecord(
        origins=origins,
        effective_trust=TrustLevel[d["effective_trust"]],
        derived_from=tuple(d["derived_from"]),
        written_by=OriginKind[d["written_by"]],
        session_id=d["session_id"], turn_id=d["turn_id"],
        written_at_day=d["written_at_day"], content_sha256=d["content_sha256"],
        claimed_trust=TrustLevel[d["claimed_trust"]] if d["claimed_trust"] else None,
    )
