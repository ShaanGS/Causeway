"""Quarantine and human review.

A refusal that cannot be undone gets the control switched off, so blocks are held rather
than dropped. Release is modelled as *re-attestation*, not mutation: a human vouching for a
quarantined memory becomes a new origin for it, and a new memory item is written rooted in
that person's authority, carrying a pointer back to the original.

Nothing is ever edited in place. The lattice invariant -- trust is the minimum over origins
-- therefore holds for released memories too, and the original stays on the record.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .policy import Decision
from .provenance import Origin, OriginKind, ProvenanceRecord, TrustLevel, content_hash
from .store import MemoryItem


class ReviewStatus(str, Enum):
    HELD = "HELD"
    RELEASED = "RELEASED"
    REJECTED = "REJECTED"


@dataclass(slots=True)
class QuarantineEntry:
    memory_id: str
    item: MemoryItem
    decision: Decision
    day: int
    status: ReviewStatus = ReviewStatus.HELD
    reviewer: str = ""
    note: str = ""
    released_as: str = ""

    def to_dict(self) -> dict:
        return {
            "memory_id": self.memory_id, "content": self.item.content,
            "decision": self.decision.to_dict(), "day": self.day,
            "status": self.status.value, "reviewer": self.reviewer,
            "note": self.note, "released_as": self.released_as,
        }


class QuarantineQueue:
    def __init__(self) -> None:
        self._entries: dict[str, QuarantineEntry] = {}

    def hold(self, item: MemoryItem, decision: Decision, *, day: int = 0) -> QuarantineEntry:
        entry = QuarantineEntry(item.id, item, decision, day)
        self._entries[item.id] = entry
        return entry

    def get(self, memory_id: str) -> QuarantineEntry | None:
        return self._entries.get(memory_id)

    def pending(self) -> list[QuarantineEntry]:
        return [e for e in self._entries.values() if e.status is ReviewStatus.HELD]

    def all(self) -> list[QuarantineEntry]:
        return list(self._entries.values())

    def reject(self, memory_id: str, *, reviewer: str, note: str = "") -> QuarantineEntry:
        entry = self._require(memory_id)
        entry.status, entry.reviewer, entry.note = ReviewStatus.REJECTED, reviewer, note
        return entry

    def release(self, memory_id: str, *, reviewer: str, note: str = "",
                day: int = 0) -> tuple[QuarantineEntry, MemoryItem]:
        """Vouch for a held memory. Produces a NEW item rooted in the reviewer's authority."""
        entry = self._require(memory_id)
        attestor = Origin.of(
            OriginKind.USER, f"reviewer/{reviewer}",
            trust=TrustLevel.USER_VERIFIED, label=f"Reviewed by {reviewer}",
        )
        attested = MemoryItem(
            id=f"{memory_id}@attested",
            content=entry.item.content,
            tags=entry.item.tags + ("attested",),
            provenance=ProvenanceRecord(
                origins=frozenset({attestor}),
                effective_trust=attestor.trust,
                derived_from=(memory_id,),
                written_by=OriginKind.USER,
                session_id=entry.item.provenance.session_id,
                turn_id=entry.item.provenance.turn_id,
                written_at_day=day,
                content_sha256=content_hash(entry.item.content),
                claimed_trust=attestor.trust,
            ),
        )
        entry.status, entry.reviewer, entry.note = ReviewStatus.RELEASED, reviewer, note
        entry.released_as = attested.id
        return entry, attested

    def _require(self, memory_id: str) -> QuarantineEntry:
        entry = self._entries.get(memory_id)
        if entry is None:
            raise KeyError(f"no quarantine entry for {memory_id!r}")
        return entry
