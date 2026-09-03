"""The Ventriloquist gateway -- the whole product surface in one class.

    gw = Gateway()
    ctx = gw.begin_turn(session_id="s1", day=0)
    gw.read_source(ctx, portal, page_text)           # agent reads a web page
    gw.remember(ctx, "Acme remittance acct GB29...")  # agent stores what it learned
    ...
    ctx = gw.begin_turn(session_id="s2", day=41)
    result = gw.recall(ctx, "Acme account", action="financial.payment")

The two things that make this work are both visible in that snippet: a write always happens
inside a turn that knows what was read, and a read always names the action it is feeding.
Neither is a burden on the agent author -- but together they are enough to authorise on
lineage instead of guessing from content.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from .audit import AuditLog
from .policy import Decision, PolicyEngine, Verdict
from .provenance import Origin, OriginKind, ProvenanceRecord, TrustLevel
from .quarantine import QuarantineEntry, QuarantineQueue
from .revocation import RevocationReport, blast_radius
from .store import InMemoryStore, MemoryItem, MemoryStore
from .taint import TurnContext


#: `mem_12` and the `mem_12@attested` a quarantine release writes both count as 12.
_SERIAL = re.compile(r"^(?:mem|turn)_(\d+)")


def _next_id(store: MemoryStore) -> int:
    """One past the highest serial the store already holds, or 1 if it is empty."""
    highest = 0
    for item in store.all():
        match = _SERIAL.match(item.id)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


@dataclass(slots=True)
class RecallResult:
    """What came back from a guarded retrieval, and why."""

    query: str
    action: str
    allowed: list[MemoryItem] = field(default_factory=list)
    blocked: list[tuple[MemoryItem, Decision]] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)

    @property
    def total_latency_us(self) -> float:
        return sum(d.latency_us for d in self.decisions)

    def to_dict(self) -> dict:
        return {
            "query": self.query, "action": self.action,
            "allowed": [i.to_dict() for i in self.allowed],
            "blocked": [{"item": i.to_dict(), "decision": d.to_dict()}
                        for i, d in self.blocked],
            "decisions": [d.to_dict() for d in self.decisions],
            "total_latency_us": round(self.total_latency_us, 2),
        }


class Gateway:
    """One gateway between any agent and its memory."""

    def __init__(self, *, store: MemoryStore | None = None,
                 policy: PolicyEngine | None = None,
                 audit: AuditLog | None = None,
                 propagate: bool = True,
                 policy_path: Path | str | None = None) -> None:
        self.store: MemoryStore = store or InMemoryStore()
        self.policy = policy or PolicyEngine(policy_path)
        self.audit = audit or AuditLog()
        self.quarantine = QuarantineQueue()
        #: Global default for taint propagation. Demonstrating the vulnerability is a
        #: matter of turning this off; it is never off in a deployed configuration.
        self.propagate = propagate
        # Resume past whatever the store already holds. On an InMemoryStore this is always
        # 1 and nothing changes; on a durable one, starting from 1 again would hand the
        # next write an id that is already taken and `put` would silently overwrite a
        # memory -- along with its lineage, which is the one thing that must not be lost.
        self._ids = itertools.count(_next_id(self.store))

    # -- turns -------------------------------------------------------------------

    def begin_turn(self, *, session_id: str, day: int = 0,
                   turn_id: str | None = None) -> TurnContext:
        turn = turn_id or f"turn_{next(self._ids)}"
        self.audit.append("turn.begin",
                          {"session_id": session_id, "turn_id": turn}, day=day)
        return TurnContext(session_id=session_id, turn_id=turn, day=day,
                           propagate=self.propagate)

    # -- the write path ----------------------------------------------------------

    def read_source(self, ctx: TurnContext, origin: Origin, content: str) -> None:
        """Register that the agent consumed external content during this turn."""
        ctx.observe_source(origin, content)
        self.audit.append("source.read", {
            "turn_id": ctx.turn_id, "origin": origin.to_dict(),
            "chars": len(content),
        }, day=ctx.day)

    def remember(self, ctx: TurnContext, content: str, *,
                 tags: tuple[str, ...] = (), memory_id: str | None = None,
                 written_by: OriginKind = OriginKind.AGENT) -> MemoryItem:
        """Store a memory, stamped with the lineage of everything read this turn."""
        mid = memory_id or f"mem_{next(self._ids)}"
        provenance = ctx.derive(content, written_by=written_by)
        item = MemoryItem(id=mid, content=content, provenance=provenance, tags=tags)
        self.store.put(item)
        self.audit.append("memory.write", {
            "memory_id": mid, "content": content, "tags": list(tags),
            "provenance": provenance.to_dict(),
        }, day=ctx.day)
        return item

    # -- the read path -----------------------------------------------------------

    def recall(self, ctx: TurnContext, query: str, *, action: str = "memory.read",
               limit: int = 5) -> RecallResult:
        """Retrieve memories for a stated purpose, enforcing lineage against that purpose."""
        result = RecallResult(query=query, action=action)
        for item in self.store.search(query, limit=limit):
            decision = self.policy.evaluate(item.provenance, action, memory_id=item.id)
            result.decisions.append(decision)

            if decision.allowed:
                result.allowed.append(item)
                # Forward propagation: whatever the agent writes next inherits from this.
                ctx.observe_memory(item.id, item.provenance)
            else:
                result.blocked.append((item, decision))
                if self.quarantine.get(item.id) is None:
                    self.quarantine.hold(item, decision, day=ctx.day)

            self.audit.append("policy.decision", {
                "turn_id": ctx.turn_id, "query": query,
                **decision.to_dict(),
            }, day=ctx.day)
        return result

    # -- review ------------------------------------------------------------------

    def release(self, memory_id: str, *, reviewer: str, note: str = "",
                day: int = 0) -> QuarantineEntry:
        entry, attested = self.quarantine.release(
            memory_id, reviewer=reviewer, note=note, day=day)
        self.store.put(attested)
        self.audit.append("quarantine.release", {
            "memory_id": memory_id, "reviewer": reviewer, "note": note,
            "attested_as": attested.id,
            "provenance": attested.provenance.to_dict(),
        }, day=day)
        return entry

    def reject(self, memory_id: str, *, reviewer: str, note: str = "") -> QuarantineEntry:
        entry = self.quarantine.reject(memory_id, reviewer=reviewer, note=note)
        self.audit.append("quarantine.reject",
                          {"memory_id": memory_id, "reviewer": reviewer, "note": note})
        return entry

    # -- revocation --------------------------------------------------------------
    #
    # The act after the act. Everything above answers "should this be allowed"; these two
    # answer the question an operator asks once something has already gone wrong -- what
    # did that source touch, and what is still standing on it.

    def blast_radius(self, origin_ref: str, *,
                     to: TrustLevel = TrustLevel.UNTRUSTED) -> RevocationReport:
        """What revoking this origin would cost. Applies nothing; safe to call on stage."""
        return blast_radius(self.store, self.policy, origin_ref, to=to)

    def revoke(self, origin_ref: str, *, reviewer: str, note: str = "",
               to: TrustLevel = TrustLevel.UNTRUSTED, day: int = 0) -> RevocationReport:
        """Declare an origin compromised, and record what that cost.

        The report is computed *before* the revocation lands, because it is the difference
        between two worlds and the second one does not exist yet. Applying it is then one
        dictionary entry -- no memory is rewritten, and the audit log still holds every
        affected record exactly as it was written.
        """
        report = self.blast_radius(origin_ref, to=to)
        self.policy.revoke(origin_ref, to=to)
        self.audit.append("origin.revoke", {
            "origin_ref": origin_ref, "reviewer": reviewer, "note": note,
            "trust_before": report.trust_before.name, "trust_after": to.name,
            "affected": [a.memory_id for a in report.affected],
            "inherited": [a.memory_id for a in report.inherited],
            "actions_revoked": report.actions_revoked,
        }, day=day)
        return replace(report, applied=True)

    def unrevoke(self, origin_ref: str, *, reviewer: str = "", day: int = 0) -> bool:
        """Undo a revocation. Restores nothing by itself -- trust simply recomputes again."""
        undone = self.policy.unrevoke(origin_ref)
        if undone:
            self.audit.append("origin.unrevoke",
                              {"origin_ref": origin_ref, "reviewer": reviewer}, day=day)
        return undone

    # -- introspection -----------------------------------------------------------

    def stats(self) -> dict:
        decisions = self.audit.by_kind("policy.decision")
        blocked = [e for e in decisions if e.payload["verdict"] != Verdict.ALLOW.value]
        latencies = sorted(e.payload["latency_us"] for e in decisions)
        intact, bad = self.audit.verify()
        return {
            "memories": len(self.store.all()),
            "decisions": len(decisions),
            "blocked": len(blocked),
            "quarantined": len(self.quarantine.pending()),
            "audit_events": len(self.audit),
            "audit_intact": intact,
            "audit_first_bad_seq": bad,
            "p50_latency_us": latencies[len(latencies) // 2] if latencies else 0.0,
            "p99_latency_us": latencies[int(len(latencies) * 0.99)] if latencies else 0.0,
            "taint_propagation": self.propagate,
        }
