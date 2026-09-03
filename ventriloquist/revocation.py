"""Retroactive revocation: what an operator needs the morning after.

Prevention is half the job. The other half arrives as a phone call, three weeks late:
*that vendor portal was compromised.* The question that follows is never "will you block
it now" -- it is **what did it already touch, and what is still standing on it?**

A memory layer that records beliefs cannot answer that at all: it kept the conclusion and
threw the derivation away. A layer that records lineage answers it exactly, and cheaply,
because ``ProvenanceRecord.origins`` is the *transitive closure* of root origins. Every
memory that traces to a compromised origin already carries it -- including the ones the
agent rewrote in its own words, which share no vocabulary with the page they came from and
which no keyword search would ever return. So the blast radius is one filter over the
store, not a graph walk:

    [i for i in store.all() if ref in {o.ref for o in i.provenance.origins}]

That is the same invariant that refuses the payment, read in the other direction. Trust is
inherited, so contamination is traceable. You do not get one of those without the other.

**Nothing in the store is rewritten.** A memory's ``effective_trust`` is stamped at write
time and never edited -- that is the lattice invariant. What revocation changes is one
fact about one *origin*, held in the policy, and every decision recomputes from origins at
evaluate time. Forty-one days of accumulated belief therefore re-evaluate themselves the
instant the origin is revoked, and the audit log still holds each memory exactly as it was
written. Revocation is a policy edit, not a migration.

The mirror image of quarantine release is deliberate. Release *raises* trust, so it must
write a new item rooted in the reviewer's authority -- editing would let trust rise with
nobody vouching for it. Revocation only ever *lowers* trust, so it needs no new authority
and can be expressed as data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .policy import PolicyEngine
from .provenance import Origin, TrustLevel
from .store import MemoryStore


@dataclass(frozen=True, slots=True)
class Affected:
    """One memory whose lineage runs back to the revoked origin."""

    memory_id: str
    content: str
    tags: tuple[str, ...]
    trust_before: TrustLevel
    trust_after: TrustLevel
    #: True when the turn that wrote this memory read the revoked origin itself. False
    #: means the contamination arrived through a chain -- the agent read a memory that
    #: came from it, and wrote something new. Those are the ones worth pointing at: they
    #: are in this list purely because of the origin closure, and nothing in their text
    #: would have led an investigator to them.
    direct: bool
    #: The write looked first-party at the time -- claimed more authority than its lineage
    #: earned. Laundered and inherited usually coincide; they are not the same question.
    laundered: bool
    #: Actions this memory could authorise before the revocation and cannot after.
    lost_actions: tuple[str, ...] = ()

    @property
    def inherited(self) -> bool:
        return not self.direct

    @property
    def levels_dropped(self) -> int:
        return max(0, int(self.trust_before) - int(self.trust_after))

    def to_dict(self) -> dict:
        return {
            "memory_id": self.memory_id,
            "content": self.content,
            "tags": list(self.tags),
            "trust_before": self.trust_before.name,
            "trust_before_label": self.trust_before.label,
            "trust_after": self.trust_after.name,
            "trust_after_label": self.trust_after.label,
            "direct": self.direct,
            "inherited": self.inherited,
            "laundered": self.laundered,
            "levels_dropped": self.levels_dropped,
            "lost_actions": list(self.lost_actions),
        }


@dataclass(frozen=True, slots=True)
class RevocationReport:
    """What revoking one origin does to a store -- computed before anything is applied."""

    origin_ref: str
    origin_label: str
    trust_before: TrustLevel
    trust_after: TrustLevel
    affected: tuple[Affected, ...]
    scanned: int
    latency_us: float
    applied: bool = False

    @property
    def direct(self) -> tuple[Affected, ...]:
        return tuple(a for a in self.affected if a.direct)

    @property
    def inherited(self) -> tuple[Affected, ...]:
        """The ones a keyword search would have missed. This is the number to say out loud."""
        return tuple(a for a in self.affected if a.inherited)

    @property
    def actions_revoked(self) -> int:
        return sum(len(a.lost_actions) for a in self.affected)

    def to_dict(self) -> dict:
        return {
            "origin_ref": self.origin_ref,
            "origin_label": self.origin_label,
            "trust_before": self.trust_before.name,
            "trust_before_label": self.trust_before.label,
            "trust_after": self.trust_after.name,
            "trust_after_label": self.trust_after.label,
            "affected": [a.to_dict() for a in self.affected],
            "affected_count": len(self.affected),
            "direct_count": len(self.direct),
            "inherited_count": len(self.inherited),
            "actions_revoked": self.actions_revoked,
            "scanned": self.scanned,
            "latency_us": round(self.latency_us, 2),
            "applied": self.applied,
        }


def known_origins(store: MemoryStore, policy: PolicyEngine) -> list[dict]:
    """Every origin present in the store, with how many memories carry it.

    This is what the console offers as revocation candidates -- an operator picks a source
    that turned out to be bad, and the only sources worth offering are the ones something
    actually stands on.
    """
    seen: dict[str, dict] = {}
    for item in store.all():
        for origin in item.provenance.origins:
            row = seen.get(origin.ref)
            if row is None:
                trust, _ = policy.effective_trust_of(origin)
                seen[origin.ref] = {
                    "ref": origin.ref,
                    "label": origin.label or origin.locator,
                    "kind": origin.kind.name,
                    "trust": trust.name,
                    "trust_label": trust.label,
                    "memories": 1,
                    "revoked": policy.is_revoked(origin.ref),
                }
            else:
                row["memories"] += 1
    return sorted(seen.values(), key=lambda r: (-r["memories"], r["ref"]))


def _origin_in(store: MemoryStore, ref: str) -> Origin | None:
    for item in store.all():
        for origin in item.provenance.origins:
            if origin.ref == ref:
                return origin
    return None


def blast_radius(store: MemoryStore, policy: PolicyEngine, origin_ref: str, *,
                 to: TrustLevel = TrustLevel.UNTRUSTED) -> RevocationReport:
    """Everything that would change if ``origin_ref`` were revoked. Pure -- applies nothing.

    Runs the real policy twice per memory per action class: once as things stand, once
    against a hypothetical in which the origin has been demoted. The difference is what an
    operator is actually asking for -- not "which memories mention this" but "which
    privileges evaporate".
    """
    started = time.perf_counter()

    origin = _origin_in(store, origin_ref)
    trust_before, _ = (policy.effective_trust_of(origin) if origin
                       else (TrustLevel.UNTRUSTED, None))
    label = (origin.label or origin.locator) if origin else origin_ref

    affected: list[Affected] = []
    scanned = 0
    for item in store.all():
        scanned += 1
        prov = item.provenance
        if origin_ref not in {o.ref for o in prov.origins}:
            continue

        before, _ = policy.effective_trust(prov)
        after, _ = policy.effective_trust(prov, revoked={**policy.revoked, origin_ref: to})

        lost = tuple(
            action_id
            for action_id, action in policy.actions.items()
            if before >= action.required_trust and after < action.required_trust
        )

        affected.append(Affected(
            memory_id=item.id,
            content=item.content,
            tags=item.tags,
            trust_before=before,
            trust_after=after,
            # `derived_from` holds a memory id for every stored memory read this turn and
            # an origin ref for every source read directly, so its membership is exactly
            # the question "did this turn read the origin itself?".
            direct=origin_ref in prov.derived_from,
            laundered=prov.is_laundered,
            lost_actions=lost,
        ))

    affected.sort(key=lambda a: (a.direct, a.memory_id))
    elapsed = (time.perf_counter() - started) * 1_000_000
    return RevocationReport(
        origin_ref=origin_ref,
        origin_label=label,
        trust_before=trust_before,
        trust_after=to,
        affected=tuple(affected),
        scanned=scanned,
        latency_us=elapsed,
    )
