"""Turning an edge set into incidents, and giving each one a confidence that rises with
corroboration.

Two numbers travel with every incident and they answer different questions. Keeping them
apart is the whole reason this layer can sit on the provenance engine without lying:

**Correlation confidence** -- *do these observations really belong together?* Combined
noisy-OR across the edges, so independent corroboration strengthens the claim. Six separate
grounds for linking two alerts should leave you more sure than one, and this number rises.

**Evidentiary trust** -- *what may we do about it?* That is `min()` over the lineage, and it
is the engine's, unchanged. An incident is only as good as its weakest supporting sensor,
so a chain resting partly on an unverified address reputation cannot on its own authorise
something disruptive. This number falls to its weakest link.

An incident can therefore be near-certain and still not authorise isolating a host, which
is exactly the position the PS describes: "evidence thresholds, alternative hypotheses, and
minimal-impact response". Collapsing the two into one score is how correlation tools end up
either over-escalating or refusing to act at all.

Writing each incident through the gateway is what buys the rest for free -- the origin
closure that `rootcause.py` queries, and the tamper-evident chain that records every step.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ventriloquist.gateway import Gateway
from ventriloquist.provenance import Origin, OriginKind, TrustLevel
from .correlate import Edge
from .dedup import Observation
from .entities import EntityResolver, evidence_label
from .schema import Alert, iso

#: An edge must be at least this confident to *join* two observations into one incident.
#: Chosen by sweep against the labelled corpus: at 0.38 every attack stage lands in one
#: incident (recall 1.00); at 0.42 reconnaissance falls out. The cost is benign context on
#: the victim's own host and account being pulled into the case, which is a trade a
#: responder will take -- a case with surrounding context is workable, a case missing its
#: first stage is misleading.
#: Weaker edges are still drawn -- an analyst should see that we noticed a faint link and
#: chose not to act on it -- but they do not merge cases. Deliberately above `MIN_EDGE`.
CLUSTER_MIN = 0.38

#: A single observation with no edges is an incident only if it is loud enough to be worth
#: an analyst's time on its own.
LONE_SEVERITY = 70


class _Union:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def join(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _noisy_or(values: list[float]) -> float:
    """Combine independent grounds. Each additional edge closes some of the remaining gap."""
    remaining = 1.0
    for v in values:
        remaining *= (1.0 - max(0.0, min(1.0, v)))
    return 1.0 - remaining


@dataclass
class Incident:
    """One reconstructed case."""

    id: str
    observations: list[Observation]
    edges: list[Edge]
    entities: list[Origin] = field(default_factory=list)
    memory_id: str = ""
    trust: TrustLevel = TrustLevel.UNTRUSTED

    @property
    def alerts(self) -> list[Alert]:
        out: list[Alert] = []
        for obs in self.observations:
            out.extend(obs.members)
        return sorted(out, key=lambda a: (a.ts, a.id))

    @property
    def alert_count(self) -> int:
        return sum(o.count for o in self.observations)

    @property
    def first_ts(self) -> int:
        return min(o.first_ts for o in self.observations)

    @property
    def last_ts(self) -> int:
        return max(o.last_ts for o in self.observations)

    @property
    def severity(self) -> int:
        return max(o.severity for o in self.observations)

    @property
    def confidence(self) -> float:
        """How sure we are these belong together. Rises with independent corroboration."""
        if not self.edges:
            return 0.0
        return _noisy_or([e.confidence for e in self.edges])

    @property
    def sensors(self) -> list[str]:
        return sorted({o.representative.sensor for o in self.observations})

    def weakest(self) -> Origin | None:
        """The entity that caps what this incident may authorise."""
        return min(self.entities, key=lambda o: (o.trust, o.ref), default=None)

    def to_dict(self) -> dict:
        weak = self.weakest()
        return {
            "id": self.id,
            "alert_count": self.alert_count,
            "observation_count": len(self.observations),
            "edge_count": len(self.edges),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "first_seen": iso(self.first_ts),
            "last_seen": iso(self.last_ts),
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "sensors": self.sensors,
            "trust": self.trust.name,
            "evidence_label": evidence_label(self.trust),
            "weakest_entity": weak.to_dict() if weak else None,
            "entities": [o.to_dict() for o in self.entities],
            "observations": [o.to_dict() for o in self.observations],
            "edges": [e.to_dict() for e in self.edges],
            "memory_id": self.memory_id,
        }


def build(observations: list[Observation], edges: list[Edge], resolver: EntityResolver, *,
          cluster_min: float = CLUSTER_MIN) -> list[Incident]:
    """Cluster observations into incidents over the sufficiently-confident edges."""
    by_id = {o.id: o for o in observations}
    union = _Union()
    for obs in observations:
        union.find(obs.id)
    for edge in edges:
        if edge.confidence >= cluster_min:
            union.join(edge.src, edge.dst)

    groups: dict[str, list[str]] = {}
    for obs in observations:
        groups.setdefault(union.find(obs.id), []).append(obs.id)

    incidents: list[Incident] = []
    n = 0
    for root, members in groups.items():
        if len(members) == 1 and by_id[members[0]].severity < LONE_SEVERITY:
            continue  # a lone quiet observation is not a case
        member_set = set(members)
        n += 1
        obs_list = sorted((by_id[m] for m in members), key=lambda o: (o.first_ts, o.id))
        inc_edges = [e for e in edges
                     if e.src in member_set and e.dst in member_set]
        # One entity may be reported by several products at different weights. Keep the
        # weakest attestation: it is the one that will cap what this incident authorises,
        # and showing an analyst the strongest would misstate the position.
        entities: dict[str, Origin] = {}
        for obs in obs_list:
            for origin in resolver.origins_of(obs.representative):
                held = entities.get(origin.ref)
                if held is None or origin.trust < held.trust:
                    entities[origin.ref] = origin
        incidents.append(Incident(
            id=f"inc-{n:04d}",
            observations=obs_list,
            edges=sorted(inc_edges, key=lambda e: (-e.confidence, e.src)),
            entities=sorted(entities.values(), key=lambda o: (o.trust, o.ref)),
        ))

    incidents.sort(key=lambda i: (-i.severity, -i.alert_count, i.first_ts))
    for rank, inc in enumerate(incidents, 1):
        inc.id = f"inc-{rank:04d}"
    return incidents


def register(incidents: list[Incident], gateway: Gateway, *, session_id: str = "soc") -> None:
    """Write each incident through the gateway so it acquires lineage and an audit entry.

    Every entity becomes a read source, so the incident's provenance closure is exactly its
    entity set -- which is what lets `blast_radius()` later answer "contain this entity and
    what stops standing up?" without a graph walk. The trust the incident comes out with is
    the engine's `min()`, computed by the engine, not by us.
    """
    for inc in incidents:
        ctx = gateway.begin_turn(session_id=session_id, day=inc.first_ts)
        for origin in inc.entities:
            gateway.read_source(ctx, origin, f"{origin.label or origin.ref}")
        summary = (
            f"Incident {inc.id}: {inc.alert_count} alerts from "
            f"{', '.join(inc.sensors)} between {iso(inc.first_ts)} and {iso(inc.last_ts)}."
        )
        item = gateway.remember(ctx, summary, tags=("incident", inc.id),
                                written_by=OriginKind.SENSOR)
        inc.memory_id = item.id
        inc.trust = item.provenance.effective_trust
