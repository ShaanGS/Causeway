"""Which *thing* to contain, and what breaks if you do.

An early version of this ranked alerts, and ranking alerts turns out to be the wrong
question. In the corpus the password spray precedes the successful login and the whole
chain hangs off it, so "earliest" and "most downstream reach" both point at a failed
authentication. That looked like a scoring bug until the obvious objection landed:
containing `j.okafor` at the moment of the spray *would* have stopped the attack. The
ranking was right and the question was wrong.

Nobody contains an alert. They disable an account, isolate a host, kill a process, block an
address. So candidates here are **entities**, and each one is scored on what an
organisation could actually do about it:

**coverage** -- how much of the incident involves this entity at all.
**earliness** -- when it first appears, because the value of containment decays.
**controllability** -- how durably it can be brought under control. An identity can be
disabled and stays disabled; an address is chosen by the attacker and costs them nothing to
change. Blocking the address is the move that feels decisive and accomplishes least.

The consequence is the useful part: two different alerts, the failed spray attempt and the
successful login, resolve to the same answer -- `account:j.okafor` -- which is what a
responder needed to be told either way.

`Alert.stage` is never read here. A scorer that can see the answer key measures nothing,
and a test asserts the module never touches it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ventriloquist.gateway import Gateway
from ventriloquist.provenance import Origin, OriginKind
from ventriloquist.revocation import RevocationReport
from .incident import Incident
from .schema import iso

#: How durably each kind of entity can be brought under control.
CONTROLLABILITY: dict[OriginKind, float] = {
    OriginKind.ACCOUNT: 1.00,
    OriginKind.PROCESS: 0.70,
    OriginKind.HOST: 0.65,
    OriginKind.ARTIFACT: 0.50,
    OriginKind.ADDRESS: 0.25,
    OriginKind.SENSOR: 0.00,   # a sensor is not a thing you contain
}

WEIGHTS = {"coverage": 0.40, "control": 0.35, "earliness": 0.25}


@dataclass(frozen=True, slots=True)
class RootCandidate:
    """One entity proposed as the thing to act on, with its arithmetic shown."""

    entity: Origin
    score: float
    coverage: float
    observations: int
    first_ts: int
    first_alert_id: str
    first_summary: str
    earliness: float
    controllability: float
    reason: str

    @property
    def ref(self) -> str:
        return self.entity.ref

    def to_dict(self) -> dict:
        return {
            "ref": self.ref,
            "entity": self.entity.to_dict(),
            "score": round(self.score, 4),
            "coverage": round(self.coverage, 3),
            "observations": self.observations,
            "first_ts": self.first_ts,
            "first_seen": iso(self.first_ts),
            "first_alert_id": self.first_alert_id,
            "first_summary": self.first_summary,
            "earliness": round(self.earliness, 3),
            "controllability": round(self.controllability, 3),
            "reason": self.reason,
        }


def rank(incident: Incident, resolver, *, top: int = 3) -> list[RootCandidate]:
    """Rank the incident's entities by how much containing them would have mattered."""
    obs = sorted(incident.observations, key=lambda o: (o.first_ts, o.id))
    if not obs:
        return []
    span_start, span_end = obs[0].first_ts, obs[-1].first_ts
    span = max(1, span_end - span_start)

    seen: dict[str, dict] = {}
    for o in obs:
        for origin in resolver.entity_origins(o.representative):
            row = seen.get(origin.ref)
            if row is None:
                seen[origin.ref] = {
                    "origin": origin, "count": 1,
                    "first_ts": o.first_ts, "first_alert": o.representative.id,
                    "first_summary": o.representative.text,
                }
            else:
                row["count"] += 1

    out: list[RootCandidate] = []
    for ref, row in seen.items():
        origin: Origin = row["origin"]
        control = CONTROLLABILITY.get(origin.kind, 0.0)
        if control <= 0.0:
            continue  # not a thing anyone can contain
        coverage = row["count"] / len(obs)
        earliness = 1.0 - ((row["first_ts"] - span_start) / span)
        score = (WEIGHTS["coverage"] * coverage
                 + WEIGHTS["control"] * control
                 + WEIGHTS["earliness"] * earliness)

        reason = (
            f"{origin.label} appears in {row['count']} of the {len(obs)} observations in "
            f"this incident, first at {iso(row['first_ts'])} "
            f"({row['first_summary']}). "
            + _control_phrase(origin.kind)
        )
        out.append(RootCandidate(
            entity=origin, score=score, coverage=coverage,
            observations=row["count"], first_ts=row["first_ts"],
            first_alert_id=row["first_alert"], first_summary=row["first_summary"],
            earliness=earliness, controllability=control, reason=reason,
        ))

    out.sort(key=lambda c: (-c.score, c.first_ts, c.ref))
    return out[:top]


def _control_phrase(kind: OriginKind) -> str:
    return {
        OriginKind.ACCOUNT: "An identity can be disabled and stays disabled.",
        OriginKind.PROCESS: "The process can be killed, though the foothold may survive it.",
        OriginKind.HOST: "The host can be isolated, at the cost of whatever runs on it.",
        OriginKind.ARTIFACT: "The file can be quarantined.",
        OriginKind.ADDRESS: ("An address is chosen by the attacker and costs nothing to "
                             "change, so blocking it rarely ends anything."),
    }.get(kind, "")


def containment_preview(gateway: Gateway, entity_ref: str) -> RevocationReport:
    """What stops standing up if this entity is contained.

    Straight through to the engine's `blast_radius`, unchanged. Because every incident was
    written through the gateway carrying its entities as lineage, "which cases rest on this
    entity" is a filter over the origin closure rather than a graph walk -- and it answers
    for cases nobody thought to link to it by name.
    """
    return gateway.blast_radius(entity_ref)
