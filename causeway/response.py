"""The smallest safe action that actually interferes, and an honest account of the rest.

Two failure modes bracket this decision. Do nothing automatically and the analyst drowns.
Automate broadly and the tool isolates a production file server at 3am because a reputation
feed had an opinion. The PS names both, so neither "recommend the strongest action we are
allowed" nor "always ask a human" is an acceptable policy.

What is defensible is a ladder ordered by *disruption*, and taking the lowest rung that is
both **effective** against the thing we would actually be containing and **authorised** by
the evidence we actually have:

    annotate < notify < re-authenticate < revoke session < rotate credential
             < isolate host < disable account

Effectiveness comes from the root-cause entity: killing a process does nothing about a
stolen identity, and isolating a host does nothing about an account already active on three
others.

Authorisation comes from the engine's `min()`, but evaluated against the **target entity's**
lineage rather than the whole incident's. That distinction was a bug before it was a design.
Taking `min()` across the entire case means a network sensor's port-scan alert joining an
incident *lowers* what that incident may authorise -- so acquiring more evidence removes
your ability to act, which is perverse and would train anyone to keep cases narrow. What
actually matters when revoking `j.okafor`'s session is how well attested *j.okafor* is. A
port scan somewhere else in the same case is irrelevant to that question, and a threat feed
being the only thing that ever mentioned the account is decisive against it.

So the weakest-link rule survives where it belongs -- across the attestations of the thing
being acted on -- and stops punishing breadth.

The interesting output is not the recommendation. It is the refusal: *isolation needs an
analyst's confirmation; this incident sits at "single sensor" because its weakest evidence
is an address seen only by the network IDS.* That sentence tells an analyst what the system
would need in order to go further, which is the difference between a control they trust and
a control they switch off.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ventriloquist.gateway import Gateway
from ventriloquist.policy import Decision, PolicyEngine
from ventriloquist.provenance import OriginKind, ProvenanceRecord, TrustLevel

from .entities import EntityResolver, evidence_label
from .incident import Incident
from .rootcause import RootCandidate

POLICY_PATH = str(Path(__file__).parent / "policies" / "soc.yaml")

#: The ladder, least disruptive first. Order is the whole point: "smallest" is defined by
#: this list and by nothing else, so changing what counts as proportionate is one edit.
LADDER: tuple[str, ...] = (
    "alert.annotate",
    "analyst.notify",
    "identity.mfa_challenge",
    "session.revoke",
    "credential.rotate",
    "host.isolate",
    "account.disable",
)

#: Rungs that *end* access already established, as opposed to merely making the next step
#: harder. An MFA challenge is real interference and no help at all against a session the
#: attacker is already inside, which is the distinction between "smallest safe action" and
#: "smallest safe action **that stops progression**" -- the PS asks for the second.
CONTAINING: frozenset[str] = frozenset({
    "session.revoke", "credential.rotate", "host.isolate", "account.disable",
})

#: An incident that has moved this far is past the point where interference is enough.
PROGRESSED_OBSERVATIONS = 3

#: Which rungs do anything about which kind of root cause. An action absent from a kind's
#: list is not "risky" -- it is *irrelevant*, and recommending an irrelevant action is how a
#: system ends up isolating hosts to deal with credential theft.
EFFECTIVE: dict[OriginKind, tuple[str, ...]] = {
    OriginKind.ACCOUNT: ("identity.mfa_challenge", "session.revoke",
                         "credential.rotate", "account.disable"),
    OriginKind.HOST: ("host.isolate",),
    OriginKind.PROCESS: ("host.isolate",),
    OriginKind.ARTIFACT: ("host.isolate",),
    OriginKind.ADDRESS: (),   # blocking an address is not containment; see rootcause.py
}


@dataclass(frozen=True, slots=True)
class Option:
    """One rung, and whether this incident's evidence reaches it."""

    action_id: str
    label: str
    rule_id: str
    required: TrustLevel
    observed: TrustLevel
    allowed: bool
    effective: bool
    reason: str
    latency_us: float

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id, "label": self.label, "rule_id": self.rule_id,
            "required": self.required.name, "required_label": evidence_label(self.required),
            "observed": self.observed.name, "observed_label": evidence_label(self.observed),
            "allowed": self.allowed, "effective": self.effective,
            "reason": self.reason, "latency_us": round(self.latency_us, 2),
        }


@dataclass(frozen=True, slots=True)
class Recommendation:
    """What to do, what we will not do, and what it would take to be allowed to."""

    incident_id: str
    target: str
    target_label: str
    recommended: str
    recommended_label: str
    options: tuple[Option, ...]
    blocked_reason: str
    needs_human: tuple[str, ...]
    model_calls: int = 0
    network_calls: int = 0

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "target": self.target, "target_label": self.target_label,
            "recommended": self.recommended, "recommended_label": self.recommended_label,
            "options": [o.to_dict() for o in self.options],
            "blocked_reason": self.blocked_reason,
            "needs_human": list(self.needs_human),
            "model_calls": self.model_calls, "network_calls": self.network_calls,
        }


def load_policy() -> PolicyEngine:
    return PolicyEngine(POLICY_PATH)


def target_provenance(incident: Incident, root: RootCandidate, resolver: EntityResolver,
                      gateway: Gateway) -> ProvenanceRecord:
    """Lineage of the entity we are about to act on: every attestation of it in this case.

    `min()` over these is the weakest sensor that ever reported *this entity*, which is the
    right ceiling for acting on it -- unlike `min()` over the whole incident, which would
    penalise the case for containing evidence about anything else.
    """
    ctx = gateway.begin_turn(session_id=f"target-{incident.id}", day=incident.first_ts)
    seen = 0
    for obs in incident.observations:
        for origin in resolver.entity_origins(obs.representative):
            if origin.ref == root.ref:
                gateway.read_source(ctx, origin, origin.label)
                seen += 1
    if not seen:
        raise ValueError(f"{root.ref} is not attested anywhere in {incident.id}")
    return ctx.derive(f"acting on {root.ref}")


def recommend(incident: Incident, root: RootCandidate | None, policy: PolicyEngine,
              prov: ProvenanceRecord) -> Recommendation:
    """Pick the lowest effective rung the evidence authorises.

    ``prov`` is the lineage the decision is evaluated against: the target entity's, from
    `target_provenance`, or the incident's own when there is no rankable target.
    """
    effective = set(EFFECTIVE.get(root.entity.kind, ())) if root else set()

    options: list[Option] = []
    for action_id in LADDER:
        action = policy.action(action_id)
        decision: Decision = policy.evaluate(prov, action_id, memory_id=incident.memory_id)
        options.append(Option(
            action_id=action_id, label=action.label, rule_id=action.rule_id,
            required=action.required_trust, observed=decision.observed_trust,
            allowed=decision.allowed, effective=action_id in effective,
            reason=decision.reason, latency_us=decision.latency_us,
        ))

    # Has the attacker already established something, or are we still ahead of them?
    progressed = (len(incident.observations) >= PROGRESSED_OBSERVATIONS
                  or incident.severity >= 70)
    needed = (lambda o: o.effective and o.action_id in CONTAINING) if progressed \
        else (lambda o: o.effective)

    chosen = next((o for o in options if needed(o) and o.allowed), None)
    fallback = next(o for o in options if o.action_id == "analyst.notify")
    picked = chosen or fallback

    why = ""
    if progressed and chosen:
        interfering = next((o for o in options
                            if o.effective and o.action_id not in CONTAINING), None)
        if interfering:
            why = (
                f"This incident already spans {len(incident.observations)} observations "
                f"across {len(incident.sensors)} products, so {interfering.label.lower()} "
                f"would not end access the attacker already holds. "
                f"{picked.label} is the smallest rung that does."
            )

    # The rungs that would help but are out of reach. This is the sentence worth reading.
    withheld = [o for o in options if needed(o) and not o.allowed]
    if withheld:
        nxt = withheld[0]
        blocked = (
            f"{nxt.label} needs {evidence_label(nxt.required)}; the evidence for "
            f"{root.entity.label if root else 'this target'} is "
            f"{evidence_label(nxt.observed)}."
        )
    else:
        blocked = "" if chosen else (
            "Nothing on the ladder would durably contain this root cause, so it goes to "
            "an analyst rather than to an action that only looks decisive."
        )
    if why:
        blocked = (why + " " + blocked).strip()

    return Recommendation(
        incident_id=incident.id,
        target=root.ref if root else "",
        target_label=root.entity.label if root else "",
        recommended=picked.action_id,
        recommended_label=picked.label,
        options=tuple(options),
        blocked_reason=blocked,
        needs_human=tuple(o.action_id for o in withheld),
    )

