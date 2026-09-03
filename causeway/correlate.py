"""Drawing the edges. This is the part the engine could not do for us.

Ventriloquist is *handed* lineage by an agent's turn context. A SOC is handed nothing: the
edges have to be inferred from what the alerts happen to mention. Three ideas do the work
here, and each is a deliberate answer to a way that alert correlation usually fails.

**Precedence is mandatory.** Every edge points forward in time. Co-occurrence is not
causation, and a correlator that will draw an edge in either direction has only found a
cluster. Turning this off is the negative control in `metrics.py` -- if the results barely
move without it, the causal claim was decoration.

**Nearest predecessor, not every predecessor.** An entity links an observation to the most
recent earlier observation that mentioned it, not to all of them. Linking to all produces a
clique -- one blob per busy host, technically connected and useless to read. Chains are what
an analyst can follow.

**Ubiquitous entities carry no signal.** The domain controller appears in everything; so
does the vulnerability scanner's source address. Joining on those merges the whole estate
into one incident. Each entity is weighted by how rare it is across the corpus -- the
standard inverse-document-frequency idea -- so a hub contributes almost nothing and a host
that appears in nine observations contributes a lot. This is why the benign Sunday does not
collapse into a single false incident, and it is the cheapest defence against the failure
mode that makes analysts abandon correlation tooling.

Process ancestry is exempt from all weighting: a parent pid *is* causation, not evidence of
it. No model runs here and nothing leaves the process.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ventriloquist.provenance import OriginKind
from .dedup import Observation
from .entities import EntityResolver

#: How much an entity of each kind is worth as a *link*, before rarity weighting. Distinct
#: from evidentiary trust in `entities.py`: an address is weak evidence but a decent
#: linker, and a sensor is decent evidence but no linker at all -- everything a product
#: emits shares its sensor, so joining on it would merge the product's entire output.
LINK_STRENGTH: dict[OriginKind, float] = {
    OriginKind.PROCESS: 0.90,
    OriginKind.ACCOUNT: 0.75,
    OriginKind.ARTIFACT: 0.70,
    OriginKind.HOST: 0.60,
    OriginKind.ADDRESS: 0.55,
    OriginKind.SENSOR: 0.0,
}

PROC_WINDOW = 3600     # a parent process may sit idle a while before its child acts
PIVOT_WINDOW = 1800    # same identity appearing on a second host
ENTITY_WINDOW = 900    # ordinary shared-entity continuity
MIN_EDGE = 0.30        # below this an edge is noise and is not drawn


@dataclass(frozen=True, slots=True)
class Edge:
    """One causal claim, with the grounds for it in words an analyst can argue with."""

    src: str            # the earlier observation -- the cause
    dst: str            # the later observation -- the effect
    rule_id: str
    confidence: float
    reason: str

    def to_dict(self) -> dict:
        return {"src": self.src, "dst": self.dst, "rule_id": self.rule_id,
                "confidence": round(self.confidence, 3), "reason": self.reason}


def entity_weights(observations: list[Observation], resolver: EntityResolver
                   ) -> dict[str, float]:
    """Rarity weight per entity ref, in [0, 1]. Ubiquitous entities score near zero."""
    total = max(1, len(observations))
    df: dict[str, int] = {}
    for obs in observations:
        for ref in {o.ref for o in resolver.entity_origins(obs.representative)}:
            df[ref] = df.get(ref, 0) + 1
    scale = math.log(total + 1)
    return {ref: min(1.0, math.log(total / count) / scale) for ref, count in df.items()}


def _refs(obs: Observation, resolver: EntityResolver) -> dict[str, OriginKind]:
    return {o.ref: o.kind for o in resolver.entity_origins(obs.representative)
            if o.kind is not OriginKind.SENSOR}


def correlate(observations: list[Observation], resolver: EntityResolver, *,
              temporal: bool = True, min_edge: float = MIN_EDGE) -> list[Edge]:
    """Build the causal edge set over observations.

    ``temporal=False`` drops the precedence requirement, which is the ablation the metrics
    harness runs to show precedence is load-bearing rather than ornamental.
    """
    ordered = sorted(observations, key=lambda o: (o.first_ts, o.id))
    weights = entity_weights(ordered, resolver)
    #: best edge per (src, dst, rule). Two entities may both link one pair -- a shared host
    #: and a shared account, say -- and the pair deserves its *strongest* grounds, not
    #: whichever the iteration happened to reach first. Keeping the first silently discards
    #: the better evidence, and does so nondeterministically enough to look like tuning.
    best: dict[tuple[str, str, str], Edge] = {}

    # last observation to mention each entity ref, and each (host, pid)
    last_ref: dict[str, Observation] = {}
    last_pid: dict[tuple[str, str], Observation] = {}

    def add(src: Observation, dst: Observation, rule_id: str, conf: float, reason: str) -> None:
        if src.id == dst.id or conf < min_edge:
            return
        key = (src.id, dst.id, rule_id)
        current = best.get(key)
        if current is None or conf > current.confidence:
            best[key] = Edge(src.id, dst.id, rule_id, conf, reason)

    for obs in ordered:
        rep = obs.representative
        refs = _refs(obs, resolver)
        host = resolver.host(rep.entity("host")) if rep.entity("host") else None

        # C-01 process ancestry. A parent pid is causation itself, so it is neither
        # rarity-weighted nor thresholded down.
        if host and (ppid := rep.entity("ppid")):
            parent = last_pid.get((host, ppid))
            if parent is not None and (not temporal or parent.first_ts <= obs.first_ts) \
                    and abs(obs.first_ts - parent.first_ts) <= PROC_WINDOW:
                add(parent, obs, "C-01", 0.95,
                    f"{rep.entity('process') or 'process'} was started by pid {ppid} "
                    f"on {host}, which {parent.representative.rule_name.lower()} reported")

        # C-02 identity pivot: one account, a second machine.
        if (user := rep.entity("user")):
            account = f"account:{resolver.user(user)}"
            prior = last_ref.get(account)
            if prior is not None and (not temporal or prior.first_ts <= obs.first_ts):
                prior_host = prior.representative.entity("host")
                prior_host = resolver.host(prior_host) if prior_host else None
                if host and prior_host and host != prior_host \
                        and abs(obs.first_ts - prior.first_ts) <= PIVOT_WINDOW:
                    conf = 0.75 * weights.get(account, 0.0)
                    add(prior, obs, "C-02", conf,
                        f"the same account {resolver.user(user)} acted on {prior_host} "
                        f"and then on {host} within "
                        f"{(obs.first_ts - prior.first_ts) // 60} minutes")

        # C-03 shared-entity continuity, nearest predecessor only, rarity weighted.
        for ref, kind in refs.items():
            prior = last_ref.get(ref)
            if prior is None:
                continue
            if temporal and prior.first_ts > obs.first_ts:
                continue
            if abs(obs.first_ts - prior.first_ts) > ENTITY_WINDOW:
                continue
            conf = LINK_STRENGTH.get(kind, 0.4) * weights.get(ref, 0.0)
            add(prior, obs, "C-03", conf,
                f"both reference {ref.split(':', 1)[1]}, seen in "
                f"{_share_phrase(weights.get(ref, 0.0))} of activity, "
                f"{abs(obs.first_ts - prior.first_ts)}s apart")

        # C-04 address handoff: traffic that arrived where earlier traffic was sent.
        if (src_ip := rep.entity("src_ip")):
            prior = last_ref.get(f"address:{src_ip}")
            if prior is not None and prior.representative.entity("dst_ip") == src_ip \
                    and (not temporal or prior.first_ts <= obs.first_ts) \
                    and abs(obs.first_ts - prior.first_ts) <= ENTITY_WINDOW:
                conf = 0.65 * weights.get(f"address:{src_ip}", 0.0)
                add(prior, obs, "C-04", conf,
                    f"traffic reached {src_ip}, which then originated this activity")

        for ref in refs:
            last_ref[ref] = obs
        if host and (pid := rep.entity("pid")):
            last_pid[(host, pid)] = obs

    return sorted(best.values(), key=lambda e: (e.src, e.dst, e.rule_id))


def _share_phrase(weight: float) -> str:
    if weight >= 0.75:
        return "almost nothing else"
    if weight >= 0.5:
        return "a small slice"
    if weight >= 0.25:
        return "a noticeable share"
    return "much"
