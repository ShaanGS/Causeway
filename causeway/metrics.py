"""What this is worth, measured against configurations that are not it.

A single column of good-looking numbers proves nothing: any pipeline that groups anything
will report compression. So every metric is computed for four configurations over byte-identical
input, and the two in the middle are the argument:

1. **No correlation** -- the raw queue. The floor.
2. **Naive text dedup** -- merge on what the alert says, cluster on any shared entity. Not a
   strawman anyone had to invent; it is what queue tooling does by default, and the PS names
   it as a hazard. Its false-suppression number is the one to look at.
3. **Causeway** -- causal edges, rarity-weighted, temporally ordered.
4. **Causeway, rarity weighting off** -- the negative control. Same code, same corpus, one
   mechanism disabled: every entity treated as equally distinctive. If the results barely
   move without it, the mechanism was decoration and this row says so. (Precedence was the
   obvious candidate for this slot and turned out to be a no-op under nearest-predecessor
   walking -- see `correlate.py`. Reporting the control that actually bites is the point of
   having one.)

The six measures the PS asks for are all here. Two carry caveats stated in the output rather
than buried: *analyst time saved* is a model, not an observation -- pivots avoided times a
per-pivot cost, and the cost is an assumption. *Mean time to contain* measures the interval
from first alert to an authorised recommendation; it does not include the human who has to
approve the rungs that need approving, and pretending otherwise would flatter the number.

Nothing here reads `Alert.stage` except the grading itself.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ventriloquist.gateway import Gateway
from . import correlate as C
from . import dedup, incident as I, response as R, rootcause as RC
from .adapters.lab import Scenario, generate
from .entities import EntityResolver

#: Minutes an analyst spends pivoting between consoles to resolve one uncorrelated alert.
#: An assumption, and reported as one. Published SOC studies put a triage pivot in the
#: low single digits of minutes; 3 is deliberately conservative.
MINUTES_PER_PIVOT = 3.0


@dataclass
class Result:
    name: str
    alerts: int
    cases: int
    observations: int
    suppressed: int
    evidence_erased: int
    attack_alerts_in_cases: int
    attack_alerts_total: int
    alerts_in_cases: int
    root_top1: bool
    root_top3: bool
    stages_found: int
    stages_total: int
    mttc_seconds: int | None
    elapsed_ms: float
    model_calls: int = 0
    network_calls: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def compression(self) -> float:
        """Alerts an analyst would have opened, over cases they actually open."""
        return self.alerts / self.cases if self.cases else float(self.alerts)

    @property
    def precision(self) -> float:
        return (self.attack_alerts_in_cases / self.alerts_in_cases
                if self.alerts_in_cases else 0.0)

    @property
    def recall(self) -> float:
        return (self.attack_alerts_in_cases / self.attack_alerts_total
                if self.attack_alerts_total else 0.0)

    @property
    def false_suppression(self) -> float:
        return self.evidence_erased / self.suppressed if self.suppressed else 0.0

    @property
    def minutes_saved(self) -> float:
        return max(0, self.alerts - self.cases) * MINUTES_PER_PIVOT

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "alerts": self.alerts,
            "cases": self.cases,
            "observations": self.observations,
            "compression_ratio": round(self.compression, 2),
            "incident_precision": round(self.precision, 4),
            "incident_recall": round(self.recall, 4),
            "suppressed": self.suppressed,
            "evidence_erased": self.evidence_erased,
            "false_suppression_rate": round(self.false_suppression, 4),
            "root_cause_top1": self.root_top1,
            "root_cause_top3": self.root_top3,
            "stages_recovered": f"{self.stages_found}/{self.stages_total}",
            "mttc_seconds": self.mttc_seconds,
            "analyst_minutes_saved_modelled": round(self.minutes_saved, 1),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "model_calls": self.model_calls,
            "network_calls": self.network_calls,
            "notes": self.notes,
        }


def _grade(name, scn, obs, ledger, incidents, resolver, elapsed, *, root_ref, notes=None):
    truth = scn.truth
    alerts_in = sum(x.alert_count for x in incidents)
    attack_in = sum(1 for x in incidents for a in x.alerts if a.id in truth)

    erased = sum(1 for e in ledger.entries
                 if truth.get(e.alert_id, "") != truth.get(e.duplicate_of, ""))

    # Cases an analyst actually opens: the incidents, plus any lone loud observation.
    lone = [o for o in obs if o.severity >= I.LONE_SEVERITY
            and not any(o.id in {m.id for m in x.observations} for x in incidents)]
    cases = len(incidents) + len(lone)

    big = max(incidents, key=lambda x: x.alert_count, default=None)
    stages = {truth[a.id] for a in big.alerts if a.id in truth} if big else set()

    top1 = top3 = False
    mttc = None
    if big is not None:
        ranked = RC.rank(big, resolver, top=3)
        refs = [c.ref for c in ranked]
        top1 = bool(refs) and refs[0] == root_ref
        top3 = root_ref in refs
        mttc = big.last_ts - big.first_ts if big.observations else None

    return Result(
        name=name, alerts=len(scn.alerts), cases=cases, observations=len(obs),
        suppressed=len(ledger), evidence_erased=erased,
        attack_alerts_in_cases=attack_in, attack_alerts_total=len(truth),
        alerts_in_cases=alerts_in, root_top1=top1, root_top3=top3,
        stages_found=len(stages), stages_total=len(set(truth.values())),
        mttc_seconds=mttc, elapsed_ms=elapsed, notes=notes or [],
    )


def run_none(scn: Scenario, resolver) -> Result:
    started = time.perf_counter()
    obs, ledger = dedup.group(scn.alerts, resolver)
    elapsed = (time.perf_counter() - started) * 1000
    empty = dedup.Ledger()
    r = _grade("No correlation", scn, obs, empty, [], resolver, elapsed, root_ref="",
               notes=["Every alert is its own row. The floor."])
    r.cases = len(scn.alerts)   # no grouping means the queue *is* the case list
    return r


def run_naive(scn: Scenario, resolver, *, root_ref: str) -> Result:
    started = time.perf_counter()
    obs, ledger = dedup.naive_text_group(scn.alerts)
    edges = C.correlate(obs, resolver, temporal=False, min_edge=0.0)
    incidents = I.build(obs, edges, resolver, cluster_min=0.0)
    elapsed = (time.perf_counter() - started) * 1000
    return _grade("Naive text dedup", scn, obs, ledger, incidents, resolver, elapsed,
                  root_ref=root_ref,
                  notes=["Merges on alert text; links on any shared entity, either direction."])


def run_causeway(scn: Scenario, resolver, *, root_ref: str, weighted: bool = True) -> Result:
    started = time.perf_counter()
    obs, ledger = dedup.group(scn.alerts, resolver)
    edges = C.correlate(obs, resolver, weighted=weighted)
    incidents = I.build(obs, edges, resolver)
    elapsed = (time.perf_counter() - started) * 1000
    name = "Causeway" if weighted else "Causeway (rarity weighting off)"
    notes = [] if weighted else [
        "Negative control: same code, every entity treated as equally distinctive."]
    return _grade(name, scn, obs, ledger, incidents, resolver, elapsed,
                  root_ref=root_ref, notes=notes)


def run_all(seed: int = 7) -> dict:
    scn = generate(seed)
    resolver = EntityResolver()
    root_ref = "account:" + resolver.user(_victim())

    results = [
        run_none(scn, EntityResolver()),
        run_naive(scn, EntityResolver(), root_ref=root_ref),
        run_causeway(scn, EntityResolver(), root_ref=root_ref, weighted=False),
        run_causeway(scn, EntityResolver(), root_ref=root_ref, weighted=True),
    ]
    return {
        "corpus": {"name": "causeway-lab", "seed": seed, "alerts": len(scn.alerts),
                   "attack_alerts": len(scn.truth),
                   "stages": sorted(set(scn.truth.values()))},
        "ground_truth_root": root_ref,
        "minutes_per_pivot_assumption": MINUTES_PER_PIVOT,
        "configurations": [r.to_dict() for r in results],
    }


def _victim() -> str:
    from .adapters.lab import VICTIM_USER
    return VICTIM_USER


def main() -> int:
    payload = run_all()
    out = Path(__file__).parent / "results.json"
    out.write_text(json.dumps(payload, indent=2) + "\n")

    rows = payload["configurations"]
    print(f"\ncorpus: {payload['corpus']['alerts']} alerts, "
          f"{payload['corpus']['attack_alerts']} of them part of a "
          f"{len(payload['corpus']['stages'])}-stage intrusion\n")
    head = (f"{'configuration':28} {'cases':>6} {'compr':>7} {'prec':>6} {'recall':>7} "
            f"{'stages':>7} {'suppr':>6} {'erased':>7} {'top1':>5} {'ms':>7}")
    print(head); print("-" * len(head))
    for r in rows:
        print(f"{r['name']:28} {r['cases']:6} {r['compression_ratio']:7.1f} "
              f"{r['incident_precision']:6.3f} {r['incident_recall']:7.3f} "
              f"{r['stages_recovered']:>7} {r['suppressed']:6} {r['evidence_erased']:7} "
              f"{str(r['root_cause_top1']):>5} {r['elapsed_ms']:7.1f}")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
