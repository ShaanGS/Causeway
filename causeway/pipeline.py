"""One object that runs the whole path, so the CLI, the tests and the server agree.

Ingest -> resolve -> suppress duplicates -> draw causal edges -> cluster -> register
through the gateway -> rank root causes -> recommend a response. Every stage is a module
that can be read on its own; this is only the wiring, and it exists so that no caller has
to remember the order or invent its own variation of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ventriloquist.gateway import Gateway

from . import correlate as C
from . import dedup
from . import incident as I
from . import response as R
from . import rootcause as RC
from .corpus import Scenario, from_jsonl
from .entities import EntityResolver, evidence_label
from .schema import Alert, iso


@dataclass
class Case:
    """An incident with everything an analyst needs decided about it."""

    incident: I.Incident
    roots: list[RC.RootCandidate]
    recommendation: R.Recommendation

    def to_dict(self) -> dict:
        d = self.incident.to_dict()
        d["roots"] = [r.to_dict() for r in self.roots]
        d["recommendation"] = self.recommendation.to_dict()
        return d


def _gateway() -> Gateway:
    return Gateway(policy_path=R.POLICY_PATH)


@dataclass
class Pipeline:
    alerts: list[Alert]
    scenario: Scenario | None = None
    resolver: EntityResolver = field(default_factory=EntityResolver)
    gateway: Gateway = field(default_factory=_gateway)
    observations: list[dedup.Observation] = field(default_factory=list)
    ledger: dedup.Ledger = field(default_factory=dedup.Ledger)
    edges: list[C.Edge] = field(default_factory=list)
    cases: list[Case] = field(default_factory=list)

    @classmethod
    def from_scenario(cls, scenario: Scenario) -> Pipeline:
        return cls(alerts=scenario.alerts, scenario=scenario)

    @classmethod
    def from_lab(cls, seed: int = 7) -> Pipeline:
        from .adapters.lab import generate
        return cls.from_scenario(generate(seed))

    @classmethod
    def from_jsonl(cls, path: str | Path) -> Pipeline:
        return cls.from_scenario(from_jsonl(path))

    def run(self) -> Pipeline:
        self.gateway = _gateway()
        self.observations, self.ledger = dedup.group(self.alerts, self.resolver)
        self.edges = C.correlate(self.observations, self.resolver)
        incidents = I.build(self.observations, self.edges, self.resolver)
        I.register(incidents, self.gateway)

        self.cases = []
        for inc in incidents:
            roots = RC.rank(inc, self.resolver)
            root = roots[0] if roots else None
            if root is not None:
                prov = R.target_provenance(inc, root, self.resolver, self.gateway)
            else:
                item = self.gateway.store.get(inc.memory_id)
                if item is None:
                    raise RuntimeError(f"{inc.id} was registered but is not in the store")
                prov = item.provenance
            rec = R.recommend(inc, root, self.gateway.policy, prov)
            self.cases.append(Case(incident=inc, roots=roots, recommendation=rec))
        return self

    # -- projections for the console ---------------------------------------------

    def case(self, incident_id: str) -> Case | None:
        return next((c for c in self.cases if c.incident.id == incident_id), None)

    def summary(self) -> dict:
        intact, first_bad = self.gateway.audit.verify()
        loud = [o for o in self.observations if o.severity >= I.LONE_SEVERITY]
        in_cases = {m.id for c in self.cases for m in c.incident.observations}
        lone_loud = [o for o in loud if o.id not in in_cases]
        return {
            "corpus": self.scenario.name if self.scenario else "",
            "alerts": len(self.alerts),
            "observations": len(self.observations),
            "suppressed": len(self.ledger),
            "incidents": len(self.cases),
            "queue_before": len(self.alerts),
            "queue_after": len(self.cases) + len(lone_loud),
            "sensors": sorted({a.sensor for a in self.alerts}),
            "window": [iso(min(a.ts for a in self.alerts)),
                       iso(max(a.ts for a in self.alerts))] if self.alerts else [],
            "audit_events": len(self.gateway.audit),
            "audit_intact": intact,
            "audit_first_bad": first_bad,
            "aliases": self.resolver.alias_report()[:12],
        }

    def state(self) -> dict:
        return {
            "summary": self.summary(),
            "cases": [c.to_dict() for c in self.cases],
            "ledger": self.ledger.to_dict(),
        }

    def graph(self, incident_id: str) -> dict:
        """Nodes and edges laid out for drawing: x is time, lanes keep edges readable."""
        case = self.case(incident_id)
        if case is None:
            return {"nodes": [], "edges": []}
        inc = case.incident
        obs = sorted(inc.observations, key=lambda o: (o.first_ts, o.id))
        t0, t1 = inc.first_ts, max(inc.last_ts, inc.first_ts + 1)
        span = max(1, t1 - t0)
        root_ref = case.roots[0].ref if case.roots else None

        def lane_of(o: dedup.Observation) -> str:
            rep = o.representative
            host = rep.entity("host") or rep.entity("dst_ip")
            return self.resolver.host(host) if host else "-"

        def mentions_root(o: dedup.Observation) -> bool:
            return root_ref is not None and any(
                x.ref == root_ref for x in self.resolver.entity_origins(o.representative))

        # Lane per host, so a pivot between machines is visible as a vertical move.
        lanes: dict[str, int] = {}
        for o in obs:
            lanes.setdefault(lane_of(o), len(lanes))
        # The root marker goes on the earliest observation that names the root entity.
        root_node = next((o.id for o in obs if mentions_root(o)), None)

        nodes = []
        for o in obs:
            rep = o.representative
            nodes.append({
                "id": o.id,
                "x": (o.first_ts - t0) / span,
                "lane": lanes[lane_of(o)],
                "lane_label": lane_of(o),
                "sensor": rep.sensor,
                "rule_name": rep.rule_name,
                "text": rep.text,
                "count": o.count,
                "severity": o.severity,
                "when": iso(o.first_ts),
                "is_root": o.id == root_node,
            })
        return {
            "incident_id": inc.id,
            "lanes": [{"label": k, "index": v} for k, v in lanes.items()],
            "nodes": nodes,
            "edges": [e.to_dict() for e in inc.edges],
            "first_seen": iso(inc.first_ts),
            "last_seen": iso(inc.last_ts),
            "evidence_label": evidence_label(inc.trust),
        }
