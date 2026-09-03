"""One object that runs the whole path, so the CLI, the tests and the server agree.

Ingest -> resolve -> suppress duplicates -> draw causal edges -> cluster -> register
through the gateway -> rank root causes -> recommend a response. Every stage is a module
that can be read on its own; this is only the wiring, and it exists so that no caller has
to remember the order or invent its own variation of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ventriloquist.gateway import Gateway
from . import correlate as C
from . import dedup, incident as I, response as R, rootcause as RC
from .adapters.lab import Scenario, generate
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


@dataclass
class Pipeline:
    alerts: list[Alert]
    scenario: Scenario | None = None
    resolver: EntityResolver = field(default_factory=EntityResolver)
    gateway: Gateway = field(default=None)
    observations: list[dedup.Observation] = field(default_factory=list)
    ledger: dedup.Ledger = field(default_factory=dedup.Ledger)
    edges: list[C.Edge] = field(default_factory=list)
    cases: list[Case] = field(default_factory=list)

    @classmethod
    def from_lab(cls, seed: int = 7) -> "Pipeline":
        scn = generate(seed)
        return cls(alerts=scn.alerts, scenario=scn)

    def run(self) -> "Pipeline":
        self.gateway = Gateway(policy_path=R.POLICY_PATH)
        self.observations, self.ledger = dedup.group(self.alerts, self.resolver)
        self.edges = C.correlate(self.observations, self.resolver)
        incidents = I.build(self.observations, self.edges, self.resolver)
        I.register(incidents, self.gateway)

        self.cases = []
        for inc in incidents:
            roots = RC.rank(inc, self.resolver)
            if roots:
                prov = R.target_provenance(inc, roots[0], self.resolver, self.gateway)
            else:
                prov = self.gateway.store.get(inc.memory_id).provenance
            rec = R.recommend(inc, roots[0] if roots else None,
                              self.gateway.policy, provenance=prov)
            self.cases.append(Case(incident=inc, roots=roots, recommendation=rec))
        return self

    # -- projections for the console ---------------------------------------------

    def case(self, incident_id: str) -> Case | None:
        return next((c for c in self.cases if c.incident.id == incident_id), None)

    def summary(self) -> dict:
        intact, first_bad = self.gateway.audit.verify()
        loud = [o for o in self.observations if o.severity >= I.LONE_SEVERITY]
        in_cases = {m.id for c in self.cases for m in c.incident.observations}
        return {
            "alerts": len(self.alerts),
            "observations": len(self.observations),
            "suppressed": len(self.ledger),
            "incidents": len(self.cases),
            "queue_before": len(self.alerts),
            "queue_after": len(self.cases) + len([o for o in loud if o.id not in in_cases]),
            "sensors": sorted({a.sensor for a in self.alerts}),
            "window": [iso(min(a.ts for a in self.alerts)),
                       iso(max(a.ts for a in self.alerts))],
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
        root_refs = {r.ref for r in case.roots[:1]}

        # Lane per host, so a pivot between machines is visible as a vertical move.
        lanes: dict[str, int] = {}
        for o in obs:
            host = o.representative.entity("host") or o.representative.entity("dst_ip") or "-"
            lanes.setdefault(self.resolver.host(host) if host != "-" else "-", len(lanes))

        nodes = []
        for o in obs:
            rep = o.representative
            host = rep.entity("host") or rep.entity("dst_ip") or "-"
            key = self.resolver.host(host) if host != "-" else "-"
            is_root = any(x.ref in root_refs
                          for x in self.resolver.entity_origins(rep))
            nodes.append({
                "id": o.id,
                "x": (o.first_ts - t0) / span,
                "lane": lanes[key],
                "lane_label": key,
                "sensor": rep.sensor,
                "rule_name": rep.rule_name,
                "text": rep.text,
                "count": o.count,
                "severity": o.severity,
                "when": iso(o.first_ts),
                "is_root": is_root and o.first_ts == min(
                    x.first_ts for x in obs
                    if any(y.ref in root_refs for y in self.resolver.entity_origins(x.representative))
                ),
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
