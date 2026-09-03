"""Tests for the correlation layer, including the controls that make the claims falsifiable.

The negative controls matter more than the positive ones. Any pipeline that groups things
will report compression, so the tests that earn trust are the ones that would fail if a
mechanism were quietly doing nothing.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from causeway import correlate as C
from causeway import dedup, incident as I, metrics, response as R, rootcause as RC
from causeway.adapters.lab import (GROUND_TRUTH_ROOT, SECOND_HOST, VICTIM_HOST,
                                   VICTIM_USER, generate)
from causeway.entities import EntityResolver
from causeway.schema import Alert
from ventriloquist.gateway import Gateway
from ventriloquist.provenance import OriginKind, TrustLevel


@pytest.fixture(scope="module")
def scn():
    return generate()


@pytest.fixture
def resolver():
    return EntityResolver()


@pytest.fixture(scope="module")
def pipeline(scn):
    r = EntityResolver()
    obs, ledger = dedup.group(scn.alerts, r)
    edges = C.correlate(obs, r)
    incidents = I.build(obs, edges, r)
    gw = Gateway(policy_path=R.POLICY_PATH)
    I.register(incidents, gw)
    return {"resolver": r, "obs": obs, "ledger": ledger, "edges": edges,
            "incidents": incidents, "gateway": gw}


# -- the corpus itself ---------------------------------------------------------

def test_corpus_is_deterministic():
    assert generate().alerts == generate().alerts


def test_corpus_has_a_full_attack_chain(scn):
    assert len(set(scn.truth.values())) == 9


# -- entity resolution ---------------------------------------------------------

def test_four_spellings_of_one_person_resolve_to_one(resolver):
    resolver.sid_map["S-1-5-21-1004-1104"] = VICTIM_USER
    names = {resolver.user(x) for x in
             [VICTIM_USER, "j.okafor@corp.local", "S-1-5-21-1004-1104", "J.Okafor"]}
    assert names == {"j.okafor"}


def test_a_process_is_scoped_to_its_host(resolver):
    """Two machines sharing a pid must not resolve to one process."""
    def proc(host):
        a = Alert(id=f"x-{host}", ts=1, sensor="edr", rule_id="r", rule_name="n",
                  severity=10, entities={"host": host, "pid": "7101"})
        return {o.ref for o in resolver.entity_origins(a) if o.kind is OriginKind.PROCESS}
    assert proc(VICTIM_HOST).isdisjoint(proc(SECOND_HOST))


def test_entity_weight_follows_the_reporting_sensor(resolver):
    """An address logged by a first-party agent is worth what that agent is worth."""
    def trust(sensor):
        a = Alert(id=f"x{sensor}", ts=1, sensor=sensor, rule_id="r", rule_name="n",
                  severity=10, entities={"src_ip": "203.0.113.47"})
        return next(o.trust for o in resolver.entity_origins(a))
    assert trust("edr") == TrustLevel.TOOL_VERIFIED
    assert trust("suricata") == TrustLevel.THIRD_PARTY
    assert trust("threat_intel") == TrustLevel.UNTRUSTED


# -- deduplication -------------------------------------------------------------

def test_causal_dedup_erases_no_evidence(scn, pipeline):
    """Nothing may be suppressed under a representative from a different attack stage."""
    truth = scn.truth
    erased = [e for e in pipeline["ledger"].entries
              if truth.get(e.alert_id, "") != truth.get(e.duplicate_of, "")]
    assert erased == []


def test_naive_text_dedup_erases_the_root_cause(scn):
    """The control. Text similarity buries the successful login under a benign one."""
    _, ledger = dedup.naive_text_group(scn.alerts)
    erased = [e for e in ledger.entries
              if scn.truth.get(e.alert_id, "") != scn.truth.get(e.duplicate_of, "")]
    assert any(scn.truth.get(e.alert_id) == GROUND_TRUTH_ROOT for e in erased), \
        "the corpus is supposed to punish text matching; it no longer does"


def test_suppressed_alerts_are_held_not_dropped(scn, pipeline):
    kept = sum(o.count for o in pipeline["obs"])
    assert kept == len(scn.alerts)
    assert len(pipeline["ledger"]) > 0


def test_distinct_files_are_not_one_observation(resolver):
    """Six archived files are six things, however alike the alerts read."""
    alerts = [Alert(id=f"f{i}", ts=100 + i, sensor="edr", rule_id="T1560",
                    rule_name="Archive created", severity=55,
                    entities={"host": SECOND_HOST, "file": f"C:\\stage\\part{i}.7z"})
              for i in range(6)]
    obs, _ = dedup.group(alerts, resolver)
    assert len(obs) == 6


# -- correlation ---------------------------------------------------------------

def test_process_ancestry_is_found(pipeline):
    assert any(e.rule_id == "C-01" for e in pipeline["edges"])


def test_every_edge_points_forward_in_time(pipeline):
    by_id = {o.id: o for o in pipeline["obs"]}
    for e in pipeline["edges"]:
        assert by_id[e.src].first_ts <= by_id[e.dst].first_ts


def test_ubiquitous_entities_carry_little_weight(pipeline):
    """The scanner's address touches everything, so it must not link anything."""
    weights = C.entity_weights(pipeline["obs"], pipeline["resolver"])
    assert weights["address:10.20.0.5"] < weights["address:203.0.113.47"]


def test_every_edge_explains_itself(pipeline):
    for e in pipeline["edges"]:
        assert len(e.reason) > 20 and not e.reason.endswith(" ")


# -- incidents -----------------------------------------------------------------

def test_the_whole_kill_chain_lands_in_one_incident(scn, pipeline):
    big = max(pipeline["incidents"], key=lambda x: x.alert_count)
    stages = {scn.truth[a.id] for a in big.alerts if a.id in scn.truth}
    assert len(stages) == 9


def test_confidence_rises_with_corroboration_but_trust_does_not(pipeline):
    """The two numbers must move in opposite directions; conflating them is the bug
    this whole layer is arranged to avoid."""
    big = max(pipeline["incidents"], key=lambda x: x.alert_count)
    assert big.confidence > 0.9
    assert big.trust <= TrustLevel.TOOL_VERIFIED
    assert big.trust == min(o.trust for o in big.entities)


def test_no_correlation_rule_reads_the_answer_key():
    """A correlator that can see `Alert.stage` is measuring its own answer."""
    import ast
    for module in (C, dedup, I, RC, R):
        tree = ast.parse(inspect.getsource(module))
        reads = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Attribute) and n.attr == "stage"]
        assert not reads, f"{module.__name__} reads the ground-truth label"


# -- root cause ----------------------------------------------------------------

def test_root_cause_names_the_compromised_identity(pipeline, resolver):
    big = max(pipeline["incidents"], key=lambda x: x.alert_count)
    ranked = RC.rank(big, pipeline["resolver"])
    assert ranked[0].ref == "account:" + resolver.user(VICTIM_USER)


def test_an_address_is_never_the_top_answer(pipeline):
    """Blocking an address feels decisive and rarely ends anything."""
    big = max(pipeline["incidents"], key=lambda x: x.alert_count)
    assert RC.rank(big, pipeline["resolver"])[0].entity.kind is not OriginKind.ADDRESS


def test_containment_preview_reaches_cases_by_lineage(pipeline):
    big = max(pipeline["incidents"], key=lambda x: x.alert_count)
    top = RC.rank(big, pipeline["resolver"])[0]
    report = RC.containment_preview(pipeline["gateway"], top.ref)
    assert report.scanned == len(pipeline["incidents"])
    assert len(report.affected) >= 1


# -- response ------------------------------------------------------------------

def test_the_biggest_incident_gets_a_containing_action(pipeline):
    big = max(pipeline["incidents"], key=lambda x: x.alert_count)
    root = RC.rank(big, pipeline["resolver"])[0]
    prov = R.target_provenance(big, root, pipeline["resolver"], pipeline["gateway"])
    rec = R.recommend(big, root, pipeline["gateway"].policy, provenance=prov)
    assert rec.recommended in R.CONTAINING


def test_the_most_destructive_rungs_still_need_a_human(pipeline):
    big = max(pipeline["incidents"], key=lambda x: x.alert_count)
    root = RC.rank(big, pipeline["resolver"])[0]
    prov = R.target_provenance(big, root, pipeline["resolver"], pipeline["gateway"])
    rec = R.recommend(big, root, pipeline["gateway"].policy, provenance=prov)
    assert rec.recommended != "account.disable"
    assert "account.disable" in rec.needs_human
    assert rec.blocked_reason


def test_annotation_is_never_refused(pipeline):
    """A control whose only options are nothing and isolation gets switched off."""
    for inc in pipeline["incidents"]:
        prov = pipeline["gateway"].store.get(inc.memory_id).provenance
        assert pipeline["gateway"].policy.evaluate(prov, "alert.annotate").allowed


def test_no_model_or_network_call_in_the_decision_path(pipeline):
    for inc in pipeline["incidents"]:
        prov = pipeline["gateway"].store.get(inc.memory_id).provenance
        for action in R.LADDER:
            d = pipeline["gateway"].policy.evaluate(prov, action)
            assert d.model_calls == 0 and d.network_calls == 0


# -- audit ---------------------------------------------------------------------

def test_the_chain_verifies_after_a_full_ingest(pipeline):
    intact, first_bad = pipeline["gateway"].audit.verify()
    assert intact and first_bad is None


# -- the measured claims -------------------------------------------------------

def test_metrics_reproduce(scn):
    payload = metrics.run_all()
    rows = {r["name"]: r for r in payload["configurations"]}
    ours = rows["Causeway"]
    assert ours["incident_recall"] == 1.0
    assert ours["stages_recovered"] == "9/9"
    assert ours["root_cause_top1"] is True
    assert ours["false_suppression_rate"] == 0.0


def test_rarity_weighting_is_load_bearing():
    """The negative control. Without it, precision must collapse -- otherwise the
    mechanism is decoration and the headline row is an accident."""
    payload = metrics.run_all()
    rows = {r["name"]: r for r in payload["configurations"]}
    off = rows["Causeway (rarity weighting off)"]
    on = rows["Causeway"]
    assert off["incident_precision"] < on["incident_precision"] / 2
    assert off["root_cause_top1"] is False
    # and it gets *better* compression while doing so, which is the point
    assert off["compression_ratio"] > on["compression_ratio"]


def test_naive_dedup_loses_stages():
    payload = metrics.run_all()
    rows = {r["name"]: r for r in payload["configurations"]}
    assert rows["Naive text dedup"]["evidence_erased"] > 0
    assert rows["Naive text dedup"]["stages_recovered"] != "9/9"
