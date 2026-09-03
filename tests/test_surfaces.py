"""The CLI and the HTTP API are projections of one `Pipeline`. These tests hold them to that:
same corpus in, same cases out, and every route answers or refuses in the documented shape."""

from __future__ import annotations

import json

import pytest

from causeway.cli import main
from causeway.pipeline import Pipeline

# -- CLI ---------------------------------------------------------------------------------


def test_run_prints_the_headline_case(capsys):
    assert main(["run", "--top", "1"]) == 0
    out = capsys.readouterr().out
    assert "938 alerts" in out
    assert "inc-0001" in out
    assert "account j.okafor" in out
    assert "recommend" in out


def test_run_json_matches_the_pipeline_state(tmp_path):
    out = tmp_path / "state.json"
    assert main(["run", "--json", str(out)]) == 0
    state = json.loads(out.read_text())
    assert state["summary"]["incidents"] == len(Pipeline.from_lab().run().cases)
    assert state["cases"][0]["recommendation"]["model_calls"] == 0


def test_metrics_writes_results_where_asked(tmp_path, capsys):
    out = tmp_path / "r.json"
    assert main(["metrics", "--out", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert [c["name"] for c in payload["configurations"]] == [
        "No correlation", "Naive text dedup", "Causeway (rarity weighting off)", "Causeway"]
    assert "Causeway" in capsys.readouterr().out


def test_export_then_run_on_the_file(tmp_path, capsys):
    path = tmp_path / "alerts.jsonl"
    assert main(["export", "--out", str(path)]) == 0
    assert main(["run", str(path), "--top", "1"]) == 0
    out = capsys.readouterr().out
    assert "corpus alerts" in out and "inc-0001" in out


def test_bad_corpus_is_an_error():
    with pytest.raises(ValueError):
        main(["run", "not-a-corpus"])


# -- HTTP ---------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from server.app import app
    assert fastapi
    return TestClient(app)


def test_health(client):
    body = client.get("/api/health").json()
    assert body["ok"] and body["audit_intact"] and body["corpus"] == "lab"


def test_state_and_graph_agree(client):
    state = client.get("/api/state").json()
    first = state["cases"][0]["id"]
    graph = client.get(f"/api/graph/{first}").json()
    assert len(graph["nodes"]) == state["cases"][0]["observation_count"]
    assert sum(n["is_root"] for n in graph["nodes"]) == 1


def test_containment_preview_names_affected_cases(client):
    first = client.get("/api/state").json()["cases"][0]["id"]
    report = client.get(f"/api/containment/{first}").json()
    assert report["scanned"] >= 1 and "affected" in report


def test_unknown_incident_is_404(client):
    assert client.get("/api/graph/inc-9999").status_code == 404
    assert client.get("/api/containment/inc-9999").status_code == 404


def test_metrics_route_reports_the_same_corpus(client):
    payload = client.get("/api/metrics").json()
    assert payload["corpus"]["name"] == "lab"
    assert payload["configurations"][-1]["name"] == "Causeway"
