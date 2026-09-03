"""HTTP surface over the pipeline. The console is a projection; nothing decides here."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from causeway import metrics as M
from causeway import rootcause as RC
from causeway.pipeline import Pipeline

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Causeway")
PIPELINE = Pipeline.from_lab().run()


@app.get("/api/state")
def state() -> dict:
    return PIPELINE.state()


@app.get("/api/graph/{incident_id}")
def graph(incident_id: str) -> dict:
    g = PIPELINE.graph(incident_id)
    if not g["nodes"]:
        raise HTTPException(404, f"no incident {incident_id}")
    return g


@app.get("/api/containment/{incident_id}")
def containment(incident_id: str) -> dict:
    case = PIPELINE.case(incident_id)
    if case is None or not case.roots:
        raise HTTPException(404, f"no incident {incident_id}")
    report = RC.containment_preview(PIPELINE.gateway, case.roots[0].ref)
    return report.to_dict()


@app.get("/api/metrics")
def measured() -> dict:
    return M.run_all()


@app.get("/api/audit")
def audit() -> dict:
    intact, first_bad = PIPELINE.gateway.audit.verify()
    return {"intact": intact, "first_bad_seq": first_bad,
            "events": [e.payload | {"seq": e.seq, "kind": e.kind, "hash": e.hash[:12]}
                       for e in list(PIPELINE.gateway.audit)[-60:]]}


@app.post("/api/reset")
def reset() -> dict:
    global PIPELINE
    PIPELINE = Pipeline.from_lab().run()
    return PIPELINE.summary()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
