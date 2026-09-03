# Interfaces

## Command line

Installed as `causeway` by `pip install -e .`; `python -m causeway` is identical.

| command | what it does |
|---|---|
| `causeway run [CORPUS] [--top N] [-v] [--json FILE]` | correlate and print cases with roots and recommendations; `-v` adds every observation and edge; `--json` writes the full state |
| `causeway metrics [CORPUS] [--window S] [--out FILE]` | run all four configurations, write `results/<corpus>.json`, print the table |
| `causeway export [CORPUS] --out FILE.jsonl` | write a corpus in the JSONL shape `run` accepts |
| `causeway serve [CORPUS] [--host H] [--port P]` | start the console (needs the `server` extra) |

`CORPUS` is `lab` (default), `ait`, or a path to a `.jsonl` file. `--scenario NAME` picks
an AIT scenario (default `russellmitchell`); `--seed N` reseeds the lab range.

### JSONL alert format

One object per line, the shape `Alert.to_dict()` emits. Only `id`, `ts` and `sensor` are
required.

```json
{"id": "a-0001", "ts": 1764626400, "sensor": "wazuh", "rule_id": "5715",
 "rule_name": "Successful remote login", "severity": 15,
 "entities": {"user": "CORP\\j.okafor", "host": "WIN-WS-041", "src_ip": "203.0.113.47"},
 "stage": ""}
```

Valid entity slots: `user, host, src_ip, dst_ip, process, pid, ppid, file, hash`. Unknown
slots are rejected at load. `stage` is optional ground truth used only for grading.

## HTTP

Started by `causeway serve` or `uvicorn server.app:app`. The corpus is chosen by the
`CAUSEWAY_CORPUS` and `CAUSEWAY_SCENARIO` environment variables, which `causeway serve`
sets from its arguments. Interactive docs are at `/docs` (FastAPI's built-in Swagger UI).

| method | path | returns |
|---|---|---|
| GET | `/` | the console |
| GET | `/api/health` | `{ok, corpus, audit_intact}` |
| GET | `/api/state` | `{summary, cases[], ledger}`: every incident with roots and recommendation, and every suppression with its grounds |
| GET | `/api/graph/{incident_id}` | nodes laid out by time and host lane, edges with reasons; 404 if unknown |
| GET | `/api/containment/{incident_id}` | `blast_radius()` for the top root entity: what stops standing up if it is contained; 404 if unknown or no rankable root |
| GET | `/api/metrics` | the four-configuration harness over the loaded corpus |
| GET | `/api/audit` | chain verification and the last 60 audit events |
| POST | `/api/reset` | rebuild the pipeline from the configured corpus |

### Shapes worth knowing

`cases[].recommendation`:

```json
{"incident_id": "inc-0001",
 "target": "account:j.okafor", "target_label": "account j.okafor (via wazuh)",
 "recommended": "session.revoke", "recommended_label": "Revoke the active session",
 "options": [{"action_id": "account.disable", "label": "Disable the account",
              "required": "USER_VERIFIED", "required_label": "Analyst approved",
              "observed": "TOOL_VERIFIED", "observed_label": "Corroborated telemetry",
              "allowed": false, "effective": true, "reason": "...", "latency_us": 12.4}],
 "blocked_reason": "Disable the account needs Analyst approved; the evidence for account j.okafor (via wazuh) is Corroborated telemetry.",
 "needs_human": ["host.isolate", "account.disable"],
 "model_calls": 0, "network_calls": 0}
```

`cases[].edges[]`:

```json
{"src": "obs-00612", "dst": "obs-00619", "rule_id": "C-01", "confidence": 0.95,
 "reason": "whoami.exe was started by pid 6612 on win-ws-041, which remote interactive shell started reported"}
```

Every edge, root candidate and option carries a `reason`. That is not decoration; a test
fails on an edge that cannot explain itself.
