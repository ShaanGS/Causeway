# Working in this repository

Instructions for anyone, human or agent, opening this codebase for the first time.

## What it is

Causeway reconstructs causal security incidents from fragmented SOC alerts, ranks the
entity to contain, and recommends the smallest evidence-authorised response. Pure Python,
no model, no network call in the decision path. Read [README.md](README.md) for the
argument and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data flow.

## Build, test, run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[server,dev]"

pytest                          # 51 tests, ~2 s
ruff check .                    # lint; must be clean
mypy causeway server            # types; must be clean

causeway run                    # correlate the lab corpus and print cases
causeway metrics                # regenerate results/lab.json (the README table)
causeway serve                  # console at http://127.0.0.1:8788
```

`make check` runs all three checks. CI ([.github/workflows/ci.yml](.github/workflows/ci.yml))
runs them on Python 3.11 and 3.12 and then runs the metrics harness.

## Layout

| path | role |
|---|---|
| `causeway/schema.py` | the one alert shape; canonical entity slots |
| `causeway/entities.py` | alias resolution; evidentiary weight per sensor |
| `causeway/dedup.py` | duplicate suppression with a ledger |
| `causeway/correlate.py` | causal edges (C-01 ancestry, C-02 pivot, C-03 shared entity, C-04 handoff) |
| `causeway/incident.py` | clustering; correlation confidence vs evidentiary trust |
| `causeway/rootcause.py` | entity ranking; containment preview |
| `causeway/response.py` | the response ladder and refusals |
| `causeway/metrics.py` | four-configuration harness with baselines and a negative control |
| `causeway/corpus.py` | the `Scenario` contract every adapter fills |
| `causeway/adapters/` | `lab.py` (self-authored, answer key), `ait.py` (public dataset) |
| `causeway/cli.py` | `causeway run / metrics / export / serve` |
| `ventriloquist/` | vendored provenance engine; do not refactor, it is upstream code |
| `server/` | FastAPI routes and the single-file console |
| `tests/` | `test_causeway.py` (pipeline + controls), `test_adapters.py`, `test_surfaces.py` |
| `results/` | what `causeway metrics` last wrote; regenerate, never hand-edit |
| `docs/` | architecture, API, decision records |

## Conventions that are enforced

- **No correlation rule may read `Alert.stage`.** It is the ground-truth label. A test
  parses the AST of every rule module and fails on any `.stage` access.
- **Every edge, root candidate and response option carries a `reason` string** an analyst
  can argue with. A test fails on an edge that cannot explain itself.
- **Numbers in documentation come from `causeway metrics`.** Do not type a metric into a
  document by hand; regenerate `results/` and copy from there.
- **Suppression holds, never drops.** Anything removed from the queue goes to the ledger
  with its grounds.
- **Module docstrings explain the why.** Each module opens with the decision it embodies
  and the failure it prevents. Keep that when editing; it is the documentation.
- Line length 100, `ruff` rule set `E,F,W,I,B,UP`, `mypy` clean. `from __future__ import
  annotations` at the top of every module.

## When changing behaviour

1. Run `causeway metrics` and `causeway metrics ait --window 5` (the latter needs
   `data/raw/ait_ads.zip`, see README *Data*).
2. If the lab table moves, update the README table from `results/lab.json` and say why in
   the commit message.
3. The negative-control test (`test_rarity_weighting_is_load_bearing`) must still pass:
   with weighting off, precision must more than halve and compression must improve.
4. Record a design decision in `docs/adr/` if it changes a threshold, a weighting or a
   rule. Existing records show the format.

## Things that look wrong and are not

- `ventriloquist/policy.py` uses `class Verdict(str, Enum)`; `UP042` is ignored for it on
  purpose so the vendored code's `repr` does not change.
- `Causeway (rarity weighting off)` has the best compression in the results table. That is
  the point of the row; see README *The result*.
- On the AIT public corpus the unweighted control beats Causeway on recall. Reported
  deliberately; see README *On somebody else's data*.
