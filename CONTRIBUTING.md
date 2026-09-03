# Contributing

Thanks for looking. This is a small codebase and the bar is simple: every change must keep
the checks green and the numbers honest.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[server,dev]"
pre-commit install          # optional; runs ruff and mypy before each commit
```

## Before opening a pull request

```bash
make check                  # ruff + mypy + pytest
causeway metrics            # regenerate results/lab.json
```

If the lab table moved, update the table in `README.md` from `results/lab.json` and explain
the move in the PR. If you touched the AIT adapter or anything in `correlate.py`, also run
`causeway metrics ait --window 5` (needs the archive; see README *Data*) and report the
change.

## Rules that a test will enforce for you

- No correlation module may read `Alert.stage`.
- Every `Edge`, `RootCandidate` and `Option` must carry a human-readable `reason`.
- With rarity weighting off, precision must more than halve and compression must improve.
- Suppression holds; it never drops.

## Style

- Python 3.11+, `from __future__ import annotations`, line length 100.
- Module docstrings explain the decision the module embodies and the failure it prevents.
  Keep that convention; it is most of the documentation.
- Thresholds and weights are named constants with a comment saying how they were chosen.
- Record a design change in `docs/adr/` when it alters a rule, a weighting or a threshold.

## Reporting a problem

Open an issue with the corpus you ran (`lab`, `ait <scenario>`, or a JSONL sample), the
command, and the output. For anything security-relevant see [SECURITY.md](SECURITY.md).
