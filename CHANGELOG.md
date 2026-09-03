# Changelog

## 0.1.0 — 2026-09-04

First submission release.

- Six-stage pipeline: normalise, resolve, suppress, correlate, cluster, recommend.
- Lab corpus with a published answer key; four-configuration metrics harness with a
  naive-text baseline and a rarity-weighting negative control.
- AIT Alert Data Set adapter: Suricata relayed inside Wazuh attributed correctly, generic
  agent names not taken as hosts, ports stripped from addresses.
- Ubiquity weighting by degree as well as frequency (ADR 0004): AIT recall 0.02 → 0.34
  with the lab table unchanged.
- `causeway` CLI (`run`, `metrics`, `export`, `serve`), FastAPI console, 51 tests, CI on
  Python 3.11 and 3.12, ruff and mypy clean.
