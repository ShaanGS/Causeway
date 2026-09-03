# Security

Causeway recommends responses; it does not execute them. Nothing in this repository
contacts a network, calls a model, or modifies the systems the alerts describe. The
decision path is pure Python over in-memory data, and a test asserts `model_calls == 0`
and `network_calls == 0` for every decision.

## What is in scope

- Correlation, ranking or policy logic that could recommend an over-broad action.
- The audit chain (`ventriloquist/audit.py`) failing to detect tampering.
- The HTTP surface (`server/app.py`) exposing something it should not. It is intended for
  a local console and binds to `127.0.0.1` by default.

## Data

No credentials or secrets are needed to run anything here. The AIT Alert Data Set is not
redistributed; users download it themselves under its CC BY 4.0 licence.

## Reporting

Open a GitHub issue for anything that is not sensitive. For something that is, contact the
maintainer directly through the GitHub profile rather than filing it publicly.
