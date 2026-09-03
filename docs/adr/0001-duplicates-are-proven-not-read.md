# 0001 — A duplicate is proven, never read

**Status:** accepted

## Problem

The queue contains genuine repeats (a sensor re-firing the same rule on the same entities
dozens of times in a minute) and near-duplicates that are not duplicates at all: the
attacker's `schtasks.exe` and the deployment service's `schtasks.exe` produce the same
sentence. Suppressing nothing drowns the analyst; suppressing on wording erases the
persistence stage.

## Decision

A merge requires four things at once: same detection rule, same sensor, identical resolved
entity tuple, and inside the repeat window. Text is never consulted. Every suppression is
written to a ledger with its grounds and stays retrievable.

The naive text baseline is kept in the codebase (`dedup.naive_text_group`) and run by the
harness, pinned to its own window so it cannot inherit our tuning.

## Consequences

- The lab corpus is built with a deliberately identical-reading pair across two stages, and
  the false-suppression metric exists to catch a merge of them. Causal dedup erases zero
  evidence; the text baseline erases four and loses five of nine stages.
- Compression is lower than text matching would give. That is accepted: compression that
  loses evidence is data loss with a metric attached.
