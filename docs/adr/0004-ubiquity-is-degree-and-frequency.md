# 0004 — An entity is a hub only if it is both frequent and connected

**Status:** accepted (supersedes frequency-only weighting)

## Problem

Correlation joins on shared entities, and the domain controller or the vulnerability
scanner's address is shared by everything. Inverse document frequency handled this on the
lab corpus. On the AIT public corpus it failed: one intruder's scanner produced a quarter
of the alert stream, so by frequency alone the attacker's address looked like
infrastructure and every edge that mattered was weighted away. First recall on AIT: 0.02.

## Decision

`correlate.entity_weights` computes two rarity scores and keeps the larger:

- inverse frequency: how many observations mention the entity;
- inverse degree: how many distinct other entities it co-occurs with.

An entity is discounted only when both tests call it a hub. A loud attacker who touches two
machines is distinctive however many alerts they generate. Loud is not the same as
everywhere.

## Consequences

- Lab table unchanged to the decimal (17 cases, precision 0.755, recall 1.0, 9/9, root ✓).
- AIT recall 0.02 → 0.34, stages 0/10 → 7/10, precision 0.02 → 0.12.
- The unweighted control still scores 0.999 recall on AIT, because "the attack is rare" is
  false there. Reported in the README, not hidden.
- A test (`test_loud_is_not_the_same_as_ubiquitous`) holds the distinction.
