# 0002 — Authorisation is evaluated against the target entity, not the incident

**Status:** accepted

## Problem

The provenance engine's rule is `min()`: a claim is only as strong as its weakest source.
Applied to a whole incident, a network sensor's port-scan alert joining a case *lowers*
what the case may authorise. Acquiring more evidence removes the ability to act, which
would train analysts to keep cases narrow.

## Decision

`response.recommend` evaluates policy against the lineage of the **entity being acted on**
(`target_provenance`): every attestation of that entity across the incident. A port scan
elsewhere in the case is irrelevant to revoking `j.okafor`'s session; a threat feed being
the only source that ever mentioned the account is decisive against it.

Correlation confidence (noisy-OR over edges, rises with corroboration) and evidentiary
trust (`min()` over lineage, falls to the weakest link) are kept as two separate numbers
throughout.

## Consequences

- An incident can be near-certain its alerts belong together and still be barred from
  isolating a host. That is the intended position.
- The weakest-link rule survives where it belongs and stops punishing breadth.
