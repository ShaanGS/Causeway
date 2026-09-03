# 0003 — Root causes are entities, not alerts

**Status:** accepted

## Problem

The first version ranked alerts. On the lab corpus the password spray precedes the
successful login and the whole chain hangs off it, so "earliest" and "most downstream
reach" both pointed at a *failed* authentication. That looked like a scoring bug.

## Decision

Nobody contains an alert; they disable an account, isolate a host, block an address.
`rootcause.rank` scores entities on coverage (0.40), controllability (0.35) and earliness
(0.25). Controllability is by kind: an account can be disabled and stays disabled (1.0); an
address is chosen by the attacker and costs nothing to change (0.25).

## Consequences

- The failed spray attempt and the successful login resolve to the same answer,
  `account:j.okafor`, which is what a responder needed either way.
- An address is never the top answer on the lab corpus, and a test asserts it.
- The response ladder gates on the root entity's *kind*: isolating a host is irrelevant to
  a stolen identity, so it is not offered as effective for one.
