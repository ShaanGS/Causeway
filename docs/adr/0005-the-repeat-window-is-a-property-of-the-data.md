# 0005 — The repeat window is a property of the data

**Status:** accepted

## Problem

`REPEAT_WINDOW` was 300 s. On the AIT corpus attack stages run as short as 2 s
(`service_stop`) and 23 s (`dirb`), so a 300 s window is longer than several entire stages
and merged across them: 11,213 evidence-erasing suppressions. At 30 s it still merges
across three adjacent scanner stages 23-39 s long (10,819, all of them between those three
stages). At 5 s it erases nothing.

## Decision

The default is 30 s, which is safe on the lab corpus at every value from 30 s to 300 s and
leaves an order of magnitude of headroom. The window is a parameter of `dedup.group`, of
`causeway metrics --window`, and public-corpus results are reported at `--window 5`. No
attempt is made to infer it: the shortest stage a deployment needs to tell apart is not
knowable from the alert stream.

## Consequences

- Two corpora, two reported windows, both stated next to the numbers.
- Any deployment must set the window from its own shortest stage rather than inherit ours.
