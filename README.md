# Causeway

**Causal SOC alert correlation and root-cause intelligence.**

A single attacker action produces dozens of technically correct alerts across products that
do not agree on what to call a person, a machine, or an address. The queue shows them as
unrelated rows. Causeway reconstructs the causal incident behind them, names the earliest
thing an organisation could actually have contained, suppresses only provable duplicates,
and recommends the smallest action that would stop the intrusion — refusing, in writing, to
go further than its evidence supports.

Built for **PS2 — Causal SOC Alert Correlation & Root-Cause Intelligence**
(Microsoft Innovation Club, VIT Chennai).

## The result

938 alerts from four products over one night, containing a nine-stage intrusion.

```
configuration                   cases  compression  precision  recall  stages  erased  root top-1
No correlation                    938         1.0×      0.000   0.000     0/9       0          ✕
Naive text dedup                    4       234.5×      0.150   1.000     4/9       4          ✕
Causeway (rarity weighting off)     2       469.0×      0.133   1.000     9/9       0          ✕
Causeway                           17        55.2×      0.755   1.000     9/9       0          ✓
```

`.venv/bin/python -m causeway.metrics` regenerates this table. No document here quotes a
number that command did not write.

**Read the third row before the fourth.** It is the same code with one mechanism disabled,
and it achieves the *best compression on the page* while getting the root cause wrong and
scoring the worst precision. Compression is the metric this problem invites you to optimise
and it is the one most easily faked by merging aggressively. That row is why it is not our
headline.

**Read the second row too.** Merging on what an alert *says* buries the successful login —
the actual root cause — underneath a routine one, because the two produce the same sentence.
It recovers four of nine stages and erases evidence four times. This is not a strawman; it
is what queue tooling does by default, and the PS names it as a hazard.

The one incident that matters holds **115 alerts, all nine stages, 26 observations across
three products**, and its top-ranked root cause is correct.

## How it works

Six stages, no model and no network call in any of them. The whole pipeline runs in ~24 ms.

**Normalise.** Every product's alert is pulled into canonical entity slots. A sensor with no
opinion about a slot omits it; correlation never joins on a missing value.

**Resolve.** `CORP\j.okafor`, `j.okafor@corp.local` and `S-1-5-21-1004-1104` are one person.
Until they spell the same, nothing downstream can join on them.

**Suppress duplicates — and only duplicates.** A merge requires *same rule ∧ same sensor ∧
identical resolved entity tuple ∧ inside the repeat window*. Never text. Everything
suppressed goes to a ledger with its grounds and stays retrievable. Compression that loses
evidence is data loss with a metric attached.

**Draw causal edges.** Three ideas carry this:

- *Precedence.* Every edge points forward in time, so the graph is a DAG and "what did this
  lead to" has an answer.
- *Nearest predecessor, not every predecessor.* Linking to all of them yields a clique — one
  blob per busy host, technically connected and unreadable. Chains are what an analyst follows.
- *Ubiquitous entities carry no signal.* The domain controller appears in everything, as does
  the vulnerability scanner's address. Each entity is weighted by rarity, so a hub contributes
  almost nothing. This is the mechanism the negative control disables, and the reason the
  benign Sunday does not collapse into one false incident.

Process ancestry (`ppid → pid`) is exempt from weighting: a parent pid *is* causation.

**Rank root causes — as entities, not alerts.** Nobody contains an alert. They disable an
account, isolate a host, block an address. Ranking alerts put a *failed* authentication on
top, which looked like a bug until the obvious objection landed: containing `j.okafor` at the
moment of the spray genuinely would have stopped the attack. The ranking was right and the
question was wrong. Scoring entities makes the failed spray attempt and the successful login
resolve to the same answer, which is what a responder needed either way.

Controllability is weighted by kind, because an identity can be disabled and stays disabled
while an address is chosen by the attacker and costs nothing to change. Blocking the address
is the move that feels decisive and accomplishes least.

**Recommend the smallest sufficient action.** A ladder ordered by disruption, gated on
evidence:

```
annotate < notify < re-authenticate < revoke session < rotate credential
         < isolate host < disable account
```

Take the lowest rung that is both *effective* against the thing being contained and
*authorised* by the evidence. An MFA challenge is real interference and no help against a
session the attacker already holds — "smallest safe action" and "smallest safe action **that
stops progression**" are different requests, and the PS asks for the second.

The interesting output is the refusal, not the recommendation:

> *Disable the account needs Analyst approved; the evidence for account j.okafor is
> Corroborated telemetry.*

That tells an analyst what the system would need to go further. A control that only says no
gets switched off.

## Where the provenance engine comes in

`ventriloquist/` is a provenance gateway built for an earlier project and vendored here
unchanged apart from six additive origin kinds. It contributes three things this problem
needs and it would have been wasteful to rebuild:

| what it does | where it lands here |
|---|---|
| lineage as a transitive origin closure | "which cases rest on this entity" is a filter, not a graph walk — including cases nobody linked to it by name |
| `blast_radius()` — pure hypothetical re-evaluation | the containment preview: *contain this and here is what stops standing up*, in ~190 µs |
| a tamper-evident hash chain | every correlation, suppression and refusal is an audit event; the console is only a projection of it |
| quarantine as hold-not-delete | the suppression ledger inherits the principle: refusals must be recoverable |

**What it does not do is the correlation.** It is *handed* lineage by an agent's turn
context; a SOC is handed nothing, and inferring the edges is the new work. Claiming
otherwise is the seam a sharp reviewer would find first.

### The one thing worth arguing about

The engine's rule is `min()` — a claim is only as strong as its weakest source. Applied
naively to an incident, that is perverse: a network sensor's port-scan alert joining a case
*lowers* what the case may authorise, so acquiring more evidence removes your ability to
act. It would train anyone to keep cases narrow.

So authorisation is evaluated against the **target entity's** lineage, not the incident's.
What matters when revoking `j.okafor`'s session is how well attested *j.okafor* is. A port
scan elsewhere in the same case is irrelevant to that; a threat feed being the only thing
that ever mentioned the account is decisive against it. The weakest-link rule survives where
it belongs and stops punishing breadth.

Correlation confidence and evidentiary trust are kept as two numbers throughout, and they
move in opposite directions by design. An incident can be near-certain its alerts belong
together and still be barred from disruptive action — certainty that a story hangs together
is not certainty about who did it. Collapsing them into one score is how correlation tools
end up either over-escalating or refusing to act at all.

## Data

The PS makes dataset sourcing the participant's responsibility and requires documented
origin and licensing.

**`causeway/adapters/lab.py` — self-generated lab corpus.** Deterministic (`seed=7`), 938
alerts across four sensor types over 24 simulated hours, containing a nine-stage intrusion
with a published answer key: which alerts belong to the attack, which alert caused which,
and which are true duplicates. Authored for this submission; no third-party data. It exists
because every metric here needs ground truth, and it is built to be *hostile* to the system
measuring against it:

- benign activity fires the attack's own rules — IT automation creates scheduled tasks, the
  backup job moves gigabytes at night, the scanner ports-scans everything on Sundays;
- there are real duplicates, so suppressing nothing would be a failure;
- there are near-duplicates that are **not** duplicates — the attacker's scheduled task and
  the deployment service's read identically. Merging them erases the persistence stage, and
  the false-suppression metric exists to catch exactly that.

No correlation rule may read the ground-truth label. A test parses the AST of every rule
module and fails if any of them touches `.stage`.

**Public corpus (in progress).** [AIT Alert Data Set](https://zenodo.org/records/8263181) —
2.65 M labelled alerts from AMiner, Wazuh and Suricata across eight scenarios of a shared
nine-stage attack, released with *Introducing a New Alert Data Set for Multi-Step Attack
Analysis* (CSET '24). Chosen because it ships **alerts rather than raw logs**, so it needs no
parsing pipeline, and because three independent sensors make the PS's "entity context is
fragmented" a real property of the data rather than something we staged. Licence and
citation to be recorded with the adapter.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install pyyaml pytest fastapi uvicorn httpx rich
.venv/bin/python -m pytest tests/ -q          # 27 tests, incl. the negative controls
.venv/bin/python -m causeway.metrics          # regenerates the table above
.venv/bin/python -m uvicorn server.app:app --port 8788
```

Then open <http://127.0.0.1:8788>.

## Tests

27 tests. The ones that matter are the controls — anything that groups will report
compression, so the tests worth trusting are those that would fail if a mechanism were
quietly doing nothing:

- rarity weighting is load-bearing: with it off, precision must more than halve **and**
  compression must improve, or the headline row was an accident;
- naive text dedup must bury the root cause, or the corpus has stopped being adversarial;
- causal dedup must erase no evidence — nothing suppressed under a representative from a
  different stage;
- no correlation rule may read the answer key (AST-checked);
- the most destructive rungs must still require a human;
- annotation must never be refused;
- every decision runs with `model_calls == 0 and network_calls == 0`;
- the audit chain must verify after a full ingest.

## Limits

Stated because a reviewer will find them anyway.

- **Precision is 0.755, not higher.** The wider entity windows that recover reconnaissance
  also pull benign activity on the victim's own host and account into the case. For triage
  that is a trade worth taking — a case carrying surrounding context is workable, a case
  missing its first stage is misleading — but it is a real cost and it is what the number
  reflects.
- **Analyst time saved is a model, not a measurement**: pivots avoided × an assumed 3
  minutes per pivot. The assumption is stated in the output rather than buried.
- **Mean time to contain** measures first alert to authorised recommendation. It excludes
  the human who has to approve the rungs that require approval, and pretending otherwise
  would flatter it.
- **Precedence does not change the grouping.** Observations are walked in time order and
  linked to their nearest predecessor, so precedence is structural rather than filtered for,
  and clustering is undirected regardless. It shapes the graph an analyst reads, not the
  clusters. This was the obvious candidate for the negative-control slot and turned out to
  be a no-op; reporting the control that actually bites is the point of having one.
- **Results are on a self-authored corpus.** The public-dataset leg is the fix and it is not
  finished.
