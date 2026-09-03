# Causeway

[![ci](https://github.com/ShaanGS/Causeway/actions/workflows/ci.yml/badge.svg)](https://github.com/ShaanGS/Causeway/actions/workflows/ci.yml)

**Causal SOC alert correlation and root-cause intelligence.**

A single attacker action produces dozens of technically correct alerts across products that
do not agree on what to call a person, a machine, or an address. The queue shows them as
unrelated rows. Causeway reconstructs the causal incident behind them, names the earliest
thing an organisation could actually have contained, suppresses only provable duplicates,
and recommends the smallest action that would stop the intrusion — refusing, in writing, to
go further than its evidence supports.

Built for **PS2 — Causal SOC Alert Correlation & Root-Cause Intelligence**
(Microsoft Innovation Club, VIT Chennai). No model and no network call anywhere in the
decision path; the whole pipeline runs in about 25 ms on the lab corpus and under a second
on 45,000 real alerts.

![The reconstructed incident: time on x, one lane per machine, root cause ringed](deck/causal-graph.png)

## The result

938 alerts from four products over one night, containing a nine-stage intrusion.

```
configuration                   cases  compression  precision  recall  stages  erased  root top-1
No correlation                    938         1.0×      0.000   0.000     0/9       0          ✕
Naive text dedup                    4       234.5×      0.150   1.000     4/9       4          ✕
Causeway (rarity weighting off)     2       469.0×      0.133   1.000     9/9       0          ✕
Causeway                           17        55.2×      0.755   1.000     9/9       0          ✓
```

`causeway metrics` regenerates this table and writes it to `results/lab.json`. No document
here quotes a number that command did not write.

**Read the third row before the fourth.** It is the same code with one mechanism disabled,
and it achieves the *best compression on the page* while getting the root cause wrong and
scoring the worst precision. Compression is the metric this problem invites you to optimise
and it is the one most easily faked by merging aggressively. That row is why it is not our
headline.

**Read the second row too.** Merging on what an alert *says* buries the successful login —
the actual root cause — underneath a routine one, because the two produce the same sentence.
It recovers four of nine stages and erases evidence four times. This is not a strawman; it
is what queue tooling does by default, and the PS names it as a hazard.

The one incident that matters holds **115 alerts, all nine stages, 31 observations across
three products**, and its top-ranked root cause is correct.

### On somebody else's data

The same four configurations over the public **AIT Alert Data Set** (scenario
`russellmitchell`: 45,544 real alerts from AMiner, Wazuh and Suricata, 12,015 of them inside
a published ten-stage attack). Nothing was tuned to it.

```
configuration                   cases  compression  precision  recall  stages  erased  root top-1
No correlation                  45544         1.0×      0.000   0.000    0/10       0        n/a
Naive text dedup                  121       376.4×      0.273   0.992    7/10    8545        n/a
Causeway (rarity weighting off)    90       506.0×      0.266   0.999    8/10       0        n/a
Causeway                          950        47.9×      0.122   0.337    7/10       0        n/a
```

`causeway metrics ait --window 5` regenerates it (`results/ait-russellmitchell.json`). The
dataset publishes attack windows but no root-cause entity, so that column is not gradable.

Two things this table says that flatter nobody. First, the negative control wins on recall
here: the attack is a quarter of the whole stream, so "the attack is rare" — the prior
behind rarity weighting — is false on this corpus, and treating every entity as
distinctive happens to work. Second, the first run of Causeway on this data scored a recall
of 0.02. Reading why produced the change described under *Ubiquitous entities* below, which
lifted it to 0.34 and seven stages without moving a single number on the lab corpus. It is
still the weakest row on the page and it is reported as such.

## How it works

Six stages, no model and no network call in any of them.

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
  the vulnerability scanner's address. Each entity is weighted by how distinctive it is, and
  ubiquity is tested two ways: by **frequency** (how many observations mention it) and by
  **degree** (how many distinct other entities it is seen with). An entity is discounted only
  when both tests call it a hub. The second test exists because of the public corpus: a loud
  attacker generated a quarter of the stream, looked like infrastructure by frequency alone,
  and every edge that mattered was weighted away. Loud is not the same as everywhere.

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

## What the problem statement asks for, and where it is answered

| PS requirement | where | how it is checked |
|---|---|---|
| Correlate alerts across products into causal incidents | `causeway/correlate.py`, `incident.py` | all nine stages land in one incident; every edge points forward in time |
| Fragmented entity context | `causeway/entities.py` | four spellings of one person resolve to one; a pid is scoped to its host |
| Deduplicate without losing evidence | `causeway/dedup.py` | zero evidence erased on both corpora; the naive baseline is shown erasing it |
| Root-cause identification | `causeway/rootcause.py` | top-1 names the compromised identity; an address is never the answer |
| Minimal-impact, evidence-gated response | `causeway/response.py`, `policies/soc.yaml` | destructive rungs still need a human; annotation is never refused |
| Explainability | every `Edge`, `RootCandidate` and `Option` carries a `reason` | a test fails on any edge that cannot explain itself |
| Auditability | `ventriloquist/audit.py` | the hash chain verifies after a full ingest |
| Measured, with baselines and controls | `causeway/metrics.py` | four configurations, byte-identical input, negative control must bite |
| Documented data provenance and licensing | *Data*, below | — |

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

**`causeway/adapters/ait.py` — AIT Alert Data Set.** Landauer, Skopik and Wurzenberger,
*Introducing a New Alert Data Set for Multi-Step Attack Analysis*, CSET '24.
[Zenodo 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), **CC BY 4.0**. 2.65 M
labelled alerts from AMiner, Wazuh and Suricata across eight scenarios of a shared attack.
Chosen because it ships **alerts rather than raw logs**, and because three independent
sensors make the PS's "entity context is fragmented" a property of the data rather than
something staged. The archive is not committed (96 MB); download it to `data/raw/ait_ads.zip`
and the adapter finds the scenarios inside it. `data/raw/labels.csv` carries the published
attack windows.

Three things the raw rows do that the adapter has to undo, each found by reading the data
rather than the paper: Suricata findings arrive twice inside Wazuh's envelope (`eve.json`
and `fast.log`) and are attributed to Suricata with the signature id as the rule, so the
relay is not credited with an observation it never made and the ledger can prove the pair
are duplicates; every agent is named `wazuh-client`, so the host comes from the syslog
header only; and addresses carry ports. The duplicate window has to be 5 s on this corpus —
attack stages run as short as 2 s — and the number that says so is in `dedup.py`.

## Run it

```bash
git clone https://github.com/ShaanGS/Causeway.git && cd Causeway
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[server,dev]"
```

```bash
causeway run                       # correlate the lab corpus, print the cases
causeway run -v --top 1            # ...with every observation and edge of the headline case
causeway metrics                   # the table above -> results/lab.json
causeway metrics ait --window 5    # the public corpus (needs data/raw/ait_ads.zip)
causeway export --out alerts.jsonl # the lab corpus in the JSONL shape `run` accepts
causeway run alerts.jsonl          # correlate your own alerts
causeway serve                     # the analyst console at http://127.0.0.1:8788
```

`python -m causeway` is the same CLI; `python -m causeway.metrics` runs the harness alone.

```bash
pytest && ruff check . && mypy causeway server
```

## Repository layout

```
causeway/            the product
  schema.py          one alert shape, whatever product emitted it
  entities.py        alias resolution; evidentiary weight per reporting sensor
  dedup.py           provable duplicates only, held in a ledger
  correlate.py       causal edges: ancestry, pivots, shared entities, address handoff
  incident.py        clustering; correlation confidence vs evidentiary trust
  rootcause.py       entities ranked by what containing them would have stopped
  response.py        the ladder, and the refusal in writing
  metrics.py         four configurations, byte-identical input
  corpus.py          the corpus contract every adapter fills
  cli.py             run / metrics / export / serve
  adapters/          lab.py (self-authored, answer key) and ait.py (public)
  policies/soc.yaml  what evidence each response requires; data, not code
ventriloquist/       the vendored provenance engine (lineage, policy, audit chain)
server/              FastAPI surface and the single-file console
tests/               51 tests, including the negative controls
results/             what `causeway metrics` last wrote
data/raw/labels.csv  AIT attack windows (the archive itself is downloaded, not committed)
deck/                the submission deck and the script that draws its figure from the pipeline
```

## Tests

51 tests, run in CI on Python 3.11 and 3.12 alongside `ruff` and `mypy`. The ones that
matter are the controls — anything that groups will report compression, so the tests worth
trusting are those that would fail if a mechanism were quietly doing nothing:

- rarity weighting is load-bearing: with it off, precision must more than halve **and**
  compression must improve, or the headline row was an accident;
- loud is not ubiquitous: an attacker firing 200 alerts at one host must keep its weight
  while a domain controller seen with 200 different people loses it;
- naive text dedup must bury the root cause, or the corpus has stopped being adversarial;
- causal dedup must erase no evidence — nothing suppressed under a representative from a
  different stage;
- no correlation rule may read the answer key (AST-checked);
- the most destructive rungs must still require a human;
- annotation must never be refused;
- every decision runs with `model_calls == 0 and network_calls == 0`;
- the audit chain must verify after a full ingest;
- the AIT adapter is tested against the exact row shapes it was written from, including the
  two encodings of one Suricata finding;
- the CLI and the HTTP API are held to the same pipeline state.

## Limits

Stated because a reviewer will find them anyway.

- **Precision is 0.755 on the lab corpus, not higher.** The wider entity windows that recover
  reconnaissance also pull benign activity on the victim's own host and account into the
  case. For triage that is a trade worth taking — a case carrying surrounding context is
  workable, a case missing its first stage is misleading — but it is a real cost.
- **Recall is 0.34 on the public corpus, and the unweighted control does better.** Rarity
  weighting assumes the attack is a small share of the stream. On AIT it is a quarter of it.
  The degree test closed most of the gap and the rest is reported, not hidden.
- **The duplicate window is a property of the data.** 30 s is safe on the lab corpus and
  wrong on AIT, where it merges across adjacent scanner stages shorter than itself. A
  deployment has to set it from its own shortest stage; nothing here can infer it.
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
- **The root-cause column is not gradable on AIT.** The dataset publishes stage windows,
  not the entity a responder should have contained, so the harness says *n/a* rather than
  inventing an answer key.

## License

MIT. The AIT Alert Data Set is CC BY 4.0 and is not redistributed here.
