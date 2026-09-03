"""Suppress proven duplicates. Nothing else, and never by reading the text.

The PS is explicit that naive deduplication is dangerous, and it is worth being precise
about why. Two alerts that *read* the same can be two different attack stages: the
attacker's `schtasks.exe` and the deployment service's `schtasks.exe` produce the same
sentence in the queue. Two alerts that read differently can share one cause. Text is
evidence of nothing.

So a merge here requires four things to hold at once, and any one of them failing leaves
both records standing:

    same detection rule  ∧  same sensor  ∧  identical resolved entity tuple
                         ∧  inside the repeat window

That is a claim about the world -- *this product fired twice about the same thing* -- rather
than a claim about wording. Everything suppressed goes to a ledger and stays retrievable;
`QuarantineQueue` already gets this right in the engine, and the principle is the same one:
holding a record is reversible, discarding it is not. Compression that loses evidence is not
compression, it is data loss with a metric attached.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .entities import EntityResolver
from .schema import Alert

#: Two firings of the same rule about the same entities, this far apart or less, are the
#: same observation.
#:
#: **This value must be shorter than the shortest thing you need to tell apart**, and that
#: is a property of the data, not a preference. It was 300 s until the AIT corpus was tried,
#: where attack stages run as short as 2 s (`service_stop`) and 23 s (`dirb`) -- a 300 s
#: window is longer than several entire stages there, so merging across them was not a bug
#: in the rule but an arithmetic certainty. On that corpus 300 s erased evidence 11,213
#: times; 5 s erased it zero times.
#:
#: 30 s is the default because it costs nothing on the lab corpus (identical incidents,
#: recall and root cause at every value from 30 s to 300 s) while leaving an order of
#: magnitude of headroom. Any deployment should set it from its own shortest stage rather
#: than inherit this number.
REPEAT_WINDOW = 30  # seconds


def _key(alert: Alert, resolver: EntityResolver) -> tuple:
    """The identity of an observation: rule, sensor, and the resolved entities.

    Deliberately built from `Origin.ref` values rather than the raw slots, so two products
    spelling one host differently do not defeat the match, and two hosts sharing a pid do
    not accidentally satisfy it.
    """
    refs = tuple(sorted(o.ref for o in resolver.entity_origins(alert)))
    return (alert.sensor, alert.rule_id, refs)


@dataclass
class Observation:
    """One thing that happened, however many times a product said so."""

    id: str
    representative: Alert          # the earliest member; what the console shows
    members: list[Alert] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def suppressed(self) -> list[Alert]:
        """Everything after the first. Held, never dropped."""
        return self.members[1:]

    @property
    def first_ts(self) -> int:
        return self.members[0].ts

    @property
    def last_ts(self) -> int:
        return self.members[-1].ts

    @property
    def severity(self) -> int:
        return max(a.severity for a in self.members)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.representative.rule_id,
            "rule_name": self.representative.rule_name,
            "sensor": self.representative.sensor,
            "text": self.representative.text,
            "count": self.count,
            "suppressed": len(self.suppressed),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "severity": self.severity,
            "alert_ids": [a.id for a in self.members],
        }


@dataclass(frozen=True, slots=True)
class Suppression:
    """One record held, and the exact grounds for holding it."""

    alert_id: str
    observation_id: str
    duplicate_of: str
    reason: str

    def to_dict(self) -> dict:
        return {"alert_id": self.alert_id, "observation_id": self.observation_id,
                "duplicate_of": self.duplicate_of, "reason": self.reason}


@dataclass
class Ledger:
    """Every suppression, with its grounds. Append-only; nothing is ever removed.

    An analyst who distrusts a merge can read exactly why it happened and pull the record
    back. That is the difference between compression an analyst will accept and compression
    that quietly costs them a case.
    """

    entries: list[Suppression] = field(default_factory=list)

    def hold(self, alert: Alert, observation: Observation, reason: str) -> None:
        self.entries.append(Suppression(
            alert_id=alert.id,
            observation_id=observation.id,
            duplicate_of=observation.representative.id,
            reason=reason,
        ))

    def released(self) -> list[str]:
        return [e.alert_id for e in self.entries]

    def __len__(self) -> int:
        return len(self.entries)

    def to_dict(self) -> dict:
        return {"suppressed": len(self.entries),
                "entries": [e.to_dict() for e in self.entries]}


def group(alerts: list[Alert], resolver: EntityResolver, *,
          window: int = REPEAT_WINDOW) -> tuple[list[Observation], Ledger]:
    """Collapse repeat firings into observations. Returns the observations and the ledger."""
    ordered = sorted(alerts, key=lambda a: (a.ts, a.id))
    open_obs: dict[tuple, Observation] = {}
    out: list[Observation] = []
    ledger = Ledger()
    n = 0

    for alert in ordered:
        key = _key(alert, resolver)
        current = open_obs.get(key)
        if current is not None and alert.ts - current.last_ts <= window:
            current.members.append(alert)
            ledger.hold(alert, current, (
                f"{alert.sensor} re-fired {alert.rule_id} on identical entities "
                f"{alert.ts - current.representative.ts}s after {current.representative.id}"
            ))
            continue
        n += 1
        obs = Observation(id=f"obs-{n:05d}", representative=alert, members=[alert])
        open_obs[key] = obs
        out.append(obs)

    return out, ledger


#: The window the strawman uses. Deliberately *not* `REPEAT_WINDOW`: the baseline exists to
#: represent what queue tooling does out of the box, and it must not silently inherit
#: whatever Causeway happens to be tuned to. Letting it track our constant made the baseline
#: look better every time we tightened ours, which measures nothing.
NAIVE_WINDOW = 300  # seconds


def naive_text_group(alerts: list[Alert], *,
                     window: int = NAIVE_WINDOW) -> tuple[list[Observation], Ledger]:
    """The strawman: merge on what the alert *says*.

    This is not a hypothetical bad idea -- it is what queue tooling does by default, and it
    is the configuration the metrics harness runs alongside ours so the false-suppression
    number has something to be better than. It merges the attacker's scheduled task into the
    deployment service's, and the exfiltration into the nightly backup.
    """
    ordered = sorted(alerts, key=lambda a: (a.ts, a.id))
    open_obs: dict[str, Observation] = {}
    out: list[Observation] = []
    ledger = Ledger()
    n = 0

    for alert in ordered:
        key = alert.rule_name
        current = open_obs.get(key)
        if current is not None and alert.ts - current.last_ts <= window:
            current.members.append(alert)
            ledger.hold(alert, current, f"same alert text as {current.representative.id}")
            continue
        n += 1
        obs = Observation(id=f"obs-{n:05d}", representative=alert, members=[alert])
        open_obs[key] = obs
        out.append(obs)

    return out, ledger
