"""One alert shape, whatever product emitted it.

A SOC's first problem is not volume, it is that the same person, host and address wear a
different name in every console. Normalising into canonical *slots* is what makes any later
correlation possible: two alerts can only be shown to share an entity if both were first
made to spell that entity the same way.

Nothing here decides anything. `entities.py` resolves the slots to real entities,
`correlate.py` draws causal edges between alerts, and only `response.py` ever acts.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: Canonical entity slots. A sensor that has no opinion about a slot simply omits it --
#: an absent slot is not an empty one, and correlation never joins on a missing value.
SLOTS: tuple[str, ...] = (
    "user",      # the acting identity, however that product spells it
    "host",      # the machine the action happened on
    "src_ip",    # where it came from
    "dst_ip",    # where it went
    "process",   # image name of the running process
    "pid",       # process id, scoped to host
    "ppid",      # parent process id, scoped to host -- the strongest causal edge there is
    "file",      # path touched
    "hash",      # content hash of a binary or attachment
)


def iso(ts: int) -> str:
    """Epoch seconds to a readable UTC stamp. The console renders this, never the integer."""
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


@dataclass(frozen=True, slots=True)
class Alert:
    """One record as a product emitted it, with its entities pulled into canonical slots.

    ``stage`` carries the ground-truth attack-stage label when the corpus supplies one. It
    is read by `metrics.py` and by nothing else -- no correlation rule may consult it, and a
    test asserts as much. A correlator that can see the labels is measuring its own answer.
    """

    id: str
    ts: int                                   # epoch seconds
    sensor: str                               # "wazuh" | "suricata" | "aminer" | ...
    rule_id: str
    rule_name: str
    severity: int                             # 0-100, as normalised from the source product
    entities: Mapping[str, str] = field(default_factory=dict)
    stage: str = ""                           # ground truth, when known
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Alert.id must be non-empty")
        unknown = set(self.entities) - set(SLOTS)
        if unknown:
            raise ValueError(
                f"Alert {self.id} carries unknown entity slots {sorted(unknown)}; "
                f"valid slots are {list(SLOTS)}"
            )

    # -- accessors ---------------------------------------------------------------

    def entity(self, slot: str) -> str | None:
        value = self.entities.get(slot)
        return value or None

    @property
    def when(self) -> str:
        return iso(self.ts)

    @property
    def text(self) -> str:
        """What a human would read in the queue. Also what a *naive* deduplicator
        compares -- which is the point of having it be this plausible."""
        who = self.entity("user") or self.entity("src_ip") or "unknown"
        where = self.entity("host") or self.entity("dst_ip") or "unknown"
        return f"{self.rule_name} — {who} on {where}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "when": self.when,
            "sensor": self.sensor,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "entities": dict(self.entities),
            "stage": self.stage,
            "text": self.text,
        }


def load_alerts(path: str) -> list[Alert]:
    """Read a JSONL alert file. One object per line, the shape `Alert.to_dict` emits."""
    alerts: list[Alert] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            alerts.append(Alert(
                id=row["id"],
                ts=int(row["ts"]),
                sensor=row["sensor"],
                rule_id=row.get("rule_id", ""),
                rule_name=row.get("rule_name", ""),
                severity=int(row.get("severity", 0)),
                entities={k: v for k, v in (row.get("entities") or {}).items() if v},
                stage=row.get("stage", ""),
                raw=row.get("raw") or {},
            ))
    return sorted(alerts, key=lambda a: (a.ts, a.id))


def dump_alerts(alerts: list[Alert], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for alert in alerts:
            handle.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
