"""A corpus is alerts plus whatever answer key its source can honestly supply.

Every adapter produces one of these, and everything downstream -- the pipeline, the metrics
harness, the CLI and the server -- consumes only this. That is the seam that lets the
self-authored lab range and a public dataset be graded by identical code.

The answer key is optional by field, not by corpus. A source that publishes attack windows
but no root cause fills ``truth`` and leaves ``root_ref`` empty, and the harness reports
the root-cause row as *not gradable* rather than as a failure. Pretending a corpus supplies
ground truth it does not have is how benchmark numbers stop meaning anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .schema import Alert, load_alerts


@dataclass(frozen=True, slots=True)
class Scenario:
    """A corpus and the answer key that grades any analysis of it."""

    name: str
    alerts: list[Alert]
    #: alert id -> attack stage, for every alert genuinely part of the attack
    truth: dict[str, str] = field(default_factory=dict)
    #: canonical entity ref (e.g. ``account:j.okafor``) a correct root-cause answer must
    #: name, or "" when the source publishes no such thing
    root_ref: str = ""
    #: alert id -> the alert id that actually caused it, where the source knows
    parents: dict[str, str] = field(default_factory=dict)
    #: ids of alerts that are true duplicates of an earlier alert (safe to suppress)
    duplicates: set[str] = field(default_factory=set)

    @property
    def stages(self) -> list[str]:
        return sorted(set(self.truth.values()))

    @property
    def root_gradable(self) -> bool:
        return bool(self.root_ref)

    def by_id(self) -> dict[str, Alert]:
        return {a.id: a for a in self.alerts}


def from_jsonl(path: str | Path) -> Scenario:
    """Alerts from a JSONL file in the shape `Alert.to_dict` emits.

    Any ``stage`` values present are taken as the answer key; a file without them is
    simply a corpus with no ground truth, which the harness reports as such.
    """
    alerts = load_alerts(str(path))
    return Scenario(
        name=Path(path).stem,
        alerts=alerts,
        truth={a.id: a.stage for a in alerts if a.stage},
    )


def load(corpus: str = "lab", *, scenario: str | None = None, seed: int = 7) -> Scenario:
    """Resolve a corpus by name: ``lab``, ``ait``, or a path to a JSONL file."""
    if corpus == "lab":
        from .adapters.lab import generate
        return generate(seed)
    if corpus == "ait":
        from .adapters import ait
        return ait.load(scenario or ait.DEFAULT_SCENARIO)
    path = Path(corpus)
    if path.suffix.lower() == ".jsonl" and path.exists():
        return from_jsonl(path)
    raise ValueError(f"unknown corpus {corpus!r}: expected 'lab', 'ait', or a .jsonl path")
