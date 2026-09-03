"""The public corpus: AIT Alert Data Set.

Zenodo doi 10.5281/zenodo.8263181, CC-BY-4.0, released with Landauer, Skopik and
Wurzenberger, *Introducing a New Alert Data Set for Multi-Step Attack Analysis*, CSET '24.

Chosen over raw-telemetry corpora for one practical reason and one honest one. Practical:
it ships **alerts**, not logs, so nothing here has to become a parsing pipeline for Windows
event XML. Honest: three independent detectors — AMiner, Wazuh and Suricata — disagree about
what to call the same host and address, so the PS's "entity context is fragmented across
products" is a property of the data rather than something the lab generator stages on
purpose. Eight scenarios each run the same ten-stage attack under different background
noise.

Ground truth comes from `labels.csv`, which gives `(scenario, attack, start, end)` as epoch
windows. An alert is labelled with whichever attack window contains its timestamp, and left
unlabelled otherwise — that unlabelled majority is the benign traffic, and it is what makes
precision mean anything.

The layout inside the archive is discovered rather than assumed: the release has been
repackaged before, and a hard-coded path would fail silently as an empty corpus rather than
loudly as a missing file.

One wrinkle in the published labels, found by reading them rather than trusting them: in the
`fox` scenario the final two stages (`service_stop`, `dnsteal`) are timestamped a day
*before* the other eight, so its chain does not run forward in wall-clock time.
`russellmitchell` is coherent — the full chain at 03:01-04:38 and the last two stages at
13:50 the same day — so it is the default here. Nothing is silently repaired; a scenario is
used as published or not used.
"""

from __future__ import annotations

import bisect
import csv
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ..schema import Alert

#: Detector name -> our sensor key. AIT prefixes each alert name with its detector.
SENSOR_PREFIX = {"wazuh": "wazuh", "suricata": "suricata", "aminer": "aminer"}

DEFAULT_ARCHIVE = Path("data/raw/ait_ads.zip")
DEFAULT_LABELS = Path("data/raw/labels.csv")


@dataclass(frozen=True, slots=True)
class Window:
    scenario: str
    attack: str
    start: float
    end: float


def load_labels(path: Path = DEFAULT_LABELS) -> dict[str, list[Window]]:
    """Attack windows per scenario, sorted by start so lookup is a bisect."""
    out: dict[str, list[Window]] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out.setdefault(row["scenario"], []).append(Window(
                scenario=row["scenario"], attack=row["attack"],
                start=float(row["start"]), end=float(row["end"]),
            ))
    for windows in out.values():
        windows.sort(key=lambda w: w.start)
    return out


def _stage_at(windows: list[Window], ts: float) -> str:
    """Which attack stage was running at `ts`, or "" for background activity."""
    i = bisect.bisect_right([w.start for w in windows], ts) - 1
    if i < 0:
        return ""
    w = windows[i]
    return w.attack if w.start <= ts <= w.end else ""


def _sensor_of(name: str) -> str:
    head = re.split(r"[:\s]", name.strip(), 1)[0].lower()
    return SENSOR_PREFIX.get(head, "aminer")


def _entities(row: dict) -> dict[str, str]:
    ent = {}
    if (ip := row.get("ip") or row.get("src_ip")):
        ent["src_ip"] = str(ip).strip()
    if (host := row.get("host") or row.get("hostname")):
        ent["host"] = str(host).strip()
    if (user := row.get("user") or row.get("username")):
        ent["user"] = str(user).strip()
    return {k: v for k, v in ent.items() if v and v.lower() not in ("none", "nan", "-")}


def _rows(archive: zipfile.ZipFile, member: str):
    """Yield dict rows from a member, whichever of the shipped formats it uses."""
    raw = archive.read(member)
    if member.endswith(".json"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:                      # JSON-lines
            for line in io.BytesIO(raw):
                line = line.strip()
                if line:
                    yield json.loads(line)
            return
        yield from (data if isinstance(data, list) else [data])
    elif member.endswith(".csv"):
        yield from csv.DictReader(io.StringIO(raw.decode("utf-8", "replace")))


def members_for(archive: zipfile.ZipFile, scenario: str) -> list[str]:
    return [n for n in archive.namelist()
            if scenario in n and n.endswith((".json", ".csv")) and not n.endswith("/")]


def scenarios(path: Path = DEFAULT_ARCHIVE) -> list[str]:
    return sorted(load_labels().keys())


def load(scenario: str = "russellmitchell", *, path: Path = DEFAULT_ARCHIVE,
         labels: Path = DEFAULT_LABELS, limit: int | None = None) -> list[Alert]:
    """Load one scenario's alerts, labelled from the published attack windows."""
    windows = load_labels(labels).get(scenario)
    if not windows:
        raise ValueError(f"no published attack windows for scenario {scenario!r}")

    alerts: list[Alert] = []
    with zipfile.ZipFile(path) as archive:
        found = members_for(archive, scenario)
        if not found:
            raise FileNotFoundError(
                f"nothing for scenario {scenario!r} inside {path}; "
                f"archive holds {len(archive.namelist())} members"
            )
        n = 0
        for member in found:
            for row in _rows(archive, member):
                ts = row.get("time") or row.get("timestamp") or row.get("ts")
                name = str(row.get("name") or row.get("rule") or "alert")
                if ts is None:
                    continue
                ts = float(ts)
                n += 1
                alerts.append(Alert(
                    id=f"ait-{scenario}-{n:06d}",
                    ts=int(ts),
                    sensor=_sensor_of(name),
                    rule_id=str(row.get("short") or row.get("rule_id") or name)[:64],
                    rule_name=name,
                    severity=int(float(row.get("severity") or 40)),
                    entities=_entities(row),
                    stage=_stage_at(windows, ts),
                ))
                if limit and n >= limit:
                    break
            if limit and n >= limit:
                break
    return sorted(alerts, key=lambda a: (a.ts, a.id))
