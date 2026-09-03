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
from datetime import datetime
from pathlib import Path

from ..schema import Alert

#: Wazuh relays Suricata's eve.json, so a Suricata finding arrives wearing Wazuh's envelope.
#: These keys identify the passenger. Attributing such an alert to Wazuh would credit the
#: relay with an observation it never made -- the same tool-echo mistake the provenance
#: engine exists to refuse -- so the sensor is the detector that actually saw it.
SURICATA_KEYS = ("event_type", "flow_id", "app_proto")

DEFAULT_ARCHIVE = Path("data/raw/ait_ads.zip")
DEFAULT_LABELS = Path("data/raw/labels.csv")

#: Wazuh rule levels run 0-15; our severity is 0-100.
WAZUH_LEVEL_SCALE = 100 / 15

_SYSLOG_HOST = re.compile(r"^\w{3}\s+\d+\s[\d:]+\s+(\S+)\s")
_IPISH = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


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


def _stage_at(windows: list[Window], starts: list[float], ts: float) -> str:
    """Which attack stage was running at `ts`, or "" for background activity."""
    i = bisect.bisect_right(starts, ts) - 1
    if i < 0:
        return ""
    w = windows[i]
    return w.attack if w.start <= ts <= w.end else ""


def _clean(value) -> str:
    text = str(value).strip() if value is not None else ""
    return "" if text.lower() in ("", "none", "nan", "-", "null") else text


def _parse_wazuh(row: dict) -> dict | None:
    stamp = row.get("@timestamp")
    if not stamp:
        return None
    ts = int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())
    rule = row.get("rule") or {}
    data = row.get("data") or {}
    pre = row.get("predecoder") or {}
    agent = row.get("agent") or {}

    sensor = "suricata" if any(k in data for k in SURICATA_KEYS) else "wazuh"
    entities = {
        "host": _clean(pre.get("hostname") or agent.get("name")),
        "src_ip": _clean(data.get("srcip") or data.get("src_ip") or agent.get("ip")),
        "dst_ip": _clean(data.get("dstip") or data.get("dest_ip")),
        "user": _clean(data.get("srcuser") or data.get("dstuser") or data.get("user")),
    }
    return {
        "ts": ts,
        "sensor": sensor,
        "rule_id": _clean(rule.get("id")) or "wazuh",
        "rule_name": _clean(rule.get("description")) or "Wazuh alert",
        "severity": int(min(100, float(rule.get("level") or 3) * WAZUH_LEVEL_SCALE)),
        "entities": {k: v for k, v in entities.items() if v},
    }


def _parse_aminer(row: dict) -> dict | None:
    log = row.get("LogData") or {}
    stamps = log.get("Timestamps") or log.get("DetectionTimestamp") or []
    if not stamps:
        return None
    ts = int(float(stamps[0]))
    comp = row.get("AnalysisComponent") or {}
    name = _clean(comp.get("AnalysisComponentName")) or "AMiner alert"

    entities: dict[str, str] = {}
    raw = (log.get("RawLogData") or [""])[0]
    if (host := _SYSLOG_HOST.match(str(raw))):
        entities["host"] = host.group(1)
    ident = _clean((row.get("AMiner") or {}).get("ID"))
    if ident and _IPISH.match(ident):
        entities["src_ip"] = ident
    return {
        "ts": ts,
        "sensor": "aminer",
        "rule_id": _clean(comp.get("AnalysisComponentType")) or "aminer",
        "rule_name": name.replace("AMiner: ", ""),
        "severity": 35,
        "entities": entities,
    }


PARSERS = {"wazuh": _parse_wazuh, "aminer": _parse_aminer}


def scenarios(labels: Path = DEFAULT_LABELS) -> list[str]:
    return sorted(load_labels(labels))


def load(scenario: str = "russellmitchell", *, path: Path = DEFAULT_ARCHIVE,
         labels: Path = DEFAULT_LABELS, limit: int | None = None,
         detectors: tuple[str, ...] = ("aminer", "wazuh")) -> list[Alert]:
    """Load one scenario's alerts, labelled from the published attack windows."""
    windows = load_labels(labels).get(scenario)
    if not windows:
        raise ValueError(f"no published attack windows for scenario {scenario!r}")
    starts = [w.start for w in windows]

    alerts: list[Alert] = []
    n = 0
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        for detector in detectors:
            member = f"{scenario}_{detector}.json"
            if member not in names:
                raise FileNotFoundError(
                    f"{member} is not in {path}; it holds {sorted(names)}")
            parse = PARSERS[detector]
            with archive.open(member) as fh:
                for raw in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        row = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    parsed = parse(row)
                    if parsed is None:
                        continue
                    n += 1
                    alerts.append(Alert(
                        id=f"ait-{scenario}-{n:07d}",
                        stage=_stage_at(windows, starts, parsed["ts"]),
                        **parsed,
                    ))
                    if limit and n >= limit:
                        break
            if limit and n >= limit:
                break
    return sorted(alerts, key=lambda a: (a.ts, a.id))
