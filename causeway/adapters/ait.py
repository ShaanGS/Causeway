"""The public corpus: AIT Alert Data Set.

Zenodo doi 10.5281/zenodo.8263181, CC-BY-4.0, released with Landauer, Skopik and
Wurzenberger, *Introducing a New Alert Data Set for Multi-Step Attack Analysis*, CSET '24.

Chosen over raw-telemetry corpora for one practical reason and one honest one. Practical:
it ships **alerts**, not logs, so nothing here has to become a parsing pipeline for Windows
event XML. Honest: three independent detectors -- AMiner, Wazuh and Suricata -- disagree
about what to call the same host and address, so the PS's "entity context is fragmented
across products" is a property of the data rather than something the lab generator stages
on purpose. Eight scenarios each run the same ten-stage attack under different background
noise.

Ground truth comes from `labels.csv`, which gives `(scenario, attack, start, end)` as epoch
windows. An alert is labelled with whichever attack window contains its timestamp, and left
unlabelled otherwise -- that unlabelled majority is the benign traffic, and it is what makes
precision mean anything. The dataset publishes no root-cause entity, so `Scenario.root_ref`
is empty and the harness reports that row as not gradable.

Three things the raw rows do that an adapter has to undo, each found by reading the data:

- **Suricata arrives twice, wearing Wazuh's envelope both times.** Wazuh relays Suricata's
  `eve.json` (rows carrying ``flow_id`` and friends) *and* its ``fast.log`` (rows decoded
  as ``snort``). Both are attributed here to Suricata with the signature id as the rule,
  so the same finding relayed twice is a duplicate the ledger can prove, and the relay is
  not credited with an observation it never made -- the tool-echo mistake the provenance
  engine exists to refuse.
- **Every agent is called ``wazuh-client``.** Taking the agent name as the host would fold
  every machine on the range into one entity, so the host comes from the syslog header
  only, and an alert with no header names no host.
- **Addresses carry ports** (``91.189.95.85:80``). The port is dropped; an address entity
  is the address.

One wrinkle in the published labels: in the `fox` scenario the final two stages
(`service_stop`, `dnsteal`) are timestamped a day *before* the other eight, so its chain
does not run forward in wall-clock time. `russellmitchell` is coherent, so it is the
default. Nothing is silently repaired; a scenario is used as published or not used.
"""

from __future__ import annotations

import bisect
import csv
import io
import json
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..corpus import Scenario
from ..schema import Alert

DEFAULT_ARCHIVE = Path("data/raw/ait_ads.zip")
DEFAULT_LABELS = Path("data/raw/labels.csv")
DEFAULT_SCENARIO = "russellmitchell"

#: Keys that identify a Suricata `eve.json` record travelling inside a Wazuh row.
SURICATA_KEYS = ("event_type", "flow_id", "app_proto")

#: Agent names that are a deployment default rather than a machine.
GENERIC_AGENT_NAMES = frozenset({"wazuh-client", "wazuh-agent", "agent"})

#: Wazuh rule levels run 0-15; our severity is 0-100.
WAZUH_LEVEL_SCALE = 100 / 15

#: Suricata alert severity is 1 (high) to 3 (low).
SURICATA_SEVERITY = {"1": 80, "2": 55, "3": 30}

_SYSLOG_HOST = re.compile(r"^\w{3}\s+\d+\s[\d:]+\s+(\S+)\s")
_IPISH = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IP_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")
_SNORT_SID = re.compile(r"^\d+:(\d+):\d+$")


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


def stage_at(windows: list[Window], ts: float) -> str:
    """Which attack stage was running at `ts`, or "" for background activity."""
    starts = [w.start for w in windows]
    i = bisect.bisect_right(starts, ts) - 1
    if i < 0:
        return ""
    w = windows[i]
    return w.attack if w.start <= ts <= w.end else ""


# -- field cleaning -----------------------------------------------------------------

def _clean(value: object) -> str:
    text = str(value).strip() if value is not None else ""
    return "" if text.lower() in ("", "none", "nan", "-", "null") else text


def _address(value: object) -> str:
    """An address without its port. ``91.189.95.85:80`` is the host ``91.189.95.85``."""
    text = _clean(value)
    m = _IP_PORT.match(text)
    return m.group(1) if m else text


def _host(value: object) -> str:
    text = _clean(value)
    return "" if text.lower() in GENERIC_AGENT_NAMES else text


def _entities(**slots: str) -> dict[str, str]:
    return {k: v for k, v in slots.items() if v}


# -- per-product parsers ----------------------------------------------------------

def _parse_wazuh(row: dict) -> dict | None:
    """One Wazuh row, which may be Wazuh's own finding or a relayed Suricata one."""
    stamp = row.get("@timestamp")
    if not stamp:
        return None
    ts = int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())
    rule = row.get("rule") or {}
    data = row.get("data") or {}
    pre = row.get("predecoder") or {}
    decoder = row.get("decoder") or {}
    level_severity = int(min(100, float(rule.get("level") or 3) * WAZUH_LEVEL_SCALE))
    host = _host(pre.get("hostname"))

    if any(k in data for k in SURICATA_KEYS):
        # eve.json relayed: the richest form, with the signature and its own severity.
        alert = data.get("alert") or {}
        return {
            "ts": ts,
            "sensor": "suricata",
            "rule_id": _clean(alert.get("signature_id")) or "suricata",
            "rule_name": _clean(alert.get("signature")) or "Suricata alert",
            "severity": SURICATA_SEVERITY.get(_clean(alert.get("severity")), level_severity),
            "entities": _entities(
                host=host,
                src_ip=_address(data.get("src_ip")),
                dst_ip=_address(data.get("dest_ip")),
            ),
        }

    if _clean(decoder.get("name")) == "snort" and (sid := _SNORT_SID.match(_clean(data.get("id")))):
        # fast.log relayed: same finding, thinner record. Same sensor, same signature id,
        # so the ledger can prove it is the eve.json row's duplicate.
        return {
            "ts": ts,
            "sensor": "suricata",
            "rule_id": sid.group(1),
            "rule_name": _clean(rule.get("description")) or "Suricata alert",
            "severity": level_severity,
            "entities": _entities(
                host=host,
                src_ip=_address(data.get("srcip")),
                dst_ip=_address(data.get("dstip")),
            ),
        }

    return {
        "ts": ts,
        "sensor": "wazuh",
        "rule_id": _clean(rule.get("id")) or "wazuh",
        "rule_name": _clean(rule.get("description")) or "Wazuh alert",
        "severity": level_severity,
        "entities": _entities(
            host=host,
            src_ip=_address(data.get("srcip")),
            dst_ip=_address(data.get("dstip")),
            user=_clean(data.get("srcuser") or data.get("dstuser") or data.get("user")),
        ),
    }


def _parse_aminer(row: dict) -> dict | None:
    log = row.get("LogData") or {}
    stamps = log.get("Timestamps") or log.get("DetectionTimestamp") or []
    if not stamps:
        return None
    ts = int(float(stamps[0]))
    comp = row.get("AnalysisComponent") or {}
    name = _clean(comp.get("AnalysisComponentName")) or "AMiner alert"

    raw = (log.get("RawLogData") or [""])[0]
    header = _SYSLOG_HOST.match(str(raw))
    ident = _clean((row.get("AMiner") or {}).get("ID"))
    return {
        "ts": ts,
        "sensor": "aminer",
        "rule_id": _clean(comp.get("AnalysisComponentType")) or "aminer",
        "rule_name": name.replace("AMiner: ", ""),
        "severity": 35,
        "entities": _entities(
            host=header.group(1) if header else "",
            src_ip=ident if _IPISH.match(ident) else "",
        ),
    }


PARSERS: dict[str, Callable[[dict], dict | None]] = {
    "wazuh": _parse_wazuh,
    "aminer": _parse_aminer,
}


# -- loading ----------------------------------------------------------------------------

def scenarios(labels: Path = DEFAULT_LABELS) -> list[str]:
    return sorted(load_labels(labels))


def parse_lines(lines: io.TextIOBase | list[str], detector: str, *, scenario: str,
                windows: list[Window], start_at: int = 0,
                limit: int | None = None) -> list[Alert]:
    """Parse one detector's JSON-lines stream into labelled alerts."""
    parse = PARSERS[detector]
    alerts: list[Alert] = []
    n = start_at
    for raw in lines:
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
            stage=stage_at(windows, parsed["ts"]),
            **parsed,
        ))
        if limit and len(alerts) >= limit:
            break
    return alerts


def load(scenario: str = DEFAULT_SCENARIO, *, path: Path = DEFAULT_ARCHIVE,
         labels: Path = DEFAULT_LABELS, limit: int | None = None,
         detectors: tuple[str, ...] = ("aminer", "wazuh")) -> Scenario:
    """Load one scenario's alerts, labelled from the published attack windows."""
    windows = load_labels(labels).get(scenario)
    if not windows:
        raise ValueError(f"no published attack windows for scenario {scenario!r}")
    if not path.exists():
        raise FileNotFoundError(
            f"{path} is missing. Download the AIT Alert Data Set from "
            f"https://zenodo.org/records/8263181 and place the archive there.")

    alerts: list[Alert] = []
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        for detector in detectors:
            member = f"{scenario}_{detector}.json"
            if member not in names:
                raise FileNotFoundError(f"{member} is not in {path}; it holds {sorted(names)}")
            with archive.open(member) as fh:
                text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace")
                alerts.extend(parse_lines(text, detector, scenario=scenario, windows=windows,
                                          start_at=len(alerts), limit=limit))
            if limit and len(alerts) >= limit:
                break

    alerts.sort(key=lambda a: (a.ts, a.id))
    return Scenario(
        name=f"ait-{scenario}",
        alerts=alerts,
        truth={a.id: a.stage for a in alerts if a.stage},
    )
