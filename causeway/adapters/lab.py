"""A lab range that emits what three products would emit, with the answer key attached.

Every metric in `metrics.py` needs ground truth, and ground truth is the one thing real
telemetry rarely ships with. So the chain is generated from a known attack graph: nine
stages, each stage knowing which alerts belong to it and which alert is genuinely its
parent. The public corpus in `ait.py` is the credibility leg; this is the measurement leg,
and it is also the fallback if a venue network cannot reach Zenodo.

Three properties are deliberate, and each one exists to make a specific claim falsifiable:

1. **Benign activity fires the attack's own rules.** IT automation creates scheduled tasks;
   the backup job moves gigabytes at night; the vulnerability scanner ports-scans everything
   every Sunday. This is the PS's "ordinary administrative activity triggers the same rules"
   and it is why rule-name matching cannot be the correlator.

2. **There are real duplicates.** A sensor re-fires the same rule on the same entities
   inside a few seconds, dozens of times. Suppressing those is correct, and a system that
   compresses nothing is no use.

3. **There are near-duplicates that are not duplicates.** The attacker's scheduled task and
   the IT automation's scheduled task read identically in the queue. Merging them erases the
   persistence stage. That single pair is what the false-suppression metric is built to
   catch, and it is why `dedup.py` refuses to look at text.

Deterministic: same seed, same corpus, byte for byte.
"""

from __future__ import annotations

import random

from ..corpus import Scenario
from ..schema import Alert

#: Ordered attack stages. The index is the ground-truth ordering used by root-cause scoring
#: *for measurement only* -- no correlation rule may read `Alert.stage`.
STAGES: tuple[str, ...] = (
    "recon",
    "password_spray",
    "initial_access",
    "discovery",
    "cred_access",
    "lateral_move",
    "persistence",
    "collection",
    "exfil",
)

#: The stage a correct root-cause answer must name. Not the loudest alert and not the
#: earliest alert -- the earliest one at which the attacker acquired standing we could
#: revoke. Nothing in the pipeline is told this; `metrics.py` only grades against it.
GROUND_TRUTH_ROOT = "initial_access"

#: The entity a correct root-cause answer must name: the account whose successful login
#: is the first thing the organisation could have revoked. `EntityResolver` canonicalises
#: `CORP\\j.okafor` to this.
GROUND_TRUTH_ROOT_REF = "account:j.okafor"

ATTACKER_IP = "203.0.113.47"
EXFIL_IP = "198.51.100.22"
VICTIM_USER = "CORP\\j.okafor"
VICTIM_HOST = "WIN-WS-041"
SECOND_HOST = "WIN-FS-002"

BENIGN_USERS = ["CORP\\a.mensah", "CORP\\l.tanaka", "CORP\\r.silva",
                "CORP\\d.novak", "CORP\\p.iyer", "CORP\\m.haddad"]
BENIGN_HOSTS = ["WIN-WS-012", "WIN-WS-027", "WIN-WS-033", "WIN-FS-001", "WIN-DC-001"]

T0 = 1764547200  # 2025-12-01 00:00:00 UTC -- the quiet part of a Sunday night


class _Emitter:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.alerts: list[Alert] = []
        self.truth: dict[str, str] = {}
        self.parents: dict[str, str] = {}
        self.duplicates: set[str] = set()
        self._n = 0

    def emit(self, ts, sensor, rule_id, rule_name, severity, entities,
             *, stage="", parent=None, duplicate_of=None) -> Alert:
        self._n += 1
        alert = Alert(
            id=f"alert-{self._n:05d}",
            ts=int(ts),
            sensor=sensor,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            entities={k: v for k, v in entities.items() if v},
            stage=stage,
        )
        self.alerts.append(alert)
        if stage:
            self.truth[alert.id] = stage
        if parent:
            self.parents[alert.id] = parent
        if duplicate_of:
            self.duplicates.add(alert.id)
            self.parents.setdefault(alert.id, duplicate_of)
        return alert

    def repeat(self, alert: Alert, times: int, *, spread: int = 90) -> None:
        """Re-fire the same rule on the same entities. These are provable duplicates."""
        for _ in range(times):
            self.emit(
                alert.ts + self.rng.randint(1, spread),
                alert.sensor, alert.rule_id, alert.rule_name, alert.severity,
                dict(alert.entities), stage=alert.stage, duplicate_of=alert.id,
            )


def _background(em: _Emitter, hours: int = 24) -> None:
    """The ordinary Sunday that the attack happens inside of."""
    rng = em.rng

    # Routine failed logins -- people mistype passwords. Same rule as the spray.
    for _ in range(140):
        em.emit(T0 + rng.randint(0, hours * 3600), "wazuh", "5710",
                "Authentication failure", 30,
                {"user": rng.choice(BENIGN_USERS), "host": rng.choice(BENIGN_HOSTS),
                 "src_ip": f"10.20.{rng.randint(1, 8)}.{rng.randint(2, 250)}"})

    # Successful logins all day. Same rule as the attacker's initial access.
    for _ in range(220):
        em.emit(T0 + rng.randint(0, hours * 3600), "wazuh", "5715",
                "Successful remote login", 15,
                {"user": rng.choice(BENIGN_USERS), "host": rng.choice(BENIGN_HOSTS),
                 "src_ip": f"10.20.{rng.randint(1, 8)}.{rng.randint(2, 250)}"})

    # IT automation creates scheduled tasks. Same rule as the attacker's persistence --
    # this is the pair that punishes text-similarity dedup.
    for i in range(24):
        em.emit(T0 + 3600 * i + rng.randint(0, 600), "edr", "T1053",
                "Scheduled task created", 45,
                {"user": "CORP\\svc.deploy", "host": rng.choice(BENIGN_HOSTS),
                 "process": "schtasks.exe", "pid": str(rng.randint(2000, 9000))})

    # Nightly backup. Same rule as exfiltration.
    for _ in range(30):
        em.emit(T0 + rng.randint(2 * 3600, 5 * 3600), "suricata", "2013028",
                "Large outbound data transfer", 35,
                {"host": rng.choice(BENIGN_HOSTS), "dst_ip": "10.30.0.9",
                 "src_ip": f"10.20.{rng.randint(1, 8)}.{rng.randint(2, 250)}"})

    # The weekly authenticated vulnerability scan. Same rule as the attacker's recon.
    for _ in range(90):
        em.emit(T0 + rng.randint(6 * 3600, 7 * 3600), "suricata", "2010935",
                "Port scan detected", 25,
                {"src_ip": "10.20.0.5",
                 "dst_ip": f"10.20.{rng.randint(1, 8)}.{rng.randint(2, 250)}"})

    # Assorted low-grade noise from all three products.
    noise = [
        ("aminer", "AM-104", "New process name observed", 20,
         lambda: {"host": rng.choice(BENIGN_HOSTS), "process": rng.choice(
             ["chrome.exe", "teams.exe", "outlook.exe", "python.exe", "code.exe"])}),
        ("wazuh", "5501", "Session opened", 10,
         lambda: {"user": rng.choice(BENIGN_USERS), "host": rng.choice(BENIGN_HOSTS)}),
        ("suricata", "2100498", "TLS certificate anomaly", 20,
         lambda: {"src_ip": f"10.20.{rng.randint(1, 8)}.{rng.randint(2, 250)}",
                  "dst_ip": f"104.18.{rng.randint(1, 60)}.{rng.randint(1, 250)}"}),
        ("aminer", "AM-221", "Unusual command line length", 30,
         lambda: {"host": rng.choice(BENIGN_HOSTS), "process": "powershell.exe",
                  "pid": str(rng.randint(2000, 9000))}),
    ]
    for _ in range(320):
        sensor, rid, name, sev, gen = rng.choice(noise)
        em.emit(T0 + rng.randint(0, hours * 3600), sensor, rid, name, sev, gen())


def _attack(em: _Emitter) -> str:
    """The nine stages. Returns the id of the alert that is the true root cause."""
    t = T0 + 22 * 3600  # 22:00 -- starts while the queue is already deep

    # 1. Recon. Same rule as the vulnerability scanner, different source address.
    recon = em.emit(t, "suricata", "2010935", "Port scan detected", 25,
                    {"src_ip": ATTACKER_IP, "dst_ip": "10.20.4.10"}, stage="recon")
    em.repeat(recon, 34, spread=400)

    # 2. Password spray -- many users, one source. Same rule as a mistyped password.
    t += 1800
    spray: list[Alert] = []
    for i, user in enumerate(BENIGN_USERS + [VICTIM_USER]):
        a = em.emit(t + i * 7, "wazuh", "5710", "Authentication failure", 30,
                    {"user": user, "host": "VPN-GW-01", "src_ip": ATTACKER_IP},
                    stage="password_spray", parent=recon.id)
        spray.append(a)
        em.repeat(a, 5, spread=40)
    spray_first = spray[0]

    # 3. Initial access -- the spray lands. This is the root cause: the first moment the
    #    attacker holds something we could take away.
    t += 900
    access = em.emit(t, "wazuh", "5715", "Successful remote login", 15,
                     {"user": VICTIM_USER, "host": VICTIM_HOST, "src_ip": ATTACKER_IP},
                     stage="initial_access", parent=spray_first.id)

    # 3b. The session's shell. A real EDR reports process creation, and without this the
    #     parent pid that stages 4 and 5 name would refer to something nothing ever saw --
    #     which is precisely how process-ancestry correlation dies in practice.
    t += 45
    shell_pid = "6612"
    shell = em.emit(t, "edr", "T1059", "Remote interactive shell started", 50,
                    {"user": VICTIM_USER, "host": VICTIM_HOST, "process": "powershell.exe",
                     "pid": shell_pid, "ppid": "6600"},
                    stage="initial_access", parent=access.id)

    # 4. Discovery, parented by the logon session's shell.
    t += 240
    for i, cmd in enumerate(["whoami.exe", "net.exe", "nltest.exe", "systeminfo.exe"]):
        d = em.emit(t + i * 30, "edr", "T1087", "Discovery command executed", 40,
                    {"user": VICTIM_USER, "host": VICTIM_HOST, "process": cmd,
                     "pid": str(7000 + i), "ppid": shell_pid},
                    stage="discovery", parent=shell.id)
        em.repeat(d, 2, spread=15)

    # 5. Credential access.
    t += 600
    creds = em.emit(t, "edr", "T1003", "Credential material accessed from LSASS", 85,
                    {"user": VICTIM_USER, "host": VICTIM_HOST, "process": "rundll32.exe",
                     "pid": "7101", "ppid": shell_pid},
                    stage="cred_access", parent=shell.id)
    em.repeat(creds, 3, spread=25)

    # 6. Lateral movement -- same identity, second host.
    t += 900
    lateral = em.emit(t, "wazuh", "5715", "Successful remote login", 15,
                      {"user": VICTIM_USER, "host": SECOND_HOST, "src_ip": "10.20.4.10"},
                      stage="lateral_move", parent=creds.id)

    # 6b. The shell on the second host, for the same reason as 3b.
    t += 60
    second_shell = em.emit(t, "edr", "T1059", "Remote interactive shell started", 50,
                           {"user": VICTIM_USER, "host": SECOND_HOST,
                            "process": "powershell.exe", "pid": "8100", "ppid": "8000"},
                           stage="lateral_move", parent=lateral.id)

    # 7. Persistence -- reads exactly like the IT automation's scheduled task.
    t += 300
    persist = em.emit(t, "edr", "T1053", "Scheduled task created", 45,
                      {"user": VICTIM_USER, "host": SECOND_HOST,
                       "process": "schtasks.exe", "pid": "8140", "ppid": "8100"},
                      stage="persistence", parent=second_shell.id)
    em.repeat(persist, 2, spread=20)

    # 8. Collection.
    t += 1200
    for i in range(6):
        em.emit(t + i * 45, "edr", "T1560", "Archive created from many files", 55,
                {"user": VICTIM_USER, "host": SECOND_HOST, "process": "7z.exe",
                 "pid": "8221", "ppid": "8100",
                 "file": f"C:\\Users\\Public\\stage\\part{i}.7z"},
                stage="collection", parent=persist.id)

    # 9. Exfiltration -- reads exactly like the nightly backup.
    t += 900
    exfil = em.emit(t, "suricata", "2013028", "Large outbound data transfer", 35,
                    {"host": SECOND_HOST, "src_ip": "10.20.4.22", "dst_ip": EXFIL_IP},
                    stage="exfil", parent=persist.id)
    em.repeat(exfil, 7, spread=120)

    return access.id


def generate(seed: int = 7) -> Scenario:
    """Build the corpus. Deterministic in `seed`."""
    em = _Emitter(random.Random(seed))
    _background(em)
    _attack(em)
    em.alerts.sort(key=lambda a: (a.ts, a.id))
    return Scenario(
        name="lab",
        alerts=em.alerts,
        truth=em.truth,
        root_ref=GROUND_TRUTH_ROOT_REF,
        parents=em.parents,
        duplicates=em.duplicates,
    )
