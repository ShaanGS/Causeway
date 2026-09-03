"""Resolving the same thing to the same name, and saying how much its word is worth.

Two jobs, both prerequisites for correlation:

**Resolution.** `CORP\\j.okafor`, `j.okafor@corp.local` and `S-1-5-21-1004-1104` are one
person. Until they spell the same, no correlator can join on them, and the PS's "entity
context is fragmented" stays true no matter how clever the graph is.

**Weight.** An entity becomes an `Origin`, which is the engine's existing unit of lineage,
so every alert derived from it inherits it and `blast_radius()` can later ask what stands on
it. Trust here is *evidentiary weight*, not authority-to-act: how much this observation is
worth as grounds for doing something disruptive.

Weight belongs to the **sensor that reported the entity**, not to the kind of entity it is.
An early version keyed it on kind -- addresses were inherently weak -- which capped every
incident that mentioned an IP at the lowest rung and made most of the response ladder
unreachable. That was wrong on the merits as well as unhelpful: an address logged by a
first-party agent on a managed endpoint is exactly as reliable as that agent. What is weak
is an address a reputation *feed* asserted something about. So an entity carries the trust
of whoever reported it, the same entity seen by two sensors carries both, and `min()` over
the lineage does the rest -- which is how an incident resting partly on an unverified feed
ends up unable to isolate a production server on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ventriloquist.provenance import Origin, OriginKind, TrustLevel

from .schema import Alert

#: Evidentiary weight per product. A first-party agent on a managed endpoint reports facts
#: it observed directly. A network IDS and an unsupervised anomaly detector report
#: inferences. A reputation feed reports someone else's assertion.
SENSOR_TRUST: dict[str, TrustLevel] = {
    "edr": TrustLevel.TOOL_VERIFIED,
    "wazuh": TrustLevel.TOOL_VERIFIED,
    "identity": TrustLevel.TOOL_VERIFIED,
    "suricata": TrustLevel.THIRD_PARTY,
    "aminer": TrustLevel.THIRD_PARTY,
    "threat_intel": TrustLevel.UNTRUSTED,
    "email_sec": TrustLevel.THIRD_PARTY,
}
DEFAULT_SENSOR_TRUST = TrustLevel.THIRD_PARTY

#: The trust lattice said in SOC words. The engine's own labels are written for the
#: agent-memory product ("User said"); a jury reading an incident screen needs to be told
#: what the level means as *evidence*. Same levels, same ordering, different audience.
EVIDENCE_LABELS: dict[str, str] = {
    "UNTRUSTED": "Unverified claim",
    "THIRD_PARTY": "Single sensor",
    "TOOL_VERIFIED": "Corroborated telemetry",
    "USER": "Analyst confirmed",
    "USER_VERIFIED": "Analyst approved",
    "SYSTEM": "Operator policy",
}


def evidence_label(trust: TrustLevel) -> str:
    return EVIDENCE_LABELS[trust.name]


_SID = re.compile(r"^S-1-5-21-[\d-]+-(\d{3,})$")
_DOMAIN_PREFIX = re.compile(r"^[A-Za-z0-9_-]+\\+(.+)$")


@dataclass
class EntityResolver:
    """Folds the aliases of one thing onto one canonical name.

    ``sid_map`` is what an identity platform would supply. It is held as data rather than
    inferred so the console can show a jury exactly which aliases were folded together --
    silent entity resolution is indistinguishable from a lucky guess.
    """

    domain_suffixes: tuple[str, ...] = ("corp.local", "corp")
    sid_map: dict[str, str] = field(default_factory=dict)
    #: canonical name -> every raw spelling that resolved to it, for display
    seen_aliases: dict[str, set[str]] = field(default_factory=dict)

    def _record(self, canonical: str, raw: str) -> str:
        if canonical != raw:
            self.seen_aliases.setdefault(canonical, set()).add(raw)
        return canonical

    def user(self, raw: str) -> str:
        value = raw.strip()
        sid = _SID.match(value)
        if sid:
            mapped = self.sid_map.get(value)
            if mapped:
                return self._record(self.user(mapped), value)
        stripped = _DOMAIN_PREFIX.sub(r"\1", value)
        if "@" in stripped:
            local, _, domain = stripped.partition("@")
            if domain.lower() in self.domain_suffixes:
                stripped = local
        return self._record(stripped.lower(), raw)

    def host(self, raw: str) -> str:
        value = raw.strip().lower()
        for suffix in self.domain_suffixes:
            if value.endswith("." + suffix):
                value = value[: -(len(suffix) + 1)]
                break
        return self._record(value, raw)

    def address(self, raw: str) -> str:
        return raw.strip()

    # -- alerts to origins -------------------------------------------------------

    def sensor_origin(self, alert: Alert) -> Origin:
        trust = SENSOR_TRUST.get(alert.sensor, DEFAULT_SENSOR_TRUST)
        return Origin.of(OriginKind.SENSOR, alert.sensor, trust=trust,
                         label=f"{alert.sensor} sensor")

    def entity_origins(self, alert: Alert) -> list[Origin]:
        """Every entity this alert names, canonicalised, as lineage origins.

        A process is scoped to its host: pid 7101 means nothing on its own, and joining two
        machines on a coincidental pid is exactly the kind of false correlation that makes
        an analyst stop trusting the tool.
        """
        out: list[Origin] = []
        host = alert.entity("host")
        canon_host = self.host(host) if host else None
        # Every entity in this alert is worth what the product that reported it is worth.
        weight = SENSOR_TRUST.get(alert.sensor, DEFAULT_SENSOR_TRUST)
        src = alert.sensor

        def make(kind: OriginKind, locator: str, label: str) -> Origin:
            return Origin.of(kind, locator, trust=weight, label=f"{label} (via {src})")

        if canon_host:
            out.append(make(OriginKind.HOST, canon_host, f"host {canon_host}"))
        if (user := alert.entity("user")):
            canon = self.user(user)
            out.append(make(OriginKind.ACCOUNT, canon, f"account {canon}"))
        for slot in ("src_ip", "dst_ip"):
            if (ip := alert.entity(slot)):
                canon = self.address(ip)
                out.append(make(OriginKind.ADDRESS, canon, f"address {canon}"))
        # A process is identified by its pid where the sensor supplied one, and by its image
        # name otherwise. Both forms are scoped to the host: pid 7101 means nothing on its
        # own, and joining two machines on a coincidental pid is exactly the kind of false
        # correlation that makes an analyst stop trusting the tool.
        image = alert.entity("process")
        if canon_host and (pid := alert.entity("pid")):
            out.append(make(OriginKind.PROCESS, f"{canon_host}/pid:{pid}",
                            f"process {image or pid} on {canon_host}"))
        elif canon_host and image:
            out.append(make(OriginKind.PROCESS, f"{canon_host}/img:{image.lower()}",
                            f"process {image} on {canon_host}"))

        # Files and hashes are entities in their own right. Leaving them out would let two
        # alerts about two different archived files look like one repeated alert, which is
        # the precise failure `dedup.py` exists to refuse.
        if (path := alert.entity("file")):
            out.append(make(OriginKind.ARTIFACT, f"file:{path.lower()}", f"file {path}"))
        if (h := alert.entity("hash")):
            out.append(make(OriginKind.ARTIFACT, f"hash:{h}", f"file hash {h[:12]}"))
        return out

    def origins_of(self, alert: Alert) -> list[Origin]:
        """Sensor plus entities. This is the alert's complete lineage footprint."""
        return [self.sensor_origin(alert), *self.entity_origins(alert)]

    def alias_report(self) -> list[dict]:
        return sorted(
            ({"canonical": k, "aliases": sorted(v)} for k, v in self.seen_aliases.items()),
            key=lambda r: r["canonical"],
        )
