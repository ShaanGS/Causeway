"""Provenance primitives: where a belief came from, and how much authority that origin carries.

This module is deliberately free of policy. It answers "where did this come from?"
It never answers "is that allowed?" -- that is `policy.py`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Iterable


class TrustLevel(IntEnum):
    """Ordered trust lattice. Comparison and ``min()`` are meaningful and load-bearing.

    The ordering is the whole point: when content is derived from several sources, the
    result can never be more trusted than its least trusted input. See `taint.py`.
    """

    UNTRUSTED = 0      # arbitrary web content, inbound email body, external ticket text
    THIRD_PARTY = 1    # an identified but unvouched external system
    TOOL_VERIFIED = 2  # output of a first-party tool we operate and trust
    USER = 3           # the principal said it, in session
    USER_VERIFIED = 4  # the principal confirmed it out-of-band (2FA, signed approval)
    SYSTEM = 5         # operator configuration; the root of trust

    @property
    def label(self) -> str:
        """Human-readable name. Matches the console's labels exactly -- a gateway that
        explains a refusal in one vocabulary while the screen shows another is a demo
        arguing with itself."""
        return TRUST_LABELS[self.name]


#: The only place trust levels are spoken to a person. Kept in lockstep with
#: ``console/src/lib/api.ts``; each name answers the same question -- who said this?
TRUST_LABELS: dict[str, str] = {
    "UNTRUSTED": "Untrusted",
    "THIRD_PARTY": "Third party",
    "TOOL_VERIFIED": "Our tools",
    "USER": "User said",
    "USER_VERIFIED": "User confirmed",
    "SYSTEM": "Operator",
}


class OriginKind(IntEnum):
    """How content entered the system. Distinct from trust: kind is factual, trust is assigned."""

    WEB = 0
    EMAIL = 1
    TICKET = 2
    DOCUMENT = 3
    TOOL = 4
    USER = 5
    SYSTEM = 6
    AGENT = 7  # the model itself produced this text

    # -- security-operations kinds -------------------------------------------------
    # Added for `ventriloquist.soc`. Values continue the sequence so nothing existing
    # shifts, and every consumer keys on `.name`, never on the integer.
    SENSOR = 8    # a detection product: EDR, IDS, identity platform, mail gateway
    HOST = 9      # a machine under management
    ACCOUNT = 10  # an identity, however many names it wears across products
    ADDRESS = 11  # an IP address -- attacker-controllable, so never strong evidence alone
    PROCESS = 12  # a running process, scoped to its host
    ARTIFACT = 13 # a file or content hash


#: Default trust assigned to each origin kind before any policy override.
#:
#: AGENT is deliberately TOOL_VERIFIED. Every mainstream memory layer treats its own agent
#: as a trusted first-party component -- the write came from inside the platform, so it is
#: tagged trusted. That assumption is exactly what the laundering channels exploit, and
#: reproducing it faithfully here is what lets us demonstrate the vulnerability honestly.
#: With taint propagation enabled this default is unreachable whenever the turn read
#: anything, because inherited trust always wins.
DEFAULT_TRUST: dict[OriginKind, TrustLevel] = {
    OriginKind.WEB: TrustLevel.UNTRUSTED,
    OriginKind.EMAIL: TrustLevel.UNTRUSTED,
    OriginKind.TICKET: TrustLevel.UNTRUSTED,
    OriginKind.DOCUMENT: TrustLevel.THIRD_PARTY,
    OriginKind.TOOL: TrustLevel.TOOL_VERIFIED,
    OriginKind.USER: TrustLevel.USER,
    OriginKind.SYSTEM: TrustLevel.SYSTEM,
    OriginKind.AGENT: TrustLevel.TOOL_VERIFIED,

    # A managed sensor and the entities it reports on are first-party telemetry, so they
    # sit at TOOL_VERIFIED. ADDRESS and ARTIFACT do not: an address is whatever the packet
    # claimed and a hash is whatever a feed asserted about it, so evidence resting on them
    # cannot on its own authorise a disruptive response. `soc/entities.py` may lower any of
    # these per sensor; policy overrides may raise them.
    OriginKind.SENSOR: TrustLevel.TOOL_VERIFIED,
    OriginKind.HOST: TrustLevel.TOOL_VERIFIED,
    OriginKind.ACCOUNT: TrustLevel.TOOL_VERIFIED,
    OriginKind.ADDRESS: TrustLevel.THIRD_PARTY,
    OriginKind.PROCESS: TrustLevel.TOOL_VERIFIED,
    OriginKind.ARTIFACT: TrustLevel.THIRD_PARTY,
}


@dataclass(frozen=True, slots=True, order=True)
class Origin:
    """A root source of content. Identity is (kind, locator)."""

    kind: OriginKind
    locator: str            # URL, email address, ticket id, tool name, user id
    trust: TrustLevel
    label: str = ""         # human-readable, for the console

    def __post_init__(self) -> None:
        if not self.locator:
            raise ValueError("Origin.locator must be non-empty")

    @classmethod
    def of(cls, kind: OriginKind, locator: str, *, trust: TrustLevel | None = None,
           label: str = "") -> "Origin":
        return cls(kind, locator, trust if trust is not None else DEFAULT_TRUST[kind], label)

    @property
    def ref(self) -> str:
        return f"{self.kind.name.lower()}:{self.locator}"

    def to_dict(self) -> dict:
        return {"kind": self.kind.name, "locator": self.locator,
                "trust": self.trust.name, "label": self.label, "ref": self.ref}


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    """The lineage stamped onto every memory item at write time.

    ``origins`` is the *transitive closure* of root origins, not just the immediate writer.
    ``effective_trust`` is ``min(o.trust for o in origins)`` and is never recomputed from
    content -- only ever inherited downward. That invariant is what defeats laundering.
    """

    origins: frozenset[Origin]
    effective_trust: TrustLevel
    derived_from: tuple[str, ...] = ()   # memory ids this was computed from
    written_by: OriginKind = OriginKind.AGENT
    session_id: str = ""
    turn_id: str = ""
    written_at_day: int = 0              # logical clock; the demo spans 41 days
    content_sha256: str = ""
    #: The trust a writer-identity system would have assigned -- i.e. what this memory
    #: would be worth if trust were attributed to whoever performed the write rather than
    #: inherited from what the write was derived from. The gap between this and
    #: ``effective_trust`` is precisely the laundering that was prevented.
    claimed_trust: TrustLevel | None = None

    def __post_init__(self) -> None:
        if not self.origins:
            raise ValueError("ProvenanceRecord requires at least one origin")
        expected = min(o.trust for o in self.origins)
        if self.effective_trust != expected:
            raise ValueError(
                f"effective_trust {self.effective_trust.name} violates the lattice; "
                f"min(origins) is {expected.name}. Trust is inherited, never re-derived."
            )

    @classmethod
    def root(cls, origin: Origin, *, content: str, session_id: str = "",
             turn_id: str = "", day: int = 0) -> "ProvenanceRecord":
        """Provenance for content entering the system directly from one origin."""
        return cls(
            origins=frozenset({origin}),
            effective_trust=origin.trust,
            written_by=origin.kind,
            session_id=session_id,
            turn_id=turn_id,
            written_at_day=day,
            content_sha256=content_hash(content),
        )

    @property
    def is_laundered(self) -> bool:
        """True when attributing trust to the writer would have over-trusted this memory.

        The signature of a laundering attempt: the write *looks* first-party -- it was made
        by the platform's own agent, inside an authenticated session -- but its lineage runs
        back to something untrusted. Surfaced in the console; never used to decide.
        """
        return self.claimed_trust is not None and self.claimed_trust > self.effective_trust

    @property
    def trust_gap(self) -> int:
        """How many lattice levels of unearned authority were stripped off this memory."""
        if self.claimed_trust is None:
            return 0
        return max(0, int(self.claimed_trust) - int(self.effective_trust))

    def weakest_origin(self) -> Origin:
        return min(self.origins, key=lambda o: (o.trust, o.ref))

    def to_dict(self) -> dict:
        return {
            "origins": [o.to_dict() for o in sorted(self.origins)],
            "effective_trust": self.effective_trust.name,
            "effective_trust_value": int(self.effective_trust),
            "derived_from": list(self.derived_from),
            "written_by": self.written_by.name,
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "written_at_day": self.written_at_day,
            "content_sha256": self.content_sha256,
            "claimed_trust": self.claimed_trust.name if self.claimed_trust else None,
            "is_laundered": self.is_laundered,
            "trust_gap": self.trust_gap,
            "weakest_origin": self.weakest_origin().to_dict(),
        }

    def canonical(self) -> str:
        """Stable serialisation, used as the leaf input to the audit hash chain."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def merge_origins(records: Iterable[ProvenanceRecord]) -> frozenset[Origin]:
    out: set[Origin] = set()
    for r in records:
        out |= r.origins
    return frozenset(out)
