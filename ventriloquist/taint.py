"""Taint propagation: trust is inherited, never re-derived.

This is the core engineering claim of Ventriloquist, and the reason it survives the three
laundering channels catalogued in arXiv 2606.24322:

  1. agent summarization        -- the agent reads untrusted text and writes its own
                                   summary, so the write is authored by a trusted component
  2. trusted-tool echo          -- untrusted text is relayed through a first-party tool and
                                   comes back wearing that tool's trust
  3. manufactured corroboration -- the same claim is planted across several sources so it
                                   appears independently confirmed

All three work the same way: they break the link between a write and the origins that
produced it, so that trust gets attributed to the *writer* instead of the *source*. Every
mainstream memory layer makes that attribution -- a memory written by the agent during your
authenticated session is recorded as your memory, carrying your authority, even when its
content came off a web page the agent happened to read.

The defence is not to inspect content. It is to never let that link break.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .provenance import (
    Origin,
    OriginKind,
    ProvenanceRecord,
    TrustLevel,
    content_hash,
    merge_origins,
)


def default_principal() -> Origin:
    """The authenticated account holder, whose authority a naive layer lends to the agent."""
    return Origin.of(
        OriginKind.USER, "principal", trust=TrustLevel.USER_VERIFIED, label="Account holder"
    )


@dataclass
class TurnContext:
    """Tracks everything read during one agent turn so writes can inherit from it.

    A "turn" is one user request and the agent's complete response, including every tool
    call. Anything written during the turn is presumed derived from everything read during
    it. That presumption is deliberately conservative -- it is what makes the summarization
    channel a dead end.
    """

    session_id: str
    turn_id: str
    day: int = 0
    #: When False the gateway reverts to writer-identity attribution: the write is stamped
    #: with the session principal's authority and the read set is discarded. This reproduces
    #: the vulnerable design faithfully so it can be demonstrated rather than asserted.
    propagate: bool = True
    principal: Origin = field(default_factory=default_principal)

    _read_records: list[ProvenanceRecord] = field(default_factory=list, repr=False)
    _read_ids: list[str] = field(default_factory=list, repr=False)

    # -- observation -------------------------------------------------------------

    def observe_memory(self, memory_id: str, provenance: ProvenanceRecord) -> None:
        """Record that the agent read a stored memory during this turn."""
        self._read_records.append(provenance)
        if memory_id not in self._read_ids:
            self._read_ids.append(memory_id)

    def observe_source(self, origin: Origin, content: str, *, ref: str | None = None) -> None:
        """Record that the agent read external content -- a web page, email, or document."""
        self._read_records.append(
            ProvenanceRecord.root(
                origin, content=content, session_id=self.session_id,
                turn_id=self.turn_id, day=self.day,
            )
        )
        marker = ref or origin.ref
        if marker not in self._read_ids:
            self._read_ids.append(marker)

    # -- derivation --------------------------------------------------------------

    @property
    def inherited_trust(self) -> TrustLevel:
        """The ceiling on anything written during this turn."""
        if not self._read_records:
            return self.principal.trust
        return min(r.effective_trust for r in self._read_records)

    def derive(self, content: str, *, written_by: OriginKind = OriginKind.AGENT
               ) -> ProvenanceRecord:
        """Build the provenance for a write made during this turn.

        With propagation on, the write inherits the transitive origin closure of everything
        read and takes the minimum trust across it. With propagation off, the write is
        attributed to the session principal and the read set is discarded.

        ``claimed_trust`` always records what writer-identity attribution *would* have
        assigned, so the console can show exactly how much unearned authority was stripped.
        """
        claimed = self.principal.trust

        if not self.propagate or not self._read_records:
            origins = frozenset({self.principal})
            return ProvenanceRecord(
                origins=origins,
                effective_trust=min(o.trust for o in origins),
                derived_from=tuple(self._read_ids) if self.propagate else (),
                written_by=written_by,
                session_id=self.session_id,
                turn_id=self.turn_id,
                written_at_day=self.day,
                content_sha256=content_hash(content),
                claimed_trust=claimed,
            )

        origins = merge_origins(self._read_records)
        return ProvenanceRecord(
            origins=origins,
            effective_trust=min(o.trust for o in origins),
            derived_from=tuple(self._read_ids),
            written_by=written_by,
            session_id=self.session_id,
            turn_id=self.turn_id,
            written_at_day=self.day,
            content_sha256=content_hash(content),
            claimed_trust=claimed,
        )

    def reset(self) -> None:
        self._read_records.clear()
        self._read_ids.clear()

    @property
    def read_ids(self) -> tuple[str, ...]:
        return tuple(self._read_ids)


def echo_through_tool(payload: ProvenanceRecord, tool: Origin,
                      *, propagate: bool = True) -> ProvenanceRecord:
    """Model the trusted-tool-echo channel.

    A tool that merely relays content does not confer its own trust on that content. With
    propagation on the tool joins the origin set for auditability, but effective trust stays
    at the minimum -- so routing untrusted text through a first-party tool launders nothing.
    With propagation off the relayed content takes the tool's trust, which is the flaw.
    """
    origins = frozenset(payload.origins | {tool})
    if not propagate:
        origins = frozenset({tool})
    return ProvenanceRecord(
        origins=origins,
        effective_trust=min(o.trust for o in origins),
        derived_from=payload.derived_from,
        written_by=OriginKind.TOOL,
        session_id=payload.session_id,
        turn_id=payload.turn_id,
        written_at_day=payload.written_at_day,
        content_sha256=payload.content_sha256,
        claimed_trust=tool.trust,
    )
