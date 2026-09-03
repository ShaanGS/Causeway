"""The enforcement decision. Deterministic, data-driven, and free of any model.

No LLM call, no network call, and no content inspection happens in this path. The decision
is a comparison on an ordered lattice, which is why it is sub-millisecond and why its
behaviour is identical for an attack phrased in English, in base64, or in Telugu.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

from .provenance import Origin, ProvenanceRecord, TrustLevel

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "default.yaml"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"


@dataclass(frozen=True, slots=True)
class ActionClass:
    id: str
    label: str
    required_trust: TrustLevel
    rule_id: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class Decision:
    """A single enforcement outcome, carrying everything needed to explain itself.

    The explanation is not decoration. An operator who cannot see why a memory was refused
    will switch the control off, so every refusal states the rule, the required trust, the
    observed trust, and the exact origin responsible.
    """

    verdict: Verdict
    action: ActionClass
    memory_id: str
    observed_trust: TrustLevel
    required_trust: TrustLevel
    weakest_origin: Origin | None
    rule_id: str
    reason: str
    latency_us: float = 0.0
    laundering_detected: bool = False
    derivation: tuple[str, ...] = ()
    model_calls: int = 0    # structurally zero; asserted in tests
    network_calls: int = 0  # structurally zero; asserted in tests

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "action": {"id": self.action.id, "label": self.action.label},
            "memory_id": self.memory_id,
            "observed_trust": self.observed_trust.name,
            "required_trust": self.required_trust.name,
            "weakest_origin": self.weakest_origin.to_dict() if self.weakest_origin else None,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "latency_us": round(self.latency_us, 2),
            "laundering_detected": self.laundering_detected,
            "derivation": list(self.derivation),
            "model_calls": self.model_calls,
            "network_calls": self.network_calls,
        }


class PolicyError(ValueError):
    pass


class PolicyEngine:
    """Loads rules from YAML and answers: may this lineage authorise this action?"""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_POLICY_PATH
        # Set before _load(), which only ever repopulates the file-backed half. Runtime
        # revocations must survive `reload()` -- an operator declaring a source
        # compromised is not undone by someone re-reading the rules file.
        self._revoked_runtime: dict[str, TrustLevel] = {}
        self._load()

    def _load(self) -> None:
        raw = yaml.safe_load(self.path.read_text())
        self.version = raw.get("version", 1)
        self.name = raw.get("name", "unnamed")
        self.on_deny = raw.get("on_deny", "quarantine")

        self.actions: dict[str, ActionClass] = {}
        for entry in raw.get("action_classes", []):
            try:
                trust = TrustLevel[entry["required_trust"]]
            except KeyError as exc:
                raise PolicyError(
                    f"unknown trust level {entry.get('required_trust')!r} in {self.path}"
                ) from exc
            self.actions[entry["id"]] = ActionClass(
                id=entry["id"], label=entry.get("label", entry["id"]),
                required_trust=trust, rule_id=entry.get("rule_id", "R-000"),
                description=entry.get("description", "").strip(),
            )

        self.origin_overrides: dict[str, TrustLevel] = {}
        for entry in raw.get("origin_overrides", []):
            self.origin_overrides[entry["ref"]] = TrustLevel[entry["trust"]]

        self._revoked_file: dict[str, TrustLevel] = {}
        for entry in raw.get("revoked_origins", []):
            self._revoked_file[entry["ref"]] = TrustLevel[entry.get("trust", "UNTRUSTED")]

    def reload(self) -> None:
        """Re-read the policy file. Lets a rule change land live during a demo."""
        self._load()

    # -- editing -----------------------------------------------------------------
    #
    # Rules are data, so changing one is a write to the YAML and a reload -- not a code
    # path. These two methods exist so a jury can do that from the console without a
    # terminal, and so the same edit is legible afterwards in `git diff`. The edit is
    # textual and surgical rather than a load/dump round-trip, because dumping would
    # discard every comment in the file and the comments are half of what makes the
    # policy readable to a reviewer.

    @property
    def baseline_path(self) -> Path:
        """Sidecar holding the file exactly as shipped, so an edit is always undoable."""
        return self.path.with_suffix(self.path.suffix + ".orig")

    def _ensure_baseline(self) -> None:
        if not self.baseline_path.exists():
            self.baseline_path.write_text(self.path.read_text())

    def set_required_trust(self, action_id: str, trust_name: str) -> TrustLevel:
        """Rewrite one action class's trust floor in the YAML, then reload.

        Raises PolicyError -- never a partial write -- if the action or the trust level is
        unknown, so a bad edit cannot leave the file in a state that fails to parse.
        """
        if action_id not in self.actions:
            raise PolicyError(
                f"unknown action class {action_id!r}; declared classes: {sorted(self.actions)}"
            )
        try:
            trust = TrustLevel[trust_name]
        except KeyError as exc:
            raise PolicyError(
                f"unknown trust level {trust_name!r}; the lattice is "
                f"{', '.join(t.name for t in TrustLevel)}"
            ) from exc

        self._ensure_baseline()
        lines = self.path.read_text().splitlines(keepends=True)
        start = None
        for i, line in enumerate(lines):
            if re.match(rf"\s*-\s*id:\s*{re.escape(action_id)}\s*(#.*)?$", line):
                start = i
                break
        if start is None:
            raise PolicyError(f"{action_id!r} is loaded but not found in {self.path}")

        for i in range(start + 1, len(lines)):
            if re.match(r"\s*-\s*id:\s", lines[i]):
                break  # walked into the next action class without finding the key
            m = re.match(r"(\s*required_trust:\s*)(\S+)(.*)$", lines[i])
            if m:
                lines[i] = f"{m.group(1)}{trust.name}{m.group(3)}\n"
                self.path.write_text("".join(lines))
                self._load()
                return trust
        raise PolicyError(f"no required_trust key under {action_id!r} in {self.path}")

    def revert(self) -> None:
        """Restore the shipped policy. A no-op if nothing was ever edited."""
        if self.baseline_path.exists():
            self.path.write_text(self.baseline_path.read_text())
        self._load()

    def edited(self) -> dict[str, str]:
        """Action id -> shipped trust level, for every class whose floor has been moved."""
        if not self.baseline_path.exists():
            return {}
        try:
            raw = yaml.safe_load(self.baseline_path.read_text())
        except Exception:
            return {}
        out: dict[str, str] = {}
        for entry in raw.get("action_classes", []):
            shipped = entry.get("required_trust")
            current = self.actions.get(entry["id"])
            if current is not None and shipped != current.required_trust.name:
                out[entry["id"]] = shipped
        return out

    def action(self, action_id: str) -> ActionClass:
        if action_id not in self.actions:
            raise PolicyError(
                f"unknown action class {action_id!r}; declared classes: "
                f"{sorted(self.actions)}"
            )
        return self.actions[action_id]

    # -- revocation ----------------------------------------------------------------
    #
    # An origin can be declared compromised after the fact. This is retroactive by
    # construction and costs no migration: trust is recomputed from origins on every
    # evaluation, so a memory written six weeks ago re-evaluates itself the moment its
    # source is revoked, and the stored record is never edited. See `revocation.py`.

    @property
    def revoked(self) -> dict[str, TrustLevel]:
        """Origins declared compromised -- file entries first, runtime revocations last."""
        return {**self._revoked_file, **self._revoked_runtime}

    def is_revoked(self, ref: str) -> bool:
        return ref in self.revoked

    def revoke(self, ref: str, *, to: TrustLevel = TrustLevel.UNTRUSTED) -> TrustLevel:
        self._revoked_runtime[ref] = to
        return to

    def unrevoke(self, ref: str) -> bool:
        return self._revoked_runtime.pop(ref, None) is not None

    def effective_trust_of(self, origin: Origin, *,
                           revoked: dict[str, TrustLevel] | None = None
                           ) -> tuple[TrustLevel, Origin]:
        """Trust for one origin: an override may raise it, a revocation may lower it.

        The asymmetry is the whole design. An override is somebody vouching out of band,
        and vouching may only ever raise. A revocation is that vouch being withdrawn -- or
        the source being declared compromised -- and may only ever lower. Revocation is
        applied last, so it wins: an origin that could be pinned but never taken back
        would be a worse failure than not pinning it at all.
        """
        marks = self.revoked if revoked is None else revoked
        trust = max(origin.trust, self.origin_overrides.get(origin.ref, origin.trust))
        if origin.ref in marks:
            trust = min(trust, marks[origin.ref])
        return trust, origin

    def effective_trust(self, provenance: ProvenanceRecord, *,
                        revoked: dict[str, TrustLevel] | None = None
                        ) -> tuple[TrustLevel, Origin]:
        """Apply overrides and revocations to every origin, then take the minimum.

        ``revoked=`` supplies a hypothetical set instead of the live one, which is how
        `revocation.blast_radius` answers "what would this cost" without applying it.
        """
        best: dict[Origin, TrustLevel] = {}
        for origin in provenance.origins:
            best[origin] = self.effective_trust_of(origin, revoked=revoked)[0]
        weakest = min(best, key=lambda o: (best[o], o.ref))
        return best[weakest], weakest

    def evaluate(self, provenance: ProvenanceRecord, action_id: str,
                 *, memory_id: str = "") -> Decision:
        started = time.perf_counter()
        action = self.action(action_id)
        observed, weakest = self.effective_trust(provenance)
        allowed = observed >= action.required_trust

        if allowed:
            reason = (
                f"{weakest.ref} carries {observed.label}, which is what "
                f"{action.label!r} requires."
            )
        else:
            reason = (
                f"{weakest.ref} carries {observed.label}; {action.label!r} requires "
                f"{action.required_trust.label}. This memory's lineage cannot authorise "
                f"the action."
            )

        return Decision(
            verdict=Verdict.ALLOW if allowed else Verdict.QUARANTINE,
            action=action,
            memory_id=memory_id,
            observed_trust=observed,
            required_trust=action.required_trust,
            weakest_origin=weakest,
            rule_id=action.rule_id,
            reason=reason,
            latency_us=(time.perf_counter() - started) * 1e6,
            laundering_detected=provenance.is_laundered,
            derivation=provenance.derived_from,
        )
