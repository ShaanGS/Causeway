"""Content detectors -- deliberately outside the trust decision.

This is the plugin layer that composes with the gateway rather than feeding it. Nothing
here can allow or refuse anything; `policy.py` never imports this module, and the tests
assert that. The point of shipping detectors at all is the opposite of the usual one:

    Run the best content-based screening you like against our attack corpus. It comes back
    clean, because the payloads *are* clean. A supplier changing bank details after a
    treasury migration is ordinary business prose. There is no token in it for a detector
    to fire on -- which is exactly why origin authorisation is the control that works.

So these are real detectors, implemented in good faith, and their honest verdict on the
demo payload is "nothing here". That verdict is evidence, not a failure.

Where a detector *does* fire -- the PII scanner sees the IBAN -- the finding is useless for
the decision, because every legitimate invoice on earth also contains one. Recognising a
bank account is not the same as knowing whose it is. Provenance is what knows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = [
    "Finding",
    "Detector",
    "PromptInjectionDetector",
    "PiiDetector",
    "SecretDetector",
    "DEFAULT_DETECTORS",
    "scan",
    "verdict",
]


@dataclass(frozen=True, slots=True)
class Finding:
    """What one detector concluded. Reported to the console; never read by the policy."""

    detector: str
    label: str
    score: float          # 0.0 clean .. 1.0 certain
    severity: str         # clean | low | medium | high
    note: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def fired(self) -> bool:
        return self.score > 0.0

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "label": self.label,
            "score": round(self.score, 2),
            "severity": self.severity,
            "note": self.note,
            "evidence": list(self.evidence),
            "fired": self.fired,
        }


@runtime_checkable
class Detector(Protocol):
    """A content screen. Add one by implementing this and appending to DEFAULT_DETECTORS."""

    name: str
    label: str

    def scan(self, content: str) -> Finding: ...


def _severity(score: float) -> str:
    if score <= 0.0:
        return "clean"
    if score < 0.4:
        return "low"
    if score < 0.75:
        return "medium"
    return "high"


# ---------------------------------------------------------------------------------
# prompt injection
# ---------------------------------------------------------------------------------

#: Patterns lifted from the shapes that actually appear in published injection corpora:
#: instruction override, role reassignment, system-prompt extraction, exfiltration
#: imperatives, and delimiter smuggling.
_INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\b", "instruction override"),
    (r"\bdisregard\s+(all\s+)?(previous|prior|above|your)\b", "instruction override"),
    (r"\byou\s+are\s+now\b", "role reassignment"),
    (r"\bact\s+as\s+(a|an|the)\b", "role reassignment"),
    (r"\bpretend\s+(to\s+be|you)\b", "role reassignment"),
    (r"\b(system|developer)\s+prompt\b", "system prompt reference"),
    (r"</?(system|instructions?|assistant)>", "delimiter smuggling"),
    (r"\bdo\s+not\s+(tell|inform|mention|reveal)\b", "concealment"),
    (r"\b(send|forward|exfiltrate|upload|post)\s+.{0,24}\b(to|at)\s+https?://", "exfiltration"),
    (r"\bnew\s+instructions?\b", "instruction override"),
    (r"\boverride\s+(your|the|all)\b", "instruction override"),
)


class PromptInjectionDetector:
    name = "prompt-injection"
    label = "Prompt injection"

    def scan(self, content: str) -> Finding:
        hits: list[str] = []
        kinds: set[str] = set()
        for pattern, kind in _INJECTION_PATTERNS:
            m = re.search(pattern, content, re.IGNORECASE)
            if m:
                hits.append(m.group(0).strip())
                kinds.add(kind)
        # Each distinct technique is worth more than a repeat of the same one.
        score = min(1.0, 0.45 * len(kinds))
        note = (
            ", ".join(sorted(kinds))
            if kinds
            else "no imperative aimed at a model, no role reassignment, no delimiter smuggling"
        )
        return Finding(
            detector=self.name, label=self.label, score=score,
            severity=_severity(score), note=note, evidence=tuple(hits[:4]),
        )


# ---------------------------------------------------------------------------------
# PII / financial identifiers
# ---------------------------------------------------------------------------------

_PII_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b[A-Z]{2}\d{2}[- ]?(?:[A-Z0-9]{4}[- ]?){1,7}[A-Z0-9]{1,4}\b", "bank account"),
    (r"\b(?:\d[ -]?){13,19}\b", "card-like number"),
    (r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "email address"),
    (r"\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b", "phone number"),
)


class PiiDetector:
    name = "pii"
    label = "PII / financial identifiers"

    def scan(self, content: str) -> Finding:
        hits: list[str] = []
        kinds: list[str] = []
        for pattern, kind in _PII_PATTERNS:
            m = re.search(pattern, content)
            if m:
                hits.append(m.group(0).strip())
                kinds.append(kind)
        # Capped deliberately: finding a bank account is a fact about the format, not a
        # judgement about the content. Every genuine invoice contains one.
        score = min(0.5, 0.25 * len(kinds))
        note = (
            f"found {', '.join(kinds)} — present in legitimate invoices too; "
            "the format says nothing about whose account it is"
            if kinds
            else "no identifiers found"
        )
        return Finding(
            detector=self.name, label=self.label, score=score,
            severity=_severity(score), note=note, evidence=tuple(hits[:4]),
        )


# ---------------------------------------------------------------------------------
# credential material
# ---------------------------------------------------------------------------------

_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bsk-[A-Za-z0-9]{16,}\b", "OpenAI-style key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "GitHub token"),
    (r"\bBearer\s+[A-Za-z0-9._-]{20,}\b", "bearer token"),
    (r"-----BEGIN[ A-Z]*PRIVATE KEY-----", "private key"),
)


class SecretDetector:
    name = "secrets"
    label = "Credential material"

    def scan(self, content: str) -> Finding:
        hits: list[str] = []
        kinds: list[str] = []
        for pattern, kind in _SECRET_PATTERNS:
            m = re.search(pattern, content)
            if m:
                hits.append(m.group(0)[:12] + "…")
                kinds.append(kind)
        score = min(1.0, 0.6 * len(kinds))
        return Finding(
            detector=self.name, label=self.label, score=score, severity=_severity(score),
            note=", ".join(kinds) if kinds else "no key or token material",
            evidence=tuple(hits[:3]),
        )


DEFAULT_DETECTORS: tuple[Detector, ...] = (
    PromptInjectionDetector(),
    PiiDetector(),
    SecretDetector(),
)


def scan(content: str, detectors: tuple[Detector, ...] = DEFAULT_DETECTORS) -> list[Finding]:
    return [d.scan(content) for d in detectors]


def verdict(findings: list[Finding]) -> dict:
    """What a purely content-based system would have concluded, on its own terms.

    ``would_block`` is what such a system would do -- and on our corpus it is False, which
    is the entire argument for provenance. It is returned for display and is never an
    input to the gateway's decision.
    """
    top = max((f.score for f in findings), default=0.0)
    return {
        "findings": [f.to_dict() for f in findings],
        "max_score": round(top, 2),
        "severity": _severity(top),
        "would_block": top >= 0.75,
        "summary": (
            "nothing to act on — this reads as ordinary business prose"
            if top < 0.4
            else "flagged, but not on anything that identifies an attacker"
            if top < 0.75
            else "would be refused on content"
        ),
    }
