"""Strict CVSS v4.0 validation without conflating technical severity with business risk."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from cvss import CVSS4
from cvss.exceptions import CVSS4Error

from .models import sha256_digest, to_primitive

CVSS40_VERSION = "4.0"
MAXIMUM_CVSS_VECTOR = 1_024
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class Cvss40ValidationError(ValueError):
    """Raised when a CVSS v4.0 vector or declared result fails closed."""


@dataclass(frozen=True, slots=True)
class ValidatedCvss40:
    vector: str
    score: float
    severity: str
    version: str = CVSS40_VERSION
    technical_severity_only: bool = True
    financial_business_impact_inferred: bool = False

    def __post_init__(self) -> None:
        if self.version != CVSS40_VERSION or not self.vector.startswith("CVSS:4.0/"):
            raise ValueError("Validated CVSS artifacts must remain pinned to CVSS v4.0.")
        if not isinstance(self.score, float) or not math.isfinite(self.score):
            raise ValueError("CVSS score must be a finite float.")
        if not 0.0 <= self.score <= 10.0 or round(self.score, 1) != self.score:
            raise ValueError("CVSS score must be a one-decimal value between 0.0 and 10.0.")
        if self.severity not in {"none", "low", "medium", "high", "critical"}:
            raise ValueError("CVSS severity is outside the v4.0 qualitative scale.")
        if self.technical_severity_only is not True:
            raise ValueError("CVSS validation must remain a technical-severity artifact.")
        if self.financial_business_impact_inferred is not False:
            raise ValueError("CVSS validation cannot infer financial business impact.")

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.cvss40-validation.v1",
            **to_primitive(self),
            "validation_digest": self.digest(),
        }


def validate_cvss40(
    vector: str,
    *,
    declared_score: float | int | None = None,
    declared_severity: str | None = None,
) -> ValidatedCvss40:
    """Validate and score one CVSS v4.0 vector under a deterministic library boundary."""

    if not isinstance(vector, str) or not vector or len(vector) > MAXIMUM_CVSS_VECTOR:
        raise Cvss40ValidationError("CVSS vector must be a bounded non-empty string.")
    if _CONTROL.search(vector):
        raise Cvss40ValidationError("CVSS vector contains control characters.")
    if not vector.startswith("CVSS:4.0/"):
        raise Cvss40ValidationError("Only CVSS version 4.0 vectors are accepted.")

    try:
        parsed = CVSS4(vector)
    except CVSS4Error as exc:
        raise Cvss40ValidationError(f"Invalid CVSS v4.0 vector: {exc}") from exc

    canonical = parsed.clean_vector()
    if not isinstance(canonical, str) or not canonical.startswith("CVSS:4.0/"):
        raise Cvss40ValidationError("CVSS implementation returned an invalid canonical vector.")
    scores = parsed.scores()
    severities = parsed.severities()
    if len(scores) != 1 or len(severities) != 1:
        raise Cvss40ValidationError("CVSS v4.0 result must contain exactly one score and severity.")
    score = float(scores[0])
    severity = str(severities[0]).strip().lower()
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        raise Cvss40ValidationError("Computed CVSS score is outside the v4.0 range.")
    score = round(score, 1)
    expected_severity = _severity_for_score(score)
    if severity != expected_severity:
        raise Cvss40ValidationError("CVSS implementation severity does not match the FIRST scale.")

    if declared_score is not None:
        if isinstance(declared_score, bool) or not isinstance(declared_score, (int, float)):
            raise Cvss40ValidationError("Declared CVSS score must be numeric.")
        declared = float(declared_score)
        if not math.isfinite(declared) or not 0.0 <= declared <= 10.0:
            raise Cvss40ValidationError("Declared CVSS score is outside 0.0 to 10.0.")
        if round(declared, 1) != score:
            raise Cvss40ValidationError("Declared CVSS score does not match the vector.")

    if declared_severity is not None:
        if not isinstance(declared_severity, str) or not declared_severity.strip():
            raise Cvss40ValidationError("Declared CVSS severity must be a string.")
        normalized = declared_severity.strip().lower()
        if normalized != severity:
            raise Cvss40ValidationError("Declared CVSS severity does not match the vector.")

    return ValidatedCvss40(vector=canonical, score=score, severity=severity)


def _severity_for_score(score: float) -> str:
    if score == 0.0:
        return "none"
    if score <= 3.9:
        return "low"
    if score <= 6.9:
        return "medium"
    if score <= 8.9:
        return "high"
    return "critical"
