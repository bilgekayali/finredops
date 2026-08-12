"""Evidence minimization and deterministic sensitive-data redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .models import StringEnum, freeze_value, sha256_digest, to_primitive


class DataFindingKind(StringEnum):
    SECRET_FIELD = "secret_field"
    PAYMENT_CARD = "payment_card"
    IBAN = "iban"
    EMAIL = "email"
    BEARER_TOKEN = "bearer_token"


@dataclass(frozen=True, slots=True)
class DataFinding:
    kind: DataFindingKind
    path: str
    action: str = "redacted"


@dataclass(frozen=True, slots=True)
class EvidenceGuardResult:
    evidence: Mapping[str, Any]
    findings: tuple[DataFinding, ...]
    original_digest: str
    sanitized_digest: str

    @property
    def redacted(self) -> bool:
        return bool(self.findings)

    def summary(self) -> dict[str, Any]:
        return {
            "redacted": self.redacted,
            "finding_count": len(self.findings),
            "finding_kinds": sorted({item.kind.value for item in self.findings}),
            "sanitized_digest": self.sanitized_digest,
        }


_SECRET_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")
_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)
_IBAN_CANDIDATE = re.compile(r"(?<![A-Z0-9])([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})(?![A-Z0-9])", re.I)
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


class EvidenceGuard:
    """Redact likely secrets and regulated identifiers without retaining matches."""

    def sanitize(self, evidence: Mapping[str, Any]) -> EvidenceGuardResult:
        original_digest = sha256_digest(evidence)
        findings: list[DataFinding] = []

        def walk(value: Any, path: str, key_hint: str | None = None) -> Any:
            if key_hint and key_hint.casefold() in _SECRET_KEYS:
                findings.append(DataFinding(DataFindingKind.SECRET_FIELD, path))
                return "[REDACTED:SECRET]"
            if isinstance(value, Mapping):
                return {
                    str(key): walk(child, f"{path}.{key}", str(key))
                    for key, child in value.items()
                }
            if isinstance(value, (list, tuple)):
                return [walk(child, f"{path}[{index}]") for index, child in enumerate(value)]
            if not isinstance(value, str):
                return value
            sanitized = value
            if _BEARER.search(sanitized):
                sanitized = _BEARER.sub("[REDACTED:BEARER_TOKEN]", sanitized)
                findings.append(DataFinding(DataFindingKind.BEARER_TOKEN, path))
            if _EMAIL.search(sanitized):
                sanitized = _EMAIL.sub("[REDACTED:EMAIL]", sanitized)
                findings.append(DataFinding(DataFindingKind.EMAIL, path))
            sanitized = _redact_valid_identifiers(sanitized, path, findings)
            return sanitized

        sanitized = walk(evidence, "$")
        frozen = freeze_value(sanitized)
        return EvidenceGuardResult(
            evidence=frozen,
            findings=tuple(findings),
            original_digest=original_digest,
            sanitized_digest=sha256_digest(frozen),
        )


def _redact_valid_identifiers(
    value: str, path: str, findings: list[DataFinding]
) -> str:
    def replace_card(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            findings.append(DataFinding(DataFindingKind.PAYMENT_CARD, path))
            return "[REDACTED:PAYMENT_CARD]"
        return match.group(0)

    def replace_iban(match: re.Match[str]) -> str:
        compact = re.sub(r"\s", "", match.group(1)).upper()
        if _iban_valid(compact):
            findings.append(DataFinding(DataFindingKind.IBAN, path))
            return "[REDACTED:IBAN]"
        return match.group(0)

    return _IBAN_CANDIDATE.sub(replace_iban, _CARD_CANDIDATE.sub(replace_card, value))


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _iban_valid(value: str) -> bool:
    if not 15 <= len(value) <= 34 or not value[:2].isalpha() or not value[2:4].isdigit():
        return False
    rearranged = value[4:] + value[:4]
    numeric = "".join(str(int(character, 36)) for character in rearranged)
    return int(numeric) % 97 == 1


def guard_summary(result: EvidenceGuardResult) -> dict[str, Any]:
    return {**result.summary(), "findings": to_primitive(result.findings)}
