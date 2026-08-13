"""Digest-bound OWASP ASVS 5.0.0 reference coverage."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .models import sha256_digest, to_primitive

ASVS_VERSION = "5.0.0"
MAXIMUM_REQUIREMENTS = 10_000
_ASVS_REF = re.compile(r"^v5\.0\.0-[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class AsvsCoverageError(ValueError):
    """Raised when ASVS coverage evidence fails closed."""


@dataclass(frozen=True, slots=True)
class AsvsRequirementCatalog:
    source_version: str
    source_sha256: str
    source_ref: str
    requirement_refs: tuple[str, ...]
    standard_name: str = "OWASP ASVS"
    requirement_text_embedded: bool = False

    def __post_init__(self) -> None:
        if self.source_version != ASVS_VERSION:
            raise ValueError("ASVS catalog must remain pinned to version 5.0.0.")
        if not _DIGEST.fullmatch(self.source_sha256):
            raise ValueError("ASVS source digest must be SHA-256.")
        _text(self.source_ref, "source_ref", 2048, 1)
        if not 1 <= len(self.requirement_refs) <= MAXIMUM_REQUIREMENTS:
            raise ValueError("ASVS catalog must contain a bounded requirement set.")
        if any(not _ASVS_REF.fullmatch(item) for item in self.requirement_refs):
            raise ValueError("ASVS requirement refs must use v5.0.0-x.y.z.")
        if len(set(self.requirement_refs)) != len(self.requirement_refs):
            raise ValueError("ASVS catalog requirement refs must be unique.")
        if self.standard_name != "OWASP ASVS" or self.requirement_text_embedded is not False:
            raise ValueError("ASVS catalog must remain reference-only.")
        object.__setattr__(self, "requirement_refs", tuple(sorted(self.requirement_refs, key=_ref_key)))

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {"schema_version": "finredops.asvs-requirement-catalog.v1", **to_primitive(self), "catalog_digest": self.digest()}


def _ref_key(value: str) -> tuple[int, int, int]:
    if not _ASVS_REF.fullmatch(value):
        raise AsvsCoverageError("Invalid ASVS requirement ref.")
    chapter, section, requirement = value.split("-", 1)[1].split(".")
    return int(chapter), int(section), int(requirement)


def _text(value: str, name: str, maximum: int, minimum: int) -> None:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or _CONTROL.search(value):
        raise ValueError(f"{name} violates the bounded text contract.")
