"""Strict JSON loaders for user-supplied governance documents."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import (
    AssetKind,
    DataClassification,
    Engagement,
    EngagementStatus,
    Environment,
    ScopeAsset,
    parse_datetime,
)


class DocumentValidationError(ValueError):
    """Raised when a governance document does not match the strict model."""


_ENGAGEMENT_KEYS = frozenset(
    {
        "engagement_id",
        "name",
        "requester_id",
        "critical_functions",
        "assets",
        "excluded_assets",
        "allowed_actions",
        "window_start",
        "window_end",
        "emergency_contacts",
        "max_requests_per_minute",
        "approval_ttl_minutes",
        "status",
    }
)
_ASSET_KEYS = frozenset(
    {
        "asset_id",
        "kind",
        "value",
        "environment",
        "data_classification",
        "critical_function",
    }
)


def read_json_document(path: Path, *, maximum_bytes: int = 256_000) -> Any:
    size = path.stat().st_size
    if size > maximum_bytes:
        raise DocumentValidationError(
            f"Document exceeds the {maximum_bytes}-byte validation limit."
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DocumentValidationError(f"Could not read valid UTF-8 JSON: {exc}") from exc


def engagement_from_document(document: Mapping[str, Any]) -> Engagement:
    if not isinstance(document, Mapping):
        raise DocumentValidationError("Engagement must be a JSON object.")
    missing = _ENGAGEMENT_KEYS - set(document)
    extra = set(document) - _ENGAGEMENT_KEYS
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("unknown " + ", ".join(sorted(extra)))
        raise DocumentValidationError("Invalid engagement fields: " + "; ".join(details) + ".")

    def string(name: str) -> str:
        value = document[name]
        if not isinstance(value, str) or not value.strip():
            raise DocumentValidationError(f"{name} must be a non-empty string.")
        return value.strip()

    def strings(name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
        value = document[name]
        if not isinstance(value, list) or (not value and not allow_empty):
            raise DocumentValidationError(f"{name} must be a non-empty string array.")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise DocumentValidationError(f"{name} must contain only non-empty strings.")
        return tuple(item.strip() for item in value)

    def integer(name: str) -> int:
        value = document[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise DocumentValidationError(f"{name} must be an integer.")
        return value

    try:
        assets = _assets(document["assets"], "assets")
        excluded_assets = _assets(document["excluded_assets"], "excluded_assets", allow_empty=True)
        return Engagement(
            engagement_id=string("engagement_id"),
            name=string("name"),
            requester_id=string("requester_id"),
            critical_functions=strings("critical_functions"),
            assets=assets,
            excluded_assets=excluded_assets,
            allowed_actions=strings("allowed_actions"),
            window_start=parse_datetime(string("window_start")),
            window_end=parse_datetime(string("window_end")),
            emergency_contacts=strings("emergency_contacts"),
            max_requests_per_minute=integer("max_requests_per_minute"),
            approval_ttl_minutes=integer("approval_ttl_minutes"),
            status=EngagementStatus(string("status")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, DocumentValidationError):
            raise
        raise DocumentValidationError(f"Invalid engagement value: {exc}") from exc


def _assets(value: Any, name: str, *, allow_empty: bool = False) -> tuple[ScopeAsset, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        requirement = "an array" if allow_empty else "a non-empty array"
        raise DocumentValidationError(f"{name} must be {requirement}.")
    parsed: list[ScopeAsset] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise DocumentValidationError(f"{name}[{index}] must be an object.")
        missing = _ASSET_KEYS - set(item)
        extra = set(item) - _ASSET_KEYS
        if missing or extra:
            raise DocumentValidationError(
                f"{name}[{index}] has invalid fields: missing {sorted(missing)}, unknown {sorted(extra)}."
            )
        if any(not isinstance(item[field], str) for field in _ASSET_KEYS):
            raise DocumentValidationError(f"{name}[{index}] fields must be strings.")
        try:
            parsed.append(
                ScopeAsset(
                    asset_id=item["asset_id"],
                    kind=AssetKind(item["kind"]),
                    value=item["value"],
                    environment=Environment(item["environment"]),
                    data_classification=DataClassification(item["data_classification"]),
                    critical_function=item["critical_function"],
                )
            )
        except ValueError as exc:
            raise DocumentValidationError(f"{name}[{index}] is invalid: {exc}") from exc
    return tuple(parsed)
