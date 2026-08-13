"""Offline operator commands for external audit-anchor artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .anchor_models import (
    AuditAnchorError,
    commitment_from_document,
    receipt_from_document,
    trust_bundle_from_document,
)
from .anchor_verify import verify_audit_anchor_chain, verify_audit_anchor_receipt

_MAX_JSON_BYTES = 1024 * 1024

ANCHOR_COMMANDS = frozenset(
    {
        "validate-audit-anchor-commitment",
        "validate-audit-anchor-trust-bundle",
        "verify-audit-anchor-receipt",
        "verify-audit-anchor-chain",
    }
)


def anchor_help() -> str:
    return """
External audit anchoring:
  validate-audit-anchor-commitment <commitment.json>
  validate-audit-anchor-trust-bundle <trust-bundle.json>
  verify-audit-anchor-receipt <commitment.json> <receipt.json> <trust-bundle.json>
  verify-audit-anchor-chain <receipts.jsonl> <trust-bundle.json>
"""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditAnchorError(f"Duplicate JSON key is not allowed: {key}")
        result[key] = value
    return result


def _read_json(path: str) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > _MAX_JSON_BYTES:
        raise AuditAnchorError("Anchor JSON document exceeds the 1 MiB limit.")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditAnchorError("Anchor document is not valid strict UTF-8 JSON.") from exc


def _read_receipts_jsonl(path: str) -> tuple[Any, ...]:
    raw = Path(path).read_bytes()
    if len(raw) > _MAX_JSON_BYTES:
        raise AuditAnchorError("Anchor receipt log exceeds the 1 MiB limit.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditAnchorError("Anchor receipt log is not UTF-8.") from exc
    receipts = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            document = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            receipts.append(receipt_from_document(document))
        except (json.JSONDecodeError, AuditAnchorError) as exc:
            raise AuditAnchorError(f"Invalid anchor receipt on line {line_number}: {exc}") from exc
    if len(receipts) > 100_000:
        raise AuditAnchorError("Anchor receipt log exceeds the record limit.")
    return tuple(receipts)


def run_anchor_command(argv: list[str]) -> int:
    if not argv or argv[0] not in ANCHOR_COMMANDS:
        return 1
    command = argv[0]
    try:
        if command == "validate-audit-anchor-commitment":
            if len(argv) != 2:
                raise AuditAnchorError("Expected one commitment JSON path.")
            item = commitment_from_document(_read_json(argv[1]))
            print(json.dumps({"valid": True, "commitment_digest": item.digest()}, indent=2))
            return 0
        if command == "validate-audit-anchor-trust-bundle":
            if len(argv) != 2:
                raise AuditAnchorError("Expected one anchor trust-bundle JSON path.")
            bundle = trust_bundle_from_document(_read_json(argv[1]))
            print(json.dumps({"valid": True, "anchor_id": bundle.anchor_id, "bundle_digest": bundle.digest()}, indent=2))
            return 0
        if command == "verify-audit-anchor-receipt":
            if len(argv) != 4:
                raise AuditAnchorError("Expected commitment, receipt, and trust-bundle paths.")
            item = commitment_from_document(_read_json(argv[1]))
            receipt = receipt_from_document(_read_json(argv[2]))
            bundle = trust_bundle_from_document(_read_json(argv[3]))
            valid = verify_audit_anchor_receipt(item, receipt, trust_bundle=bundle)
            print(json.dumps({"valid": valid, "receipt_digest": receipt.digest()}, indent=2))
            return 0 if valid else 2
        if len(argv) != 3:
            raise AuditAnchorError("Expected receipt JSONL and trust-bundle paths.")
        receipts = _read_receipts_jsonl(argv[1])
        bundle = trust_bundle_from_document(_read_json(argv[2]))
        valid, errors = verify_audit_anchor_chain(receipts, trust_bundle=bundle)
        print(json.dumps({"valid": valid, "receipt_count": len(receipts), "errors": list(errors)}, indent=2))
        return 0 if valid else 2
    except (AuditAnchorError, OSError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        return 2
