"""Strict HTTPS client adapter for an independent audit-anchor service."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .anchor_models import AuditAnchorCommitment, AuditAnchorError, AuditAnchorReceipt, receipt_from_document
from .models import canonical_json

_MAX_RESPONSE_BYTES = 128 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class HttpsAuditAnchorProvider:
    """Submit canonical commitments to one pinned HTTPS endpoint and parse strict receipts."""

    def __init__(
        self,
        endpoint: str,
        *,
        anchor_id: str,
        timeout_seconds: float = 10.0,
        ssl_context: ssl.SSLContext | None = None,
        opener: Any | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise AuditAnchorError("External anchor endpoint must be an exact HTTPS URL without userinfo, query, or fragment.")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise AuditAnchorError("Anchor HTTP timeout must be within (0, 60] seconds.")
        self.endpoint = endpoint
        self.anchor_id = anchor_id
        self.timeout_seconds = timeout_seconds
        self._ssl_context = ssl_context or ssl.create_default_context()
        self._opener = opener or urllib.request.build_opener(_NoRedirect())

    def append(self, commitment: AuditAnchorCommitment) -> AuditAnchorReceipt:
        body = canonical_json(commitment.as_dict()).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            response = self._opener.open(
                request,
                timeout=self.timeout_seconds,
                context=self._ssl_context,
            )
            with response:
                if getattr(response, "status", 0) not in {200, 201}:
                    raise AuditAnchorError("External anchor service returned an unexpected status.")
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except AuditAnchorError:
            raise
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise AuditAnchorError("External anchor service request failed.") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise AuditAnchorError("External anchor service response exceeds the size limit.")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditAnchorError("External anchor service returned invalid JSON.") from exc
        receipt = receipt_from_document(document)
        if receipt.anchor_id != self.anchor_id:
            raise AuditAnchorError("External anchor receipt came from an unexpected anchor id.")
        return receipt
