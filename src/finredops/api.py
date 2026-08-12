"""Read-only local API for the synthetic FinRedOps demonstration."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import __version__
from .catalog import ACTION_CATALOG
from .dashboard import render_dashboard
from .models import sha256_digest, to_primitive
from .regulations import AssessmentType
from .reporting import REQUIRED_COVERAGE


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _openapi_document() -> dict[str, Any]:
    paths = {
        "/api/v1/health": "Service health and safety mode",
        "/api/v1/catalog": "Closed action catalog",
        "/api/v1/engagement": "Synthetic engagement snapshot",
        "/api/v1/preflight": "Institution policy preflight report",
        "/api/v1/regulatory/profile": "Versioned Turkish regulatory crosswalk profile",
        "/api/v1/regulatory/applicability": "Human-confirmed applicability decisions",
        "/api/v1/evidence/manifest": "Metadata-only evidence custody manifest",
        "/api/v1/audit-bundle/status": "Audit dossier readiness and verification status",
        "/api/v1/reporting/capabilities": "Supported report types and mandatory coverage",
        "/api/v1/audit/verification": "Audit-chain verification result",
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "FinRedOps read-only demonstration API",
            "version": __version__,
            "description": "Synthetic, local-only control-plane visibility. No write operations.",
        },
        "servers": [{"url": "http://127.0.0.1:8080"}],
        "paths": {
            path: {
                "get": {
                    "summary": summary,
                    "responses": {
                        "200": {
                            "description": "Successful synthetic response",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        }
                    },
                }
            }
            for path, summary in paths.items()
        },
    }


def create_read_only_server(
    snapshot: Mapping[str, Any],
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> ThreadingHTTPServer:
    """Create a server exposing only synthetic GET/HEAD endpoints."""

    dashboard = render_dashboard(snapshot).encode("utf-8")
    snapshot_digest = sha256_digest(snapshot)
    audit_events = list(snapshot.get("audit", []))
    audit_valid = _verify_snapshot_audit(audit_events)
    assurance = dict(snapshot.get("assurance", {}))
    routes: dict[str, tuple[str, bytes, str | None]] = {
        "/": ("text/html; charset=utf-8", dashboard, snapshot_digest),
        "/index.html": ("text/html; charset=utf-8", dashboard, snapshot_digest),
        "/api/v1/health": (
            "application/json; charset=utf-8",
            _json_bytes(
                {
                    "status": "ok" if audit_valid else "degraded",
                    "version": __version__,
                    "mode": "synthetic_simulation_only",
                    "write_operations": False,
                    "outbound_target_access": False,
                    "audit_chain_valid": audit_valid,
                }
            ),
            None,
        ),
        "/api/v1/catalog": (
            "application/json; charset=utf-8",
            _json_bytes(
                {
                    "catalog_version": "v1",
                    "actions": [to_primitive(item) for item in ACTION_CATALOG.values()],
                }
            ),
            None,
        ),
        "/api/v1/engagement": (
            "application/json; charset=utf-8",
            _json_bytes(dict(snapshot)),
            snapshot_digest,
        ),
        "/api/v1/preflight": (
            "application/json; charset=utf-8",
            _json_bytes(snapshot.get("preflight", {})),
            None,
        ),
        "/api/v1/regulatory/profile": (
            "application/json; charset=utf-8",
            _json_bytes(snapshot.get("regulatory_profile", {})),
            None,
        ),
        "/api/v1/regulatory/applicability": (
            "application/json; charset=utf-8",
            _json_bytes(assurance.get("applicability", {})),
            None,
        ),
        "/api/v1/evidence/manifest": (
            "application/json; charset=utf-8",
            _json_bytes(assurance.get("evidence_manifest", {})),
            None,
        ),
        "/api/v1/audit-bundle/status": (
            "application/json; charset=utf-8",
            _json_bytes(assurance.get("audit_bundle", {})),
            None,
        ),
        "/api/v1/reporting/capabilities": (
            "application/json; charset=utf-8",
            _json_bytes(
                {
                    "report_types": [item.value for item in AssessmentType],
                    "required_coverage": {
                        item.value: sorted(REQUIRED_COVERAGE[item])
                        for item in AssessmentType
                    },
                    "human_issue_approval_required": True,
                    "report_delta_supported": True,
                    "metadata_only_audit_bundle_supported": True,
                    "audit_support_only": True,
                }
            ),
            None,
        ),
        "/api/v1/audit/verification": (
            "application/json; charset=utf-8",
            _json_bytes(
                {
                    "valid": audit_valid,
                    "event_count": len(audit_events),
                    "last_event_hash": audit_events[-1]["event_hash"] if audit_events else None,
                }
            ),
            None,
        ),
        "/api/v1/openapi.json": (
            "application/json; charset=utf-8",
            _json_bytes(_openapi_document()),
            None,
        ),
    }

    class ReadOnlyHandler(BaseHTTPRequestHandler):
        server_version = "FinRedOps"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._respond(include_body=True)

        def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._respond(include_body=False)

        def do_POST(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def do_PUT(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def do_PATCH(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def do_DELETE(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def _method_not_allowed(self) -> None:
            body = _json_bytes(
                {
                    "error": "method_not_allowed",
                    "message": "The v0.3 demonstration API is deliberately read-only.",
                }
            )
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD")
            self._security_headers("application/json; charset=utf-8", len(body))
            self.end_headers()
            self.wfile.write(body)

        def _respond(self, *, include_body: bool) -> None:
            if len(self.path) > 2_048:
                self.send_error(414)
                return
            path = urlsplit(self.path).path
            route = routes.get(path)
            if route is None:
                body = _json_bytes({"error": "not_found"})
                self.send_response(404)
                self._security_headers("application/json; charset=utf-8", len(body))
                self.end_headers()
                if include_body:
                    self.wfile.write(body)
                return
            content_type, body, etag_value = route
            etag = f'"{etag_value}"' if etag_value else None
            if etag and self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self._security_headers(content_type, 0)
                self.send_header("ETag", etag)
                self.end_headers()
                return
            self.send_response(200)
            self._security_headers(content_type, len(body))
            if etag:
                self.send_header("ETag", etag)
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def _security_headers(self, content_type: str, length: int) -> None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", _content_security_policy())
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-FinRedOps-Mode", "synthetic-simulation-only")

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), ReadOnlyHandler)


def serve_read_only_api(
    snapshot: Mapping[str, Any], *, host: str = "127.0.0.1", port: int = 8080
) -> None:
    server = create_read_only_server(snapshot, host=host, port=port)
    actual_host, actual_port = server.server_address[:2]
    print(f"FinRedOps synthetic dashboard: http://{actual_host}:{actual_port}")
    print("Read-only API: /api/v1/openapi.json")
    print("Simulation-only: the runner never contacts proposal targets.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _verify_snapshot_audit(events: list[Mapping[str, Any]]) -> bool:
    if not events:
        return False
    from .audit import AuditChain  # Local import keeps API startup surface small.

    document = "\n".join(json.dumps(event, separators=(",", ":"), sort_keys=True) for event in events)
    try:
        valid, _ = AuditChain.from_jsonl(document).verify()
    except ValueError:
        return False
    return valid


def _content_security_policy() -> str:
    return (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
