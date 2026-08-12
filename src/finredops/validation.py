"""Bounded active validation for explicitly authorized, non-production targets.

The module deliberately implements one closed proof-of-exposure action.  It is
not a general-purpose scanner or exploit framework: it performs one TLS-protected
HEAD request, never follows redirects, never reads a response body, and never
accepts model-generated commands or payloads.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from .evidence import EvidenceGuard, guard_summary
from .models import (
    ActionProposal,
    Engagement,
    Environment,
    ExecutionReceipt,
    ExecutionStatus,
    StringEnum,
    ensure_aware,
    sha256_digest,
)


CONTROLLED_HTTP_ACTION = "http.security_posture.validate"
METHODOLOGY_PROFILE = "tse-nist-owasp-v1"
NIST_SP_800_115 = "https://csrc.nist.gov/pubs/sp/800/115/final"
TSE_PENETRATION_TESTING = "https://www.tse.org.tr/sizma-testleri/"
OWASP_WSTG_HSTS = (
    "https://owasp.org/www-project-web-security-testing-guide/v42/"
    "4-Web_Application_Security_Testing/"
    "02-Configuration_and_Deployment_Management_Testing/"
    "07-Test_HTTP_Strict_Transport_Security"
)
OWASP_WSTG_COOKIE_ATTRIBUTES = (
    "https://owasp.org/www-project-web-security-testing-guide/v42/"
    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
    "02-Testing_for_Cookies_Attributes"
)

_COMMON_CONTROL_REFS = (
    "TR-KVKK-6698-12",
    "TR-KVKK-GUIDE-3.2",
    "TR-TSE-SIZMA-TESTI-KAPSAMI",
)
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]*$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class ValidationSeverity(StringEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    """Minimal response metadata retained in memory for deterministic analysis."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    tls_version: str
    certificate_not_after: datetime
    peer_address: str

    def __post_init__(self) -> None:
        if not 200 <= self.status_code <= 599:
            raise ValueError("Final HTTP status must be between 200 and 599.")
        if not self.tls_version.strip():
            raise ValueError("TLS version is required.")
        ipaddress.ip_address(self.peer_address)
        object.__setattr__(
            self, "certificate_not_after", ensure_aware(self.certificate_not_after)
        )
        object.__setattr__(self, "headers", tuple(self.headers))


class ProbeTransport(Protocol):
    def head(
        self,
        *,
        target: str,
        port: int,
        path: str,
        timeout_seconds: int,
    ) -> ProbeResponse: ...


class ProbeFailure(RuntimeError):
    """A bounded operational failure with a safe, non-sensitive error code."""

    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message


class BoundedTlsHeadTransport:
    """Make one TLS HEAD request to one resolved address without redirects."""

    maximum_header_bytes = 65_536
    user_agent = "FinRedOps/0.4 controlled-validation"

    def __init__(self, ssl_context: ssl.SSLContext | None = None) -> None:
        context = ssl_context or ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError(
                "The controlled transport requires hostname and certificate verification."
            )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ssl_context = context

    def head(
        self,
        *,
        target: str,
        port: int,
        path: str,
        timeout_seconds: int,
    ) -> ProbeResponse:
        peer = self._resolve_once(target, port)
        host_header = f"[{target}]" if ":" in target else target
        if port != 443:
            host_header = f"{host_header}:{port}"
        request = (
            f"HEAD {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            with socket.create_connection((peer, port), timeout=timeout_seconds) as raw:
                raw.settimeout(timeout_seconds)
                with self.ssl_context.wrap_socket(raw, server_hostname=target) as secured:
                    secured.settimeout(timeout_seconds)
                    secured.sendall(request)
                    block = self._read_headers(secured)
                    status_code, headers = self._parse_headers(block)
                    certificate = secured.getpeercert()
                    expires = certificate.get("notAfter")
                    if not isinstance(expires, str) or not expires:
                        raise ProbeFailure(
                            "TLS_CERTIFICATE_METADATA_MISSING",
                            "The peer certificate did not expose an expiry value.",
                        )
                    not_after = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(expires), tz=timezone.utc
                    )
                    tls_version = secured.version() or "unknown"
        except ProbeFailure:
            raise
        except ssl.SSLCertVerificationError as exc:
            raise ProbeFailure(
                "TLS_CERTIFICATE_INVALID",
                "TLS certificate verification failed for the approved target.",
            ) from exc
        except ssl.SSLError as exc:
            raise ProbeFailure(
                "TLS_HANDSHAKE_FAILED",
                "The approved target did not complete a TLS 1.2+ handshake.",
            ) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise ProbeFailure(
                "PROBE_TIMEOUT", "The bounded validation request timed out."
            ) from exc
        except OSError as exc:
            raise ProbeFailure(
                "CONNECTION_FAILED",
                "A connection to the approved target could not be established.",
            ) from exc
        return ProbeResponse(
            status_code=status_code,
            headers=headers,
            tls_version=tls_version,
            certificate_not_after=not_after,
            peer_address=peer,
        )

    def _resolve_once(self, target: str, port: int) -> str:
        try:
            records = socket.getaddrinfo(
                target,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise ProbeFailure(
                "DNS_RESOLUTION_FAILED",
                "The approved target could not be resolved.",
            ) from exc
        candidates: dict[bytes, str] = {}
        for record in records:
            value = record[4][0]
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if (
                address.is_unspecified
                or address.is_multicast
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
            ):
                continue
            candidates[address.packed] = str(address)
        if not candidates:
            raise ProbeFailure(
                "RESOLVED_ADDRESS_DENIED",
                "The target resolved only to an unsafe or unsupported address class.",
            )
        return candidates[sorted(candidates)[0]]

    def _read_headers(self, secured: ssl.SSLSocket) -> bytes:
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = secured.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > self.maximum_header_bytes:
                raise ProbeFailure(
                    "RESPONSE_HEADERS_TOO_LARGE",
                    "Response headers exceeded the bounded collection limit.",
                )
        marker = response.find(b"\r\n\r\n")
        if marker < 0:
            raise ProbeFailure(
                "HTTP_HEADERS_INCOMPLETE",
                "The target did not return a complete HTTP header block.",
            )
        return bytes(response[:marker])

    def _parse_headers(self, block: bytes) -> tuple[int, tuple[tuple[str, str], ...]]:
        lines = block.split(b"\r\n")
        try:
            status_line = lines[0].decode("ascii")
        except (IndexError, UnicodeDecodeError) as exc:
            raise ProbeFailure(
                "HTTP_STATUS_INVALID", "The response status line was invalid."
            ) from exc
        match = re.fullmatch(r"HTTP/\d(?:\.\d)? ([2-5]\d\d)(?: .*)?", status_line)
        if match is None:
            raise ProbeFailure(
                "HTTP_STATUS_INVALID", "The response status line was invalid."
            )
        headers: list[tuple[str, str]] = []
        for raw in lines[1:]:
            if raw[:1] in {b" ", b"\t"} or b":" not in raw:
                raise ProbeFailure(
                    "HTTP_HEADER_INVALID", "The response contained an invalid header line."
                )
            name_raw, value_raw = raw.split(b":", 1)
            try:
                name = name_raw.decode("ascii").strip().casefold()
                value = value_raw.decode("latin-1").strip()
            except UnicodeDecodeError as exc:
                raise ProbeFailure(
                    "HTTP_HEADER_INVALID", "The response contained an invalid header."
                ) from exc
            if not _HEADER_NAME.fullmatch(name):
                raise ProbeFailure(
                    "HTTP_HEADER_INVALID", "The response contained an invalid header name."
                )
            headers.append((name, value))
        return int(match.group(1)), tuple(headers)


class ControlledValidationRunner:
    """Turn one bounded active observation into reviewable finding metadata."""

    name = "finredops-controlled-validation:v1"

    def __init__(
        self,
        transport: ProbeTransport,
        evidence_guard: EvidenceGuard | None = None,
    ) -> None:
        self.transport = transport
        self.evidence_guard = evidence_guard or EvidenceGuard()

    @classmethod
    def for_authorized_network(
        cls, ssl_context: ssl.SSLContext | None = None
    ) -> "ControlledValidationRunner":
        """Explicitly opt in, optionally with institution-owned trust roots."""

        return cls(BoundedTlsHeadTransport(ssl_context))

    def execute(
        self,
        proposal: ActionProposal,
        engagement: Engagement,
        *,
        now: datetime,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> ExecutionReceipt:
        now = ensure_aware(now)
        is_cancelled = is_cancelled or (lambda: False)
        if proposal.action_id != CONTROLLED_HTTP_ACTION:
            raise ValueError("The controlled runner only accepts its closed HTTP action.")
        matching_assets = tuple(
            asset for asset in engagement.assets if asset.contains(proposal.target)
        )
        if not matching_assets or any(
            asset.contains(proposal.target) for asset in engagement.excluded_assets
        ):
            raise PermissionError("The controlled runner requires an exact in-scope target.")
        if any(asset.environment == Environment.PRODUCTION for asset in matching_assets):
            raise PermissionError(
                "The built-in controlled runner refuses production targets in v0.4."
            )
        port, path, timeout_seconds, change_reference = validate_controlled_parameters(
            proposal.parameters
        )
        if is_cancelled():
            return self._receipt(
                proposal,
                now=now,
                status=ExecutionStatus.CANCELLED,
                evidence={
                    "active_validation": True,
                    "network_activity": False,
                    "cancelled_before_connection": True,
                    "change_reference": change_reference,
                    "findings": [],
                },
            )
        try:
            response = self.transport.head(
                target=proposal.target,
                port=port,
                path=path,
                timeout_seconds=timeout_seconds,
            )
        except ProbeFailure as exc:
            return self._receipt(
                proposal,
                now=now,
                status=ExecutionStatus.FAILED,
                evidence={
                    "active_validation": True,
                    "network_activity": True,
                    "validation_completed": False,
                    "error_code": exc.code,
                    "error": exc.safe_message,
                    "change_reference": change_reference,
                    "response_body_collected": False,
                    "redirect_followed": False,
                    "findings": [],
                },
            )
        if is_cancelled():
            return self._receipt(
                proposal,
                now=now,
                status=ExecutionStatus.CANCELLED,
                evidence={
                    "active_validation": True,
                    "network_activity": True,
                    "cancelled_after_response_headers": True,
                    "change_reference": change_reference,
                    "response_body_collected": False,
                    "redirect_followed": False,
                    "findings": [],
                },
            )
        if response.status_code in {405, 501}:
            return self._receipt(
                proposal,
                now=now,
                status=ExecutionStatus.FAILED,
                evidence={
                    "active_validation": True,
                    "network_activity": True,
                    "validation_completed": False,
                    "error_code": "HTTP_HEAD_UNSUPPORTED",
                    "error": "The approved path did not support the bounded HEAD method.",
                    "change_reference": change_reference,
                    "response_status_code": response.status_code,
                    "response_body_collected": False,
                    "redirect_followed": False,
                    "findings": [],
                },
            )
        findings, observations = _analyze_response(
            proposal,
            engagement,
            response,
            now=now,
        )
        evidence = {
            "source": "bounded active validation",
            "active_validation": True,
            "network_activity": True,
            "validation_completed": True,
            "methodology_profile": METHODOLOGY_PROFILE,
            "methodology_references": [
                NIST_SP_800_115,
                TSE_PENETRATION_TESTING,
                OWASP_WSTG_HSTS,
                OWASP_WSTG_COOKIE_ATTRIBUTES,
            ],
            "change_reference": change_reference,
            "request": {
                "method": "HEAD",
                "port": port,
                "path": path,
                "request_count": 1,
            },
            "response": {
                "status_code": response.status_code,
                "tls_version": response.tls_version,
                "certificate_not_after": response.certificate_not_after,
                "peer_address_digest": sha256_digest(response.peer_address),
                **observations,
            },
            "response_body_collected": False,
            "redirect_followed": False,
            "findings": findings,
            "limitations": [
                "One approved path and one HEAD response were assessed.",
                "No exploit payload, authentication flow, response body, or business logic was tested.",
                "Every generated finding requires qualified human validation before issue.",
            ],
        }
        return self._receipt(
            proposal,
            now=now,
            status=ExecutionStatus.VALIDATED,
            evidence=evidence,
        )

    def _receipt(
        self,
        proposal: ActionProposal,
        *,
        now: datetime,
        status: ExecutionStatus,
        evidence: dict[str, Any],
    ) -> ExecutionReceipt:
        guard_result = self.evidence_guard.sanitize(evidence)
        guarded = {**guard_result.evidence, "data_guard": guard_summary(guard_result)}
        digest = sha256_digest(guarded)
        return ExecutionReceipt(
            execution_id="EXEC-" + sha256_digest(
                {
                    "proposal_digest": proposal.digest(),
                    "evidence_digest": digest,
                    "runner": self.name,
                }
            )[:16].upper(),
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.digest(),
            status=status,
            runner=self.name,
            started_at=now,
            finished_at=now,
            evidence=guarded,
            evidence_digest=digest,
        )


def validate_controlled_parameters(parameters: Any) -> tuple[int, str, int, str]:
    """Validate the complete scalar parameter contract before authorization."""
    port = parameters.get("port", 443)
    path = parameters.get("path", "/")
    timeout_seconds = parameters.get("timeout_seconds", 3)
    change_reference = parameters.get("change_reference")
    methodology = parameters.get("methodology_profile", METHODOLOGY_PROFILE)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("port must be an integer between 1 and 65535.")
    if (
        not isinstance(path, str)
        or len(path) > 200
        or not _SAFE_PATH.fullmatch(path)
        or ".." in path
        or "%2e" in path.casefold()
    ):
        raise ValueError("path must be a bounded absolute path without traversal or query data.")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 5
    ):
        raise ValueError("timeout_seconds must be an integer between 1 and 5.")
    if not isinstance(change_reference, str) or not change_reference.strip():
        raise ValueError("change_reference is required for controlled validation.")
    if methodology != METHODOLOGY_PROFILE:
        raise ValueError("Unknown controlled-validation methodology profile.")
    return port, path, timeout_seconds, change_reference.strip()


def _header_map(headers: tuple[tuple[str, str], ...]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for name, value in headers:
        result.setdefault(name.casefold(), []).append(value)
    return result


def _analyze_response(
    proposal: ActionProposal,
    engagement: Engagement,
    response: ProbeResponse,
    *,
    now: datetime,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    headers = _header_map(response.headers)
    findings: list[dict[str, Any]] = []
    confidence = "high" if response.status_code < 400 else "medium"

    def add(
        rule_id: str,
        title: str,
        severity: ValidationSeverity,
        summary: str,
        business_impact: str,
        recommendation: str,
        methodology_refs: tuple[str, ...],
    ) -> None:
        finding_id = "FRX-ACT-" + sha256_digest(
            {
                "engagement_id": engagement.engagement_id,
                "proposal_id": proposal.proposal_id,
                "target": proposal.target,
                "rule_id": rule_id,
            }
        )[:12].upper()
        findings.append(
            {
                "finding_id": finding_id,
                "rule_id": rule_id,
                "title": title,
                "severity": severity.value,
                "confidence": confidence,
                "affected_assets": [proposal.target],
                "summary": summary,
                "business_impact": business_impact,
                "recommendation": recommendation,
                "evidence_refs": [
                    f"evidence://{engagement.engagement_id}/proposal/"
                    f"{proposal.proposal_id}/{rule_id}"
                ],
                "control_refs": list(_COMMON_CONTROL_REFS),
                "methodology_refs": list(methodology_refs),
                "human_validation_required": True,
            }
        )

    hsts_values = headers.get("strict-transport-security", [])
    hsts_valid = any(
        re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9]\d*", value, re.IGNORECASE)
        for value in hsts_values
    )
    if not hsts_valid:
        add(
            "HTTP-HSTS-001",
            "HSTS is missing or ineffective on the assessed response",
            ValidationSeverity.MEDIUM,
            "The bounded HTTPS response did not contain an effective positive max-age directive.",
            "Users may be more exposed to downgrade or first-visit interception risks where HTTP remains reachable.",
            "Define an institution-approved HSTS policy, deploy it after dependency review, and retest the exact host.",
            (OWASP_WSTG_HSTS,),
        )

    if "content-security-policy" not in headers:
        add(
            "HTTP-CSP-001",
            "Content Security Policy was not observed",
            ValidationSeverity.LOW,
            "No Content-Security-Policy header was observed on the single assessed path.",
            "The browser has fewer policy-level restrictions if script or content injection is introduced elsewhere.",
            "Define and test a least-privilege CSP for the application; confirm coverage across authenticated and unauthenticated paths.",
            ("https://owasp.org/www-project-secure-headers/",),
        )

    if not any(value.casefold() == "nosniff" for value in headers.get("x-content-type-options", [])):
        add(
            "HTTP-NOSNIFF-001",
            "MIME sniffing protection was not observed",
            ValidationSeverity.LOW,
            "The assessed response did not set X-Content-Type-Options to nosniff.",
            "Some user agents may infer content types in ways that increase the impact of unsafe content handling.",
            "Return X-Content-Type-Options: nosniff consistently and verify content types for downloadable responses.",
            ("https://owasp.org/www-project-secure-headers/",),
        )

    cookie_gaps: list[dict[str, Any]] = []
    for value in headers.get("set-cookie", []):
        parts = [part.strip() for part in value.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else ""
        attributes = {
            part.split("=", 1)[0].strip().casefold() for part in parts[1:] if part
        }
        missing = sorted({"secure", "httponly", "samesite"} - attributes)
        if missing:
            cookie_gaps.append(
                {
                    "cookie_name_digest": sha256_digest(name),
                    "missing_attributes": missing,
                }
            )
    if cookie_gaps:
        add(
            "HTTP-COOKIE-001",
            "Cookie security attributes require review",
            ValidationSeverity.MEDIUM,
            f"{len(cookie_gaps)} cookie header(s) omitted one or more baseline security attributes.",
            "Session or state cookies may receive weaker transport, script-access, or cross-site request protections.",
            "Classify each cookie, apply Secure, HttpOnly and an appropriate SameSite policy where applicable, then retest authenticated flows.",
            (OWASP_WSTG_COOKIE_ATTRIBUTES,),
        )

    remaining_days = int(
        (response.certificate_not_after - now).total_seconds() // 86_400
    )
    if remaining_days < 0:
        add(
            "TLS-CERT-EXPIRED-001",
            "TLS certificate is expired",
            ValidationSeverity.CRITICAL,
            "The peer certificate expiry date precedes the controlled observation time.",
            "Clients may reject the service and users may be trained to bypass certificate warnings.",
            "Replace the certificate through the approved certificate lifecycle and verify the complete chain before service restoration.",
            (NIST_SP_800_115,),
        )
    elif remaining_days <= 30:
        add(
            "TLS-CERT-EXPIRY-001",
            "TLS certificate is close to expiry",
            ValidationSeverity.MEDIUM,
            f"The peer certificate had {remaining_days} whole day(s) remaining at observation time.",
            "An unplanned certificate expiry can interrupt customer and system-to-system access.",
            "Confirm automated renewal, ownership, monitoring and a tested replacement path before expiry.",
            (NIST_SP_800_115,),
        )

    observations = {
        "headers_observed": sorted(headers),
        "set_cookie_count": len(headers.get("set-cookie", [])),
        "cookie_attribute_gaps": cookie_gaps,
        "certificate_days_remaining": remaining_days,
        "location_header_present": "location" in headers,
    }
    return findings, observations


def receipt_to_security_findings(receipt: ExecutionReceipt) -> tuple[Any, ...]:
    """Convert validated receipt metadata into draft report findings.

    Importing the reporting types locally keeps the execution boundary independent
    from report rendering while still providing a deterministic hand-off.
    """

    if receipt.status != ExecutionStatus.VALIDATED:
        return ()
    from .reporting import (  # Local import avoids a reporting/execution cycle.
        FindingSeverity,
        SecurityFinding,
    )

    converted = []
    for item in receipt.evidence.get("findings", ()):
        converted.append(
            SecurityFinding(
                finding_id=str(item["finding_id"]),
                title=str(item["title"]),
                severity=FindingSeverity(str(item["severity"])),
                affected_assets=tuple(item["affected_assets"]),
                summary=str(item["summary"]),
                business_impact=str(item["business_impact"]),
                recommendation=str(item["recommendation"]),
                evidence_refs=tuple(item["evidence_refs"]),
                control_refs=tuple(item["control_refs"]),
            )
        )
    return tuple(converted)
