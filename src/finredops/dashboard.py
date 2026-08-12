"""Self-contained visual operations dashboard for a FinRedOps snapshot."""

from __future__ import annotations

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import Counter
from typing import Any, Mapping

from .catalog import ACTION_CATALOG


def _safe(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _short(value: str, length: int = 12) -> str:
    return _safe(value[:length])


def render_dashboard(snapshot: Mapping[str, Any]) -> str:
    engagement = snapshot["engagement"]
    proposals = list(snapshot.get("proposals", []))
    decisions = dict(snapshot.get("decisions", {}))
    receipts = dict(snapshot.get("receipts", {}))
    approvals = list(snapshot.get("approvals", []))
    audit = list(snapshot.get("audit", []))
    preflight = dict(snapshot.get("preflight", {}))
    regulatory_profile = dict(snapshot.get("regulatory_profile", {}))
    regulatory_controls = list(regulatory_profile.get("controls", []))
    authority_counts = Counter(item.get("authority", "OTHER") for item in regulatory_controls)
    assurance = dict(snapshot.get("assurance", {}))
    applicability = dict(assurance.get("applicability", {}))
    evidence_manifest = dict(assurance.get("evidence_manifest", {}))
    audit_bundle = dict(assurance.get("audit_bundle", {}))
    redactions = sum(
        int(receipt.get("evidence", {}).get("data_guard", {}).get("finding_count", 0))
        for receipt in receipts.values()
    )
    simulated = len(receipts)
    denied = sum(1 for decision in decisions.values() if not decision["allowed"])
    allowed = sum(1 for decision in decisions.values() if decision["allowed"])
    coverage = min(100, round((len(approvals) / max(1, 2 + len(proposals) * 2)) * 100))
    applicability_state = (
        "AUDIT READY" if applicability.get("ready_for_audit") else "NEEDS REVIEW"
    )
    evidence_state = (
        f"{len(evidence_manifest.get('artifacts', []))} ITEMS · "
        f"{'VALID' if evidence_manifest.get('valid') else 'UNVERIFIED'}"
    )
    if audit_bundle.get("built"):
        dossier_state = (
            "VERIFIED · REVIEW"
            if audit_bundle.get("verification_valid")
            else "VERIFICATION FAILED"
        )
    else:
        dossier_state = "NOT BUILT"

    scope_cards = "".join(
        f"""
        <div class="asset">
          <div><span class="dot"></span><strong>{_safe(asset['value'])}</strong></div>
          <span class="tag">{_safe(asset['environment'])}</span>
          <p>{_safe(asset['critical_function'])} · {_safe(asset['data_classification'])}</p>
        </div>"""
        for asset in engagement["assets"]
    )
    excluded_cards = "".join(
        f'<span class="excluded">⊘ {_safe(asset["value"])}</span>'
        for asset in engagement["excluded_assets"]
    )

    action_rows = []
    for proposal in proposals:
        proposal_id = proposal["proposal_id"]
        definition = ACTION_CATALOG[proposal["action_id"]]
        decision = decisions.get(proposal_id)
        receipt = receipts.get(proposal_id)
        if receipt:
            state, state_class = "SIMULATED", "ok"
            evidence = _short(receipt["evidence_digest"])
        elif decision and not decision["allowed"]:
            state, state_class = "DENIED", "deny"
            evidence = "—"
        else:
            state, state_class = "PENDING", "pending"
            evidence = "—"
        reason = decision["reasons"][0] if decision else "Awaiting policy evaluation."
        action_rows.append(
            f"""
            <tr>
              <td><strong>{_safe(definition.name)}</strong><small>{_safe(proposal['action_id'])}</small></td>
              <td>{_safe(proposal['target'])}</td>
              <td><span class="risk">{_safe(definition.risk_level.value)}</span></td>
              <td><span class="state {state_class}">{state}</span></td>
              <td class="mono" title="{_safe(reason)}">{evidence}</td>
            </tr>"""
        )

    event_rows = "".join(
        f"""
        <li>
          <span class="event-icon">{int(event['sequence']):02d}</span>
          <div><strong>{_safe(event['event_type'].replace('.', ' · '))}</strong>
          <p>{_safe(event['actor_id'])} · {_safe(event['timestamp'])}</p></div>
          <code>{_short(event['event_hash'], 10)}</code>
        </li>"""
        for event in audit[-8:][::-1]
    )

    template = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>FinRedOps · Governed Operations</title>
  <style>
    :root{--bg:#07100e;--panel:#0d1916;--panel2:#10221d;--line:#203b33;--text:#e9f8f1;--muted:#85a59a;--mint:#68f5b5;--lime:#c9ff67;--red:#ff7f75;--amber:#ffc764}
    *{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 85% 0,#12372c 0,transparent 28%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}
    .shell{display:grid;grid-template-columns:230px minmax(0,1fr);min-height:100vh}.side{border-right:1px solid var(--line);padding:26px 20px;background:#08130ff2;position:sticky;top:0;height:100vh}.brand{font-size:21px;font-weight:760;letter-spacing:-.5px}.brand b{color:var(--mint)}.version{font:11px ui-monospace,monospace;color:var(--muted);margin:5px 0 34px}.nav{display:grid;gap:6px}.nav span{padding:10px 12px;color:var(--muted);border-radius:8px}.nav .active{background:#173128;color:var(--text);box-shadow:inset 2px 0 var(--mint)}.boundary{position:absolute;bottom:26px;left:20px;right:20px;border:1px solid #4c4430;background:#1d1b12;padding:12px;border-radius:9px;color:var(--amber);font-size:11px;letter-spacing:.08em}.main{padding:28px clamp(20px,4vw,56px);max-width:1500px;width:100%}.top{display:flex;justify-content:space-between;align-items:start;gap:20px;margin-bottom:26px}.eyebrow{color:var(--mint);font-size:11px;font-weight:700;letter-spacing:.13em;text-transform:uppercase}.top h1{font-size:30px;line-height:1.15;margin:7px 0 5px;letter-spacing:-.8px}.sub{color:var(--muted)}.status{border:1px solid #2f6c58;background:#10251e;padding:9px 12px;border-radius:99px;color:var(--mint);font-weight:700;font-size:12px;white-space:nowrap}.grid{display:grid;gap:16px}.metrics{grid-template-columns:repeat(4,1fr);margin-bottom:16px}.metric,.panel{border:1px solid var(--line);background:linear-gradient(145deg,#10201b,#0b1714);border-radius:12px}.metric{padding:17px}.metric p{color:var(--muted);margin:0;font-size:12px}.metric strong{display:block;font-size:27px;margin-top:4px;letter-spacing:-.7px}.metric em{font-style:normal;color:var(--mint);font-size:11px}.assurance-strip{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;border:1px solid var(--line);background:var(--line);border-radius:10px;overflow:hidden;margin-bottom:16px}.assurance-strip div{background:#0b1714;padding:12px 14px}.assurance-strip span{display:block;color:var(--muted);font-size:10px}.assurance-strip b{font:11px ui-monospace,monospace;color:var(--lime)}.two{grid-template-columns:1.05fr .95fr;margin-bottom:16px}.panel{padding:20px}.panel-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}.panel h2{font-size:14px;margin:0}.panel-head span{color:var(--muted);font-size:11px}.asset{padding:12px 0;border-top:1px solid var(--line)}.asset:first-of-type{border-top:0}.dot{width:7px;height:7px;background:var(--mint);box-shadow:0 0 10px var(--mint);border-radius:50%;display:inline-block;margin-right:8px}.tag,.risk{float:right;border:1px solid var(--line);border-radius:99px;padding:2px 7px;color:var(--muted);font-size:10px}.asset p{margin:5px 0 0 15px;color:var(--muted);font-size:11px}.exclusions{margin-top:11px;padding-top:12px;border-top:1px solid var(--line)}.excluded{display:inline-block;margin:4px 5px 0 0;color:var(--red);background:#2b1715;border-radius:5px;padding:4px 7px;font-size:10px}.gauge{height:8px;border-radius:10px;background:#1c302a;overflow:hidden;margin:14px 0 9px}.gauge b{display:block;height:100%;width:__COVERAGE__%;background:linear-gradient(90deg,var(--mint),var(--lime))}.approval-list{display:grid;gap:8px;margin-top:16px}.approval-list div{display:flex;justify-content:space-between;padding:9px 11px;background:#0a1512;border-radius:7px;color:var(--muted);font-size:12px}.approval-list b{color:var(--text)}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:760px}th{text-align:left;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-size:9px;padding:10px;border-bottom:1px solid var(--line)}td{padding:13px 10px;border-bottom:1px solid #183027}td small{display:block;color:var(--muted);margin-top:3px}.risk{float:none}.state{font-size:9px;letter-spacing:.1em;font-weight:800;border-radius:4px;padding:4px 7px}.state.ok{color:var(--mint);background:#123426}.state.deny{color:var(--red);background:#321b18}.state.pending{color:var(--amber);background:#302713}.mono,code{font:11px ui-monospace,SFMono-Regular,monospace;color:var(--muted)}.lower{grid-template-columns:1.2fr .8fr;margin-top:16px}.timeline{list-style:none;margin:0;padding:0}.timeline li{display:grid;grid-template-columns:30px 1fr auto;gap:10px;align-items:center;padding:9px 0;border-top:1px solid var(--line)}.timeline li:first-child{border-top:0}.timeline p{margin:2px 0 0;color:var(--muted);font-size:10px}.event-icon{width:25px;height:25px;display:grid;place-items:center;border-radius:50%;background:#183329;color:var(--mint);font:9px ui-monospace,monospace}.controls{display:grid;grid-template-columns:1fr 1fr;gap:9px}.control{padding:12px;border:1px solid var(--line);border-radius:8px;background:#0a1512}.control b{display:block;color:var(--lime);font:11px ui-monospace,monospace}.control span{color:var(--muted);font-size:11px}.foot{color:var(--muted);font-size:10px;margin-top:18px;text-align:right}
    @media(max-width:900px){.shell{grid-template-columns:1fr}.side{height:auto;position:static;border-right:0;border-bottom:1px solid var(--line)}.nav,.boundary{display:none}.version{margin-bottom:0}.metrics,.two,.lower,.assurance-strip{grid-template-columns:1fr 1fr}}
    @media(max-width:600px){.metrics,.two,.lower{grid-template-columns:1fr}.main{padding:20px}.top{display:block}.status{display:inline-block;margin-top:12px}}
  </style>
</head>
<body>
<div class="shell">
  <aside class="side"><div class="brand">Fin<b>RedOps</b></div><div class="version">ASSURANCE CONTROL PLANE · v0.3</div><div class="nav"><span class="active">Operations</span><span>Engagements</span><span>Approvals</span><span>Evidence</span><span>Regulatory reports</span><span>Audit chain</span></div><div class="boundary">● SIMULATION-ONLY RUNNER<br>No network or shell capability</div></aside>
  <main class="main">
    <header class="top"><div><div class="eyebrow">Governed security validation</div><h1>__NAME__</h1><div class="sub">__ENGAGEMENT_ID__ · digest __DIGEST__</div></div><div class="status">● __PREFLIGHT__ · __STATUS__</div></header>
    <section class="grid metrics"><div class="metric"><p>Approved scope</p><strong>__ASSETS__</strong><em>exact assets</em></div><div class="metric"><p>Proposed actions</p><strong>__PROPOSALS__</strong><em>closed catalog</em></div><div class="metric"><p>Simulated safely</p><strong>__SIMULATED__</strong><em>zero network calls</em></div><div class="metric"><p>Policy denials</p><strong>__DENIED__</strong><em>fail closed</em></div></section>
    <section class="assurance-strip"><div><span>Institution profile</span><b>__POLICY_PROFILE__</b></div><div><span>Regulatory profile</span><b>__REG_CONTROLS__ CONTROLS · __REG_PROFILE__</b></div><div><span>Applicability</span><b>__APPLICABILITY__</b></div><div><span>Evidence custody</span><b>__EVIDENCE_MANIFEST__</b></div><div><span>Audit dossier</span><b>__DOSSIER__</b></div></section>
    <section class="grid two"><article class="panel"><div class="panel-head"><h2>Scope lock</h2><span>Allowlist + explicit exclusions</span></div>__SCOPE__<div class="exclusions">__EXCLUSIONS__</div></article><article class="panel"><div class="panel-head"><h2>Approval integrity</h2><span>Digest-bound and time-limited</span></div><strong>__COVERAGE__% control coverage</strong><div class="gauge"><b></b></div><div class="approval-list"><div>Engagement separation <b>2 roles</b></div><div>Proposal separation <b>2 roles / action</b></div><div>Authorized decisions <b>__ALLOWED__</b></div><div>Emergency stop <b>READY</b></div></div></article></section>
    <section class="panel"><div class="panel-head"><h2>Action control queue</h2><span>Every decision is visible and attributable</span></div><div class="table-wrap"><table><thead><tr><th>Catalog action</th><th>Exact target</th><th>Risk</th><th>Decision</th><th>Evidence hash</th></tr></thead><tbody>__ACTION_ROWS__</tbody></table></div></section>
    <section class="grid lower"><article class="panel"><div class="panel-head"><h2>Tamper-evident audit trail</h2><span>SHA-256 hash chain · __EVENTS__ events</span></div><ol class="timeline">__EVENT_ROWS__</ol></article><article class="panel"><div class="panel-head"><h2>Türkiye regulatory assurance</h2><span>Source-linked mapping, not certification</span></div><div class="controls"><div class="control"><b>BDDK · __BDDK__</b><span>BSEBY + 2012/1 scope</span></div><div class="control"><b>SPK · __SPK__</b><span>Current VII-128.10</span></div><div class="control"><b>KVKK · __KVKK__</b><span>Article 12 + security guide</span></div><div class="control"><b>TSE · __TSE__</b><span>TS 13638/T2 + current scope</span></div><div class="control"><b>ISO/IEC · __ISO__</b><span>27001:2022 mapped objectives</span></div></div></article></section>
    <p class="foot">Synthetic audit-support demonstration · legal/compliance sign-off and licensed TSE/ISO text remain mandatory</p>
  </main>
</div>
</body></html>"""
    replacements = {
        "__COVERAGE__": str(coverage),
        "__NAME__": _safe(engagement["name"]),
        "__ENGAGEMENT_ID__": _safe(engagement["engagement_id"]),
        "__DIGEST__": _short(snapshot["engagement_digest"], 14),
        "__STATUS__": _safe(engagement["status"]).upper(),
        "__PREFLIGHT__": "PREFLIGHT PASS" if preflight.get("allowed") else "PREFLIGHT BLOCKED",
        "__POLICY_PROFILE__": _safe(snapshot.get("policy_profile", {}).get("profile_id", "unknown")),
        "__REG_PROFILE__": _safe(regulatory_profile.get("profile_id", "unknown")),
        "__REG_CONTROLS__": str(len(regulatory_controls)),
        "__APPLICABILITY__": applicability_state,
        "__EVIDENCE_MANIFEST__": evidence_state,
        "__DOSSIER__": dossier_state,
        "__REDACTIONS__": str(redactions),
        "__BDDK__": str(authority_counts.get("BDDK", 0)),
        "__SPK__": str(authority_counts.get("SPK", 0)),
        "__KVKK__": str(authority_counts.get("KVKK", 0)),
        "__TSE__": str(authority_counts.get("TSE", 0)),
        "__ISO__": str(authority_counts.get("ISO/IEC", 0)),
        "__ASSETS__": str(len(engagement["assets"])),
        "__PROPOSALS__": str(len(proposals)),
        "__SIMULATED__": str(simulated),
        "__DENIED__": str(denied),
        "__SCOPE__": scope_cards,
        "__EXCLUSIONS__": excluded_cards,
        "__ALLOWED__": str(allowed),
        "__ACTION_ROWS__": "".join(action_rows),
        "__EVENTS__": str(len(audit)),
        "__EVENT_ROWS__": event_rows,
    }
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    return template


def serve_dashboard(document: str, *, host: str, port: int) -> None:
    content = document.encode("utf-8")

    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path not in {"/", "/index.html"}:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"FinRedOps synthetic dashboard: http://{host}:{port}")
    print("Simulation-only: the server does not contact proposal targets.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
