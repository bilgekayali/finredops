"""Command-line interface for the FinRedOps demonstration control plane."""

from __future__ import annotations

import argparse
from pathlib import Path

from .audit import AuditChain
from .dashboard import render_dashboard, serve_dashboard
from .demo import build_demo_service, write_demo


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finredops",
        description="Governance-first, simulation-only security testing orchestration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="Generate a synthetic dashboard and audit trail.")
    demo.add_argument("--output", type=Path, default=Path("demo-output"))
    verify = subparsers.add_parser("verify-audit", help="Verify a generated audit hash chain.")
    verify.add_argument("path", type=Path)
    serve = subparsers.add_parser("serve", help="Serve the synthetic dashboard locally.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def entrypoint(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        paths = write_demo(args.output)
        print(f"Dashboard: {paths['dashboard']}")
        print(f"Audit log: {paths['audit']}")
        print(f"Snapshot: {paths['snapshot']}")
        return 0
    if args.command == "verify-audit":
        chain = AuditChain.read(args.path)
        valid, errors = chain.verify()
        if valid:
            print(f"VALID: {len(chain.events)} audit events form an intact hash chain.")
            return 0
        for error in errors:
            print(f"INVALID: {error}")
        return 1
    if args.command == "serve":
        if not 1 <= args.port <= 65535:
            raise SystemExit("Port must be between 1 and 65535.")
        service, engagement_id = build_demo_service()
        serve_dashboard(
            render_dashboard(service.snapshot(engagement_id)),
            host=args.host,
            port=args.port,
        )
        return 0
    return 2
