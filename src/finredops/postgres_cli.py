"""CLI for PostgreSQL RLS installation and live runtime verification."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .postgres_rls import PostgresRLSContract, VerifiedPostgresSession

POSTGRES_COMMANDS = frozenset(
    {
        "postgres-rls-install-sql",
        "postgres-service-account-sql",
        "postgres-disable-service-account-sql",
        "verify-postgres-runtime",
    }
)


def _contract(args: argparse.Namespace) -> PostgresRLSContract:
    return PostgresRLSContract(
        schema_name=args.schema,
        owner_role=args.owner_role,
        reader_role=args.reader_role,
        writer_role=args.writer_role,
    )


def _add_contract_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--schema", default="finredops_secure")
    parser.add_argument("--owner-role", default="finredops_owner")
    parser.add_argument("--reader-role", default="finredops_reader")
    parser.add_argument("--writer-role", default="finredops_writer")


def _write_new(path: str, content: str) -> None:
    target = Path(path)
    if target.exists():
        raise SystemExit(f"Refusing to overwrite existing output: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("postgres-rls-install-sql")
    _add_contract_args(install)
    install.add_argument("--output", required=True)

    register = sub.add_parser("postgres-service-account-sql")
    _add_contract_args(register)
    register.add_argument("--service-role", required=True)
    register.add_argument("--institution", required=True)
    register.add_argument("--access", choices=("read", "write"), required=True)
    register.add_argument("--output", required=True)

    disable = sub.add_parser("postgres-disable-service-account-sql")
    _add_contract_args(disable)
    disable.add_argument("--service-role", required=True)
    disable.add_argument("--output", required=True)

    verify = sub.add_parser("verify-postgres-runtime")
    _add_contract_args(verify)
    verify.add_argument("--dsn-env", default="FINREDOPS_POSTGRES_DSN")
    verify.add_argument("--institution", required=True)
    verify.add_argument("--access", choices=("read", "write"), required=True)
    verify.add_argument("--output")
    return parser


def run_postgres_command(argv: Sequence[str]) -> int:
    args = _parser().parse_args(list(argv))
    contract = _contract(args)

    if args.command == "postgres-rls-install-sql":
        _write_new(args.output, contract.installation_sql())
        print(f"PostgreSQL RLS installation SQL: {args.output}")
        return 0

    if args.command == "postgres-service-account-sql":
        sql = contract.register_service_account_sql(
            service_role=args.service_role,
            institution_id=args.institution,
            access_mode=args.access,
        )
        _write_new(args.output, sql)
        print(f"PostgreSQL service-account mapping SQL: {args.output}")
        return 0

    if args.command == "postgres-disable-service-account-sql":
        _write_new(
            args.output,
            contract.disable_service_account_sql(service_role=args.service_role),
        )
        print(f"PostgreSQL service-account disable SQL: {args.output}")
        return 0

    dsn = os.environ.get(args.dsn_env)
    if not dsn:
        raise SystemExit(
            f"Environment variable {args.dsn_env!r} is required; DSNs are not accepted on the command line."
        )
    with VerifiedPostgresSession.connect(
        dsn,
        expected_institution_id=args.institution,
        expected_access=args.access,
        contract=contract,
        as_of=datetime.now(timezone.utc),
    ) as session:
        document = session.assessment.as_dict()
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        _write_new(args.output, rendered)
        print(f"Verified PostgreSQL runtime assessment: {args.output}")
    else:
        print(rendered, end="")
    return 0


def postgres_help() -> str:
    return """
PostgreSQL RLS / service-account commands:
  postgres-rls-install-sql            Write deterministic RLS/schema installation SQL
  postgres-service-account-sql        Write SQL binding one LOGIN role to one institution/access mode
  postgres-disable-service-account-sql Write SQL revoking and disabling a service-account mapping
  verify-postgres-runtime             Verify live PostgreSQL RLS and service-account isolation
"""
