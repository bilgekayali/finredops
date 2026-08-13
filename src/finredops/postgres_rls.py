"""PostgreSQL row-level security and service-account isolated persistence.

Tenant selection is derived from the authenticated PostgreSQL ``session_user``
through an administrator-owned registry. Runtime roles cannot select an institution
with a client-controlled session variable. FinRedOps data tables use ENABLE + FORCE
ROW LEVEL SECURITY and runtime accounts must be non-superuser, non-BYPASSRLS roles
with no SET ROLE path to a privileged/bypass role.

The optional psycopg dependency is imported only when a live connection is opened.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .audit import AuditChain, GENESIS_HASH
from .crypto_provider import KmsHsmProvider
from .envelope import EnvelopeError, decrypt_json, encrypt_json, envelope_from_document
from .institution import InstitutionSecurityContext
from .models import canonical_json, ensure_aware, sha256_digest, to_primitive
from .store import PersistedSnapshot, PersistenceConflict

_PG_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_INSTITUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_ACCESS_MODES = frozenset({"read", "write"})
_TABLES = ("engagement_snapshots", "audit_events", "idempotency_records")


class PostgresSecurityError(RuntimeError):
    """Raised when PostgreSQL runtime isolation is absent or ambiguous."""


def _pg_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not _PG_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase PostgreSQL identifier up to 63 characters.")
    return value


def _institution_id(value: str) -> str:
    if not isinstance(value, str) or not _INSTITUTION_ID.fullmatch(value):
        raise ValueError("institution_id is not a valid bounded identifier.")
    return value


def _access_mode(value: str) -> str:
    if value not in _ACCESS_MODES:
        raise ValueError("access_mode must be 'read' or 'write'.")
    return value


def _qi(value: str) -> str:
    return '"' + _pg_identifier(value, "identifier") + '"'


def _ql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass(frozen=True, slots=True)
class PostgresRLSContract:
    """Identifiers and deterministic SQL for the FinRedOps PostgreSQL boundary."""

    schema_name: str = "finredops_secure"
    owner_role: str = "finredops_owner"
    reader_role: str = "finredops_reader"
    writer_role: str = "finredops_writer"

    def __post_init__(self) -> None:
        for name in ("schema_name", "owner_role", "reader_role", "writer_role"):
            _pg_identifier(getattr(self, name), name)
        if len({self.owner_role, self.reader_role, self.writer_role}) != 3:
            raise ValueError("PostgreSQL owner/reader/writer roles must be distinct.")

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.postgres-rls-contract.v1",
            "schema_name": self.schema_name,
            "owner_role": self.owner_role,
            "reader_role": self.reader_role,
            "writer_role": self.writer_role,
            "tenant_source": "session_user_registry",
            "runtime_roles_require_nobypassrls": True,
            "runtime_roles_require_no_privileged_set_role_path": True,
            "force_row_level_security": True,
            "tables": list(_TABLES),
        }
        return {**body, "contract_digest": sha256_digest(body)}

    def installation_sql(self) -> str:
        s = _qi(self.schema_name)
        owner = _qi(self.owner_role)
        reader = _qi(self.reader_role)
        writer = _qi(self.writer_role)
        contract_digest = self.as_dict()["contract_digest"]

        role_blocks = []
        for role_name in (self.owner_role, self.reader_role, self.writer_role):
            role_lit = _ql(role_name)
            role_ident = _qi(role_name)
            role_blocks.append(
                f"""DO $frx$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_lit}) THEN
        CREATE ROLE {role_ident}
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
            NOREPLICATION NOBYPASSRLS;
    ELSIF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = {role_lit}
          AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'Existing FinRedOps boundary role % has unsafe attributes', {role_lit};
    END IF;
END
$frx$;"""
            )

        table_specs = {
            "engagement_snapshots": """institution_id TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision > 0),
                snapshot_json TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
                created_at TIMESTAMPTZ NOT NULL,
                protection_mode TEXT NOT NULL CHECK (protection_mode = 'envelope_v1'),
                protection_key_id TEXT NOT NULL,
                PRIMARY KEY (institution_id, engagement_id, revision),
                UNIQUE (institution_id, engagement_id, snapshot_digest)""",
            "audit_events": """institution_id TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                event_json TEXT NOT NULL,
                event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
                previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
                protection_mode TEXT NOT NULL CHECK (protection_mode = 'envelope_v1'),
                protection_key_id TEXT NOT NULL,
                PRIMARY KEY (institution_id, engagement_id, sequence),
                UNIQUE (institution_id, engagement_id, event_hash)""",
            "idempotency_records": """institution_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                result_digest TEXT NOT NULL CHECK (length(result_digest) = 64),
                created_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (institution_id, idempotency_key)""",
        }

        create_tables: list[str] = []
        policies: list[str] = []
        grants: list[str] = []
        for table, columns in table_specs.items():
            qt = f"{s}.{_qi(table)}"
            create_tables.append(
                f"""CREATE TABLE IF NOT EXISTS {qt} (
                {columns}
);
ALTER TABLE {qt} OWNER TO {owner};
ALTER TABLE {qt} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {qt} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE {qt} FROM PUBLIC;"""
            )
            select_policy = _qi(f"{table}_tenant_select")
            insert_policy = _qi(f"{table}_tenant_insert")
            policies.append(
                f"""DROP POLICY IF EXISTS {select_policy} ON {qt};
CREATE POLICY {select_policy} ON {qt}
    FOR SELECT TO {reader}, {writer}
    USING (institution_id = {s}."current_institution"());

DROP POLICY IF EXISTS {insert_policy} ON {qt};
CREATE POLICY {insert_policy} ON {qt}
    FOR INSERT TO {writer}
    WITH CHECK (
        institution_id = {s}."current_institution"()
        AND {s}."current_access_mode"() = 'write'
    );"""
            )
            grants.append(
                f"""GRANT SELECT ON TABLE {qt} TO {reader}, {writer};
GRANT INSERT ON TABLE {qt} TO {writer};
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE {qt} FROM {reader}, {writer};"""
            )

        parts = [
            "BEGIN;",
            *role_blocks,
            f"""CREATE SCHEMA IF NOT EXISTS {s} AUTHORIZATION {owner};
ALTER SCHEMA {s} OWNER TO {owner};
REVOKE ALL ON SCHEMA {s} FROM PUBLIC;
GRANT USAGE ON SCHEMA {s} TO {reader}, {writer};

CREATE TABLE IF NOT EXISTS {s}."tenant_service_accounts" (
    role_name NAME PRIMARY KEY,
    institution_id TEXT NOT NULL,
    access_mode TEXT NOT NULL CHECK (access_mode IN ('read', 'write')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (institution_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{{0,199}}$')
);
ALTER TABLE {s}."tenant_service_accounts" OWNER TO {owner};
REVOKE ALL ON TABLE {s}."tenant_service_accounts" FROM PUBLIC;
REVOKE ALL ON TABLE {s}."tenant_service_accounts" FROM {reader}, {writer};

CREATE TABLE IF NOT EXISTS {s}."boundary_metadata" (
    metadata_key TEXT PRIMARY KEY,
    metadata_value TEXT NOT NULL
);
ALTER TABLE {s}."boundary_metadata" OWNER TO {owner};
REVOKE ALL ON TABLE {s}."boundary_metadata" FROM PUBLIC;
GRANT SELECT ON TABLE {s}."boundary_metadata" TO {reader}, {writer};
INSERT INTO {s}."boundary_metadata" (metadata_key, metadata_value)
VALUES ('contract_digest', {_ql(contract_digest)})
ON CONFLICT (metadata_key) DO UPDATE SET metadata_value = EXCLUDED.metadata_value;""",
            f"""CREATE OR REPLACE FUNCTION {s}."current_institution"()
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, {s}
AS $frxfn$
DECLARE
    resolved TEXT;
BEGIN
    SELECT tsa.institution_id INTO resolved
    FROM {s}."tenant_service_accounts" AS tsa
    WHERE tsa.role_name = session_user AND tsa.active;
    IF resolved IS NULL THEN
        RAISE EXCEPTION 'FinRedOps service account is not mapped to an active institution'
            USING ERRCODE = '42501';
    END IF;
    RETURN resolved;
END
$frxfn$;
ALTER FUNCTION {s}."current_institution"() OWNER TO {owner};
REVOKE ALL ON FUNCTION {s}."current_institution"() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION {s}."current_institution"() TO {reader}, {writer};

CREATE OR REPLACE FUNCTION {s}."current_access_mode"()
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, {s}
AS $frxfn$
DECLARE
    resolved TEXT;
BEGIN
    SELECT tsa.access_mode INTO resolved
    FROM {s}."tenant_service_accounts" AS tsa
    WHERE tsa.role_name = session_user AND tsa.active;
    IF resolved IS NULL THEN
        RAISE EXCEPTION 'FinRedOps service account has no active access mapping'
            USING ERRCODE = '42501';
    END IF;
    RETURN resolved;
END
$frxfn$;
ALTER FUNCTION {s}."current_access_mode"() OWNER TO {owner};
REVOKE ALL ON FUNCTION {s}."current_access_mode"() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION {s}."current_access_mode"() TO {reader}, {writer};""",
            *create_tables,
            f"""CREATE INDEX IF NOT EXISTS "idx_postgres_snapshot_latest"
    ON {s}."engagement_snapshots" (institution_id, engagement_id, revision DESC);""",
            *policies,
            *grants,
            "COMMIT;",
        ]
        return "\n\n".join(parts) + "\n"

    def register_service_account_sql(
        self, *, service_role: str, institution_id: str, access_mode: str
    ) -> str:
        service_role = _pg_identifier(service_role, "service_role")
        institution_id = _institution_id(institution_id)
        access_mode = _access_mode(access_mode)
        s = _qi(self.schema_name)
        service = _qi(service_role)
        reader = _qi(self.reader_role)
        writer = _qi(self.writer_role)
        owner = _qi(self.owner_role)
        grant_role = reader if access_mode == "read" else writer
        role_lit = _ql(service_role)
        owner_lit = _ql(self.owner_role)
        return f"""BEGIN;

DO $frx$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_lit}) THEN
        RAISE EXCEPTION 'Service role % does not exist; create the LOGIN role outside FinRedOps first', {role_lit};
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = {role_lit}
          AND (NOT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'Service role % has unsafe PostgreSQL attributes', {role_lit};
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_roles AS reachable
        WHERE reachable.rolname <> {role_lit}
          AND (
              reachable.rolsuper OR reachable.rolcreatedb OR reachable.rolcreaterole
              OR reachable.rolreplication OR reachable.rolbypassrls
              OR reachable.rolname = {owner_lit}
          )
          AND pg_has_role({role_lit}, reachable.oid, 'SET')
    ) THEN
        RAISE EXCEPTION 'Service role % can SET ROLE to a privileged or RLS-bypass role', {role_lit};
    END IF;
END
$frx$;

REVOKE {reader}, {writer}, {owner} FROM {service};
GRANT {grant_role} TO {service};

INSERT INTO {s}."tenant_service_accounts" (role_name, institution_id, access_mode, active)
VALUES ({role_lit}::name, {_ql(institution_id)}, {_ql(access_mode)}, TRUE)
ON CONFLICT (role_name) DO UPDATE
SET institution_id = EXCLUDED.institution_id,
    access_mode = EXCLUDED.access_mode,
    active = TRUE;

COMMIT;
"""

    def disable_service_account_sql(self, *, service_role: str) -> str:
        service_role = _pg_identifier(service_role, "service_role")
        s = _qi(self.schema_name)
        service = _qi(service_role)
        return f"""BEGIN;
UPDATE {s}."tenant_service_accounts"
SET active = FALSE
WHERE role_name = {_ql(service_role)}::name;
REVOKE {_qi(self.reader_role)}, {_qi(self.writer_role)} FROM {service};
COMMIT;
"""


@dataclass(frozen=True, slots=True)
class PostgresRuntimeAssessment:
    session_user: str
    current_user: str
    institution_id: str
    access_mode: str
    reader_member: bool
    writer_member: bool
    owner_member: bool
    rls_tables: tuple[str, ...]
    policy_count: int
    verified_at: datetime
    contract_digest: str

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.postgres-runtime-assessment.v1",
            "session_user": self.session_user,
            "current_user": self.current_user,
            "institution_id": self.institution_id,
            "access_mode": self.access_mode,
            "reader_member": self.reader_member,
            "writer_member": self.writer_member,
            "owner_member": self.owner_member,
            "rls_tables": list(self.rls_tables),
            "policy_count": self.policy_count,
            "verified_at": self.verified_at,
            "contract_digest": self.contract_digest,
            "database_rls_verified": True,
            "service_account_isolation_verified": True,
            "rls_bypass_role_verified_absent": True,
            "privileged_set_role_path_verified_absent": True,
        }
        return {**to_primitive(body), "assessment_digest": sha256_digest(body)}


def verify_postgres_connection(
    connection: Any,
    *,
    expected_institution_id: str,
    expected_access: str,
    contract: PostgresRLSContract | None = None,
    as_of: datetime,
) -> PostgresRuntimeAssessment:
    """Verify a live connection before FinRedOps uses it for tenant persistence."""

    expected_institution_id = _institution_id(expected_institution_id)
    expected_access = _access_mode(expected_access)
    contract = contract or PostgresRLSContract()
    s = _qi(contract.schema_name)

    with connection.cursor() as cursor:
        cursor.execute("SELECT session_user, current_user")
        session_user, current_user = cursor.fetchone()
        if session_user != current_user:
            raise PostgresSecurityError(
                "SET ROLE/current_user changes are not allowed on FinRedOps runtime connections."
            )

        cursor.execute(
            """SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
               FROM pg_roles WHERE rolname = session_user"""
        )
        flags = cursor.fetchone()
        if flags is None or any(bool(value) for value in flags):
            raise PostgresSecurityError(
                "Runtime service account must be NOSUPERUSER/NOCREATEDB/NOCREATEROLE/"
                "NOREPLICATION/NOBYPASSRLS."
            )

        cursor.execute(
            """SELECT reachable.rolname
               FROM pg_roles AS reachable
               WHERE reachable.rolname <> session_user
                 AND (
                     reachable.rolsuper OR reachable.rolcreatedb OR reachable.rolcreaterole
                     OR reachable.rolreplication OR reachable.rolbypassrls
                     OR reachable.rolname = %s
                 )
                 AND pg_has_role(session_user, reachable.oid, 'SET')
               ORDER BY reachable.rolname""",
            (contract.owner_role,),
        )
        reachable_unsafe_roles = tuple(str(row[0]) for row in cursor.fetchall())
        if reachable_unsafe_roles:
            raise PostgresSecurityError(
                "Runtime service account can SET ROLE to privileged/RLS-bypass role(s): "
                + ", ".join(reachable_unsafe_roles)
            )

        cursor.execute(
            "SELECT pg_has_role(session_user, %s, 'member'), "
            "pg_has_role(session_user, %s, 'member'), "
            "pg_has_role(session_user, %s, 'member')",
            (contract.reader_role, contract.writer_role, contract.owner_role),
        )
        reader_member, writer_member, owner_member = (bool(value) for value in cursor.fetchone())
        if owner_member:
            raise PostgresSecurityError("Runtime service account must not inherit the FinRedOps owner role.")
        if expected_access == "read":
            if not reader_member or writer_member:
                raise PostgresSecurityError("Read runtime requires reader membership only.")
        elif not writer_member or reader_member:
            raise PostgresSecurityError("Write runtime requires writer membership only.")

        cursor.execute(f"SELECT {s}.\"current_institution\"(), {s}.\"current_access_mode\"()")
        institution_id, access_mode = cursor.fetchone()
        if institution_id != expected_institution_id or access_mode != expected_access:
            raise PostgresSecurityError(
                "Service-account registry mapping does not match the expected tenant/access mode."
            )

        cursor.execute(
            f"SELECT metadata_value FROM {s}.\"boundary_metadata\" WHERE metadata_key = 'contract_digest'"
        )
        metadata = cursor.fetchone()
        contract_digest = contract.as_dict()["contract_digest"]
        if metadata is None or metadata[0] != contract_digest:
            raise PostgresSecurityError("Installed PostgreSQL boundary contract digest is stale or invalid.")

        cursor.execute(
            """SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
               FROM pg_class AS c
               JOIN pg_namespace AS n ON n.oid = c.relnamespace
               WHERE n.nspname = %s AND c.relname = ANY(%s)
               ORDER BY c.relname""",
            (contract.schema_name, list(_TABLES)),
        )
        rows = cursor.fetchall()
        if len(rows) != len(_TABLES):
            raise PostgresSecurityError("Required FinRedOps PostgreSQL tables are missing.")
        for table_name, row_security, force_row_security in rows:
            if not row_security or not force_row_security:
                raise PostgresSecurityError(f"PostgreSQL RLS is not forced for table {table_name!r}.")

        cursor.execute(
            """SELECT tablename, policyname, cmd
               FROM pg_policies
               WHERE schemaname = %s AND tablename = ANY(%s)
               ORDER BY tablename, policyname""",
            (contract.schema_name, list(_TABLES)),
        )
        policy_rows = cursor.fetchall()
        expected_policies = {
            (table, f"{table}_tenant_select", "SELECT") for table in _TABLES
        } | {
            (table, f"{table}_tenant_insert", "INSERT") for table in _TABLES
        }
        if not expected_policies.issubset(set(policy_rows)):
            raise PostgresSecurityError("Required FinRedOps tenant RLS policies are missing or changed.")

        for table in _TABLES:
            qualified = f"{contract.schema_name}.{table}"
            cursor.execute(
                "SELECT has_table_privilege(session_user, %s, 'SELECT'), "
                "has_table_privilege(session_user, %s, 'INSERT'), "
                "has_table_privilege(session_user, %s, 'UPDATE'), "
                "has_table_privilege(session_user, %s, 'DELETE')",
                (qualified, qualified, qualified, qualified),
            )
            can_select, can_insert, can_update, can_delete = (
                bool(value) for value in cursor.fetchone()
            )
            if not can_select or can_update or can_delete:
                raise PostgresSecurityError(
                    "Runtime table privileges exceed the FinRedOps persistence contract."
                )
            if can_insert != (expected_access == "write"):
                raise PostgresSecurityError(
                    "Runtime INSERT privilege does not match the registered access mode."
                )

    return PostgresRuntimeAssessment(
        session_user=str(session_user),
        current_user=str(current_user),
        institution_id=str(institution_id),
        access_mode=str(access_mode),
        reader_member=reader_member,
        writer_member=writer_member,
        owner_member=owner_member,
        rls_tables=tuple(sorted(str(row[0]) for row in rows)),
        policy_count=len(policy_rows),
        verified_at=ensure_aware(as_of),
        contract_digest=contract_digest,
    )


class VerifiedPostgresSession:
    """Live PostgreSQL session accepted only after catalog-backed isolation checks."""

    def __init__(
        self,
        connection: Any,
        assessment: PostgresRuntimeAssessment,
        contract: PostgresRLSContract,
    ) -> None:
        self.connection = connection
        self.assessment = assessment
        self.contract = contract

    @classmethod
    def connect(
        cls,
        dsn: str,
        *,
        expected_institution_id: str,
        expected_access: str,
        contract: PostgresRLSContract | None = None,
        as_of: datetime,
    ) -> "VerifiedPostgresSession":
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN must be a non-empty string.")
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover
            raise PostgresSecurityError(
                "PostgreSQL support requires the optional 'finredops[postgres]' dependency."
            ) from exc
        selected = contract or PostgresRLSContract()
        connection = psycopg.connect(dsn, autocommit=True)
        try:
            assessment = verify_postgres_connection(
                connection,
                expected_institution_id=expected_institution_id,
                expected_access=expected_access,
                contract=selected,
                as_of=as_of,
            )
        except Exception:
            connection.close()
            raise
        return cls(connection, assessment, selected)

    def require_access(self, access: str) -> None:
        access = _access_mode(access)
        if access == "write" and self.assessment.access_mode != "write":
            raise PostgresSecurityError("Verified PostgreSQL session is read-only.")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "VerifiedPostgresSession":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


class PostgresGovernanceStore:
    """Envelope-encrypted FinRedOps persistence behind verified PostgreSQL RLS."""

    def __init__(
        self,
        session: VerifiedPostgresSession,
        *,
        security_context: InstitutionSecurityContext,
        crypto_provider: KmsHsmProvider,
    ) -> None:
        if security_context.institution_id != session.assessment.institution_id:
            raise PostgresSecurityError(
                "Institution security context does not match the verified database tenant."
            )
        data_key = security_context.active_key("data_encryption")
        if crypto_provider.provider_name != data_key.provider:
            raise PostgresSecurityError(
                "Crypto provider does not match the institution data-encryption key."
            )
        self.session = session
        self.security_context = security_context
        self.crypto_provider = crypto_provider
        self.institution_id = security_context.institution_id
        self._schema = _qi(session.contract.schema_name)

    def _table(self, table: str) -> str:
        if table not in _TABLES:
            raise ValueError("Unknown PostgreSQL persistence table.")
        return f"{self._schema}.{_qi(table)}"

    def _protect_document(
        self, value: Any, *, object_type: str, object_id: str, now: datetime
    ) -> tuple[str, str]:
        envelope = encrypt_json(
            value,
            institution_context=self.security_context,
            provider=self.crypto_provider,
            object_type=object_type,
            object_id=object_id,
            created_at=ensure_aware(now),
        )
        return canonical_json(envelope.as_dict()), envelope.key_id

    def _unprotect_document(self, stored: str, *, object_type: str, object_id: str) -> Any:
        try:
            envelope = envelope_from_document(json.loads(stored))
            if envelope.object_type != object_type or envelope.object_id != object_id:
                raise PersistenceConflict("Encrypted PostgreSQL object binding is invalid.")
            return decrypt_json(
                envelope,
                institution_context=self.security_context,
                provider=self.crypto_provider,
            )
        except (EnvelopeError, json.JSONDecodeError) as exc:
            raise PersistenceConflict("Encrypted PostgreSQL content failed authentication.") from exc

    def _lock(self, cursor: Any, scope: str) -> None:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"finredops:{self.institution_id}:{scope}",),
        )

    def save_snapshot(
        self, snapshot: Mapping[str, Any], *, now: datetime
    ) -> PersistedSnapshot:
        self.session.require_access("write")
        now = ensure_aware(now)
        if snapshot.get("schema_version") != "finredops.snapshot.v2":
            raise ValueError("Only FinRedOps v2 snapshots can be persisted.")
        engagement = snapshot.get("engagement")
        if not isinstance(engagement, Mapping) or not engagement.get("engagement_id"):
            raise ValueError("Snapshot is missing its engagement identity.")
        engagement_id = str(engagement["engagement_id"])
        digest = sha256_digest(snapshot)
        table = self._table("engagement_snapshots")
        with self.session.connection.transaction():
            with self.session.connection.cursor() as cursor:
                self._lock(cursor, f"snapshot:{engagement_id}")
                cursor.execute(
                    f"""SELECT revision, snapshot_digest, created_at FROM {table}
                        WHERE institution_id = %s AND engagement_id = %s AND snapshot_digest = %s""",
                    (self.institution_id, engagement_id, digest),
                )
                existing = cursor.fetchone()
                if existing:
                    return PersistedSnapshot(
                        engagement_id=engagement_id,
                        revision=int(existing[0]),
                        snapshot_digest=str(existing[1]),
                        created_at=existing[2],
                        institution_id=self.institution_id,
                    )
                cursor.execute(
                    f"""SELECT COALESCE(MAX(revision), 0) + 1 FROM {table}
                        WHERE institution_id = %s AND engagement_id = %s""",
                    (self.institution_id, engagement_id),
                )
                revision = int(cursor.fetchone()[0])
                protected, key_id = self._protect_document(
                    snapshot,
                    object_type="snapshot",
                    object_id=f"{engagement_id}:{revision}",
                    now=now,
                )
                cursor.execute(
                    f"""INSERT INTO {table}
                        (institution_id, engagement_id, revision, snapshot_json, snapshot_digest,
                         created_at, protection_mode, protection_key_id)
                        VALUES (%s, %s, %s, %s, %s, %s, 'envelope_v1', %s)""",
                    (self.institution_id, engagement_id, revision, protected, digest, now, key_id),
                )
        return PersistedSnapshot(
            engagement_id=engagement_id,
            revision=revision,
            snapshot_digest=digest,
            created_at=now,
            institution_id=self.institution_id,
        )

    def load_latest(self, engagement_id: str) -> dict[str, Any] | None:
        self.session.require_access("read")
        table = self._table("engagement_snapshots")
        with self.session.connection.cursor() as cursor:
            cursor.execute(
                f"""SELECT revision, snapshot_json FROM {table}
                    WHERE institution_id = %s AND engagement_id = %s
                    ORDER BY revision DESC LIMIT 1""",
                (self.institution_id, engagement_id),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        value = self._unprotect_document(
            str(row[1]), object_type="snapshot", object_id=f"{engagement_id}:{int(row[0])}"
        )
        if not isinstance(value, dict):
            raise PersistenceConflict(
                "Persisted PostgreSQL snapshot plaintext is not a JSON object."
            )
        return value

    def list_engagements(self) -> tuple[dict[str, Any], ...]:
        self.session.require_access("read")
        table = self._table("engagement_snapshots")
        with self.session.connection.cursor() as cursor:
            cursor.execute(
                f"""SELECT DISTINCT ON (engagement_id)
                    engagement_id, revision, snapshot_digest, created_at,
                    protection_mode, protection_key_id
                    FROM {table} WHERE institution_id = %s
                    ORDER BY engagement_id, revision DESC""",
                (self.institution_id,),
            )
            rows = cursor.fetchall()
        keys = (
            "engagement_id", "revision", "snapshot_digest", "created_at",
            "protection_mode", "protection_key_id",
        )
        return tuple(dict(zip(keys, row)) for row in rows)

    def persist_audit_chain(self, engagement_id: str, chain: AuditChain) -> int:
        self.session.require_access("write")
        valid, errors = chain.verify()
        if not valid:
            raise ValueError("Cannot persist an invalid audit chain: " + " ".join(errors))
        if any(event.engagement_id != engagement_id for event in chain.events):
            raise ValueError("Audit chain contains an event for a different engagement.")
        incoming = [canonical_json(event) for event in chain.events]
        table = self._table("audit_events")
        with self.session.connection.transaction():
            with self.session.connection.cursor() as cursor:
                self._lock(cursor, f"audit:{engagement_id}")
                cursor.execute(
                    f"""SELECT sequence, event_json FROM {table}
                        WHERE institution_id = %s AND engagement_id = %s ORDER BY sequence""",
                    (self.institution_id, engagement_id),
                )
                rows = cursor.fetchall()
                for index, row in enumerate(rows):
                    sequence = int(row[0])
                    stored = self._unprotect_document(
                        str(row[1]),
                        object_type="audit_event",
                        object_id=f"{engagement_id}:{sequence}",
                    )
                    if index >= len(incoming) or canonical_json(stored) != incoming[index]:
                        raise PersistenceConflict(
                            "Persisted PostgreSQL audit history is not an exact prefix of the incoming chain."
                        )
                for event in chain.events[len(rows):]:
                    protected, key_id = self._protect_document(
                        to_primitive(event),
                        object_type="audit_event",
                        object_id=f"{engagement_id}:{event.sequence}",
                        now=event.timestamp,
                    )
                    cursor.execute(
                        f"""INSERT INTO {table}
                            (institution_id, engagement_id, sequence, event_json, event_hash,
                             previous_hash, protection_mode, protection_key_id)
                            VALUES (%s, %s, %s, %s, %s, %s, 'envelope_v1', %s)""",
                        (
                            self.institution_id, engagement_id, event.sequence, protected,
                            event.event_hash, event.previous_hash, key_id,
                        ),
                    )
        return len(incoming) - len(rows)

    def verify_persisted_audit(self, engagement_id: str) -> tuple[bool, tuple[str, ...]]:
        self.session.require_access("read")
        table = self._table("audit_events")
        with self.session.connection.cursor() as cursor:
            cursor.execute(
                f"""SELECT sequence, event_json FROM {table}
                    WHERE institution_id = %s AND engagement_id = %s ORDER BY sequence""",
                (self.institution_id, engagement_id),
            )
            rows = cursor.fetchall()
        if not rows:
            return False, (
                "No persisted PostgreSQL audit events exist for the engagement in this institution.",
            )
        try:
            documents = [
                canonical_json(
                    self._unprotect_document(
                        str(row[1]),
                        object_type="audit_event",
                        object_id=f"{engagement_id}:{int(row[0])}",
                    )
                )
                for row in rows
            ]
        except PersistenceConflict as exc:
            return False, (str(exc),)
        chain = AuditChain.from_jsonl("\n".join(documents))
        valid, errors = chain.verify()
        if chain.events and chain.events[0].previous_hash != GENESIS_HASH:
            return False, (*errors, "Persisted PostgreSQL audit chain does not begin at genesis.")
        if any(event.engagement_id != engagement_id for event in chain.events):
            return False, (
                *errors,
                "Persisted PostgreSQL audit chain contains a different engagement id.",
            )
        return valid and not errors, errors

    def record_idempotency(
        self,
        key: str,
        *,
        request: Mapping[str, Any],
        result: Mapping[str, Any],
        now: datetime,
    ) -> bool:
        self.session.require_access("write")
        if not 16 <= len(key) <= 128 or not all(
            character.isalnum() or character in "-_." for character in key
        ):
            raise ValueError("Idempotency key must contain 16 to 128 safe characters.")
        now = ensure_aware(now)
        request_digest = sha256_digest(request)
        result_digest = sha256_digest(result)
        table = self._table("idempotency_records")
        with self.session.connection.transaction():
            with self.session.connection.cursor() as cursor:
                self._lock(cursor, f"idempotency:{key}")
                cursor.execute(
                    f"""SELECT request_digest, result_digest FROM {table}
                        WHERE institution_id = %s AND idempotency_key = %s""",
                    (self.institution_id, key),
                )
                existing = cursor.fetchone()
                if existing:
                    if existing[0] != request_digest or existing[1] != result_digest:
                        raise PersistenceConflict(
                            "Idempotency key was reused for different content."
                        )
                    return False
                cursor.execute(
                    f"""INSERT INTO {table}
                        (institution_id, idempotency_key, request_digest, result_digest, created_at)
                        VALUES (%s, %s, %s, %s, %s)""",
                    (self.institution_id, key, request_digest, result_digest, now),
                )
        return True

    def metadata(self) -> dict[str, Any]:
        return {
            "backend": "postgresql",
            "institution_id": self.institution_id,
            "access_mode": self.session.assessment.access_mode,
            "database_rls_verified": True,
            "service_account_isolation_verified": True,
            "envelope_encryption_required": True,
            "runtime_assessment_digest": self.session.assessment.as_dict()["assessment_digest"],
        }

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "PostgresGovernanceStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
