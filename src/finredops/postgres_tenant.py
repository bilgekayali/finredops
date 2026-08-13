"""Bridge authenticated tenant authorization to verified PostgreSQL persistence."""

from __future__ import annotations

from datetime import datetime

from .crypto_provider import KmsHsmProvider
from .postgres_rls import (
    PostgresGovernanceStore,
    PostgresRLSContract,
    VerifiedPostgresSession,
)
from .tenant_auth import AuthorizedTenantSession, TenantAuthorizationError


def open_authorized_postgres_store(
    tenant_session: AuthorizedTenantSession,
    dsn: str,
    *,
    access: str,
    crypto_provider: KmsHsmProvider,
    as_of: datetime,
    contract: PostgresRLSContract | None = None,
) -> PostgresGovernanceStore:
    """Open PostgreSQL only when application and database tenant boundaries agree.

    The institution id is never accepted as a caller argument. It is derived from
    the already verified ``AuthorizedTenantSession`` and must independently match
    the PostgreSQL ``session_user`` mapping verified by ``VerifiedPostgresSession``.
    """

    if access not in {"read", "write"}:
        raise TenantAuthorizationError("PostgreSQL access must be 'read' or 'write'.")
    tenant_session.require("store_read" if access == "read" else "store_write")
    db_session = VerifiedPostgresSession.connect(
        dsn,
        expected_institution_id=tenant_session.context.institution_id,
        expected_access=access,
        contract=contract,
        as_of=as_of,
    )
    try:
        return PostgresGovernanceStore(
            db_session,
            security_context=tenant_session.context,
            crypto_provider=crypto_provider,
        )
    except Exception:
        db_session.close()
        raise
