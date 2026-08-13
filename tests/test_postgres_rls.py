from __future__ import annotations

import os
import unittest

from finredops.demo import build_demo_service
from finredops.postgres_rls import (
    PostgresGovernanceStore,
    PostgresRLSContract,
    PostgresSecurityError,
    VerifiedPostgresSession,
)

from tests.helpers import NOW
from tests.test_kms_envelope import MemoryInstitutionProvider, institution_context


class PostgresContractTests(unittest.TestCase):
    def test_installation_sql_uses_session_user_and_forced_rls(self) -> None:
        contract = PostgresRLSContract()
        sql = contract.installation_sql()
        self.assertIn("session_user", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertIn("NOBYPASSRLS", sql)
        self.assertIn("SECURITY DEFINER", sql)
        self.assertIn("protection_mode = 'envelope_v1'", sql)
        self.assertNotIn("set_config(", sql.lower())
        self.assertNotIn("current_setting(", sql.lower())
        self.assertEqual(len(contract.as_dict()["contract_digest"]), 64)

    def test_service_mapping_requires_existing_safe_login_role(self) -> None:
        contract = PostgresRLSContract()
        sql = contract.register_service_account_sql(
            service_role="bank_a_writer",
            institution_id="bank-a",
            access_mode="write",
        )
        self.assertIn("NOT rolcanlogin", sql)
        self.assertIn("rolbypassrls", sql)
        self.assertIn("GRANT \"finredops_writer\" TO \"bank_a_writer\"", sql)
        self.assertIn("'bank-a'", sql)
        with self.assertRaises(ValueError):
            contract.register_service_account_sql(
                service_role="unsafe;drop role x",
                institution_id="bank-a",
                access_mode="write",
            )

    def test_contract_rejects_ambiguous_roles(self) -> None:
        with self.assertRaises(ValueError):
            PostgresRLSContract(reader_role="finredops_writer")


@unittest.skipUnless(
    os.environ.get("FINREDOPS_TEST_POSTGRES_ADMIN_DSN"),
    "live PostgreSQL integration DSN is not configured",
)
class LivePostgresRLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import psycopg

        cls.psycopg = psycopg
        cls.contract = PostgresRLSContract()
        cls.admin_dsn = os.environ["FINREDOPS_TEST_POSTGRES_ADMIN_DSN"]
        cls.admin = psycopg.connect(cls.admin_dsn, autocommit=True)
        with cls.admin.cursor() as cursor:
            cursor.execute(cls.contract.installation_sql(), prepare=False)
            for role, password in (
                ("frx_a_reader", "frx-a-reader-test"),
                ("frx_a_writer", "frx-a-writer-test"),
                ("frx_b_writer", "frx-b-writer-test"),
            ):
                cursor.execute(
                    f"DROP ROLE IF EXISTS {role}"
                )
                cursor.execute(
                    f"CREATE ROLE {role} LOGIN PASSWORD %s "
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS",
                    (password,),
                )
            cursor.execute(
                cls.contract.register_service_account_sql(
                    service_role="frx_a_reader",
                    institution_id="bank-a",
                    access_mode="read",
                ),
                prepare=False,
            )
            cursor.execute(
                cls.contract.register_service_account_sql(
                    service_role="frx_a_writer",
                    institution_id="bank-a",
                    access_mode="write",
                ),
                prepare=False,
            )
            cursor.execute(
                cls.contract.register_service_account_sql(
                    service_role="frx_b_writer",
                    institution_id="bank-b",
                    access_mode="write",
                ),
                prepare=False,
            )
        cls.a_reader_dsn = cls._dsn("frx_a_reader", "frx-a-reader-test")
        cls.a_writer_dsn = cls._dsn("frx_a_writer", "frx-a-writer-test")
        cls.b_writer_dsn = cls._dsn("frx_b_writer", "frx-b-writer-test")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.admin.close()

    @classmethod
    def _dsn(cls, user: str, password: str) -> str:
        base = os.environ.get(
            "FINREDOPS_TEST_POSTGRES_RUNTIME_BASE",
            "host=127.0.0.1 port=5432 dbname=finredops",
        )
        return f"{base} user={user} password={password}"

    def _session(self, dsn: str, institution: str, access: str) -> VerifiedPostgresSession:
        return VerifiedPostgresSession.connect(
            dsn,
            expected_institution_id=institution,
            expected_access=access,
            contract=self.contract,
            as_of=NOW,
        )

    def test_live_catalog_verification_and_cross_tenant_rls(self) -> None:
        with self._session(self.a_writer_dsn, "bank-a", "write") as writer_a:
            assessment = writer_a.assessment.as_dict()
            self.assertTrue(assessment["database_rls_verified"])
            self.assertTrue(assessment["service_account_isolation_verified"])
            self.assertEqual(assessment["institution_id"], "bank-a")
            with writer_a.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO finredops_secure.idempotency_records
                       (institution_id, idempotency_key, request_digest, result_digest, created_at)
                       VALUES ('bank-a', 'rls-direct-test-0001', %s, %s, %s)
                       ON CONFLICT (institution_id, idempotency_key) DO NOTHING""",
                    ("a" * 64, "b" * 64, NOW),
                )
                with self.assertRaises(self.psycopg.Error):
                    cursor.execute(
                        """INSERT INTO finredops_secure.idempotency_records
                           (institution_id, idempotency_key, request_digest, result_digest, created_at)
                           VALUES ('bank-b', 'rls-cross-tenant-0001', %s, %s, %s)""",
                        ("c" * 64, "d" * 64, NOW),
                    )

        with self._session(self.b_writer_dsn, "bank-b", "write") as writer_b:
            with writer_b.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM finredops_secure.idempotency_records"
                )
                self.assertEqual(cursor.fetchone()[0], 0)

        with self._session(self.a_reader_dsn, "bank-a", "read") as reader_a:
            with reader_a.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM finredops_secure.idempotency_records"
                )
                self.assertGreaterEqual(cursor.fetchone()[0], 1)
                with self.assertRaises(self.psycopg.Error):
                    cursor.execute(
                        """INSERT INTO finredops_secure.idempotency_records
                           (institution_id, idempotency_key, request_digest, result_digest, created_at)
                           VALUES ('bank-a', 'reader-write-denied-01', %s, %s, %s)""",
                        ("e" * 64, "f" * 64, NOW),
                    )

    def test_verified_store_is_encrypted_and_tenant_scoped(self) -> None:
        provider = MemoryInstitutionProvider()
        context = institution_context("bank-a")
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)

        writer_session = self._session(self.a_writer_dsn, "bank-a", "write")
        with PostgresGovernanceStore(
            writer_session,
            security_context=context,
            crypto_provider=provider,
        ) as store:
            first = store.save_snapshot(snapshot, now=NOW)
            duplicate = store.save_snapshot(snapshot, now=NOW)
            self.assertEqual(first.revision, duplicate.revision)
            self.assertEqual(store.persist_audit_chain(engagement_id, service.audit), len(service.audit.events))
            self.assertTrue(
                store.record_idempotency(
                    "postgres-request-0001",
                    request={"tenant": "a"},
                    result={"ok": True},
                    now=NOW,
                )
            )
            self.assertTrue(store.metadata()["database_rls_verified"])

        reader_session = self._session(self.a_reader_dsn, "bank-a", "read")
        with PostgresGovernanceStore(
            reader_session,
            security_context=context,
            crypto_provider=provider,
        ) as store:
            self.assertEqual(store.load_latest(engagement_id), snapshot)
            self.assertEqual(store.verify_persisted_audit(engagement_id), (True, ()))

        with self.admin.cursor() as cursor:
            cursor.execute(
                """SELECT snapshot_json, protection_mode
                   FROM finredops_secure.engagement_snapshots
                   WHERE institution_id = 'bank-a' AND engagement_id = %s""",
                (engagement_id,),
            )
            stored, mode = cursor.fetchone()
            self.assertEqual(mode, "envelope_v1")
            self.assertNotIn('"engagement":', stored)

    def test_wrong_expected_tenant_and_access_fail_closed(self) -> None:
        with self.assertRaises(PostgresSecurityError):
            self._session(self.a_reader_dsn, "bank-b", "read")
        with self.assertRaises(PostgresSecurityError):
            self._session(self.a_reader_dsn, "bank-a", "write")


if __name__ == "__main__":
    unittest.main()
