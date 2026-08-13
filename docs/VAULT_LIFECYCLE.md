# Vault lifecycle

FinRedOps v0.9.0 introduces an institution-scoped encrypted evidence lifecycle. Records use the existing envelope-encryption boundary and append-only custody history. Retention may only move forward, legal holds are derived from history, and recovery preserves institution and cryptographic bindings.

The SQLite implementation is a reference backend and does not claim storage-level immutability or compliance certification.
