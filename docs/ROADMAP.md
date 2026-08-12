# Roadmap

Roadmap items remain subject to the safety boundary and institutional review.

## v0.1 — governed simulation

- [x] typed scope and closed action catalog;
- [x] digest-bound two-person approval;
- [x] deterministic deny-by-default policy;
- [x] network-free synthetic runner;
- [x] hash-chained audit export and verifier;
- [x] self-contained operations dashboard;
- [x] security boundary, threat model, control mapping, and tests.

## v0.2 — durable assurance (current branch)

- [x] append-only SQLite snapshot revisions and audit-prefix verification;
- [x] financial-institution policy preflight;
- [x] deterministic evidence minimization and sensitive-data redaction;
- [x] read-only local API with security headers;
- [x] versioned BDDK, current SPK VII-128.10, KVKK and ISO/IEC crosswalk;
- [x] annual bank, vendor source-code and vendor application report templates;
- [x] mandatory coverage, finding ownership and retest-evidence validation;
- [x] JSON schemas and synthetic audit-support report package;
- [ ] signed identities using an external identity provider;
- [ ] tenant isolation and institution-owned encryption keys;
- [ ] key-backed approval and receipt signatures;
- [ ] immutable external audit anchoring;
- [ ] evidence-vault integration, retention, legal hold and deletion policy;
- [ ] policy bundle signatures and independent change approval;
- [ ] independent legal, accessibility and security review.

## Later — separately reviewed passive runner

A live adapter is not promised. Before any implementation, it would need a
separate threat model, legal and control review, signed workloads, strict
egress allowlisting, one-time credentials, isolated workers, bounded rate,
tested emergency stop, and a catalog limited to non-impacting collection.
Exploit delivery, credential attacks, arbitrary commands, and autonomous target
discovery remain out of scope.
