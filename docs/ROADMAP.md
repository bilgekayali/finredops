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

## v0.2 — durable governance

- [ ] signed identities using an external identity provider;
- [ ] database-backed state machine with tenant isolation;
- [ ] key-backed approval and receipt signatures;
- [ ] immutable external audit anchoring;
- [ ] evidence encryption, retention, and deletion policy;
- [ ] policy-as-code bundles with independent change approval;
- [ ] accessibility and security review of the dashboard.

## Later — separately reviewed passive runner

A live adapter is not promised. Before any implementation, it would need a
separate threat model, legal and control review, signed workloads, strict
egress allowlisting, one-time credentials, isolated workers, bounded rate,
tested emergency stop, and a catalog limited to non-impacting collection.
Exploit delivery, credential attacks, arbitrary commands, and autonomous target
discovery remain out of scope.
