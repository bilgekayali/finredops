# Evidence manifest and chain of custody

FinRedOps v0.3 records evidence metadata without becoming an evidence vault.
Raw screenshots, logs, source files, credentials, customer data and request or
response bodies stay in institution-owned storage.

Each artifact records:

- a stable evidence identifier and human title;
- an opaque `vault://`, `evidence://`, `attachment://` or
  `qualification-evidence://` locator;
- SHA-256 of the externally stored content, byte size and normalized MIME type;
- source system, collector and timezone-aware collection time;
- data classification, personal-data and sanitization flags;
- retention date and a safe description.

Custody activity is append-only and hash chained. Supported events are
registration, verification, access, transfer, supersession, legal-hold
application/release and disposal. An artifact must begin with exactly one
registration event bound to its metadata digest. Activity before collection,
after disposal, for another engagement or for an unknown artifact invalidates
the manifest.

```bash
python -m finredops validate-evidence-manifest evidence-manifest.json
```

SHA-256 chaining provides tamper evidence, not non-repudiation. Production use
still needs authenticated identities, institution-owned encryption and keys,
vault authorization, DLP, approved retention/disposal, legal hold, immutable
timestamps and external signature or anchoring controls.
