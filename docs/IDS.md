# Trooth stable identifiers

Version 1.1, October 7, 2026. Version 1.1 adds `cik` and `lei`.

One grammar names everything Trooth publishes about a reading, so a reference means the same thing in a statement, a bundle, an SDK, a log entry and a citation, and never depends on a URL that could move:

```
trooth:<type>:<value>
```

| Type | Value | Example | Names |
|---|---|---|---|
| `domain` | Lowercase ASCII domain (IDNA A-labels), no trailing dot | `trooth:domain:trooth.co` | The company record Trooth keeps for that domain |
| `reading` | The reading id a statement carries | `trooth:reading:rw_mux3srh0_ae207512e4b943d4` | One witness reading |
| `statement` | Lowercase hex SHA-256 of the exact payload bytes | `trooth:statement:6e72386f…0d65` | One signed statement, by content |
| `key` | A `kid` on https://api.trooth.co/public/keys | `trooth:key:trooth-master-2026-09` | One signing key |
| `mapping` | A check mapping version | `trooth:mapping:1.0.1` | The immutable document at https://trooth.co/standard/check-mapping/1.0.1.json |
| `cik` | The SEC Central Index Key, 10 digits with leading zeros | `trooth:cik:0000320193` | An SEC filer (EDGAR) |
| `lei` | An ISO 17442 Legal Entity Identifier: 20 characters, upper case (a checker also tests its ISO 7064 check digits) | `trooth:lei:HWUPKR0MPOU8FGXBT394` | A legal entity in the GLEIF register |
| `entity` | A lowercase UUID | `trooth:entity:00000000-0000-4000-8000-000000000000` | Reserved for the entity graph; not issued yet |

Rules:

- An id is compared as an exact string. `formatId` lowercases a domain and drops a trailing dot before it builds one; `parseId` accepts only the canonical form.
- A `statement` id is derived, not assigned: anyone holding the payload bytes computes the same id, and different bytes always give a different id.
- A `cik` or `lei` id names a registry entry. Whether it belongs to a domain is a separate question, answered with evidence in a public-record reading ([EVIDENCE.md](EVIDENCE.md)).
- An id names something; it asserts nothing about it. `trooth:domain:example.com` does not say the record exists, who controls the domain, or that anything in the record is true.
- A type not in this table is not a Trooth id. New types are added here first.

`bin/lib/ids.mjs` (`trooth/ids` in the npm package) implements this grammar, and a v3 statement names its subject with a `domain` id.
