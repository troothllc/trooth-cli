# Trooth stable identifiers

Version 1.5, October 7, 2026. Version 1.5 adds `company`, `product` and `person`, and a second form of `key` for a company's own key, the subjects a public record reading names from Trooth's record of a claim and from a domain-signed declaration ([DECLARATION.md](DECLARATION.md)). Version 1.4 added `contact`, a contact a site publishes in security.txt, named as a `representative` subject in a public record reading. Version 1.3 added `jurisdiction`, `registry`, `uei`, `repo`, `api` and `mcp`, the subjects a public record reading or an MCP tool reading names. Version 1.2 defined `entity`. Version 1.1 added `cik` and `lei`.

One grammar names everything Trooth publishes about a reading, so a reference means the same thing in a statement, a bundle, an SDK, a log entry and a citation, and never depends on a URL that could move:

```
trooth:<type>:<value>
```

| Type | Value | Example | Names |
|---|---|---|---|
| `domain` | Lowercase ASCII domain (IDNA A-labels), no trailing dot | `trooth:domain:trooth.co` | The company record Trooth keeps for that domain |
| `reading` | The reading id a statement carries | `trooth:reading:rw_mux3srh0_ae207512e4b943d4` | One witness reading |
| `statement` | Lowercase hex SHA-256 of the exact payload bytes | `trooth:statement:6e72386f…0d65` | One signed statement, by content |
| `key` | A `kid` on https://api.trooth.co/public/keys, or (since 1.5) a domain, `#`, and the RFC 7638 JWK thumbprint of a company's own Ed25519 key, base64url | `trooth:key:trooth-master-2026-09`, `trooth:key:acme.com#kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` | One signing key: Trooth's, or a company's own key published in a declaration that checks ([DECLARATION.md](DECLARATION.md)) |
| `mapping` | A check mapping version | `trooth:mapping:1.0.1` | The immutable document at https://trooth.co/standard/check-mapping/1.0.1.json |
| `cik` | The SEC Central Index Key, 10 digits with leading zeros | `trooth:cik:0000320193` | An SEC filer (EDGAR) |
| `lei` | An ISO 17442 Legal Entity Identifier: 20 characters, upper case (a checker also tests its ISO 7064 check digits) | `trooth:lei:HWUPKR0MPOU8FGXBT394` | A legal entity in the GLEIF register |
| `entity` | `lei:` and an LEI, or `cik:` and a 10-digit CIK | `trooth:entity:lei:HWUPKR0MPOU8FGXBT394` | A legal entity, named by its own registry identifier: the LEI when a public record reading corroborates the LEI binding, otherwise the SEC CIK when that is corroborated. Trooth mints no number of its own for an entity, so anyone holding the LEI or CIK derives the same id. The UUID form reserved in version 1.0 was never issued |
| `jurisdiction` | An ISO 3166-1 alpha-2 country code, or an ISO 3166-2 subdivision code | `trooth:jurisdiction:US-DE` | A jurisdiction, as a registry records where an entity was formed |
| `registry` | An ISO 3166-2 code, a colon, and the entity's number in that state's business registry | `trooth:registry:US-NY:4986044` | One entry in a state business registry ([EVIDENCE.md](EVIDENCE.md) section 2.2) |
| `uei` | A SAM.gov Unique Entity ID, 12 characters, upper case | `trooth:uei:ABCDEFG12345` | One SAM.gov entity registration |
| `repo` | A code host and an owner, lower case | `trooth:repo:github.com/troothllc` | An organization or user on a code host |
| `api` | A host and an optional path, lower case, without scheme, query or fragment | `trooth:api:developer.nvidia.com` | A company's API or its documentation |
| `mcp` | A host and a path, lower case, without scheme, query or fragment | `trooth:mcp:api.trooth.co/public/mcp` | An MCP server endpoint ([EVIDENCE.md](EVIDENCE.md) section 9) |
| `company` | The slug of a company's Trooth record: 1 to 64 lowercase letters, digits and hyphens, not starting or ending with a hyphen | `trooth:company:acme` | The company record at https://trooth.co/network/company/acme. It names the record, not a legal entity |
| `product` | A domain (lower case), `/`, and a product id from that domain's signed declaration (`^[a-z0-9][a-z0-9-]{0,62}$`) | `trooth:product:acme.com/widget` | A product the domain's owner names in its signed declaration. Never inferred from a name match |
| `person` | 16 lowercase hexadecimal characters Trooth assigns | `trooth:person:3f9a0c2b7d1e4a65` | The representative Trooth recorded when the company claimed its record. The id carries no personal data and is not derived from a name or an address |
| `contact` | `mailto:` and an address with the domain lower case, or a host (lower case) and an optional path, without scheme, query, fragment or trailing slash | `trooth:contact:mailto:psirt@example.com`, `trooth:contact:security.example.com/report` | A contact a site publishes in security.txt ([EVIDENCE.md](EVIDENCE.md) section 10). It is a contact the site publishes, not a person authorized to act for the entity. Only `mailto:` and `https:` contacts are kept |

Rules:

- An id is compared as an exact string. `formatId` lowercases a domain (and a `company` slug, and the domain of a `product`) and drops a trailing dot before it builds one; for a `contact` it lowercases the mail domain, or turns an `https:` address into its host and path without query, fragment or trailing slash. `parseId` accepts only the canonical form.
- The `contact` value matches `^(?:mailto:[^\s?#@]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]|(?=.{1,500}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}(?:\/[^\s?#]*)?)$`. The local part of an address keeps its case, as mail does.
- A `statement` id is derived, not assigned: anyone holding the payload bytes computes the same id, and different bytes always give a different id.
- A `registry` or `uei` id that a reading found by searching a legal name is a name match; the reading says so beside it, and it is not an identification.
- A `cik` or `lei` id names a registry entry. Whether it belongs to a domain is a separate question, answered with evidence in a public-record reading ([EVIDENCE.md](EVIDENCE.md)).
- An id names something; it asserts nothing about it. `trooth:domain:example.com` does not say the record exists, who controls the domain, or that anything in the record is true.
- A `key` id of the form `<domain>#<thumbprint>` names a key the domain's site published; it says nothing about who holds it beyond that. Its thumbprint is the RFC 7638 SHA-256 over `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`.
- A `person` id names a representative only as Trooth recorded one at claim time; it does not establish that the person may act for the legal entity.
- A type not in this table is not a Trooth id. New types are added here first.

`bin/lib/ids.mjs` (`trooth/ids` in the npm package) implements this grammar, and a v3 statement names its subject with a `domain` id.
