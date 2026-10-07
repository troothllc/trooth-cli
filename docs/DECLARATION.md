# The domain-signed declaration

Version 1.0, October 7, 2026. Normative for `trooth.declaration.v1` ([schema](../schemas/declaration.v1.schema.json)), `trooth declare` and `trooth/declaration` (bin/lib/declaration.mjs). Added in trooth 0.14.0.

A company can publish, on its own site, one small document signed with its own key. It names that key, the company's products, its APIs (with the hash of an MCP server's tool manifest) and its code repositories. Trooth reads it as part of a public record reading, signs and logs that reading, and carries what checked into the record's subjects and proofs ([EVIDENCE.md](EVIDENCE.md) section 11).

## 1. Where it lives

```
https://<domain>/.well-known/trooth.json
```

- Served over HTTPS from the domain itself, with status 200. A redirect, to any host, means the document is not read: it is reported as invalid.
- At most 64 KB (65,536 bytes).
- The document's `domain` equals the host it is served from. A subdomain serves its own document, naming itself.
- No URL inside it is ever fetched, by the CLI or by Trooth. URLs are checked as text.

## 2. The format

```json
{
  "format": "trooth.declaration.v1",
  "domain": "acme.com",
  "issued_at": "2026-10-07T00:00:00Z",
  "expires_at": "2027-10-07T00:00:00Z",
  "record": "https://trooth.co/network/company/acme",
  "keys": [ { "kid": "acme.com#<thumbprint>", "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" } ],
  "products": [ { "id": "widget", "name": "Widget", "url": "https://acme.com/widget" } ],
  "apis": [ { "base_url": "https://api.acme.com", "mcp": { "url": "https://api.acme.com/mcp", "manifest_sha256": "<64 hex>" } } ],
  "repositories": [ "https://github.com/acme" ],
  "signature": { "kid": "acme.com#<thumbprint>", "alg": "Ed25519", "canonicalization": "RFC8785", "value": "ed25519:<base64>" }
}
```

A declaration checks when every rule below holds. `trooth declare check` and `checkDeclaration` apply all of them; the first that fails is the reason, and every failure is listed.

1. Size and syntax: at most 64 KB, valid JSON, a JSON object, with no member outside the ones above. Numbers are not used; a fraction has no form under the RFC 8785 profile ([VERIFY.md](VERIFY.md) section 2.1) and fails.
2. `format` is `trooth.declaration.v1`.
3. `domain` is a lowercase domain name and equals the host the document was served from. (Read from a file, the host is not known; `--domain` requires one, and without it this rule is reported as not checked.)
4. `issued_at` and `expires_at` are ISO 8601 times in UTC; `expires_at` is after `issued_at` and at most 400 days after it; `issued_at` is not more than five minutes in the future.
5. `record`, when present, is `https://trooth.co/network/company/<slug>`: the company's Trooth record, and the one URL not on the domain.
6. `keys` holds one to eight Ed25519 public keys as JWKs (RFC 8037), each with exactly `kid`, `kty` (`OKP`), `crv` (`Ed25519`) and `x` (32 bytes, base64url). A key with `d`, a private key, fails. Each `kid` is `<domain>#<thumbprint>`, where the thumbprint is the RFC 7638 JWK thumbprint: SHA-256 over `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`, base64url without padding. No `kid` repeats.
7. Every URL in `products` and `apis` (including `mcp.url`) is `https`, with no user name, password, port or fragment, on the domain or a subdomain of it. `products[].id` matches `^[a-z0-9][a-z0-9-]{0,62}$` and is unique; `name` is 1 to 200 characters. `mcp.manifest_sha256` is 64 lowercase hex characters (the manifest hash of [EVIDENCE.md](EVIDENCE.md) section 9). At most 100 entries in each list.
8. `repositories` are organizations or users on github.com, gitlab.com, bitbucket.org or codeberg.org: `https://<host>/<owner>`.
9. `signature.alg` is `Ed25519`, `canonicalization` is `RFC8785`, `kid` is one of `keys`, and `value` (`ed25519:` and base64) is a valid Ed25519 signature by that key over the RFC 8785 canonical bytes of the document with the `signature` member removed.
10. When all of the above hold and `expires_at` has passed, the declaration is `expired`, not `checked`.

Only a declaration that checks carries anything into a record's subjects. One that is invalid or expired carries nothing but its status and reason.

## 3. Publishing one

```
trooth declare init --domain acme.com
trooth declare sign --domain acme.com --key ~/.trooth/declaration-key/acme.com.jwk \
  --record https://trooth.co/network/company/acme \
  --product widget=Widget=https://acme.com/widget \
  --api https://api.acme.com,https://api.acme.com/mcp,<manifest sha256> \
  --repo https://github.com/acme \
  --out trooth.json
trooth declare check --file trooth.json --domain acme.com
```

Then serve `trooth.json` at `https://acme.com/.well-known/trooth.json`, and run `trooth declare check acme.com`.

- `init` makes an Ed25519 key with node:crypto and writes it as a private JWK to `--key`, by default `~/.trooth/declaration-key/<domain>.jwk`, with mode 0600 in a directory with mode 0700. It never overwrites a file. It prints the path, the `kid` and the DNS pin line; it never prints the private key.
- `sign` writes the signed document to `--out` (never overwriting). The validity is `--days`, 365 by default and at most 400. `--product`, `--api`, `--repo` and `--add-key` repeat. It checks the result against every rule before writing, and refuses (exit 2) what would not check, such as a product URL on another host. It prints where to publish the document and the TXT line for the pin.
- `check <domain>` fetches the document (no redirects, 64 KB, the CLI's deadline), checks every rule, and reads the pin over DNS over HTTPS. `check --file <path>` checks a saved copy. `--no-dns` skips the pin; `--json` prints one JSON document.

Keep the key file off shared machines and out of repositories. Anyone holding it can sign a declaration for the domain; but only someone who controls the site's content can publish one there.

## 4. The DNS pin

A TXT record at `_trooth-key.<domain>` whose value is `trooth-key=<thumbprint>` names the key in the zone:

```
_trooth-key.acme.com TXT "trooth-key=kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
```

It is optional. When it is present and names a key in a declaration that checks, the key is bound to the zone by `dns_txt` as well as to the web server by `domain_signed_declaration`: two proofs, through two different systems an attacker would have to control. When it names a key the declaration does not list, `trooth declare check` reports it and exits 9. The CLI reads it from `https://cloudflare-dns.com/dns-query` (`application/dns-json`; `TROOTH_DOH` names another endpoint). A DNS answer that cannot be read is reported as not read and does not change the exit code.

## 5. What it shows, and what it does not

A declaration is self-signed. What one that checks shows is that whoever controlled the site's content when it was read published this key and these subjects. With the pin, the same holds for whoever controlled the DNS zone.

It does not establish the legal entity behind the domain, a person's authority to act for it, that the products exist or do what their names say, that the APIs are safe to call, or that the company controls the repositories it lists (the `repository_control` proof is a separate reading of the code host). A site that is taken over can publish a new declaration with a new key.

What Trooth adds is continuity. Each reading of the declaration is signed and logged, so the first key Trooth saw and every later change are public: the record's continuity events `declaration_appeared`, `declaration_key_changed` and `declaration_disappeared` ([EVIDENCE.md](EVIDENCE.md) section 11). A reader can see when a domain's key changed and decide what that means under its own policy. Evidence from a declaration is stale after 30 days (`domain_declaration`).

## 6. Rotating the key

1. `trooth declare init --domain acme.com --key ~/.trooth/declaration-key/acme.com.next.jwk` makes the new key.
2. Sign with the current key and list the new one beside it: `trooth declare sign ... --key <current> --add-key <new key file> --out trooth.json` (`--add-key` reads only the public half). Publish it. Readers now see both keys.
3. When ready, sign with the new key alone and publish that. If you use the DNS pin, change the TXT record to the new thumbprint at the same time.
4. Destroy the old key file.

Each step is a change Trooth's readings record as `declaration_key_changed`. A key that is lost or exposed is replaced the same way, without step 2: publish a declaration signed by a new key, and change the pin.

## 7. Exit codes of `trooth declare`

| Command | Code | Meaning |
|---|---|---|
| check | 0 | the declaration checks (and the DNS pin, when present, names one of its keys) |
| check | 1 | the site answers 404 or 410: it publishes no declaration |
| check | 3 | the site could not be read (no answer, the deadline, another status) |
| check | 8 | the signature does not check, or its `kid` is not one of the keys |
| check | 9 | another rule fails (the domain, a URL on another host, more than 400 days, oversize, not JSON, a redirect, an unknown member), or the DNS pin names a key the declaration does not list |
| check | 11 | the declaration checks in every other way, and has expired |
| init, sign | 0 | the key or the document was written |
| all | 2 | usage error, including a refusal to overwrite a file and a document `sign` would not write because it would not check |
| all | 7 | output not delivered |

11 is new in trooth 0.14.0; the others are the CLI's existing codes with their existing meanings.
