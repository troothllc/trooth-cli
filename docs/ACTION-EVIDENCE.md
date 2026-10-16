# Delegation receipts and action evidence references

Version 1.0, October 15, 2026. Normative for `trooth evidence verify`, `trooth delegation verify`, the library export `trooth/evidence` (`bin/lib/evidence.mjs`) and any other implementation. The objects are built and signed by the API worker at api.trooth.co (`src/action-authz.ts`); this document describes them as that code builds them.

Trooth signs witness statements for readings it takes of a company's public surface ([VERIFY.md](VERIFY.md)) and, for workspaces that create a delegation, two more objects described here:

- a **delegation receipt** for each event in a delegation's life (created, revoked): what Trooth recorded, when, and how it was approved;
- an **action evidence reference** for each action Trooth authorizes under a delegation: a ten-minute, single-use object the agent attaches to the payment partner's own mandate (AP2 `risk_data`, ACP delegated-payment metadata, a Trusted Agent Protocol consumer field), where the partner can check it offline.

Action authorization is switched on per deployment. While it is off, every route below answers 404.

## 1. Where they come from

| Object | Returned by | JSON member |
|---|---|---|
| Delegation receipt (created) | `POST /v1/delegations` (a person in the workspace, freshly signed in) | `receipt`, beside `delegation` (the delegation document) and `digest` |
| Delegation receipt (revoked) | `POST /v1/delegations/<id>/revoke` | `receipt` |
| Every receipt of every delegation | `GET /v1/delegations` | `delegations[].receipts[].receipt` |
| Action evidence reference | `POST /v1/action-authorizations` (201), `GET /v1/action-authorizations/<id>` once issued | `evidence`, beside `jti` and `expires_at` |
| The same reference, by pointer | `GET /public/action-evidence/<jti>/reference?sha256=<sha256 of the JWS>` | `evidence` |

A receipt can be missing (`receipt: null`) when no published key could sign it at that moment; the event still happened, and `GET /v1/delegations` lists the receipt once it exists.

## 2. The key

Both objects are signed with Trooth's **evidence key**. `GET https://api.trooth.co/public/keys` publishes it as:

```json
{
  "kid": "trooth-evidence-2026-10",
  "public_key": "<64 hex characters: the raw 32-byte Ed25519 public key>",
  "alg": "Ed25519",
  "encoding": "hex",
  "signs": "short-lived signed references issued by api.trooth.co that name this kid",
  "status": "active",
  "purpose": "signed-references",
  "state": "active",
  "fingerprint": "…", "created_at": null, "revoked_at": null,
  "activated_at": null, "retired_at": null, "compromised_at": null, "events": [], "first_listed_at": "…"
}
```

inside `{"keys": [...], "active_kid", "active_kids", "revocations", "list_read_at", ...}` beside Trooth's other keys. The public half is derived from the same secret that signs, so the two cannot drift apart. Only a key with `purpose` `signed-references` vouches for these objects: a key published for the trust ledger or for readings and receipts does not, even if its signature verifies. The key's lifecycle (active, retired at a time, compromised, revoked) is read exactly as for a witness statement ([VERIFY.md](VERIFY.md) section 4), at the object's `iat`.

## 3. The form

Each object is an RFC 7515 compact JWS: `BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)`, base64url without padding.

- The header is `{"alg":"EdDSA","typ":"<typ>","kid":"trooth-evidence-2026-10"}`, serialized in that order.
- The payload is the claims below as canonical JSON: object members sorted by key, no whitespace, members whose value is undefined left out.
- The signature is Ed25519 (RFC 8032) over the ASCII bytes of `BASE64URL(header) "." BASE64URL(payload)`.

| Object | `typ` | `format` |
|---|---|---|
| Delegation receipt | `trooth-delegation-receipt+jwt` | `trooth.delegation-receipt.v1` |
| Action evidence reference | `trooth-action-evidence+jwt` | `trooth.action-evidence.v1` |

## 4. The claims

### 4.1 Delegation receipt

[schemas/delegation-receipt.v1.schema.json](../schemas/delegation-receipt.v1.schema.json).

| Claim | Meaning |
|---|---|
| `format` | `trooth.delegation-receipt.v1` |
| `iss` | `https://api.trooth.co` |
| `iat` | When Trooth recorded the event, in seconds (`recorded_at` truncated) |
| `event` | `created` or `revoked` |
| `recorded_at` | The same time, RFC 3339 with milliseconds |
| `by` | The id of the person who acted |
| `approval` | Created receipts only: `approved_by`, `approved_at`, `method` (`identity_provider` or `session_reauth`), `acr`, `auth_time`, `idp` (`{provider, domain}` or null) |
| `delegation.id` | `dlg_` and 20 hex characters |
| `delegation.sha256` | SHA-256 (hex) of the delegation document's canonical JSON |
| `delegation.format` | `trooth.delegation.v1` |
| `delegation.principal` | `{workspace, user}` |
| `delegation.agent.jkt` | The RFC 7638 thumbprint of the agent's DPoP key: the credential is accepted only with a proof signed by that key |
| `delegation.target.domain` | The counterparty |
| `delegation.actions` | `trooth_payment`, `trooth_data_share` or both |
| `delegation.expires_at` | When the delegation expires (at most 90 days after creation) |
| `meaning` | What the receipt says, in a sentence |
| `verify` | `{keys: "https://api.trooth.co/public/keys", kid}` |

The receipt does **not** carry the delegation's limit, data class, approval threshold or role. It binds them through `delegation.sha256`: the delegation document (the `delegation` member of the create response, or an entry of `GET /v1/delegations` without its `digest`, `revoked_at` and `receipts` members) hashes, as canonical JSON, to exactly that digest. Its members are `format`, `id`, `principal`, `agent` (`jkt`, `label`), `role`, `target`, `actions`, `limit` (`{amount, currency}` or null), `data_class` (or null), `approval_above` (an amount, or null), `expires_at`, `created_at` and `approval`.

### 4.2 Action evidence reference

[schemas/action-evidence.v1.schema.json](../schemas/action-evidence.v1.schema.json).

| Claim | Meaning |
|---|---|
| `format` | `trooth.action-evidence.v1` |
| `iss` | `https://api.trooth.co` |
| `iat`, `exp` | Issued and expiry times in seconds; `exp` is `iat` + 600 |
| `jti` | `ev_` and 32 hex characters; single use |
| `authorization_id` | `act_` and 20 hex characters |
| `authorization_details` | Exactly one RFC 9396 object: `{type: "trooth_payment", actions: ["pay"], locations, instructedAmount: {currency, amount}, creditorName?, description?}` or `{type: "trooth_data_share", actions: ["share"], locations, datatypes: [<class>], description?}`. Every location is an https URL on the counterparty's domain or a subdomain |
| `binding` | `{protocol, reference_sha256}`: the payment partner's mandate, with `reference_sha256` = SHA-256 (hex) of `<protocol> "\n" <reference>`. One authorization per delegation, protocol and reference |
| `principal` | `{workspace, user}` |
| `delegation` | `{id, sha256, agent: {jkt}, role, target: {domain}, actions, limit, data_class, expires_at}`: the delegation the action was checked against |
| `approval` | `{delegation, action}`: how the delegation was approved, and, for an action above the delegation's approval threshold, how a person approved this action through the workspace's identity provider (else null) |
| `counterparty` | `{domain, reading}`: `reading.status` is `read` (with `read_at`, `log_index`, `statement_sha256` of the public record answer, and `source`) or `not_read` (then nothing about the counterparty is attested) |
| `responsibility` | The written responsibility boundary: `version` (now `trooth.responsibility-boundary.v1-draft`), and the lists `trooth_observed`, `buyer_approved`, `vendor_represented` and `not_established` |
| `verify` | `{keys, kid, status: "https://api.trooth.co/public/action-evidence/<jti>"}` |

The amount was checked to be at or under the delegation's limit and in its currency, the data class at or under its data class, the action one it permits, every location on its target, and the time before its expiry, when Trooth issued the reference.

### 4.3 Public state and redemption

`GET https://api.trooth.co/public/action-evidence/<jti>` answers `{jti, state, expires_at, redeemed_at}`, where `state` is `issued`, `redeemed`, `expired` or `revoked` (the delegation behind it was revoked), or 404 when Trooth does not know the jti. The partner redeems a reference once with `POST /public/action-evidence/<jti>/redeem` and `{"evidence": "<the JWS>"}`; a second redemption answers 409 `already_redeemed`, as do an expired or revoked reference.

## 5. Checking one offline

An implementation MUST apply these steps in order and MUST NOT fetch any URL a payload names. `trooth/evidence` returns the first failing step's class as `status`.

1. Split the JWS into three base64url segments; the header and payload MUST decode to JSON objects. Otherwise: **not trusted**.
2. The header's `alg` MUST be `EdDSA` and its `kid` MUST be on the key list. Otherwise: **not trusted**.
3. That key's `purpose` MUST be `signed-references`, and its lifecycle MUST make it trusted at `iat` (active; or retired after `iat`). Otherwise: **not trusted**.
4. The Ed25519 signature MUST verify over the signing input with the key's 32 bytes (`encoding` hex). Otherwise: **not trusted**.
5. The header's `typ` and the payload's `format` MUST be the pair in section 3 for the object expected, `iss` MUST be `https://api.trooth.co`, `iat` a whole number, `verify.kid` the header's `kid`, and the claims MUST have the shapes in section 4. For a reference, `exp` MUST be after `iat` by at most 600 seconds, and `iat` MUST NOT be more than 60 seconds ahead of the checker's clock. For a receipt, `event` MUST be `created` or `revoked` and `recorded_at` MUST be the time `iat` names. When a mandate is given, `binding` MUST be that protocol and SHA-256 of its protocol, a newline and its reference. When a delegation document is given, its canonical SHA-256 MUST be `delegation.sha256`. Otherwise: **mismatch**.
6. A reference whose `exp` has passed is **expired**: everything checked, and it is past its time. This is a state, not an error. A receipt does not expire; whether the delegation it names has expired is reported beside it.
7. Otherwise: **valid**.

```js
import { verifyEvidence, verifyDelegationReceipt, extractJws } from 'trooth/evidence';

const keys = await (await fetch('https://api.trooth.co/public/keys')).json();   // or a saved copy
const r = verifyEvidence(jws, keys, { binding: { protocol: 'ap2', reference: mandateId } });
if (r.status !== 'valid') throw new Error(`evidence ${r.status}: ${r.reason}`);
console.log(r.summary.amount, r.summary.currency, r.summary.target_domain, r.summary.delegation.id);
```

Both functions never throw on bad input; `extractJws(text, 'evidence' | 'delegation')` finds the JWS in the JSON the API answers with. The result carries `status`, `reason`, `problems`, `signature`, `kid`, `key`, the decoded `header` and `payload`, the JWS's `sha256` (the digest the redeem pointer uses), `issued_at`, `expires_at` and a `summary`; types are in [types/evidence.d.ts](../types/evidence.d.ts).

### 5.1 In the public witness log

The witness log at `https://api.trooth.co/scan/log/v1/` is public, and these objects are not: a reference names the workspace and the user, the amount, the creditor, the description, the approvals and the identity provider's domain, and a receipt names the agent key's thumbprint and the scope. So the log never holds one. For each receipt and reference, the API worker signs a **commitment** with the same key and appends only that:

```
header  {"alg": "EdDSA", "kid": "trooth-evidence-2026-10", "typ": "trooth-log-commitment+jwt"}
payload {"format": "trooth.log-commitment.v1",
         "kind": "delegation_receipt" | "action_evidence",
         "sha256": "<lowercase hex SHA-256 of the object's compact JWS, its UTF-8 bytes>",
         "iat": <seconds>}
```

The payload has exactly those four keys. The API answers each object with `log` (`receipt_log` from `POST /v1/delegations` and its revoke): `{statement_id, index, url}`, or `null` while the append is pending. The entry at `https://api.trooth.co/scan/log/v1/entries/<index>` carries the commitment JWS as its envelope's `payload` (`entry.statement.payload`; `alg` `EdDSA`, `canonicalization` `jws-compact`, `signature` empty because the signature is inside the JWS), and its `statement_id` is `trooth:statement:<sha256>`.

To check that an object was logged, after it checks under section 5:

1. Read `entries/<index>`; its `kind` MUST be `delegation_receipt` for a receipt or `action_evidence` for a reference, and its envelope payload MUST be a compact JWS. Otherwise: **mismatch**.
2. Apply section 5 steps 1 to 4 to the commitment (alg, kid on the list with purpose `signed-references` and trusted at the commitment's `iat`, signature). Otherwise: **not trusted**.
3. Its `typ` MUST be `trooth-log-commitment+jwt`, its payload exactly `format`, `kind`, `sha256`, `iat` with `format` `trooth.log-commitment.v1`, `kind` the object's kind, `iat` a whole number, and `sha256` the SHA-256 of the object's compact JWS exactly as held. Otherwise: **mismatch**.

`verifyLogCommitment(commitmentJws, originalJws, keys)` applies steps 2 and 3 (the kind comes from the original's `typ`, or `opts.kind`), and `commitmentFromLogEntry(entry)` takes the commitment out of an entry. Anyone else reading the log learns only that Trooth signed a receipt or a reference at `iat`, and its digest: nothing about the action, the parties or the amount.

## 6. The commands

`trooth evidence verify <file|->` and `trooth delegation verify <file|->` read the JWS, or JSON holding it (section 1), from a file or stdin, read the key list from `https://api.trooth.co/public/keys` (`TROOTH_API` names another host) or from `--keys <file>` (then nothing is sent), apply section 5 and print the summary; `--json` prints the result with `ok`, `exit`, `online` and `sources` (`EvidenceVerifyOutput`, `DelegationVerifyOutput` in types/evidence.d.ts).

- `evidence verify --online` also reads the public state (section 4.3), only for a reference that checked; `--protocol <p> --reference <r>` checks the mandate binding.
- `delegation verify --delegation <file>` checks a delegation document's digest; the create response carries the document already, and then the limit, data class, approval threshold and role are printed.
- `--log` (both commands, online) checks the object's commitment in the public witness log (section 5.1) at the index the input JSON names (`log.index`, `receipt_log.index`, or a listed receipt's `log.index`), or at `--log-index N` (which implies `--log`; a bare JWS carries no index). It prints `logged at index N`, or why not; `--json` adds `log` (`LogOutput`) and `sources.log`. Only an object that checked is looked up. New in 0.22.0.

| Exit | When |
|---|---|
| 0 | It checks (with `--online`, its state is issued; with `--log`, it is logged). A receipt for an expired delegation also exits 0. |
| 1 | `evidence verify --online`: the state endpoint does not know the reference (404). |
| 2 | Usage: no file, a file not found, input that is not a compact JWS or JSON holding one, `--protocol` without `--reference`, `--log` with no log index (or `log` still null). |
| 3 | The key list, the public state or (`--log`) the log entry could not be read. |
| 8 | Not trusted (section 5 steps 1 to 4); with `--log`, also the commitment (section 5.1 step 2). |
| 9 | Mismatch (section 5 step 5); with `--log`, also no entry at that index, or a commitment of another kind or to another digest (section 5.1 steps 1 and 3). |
| 11 | `evidence verify`: expired, by its `exp` or by `--online`. |
| 12 | `evidence verify --online`: redeemed or revoked. New in 0.22.0. |

With `--log`, a failed log check (3, 8 or 9) takes the place of 0, 11 or 12.

## 7. What they mean, and what they do not

A delegation receipt that checks shows that Trooth recorded this delegation, with this digest, at `recorded_at`, approved as stated, or recorded its revocation then. It does not say that any action taken under the delegation is proper.

An action evidence reference that checks shows that, at `iat`, Trooth checked this one action against this delegation and recorded the approvals, the binding to the partner's mandate and its own latest signed reading of the counterparty, with the responsibility boundary written out. Trooth does not move money, hold credentials, sign on the customer's behalf, or decide whether a payment is made: the partner's own mandate and controls govern execution. The reference does not establish delivery, settlement, available funds, that the agent will act within the authorization, any person's authority beyond what the delegation records, or anything after it expires (the boundary's `not_established`).
