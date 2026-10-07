# Trooth's witness statement log

Version 1.1, October 7, 2026. Version 1.1 adds the `public_record` entry kind, witness cosignatures (section 7), COSE receipts and the COSE key set (section 8). Normative for Trooth's log, for `trooth verify`, `trooth log`, `trooth public-record`, the SDKs in `sdk/`, and any other implementation. The cases any implementation must agree on are in [`tests/vectors/log.json`](../tests/vectors/log.json) and [`tests/vectors/witness-cose.json`](../tests/vectors/witness-cose.json); Go's `golang.org/x/mod/sumdb` packages also check its notes, roots and proofs, litewitness (filippo.io/torchwood) has cosigned its checkpoints in a test, and pycose has checked its receipts.

Every witness statement Trooth publishes, every public record reading it serves, and every correction it issues, is entered in one public, append-only log. A receipt from the log shows that a statement was published in a particular order, and that Trooth cannot later show different readers different histories without that being detectable by anyone who keeps a checkpoint.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. What is logged, and when

- A **witness statement** is entered when its reading is published to the Trooth Network: at first publication, and each time the reading is taken again for a published listing. A reading that was never published is never logged, so the log cannot reveal that a domain was read privately.
- A **public record statement** is entered when a public record reading is served ([EVIDENCE.md](EVIDENCE.md) section 5). That reading is public from the moment it exists, so logging it reveals nothing private. At most 200 are entered an hour across all domains; a reading beyond that is signed and says it was not logged.
- A **correction** (section 6) is entered when Trooth issues one.
- Entries are never edited or removed. A statement that was wrong stays in the log; a later correction says so.
- Appending is idempotent: the same envelope is entered once.

## 2. Entries and the tree

An entry is the UTF-8 bytes of the RFC 8785 (JCS) form of:

```json
{"kind": "witness_statement" | "public_record" | "correction", "statement": {"alg": …, "canonicalization": …, "key_id": …, "payload": …, "signature": …}}
```

`statement` holds exactly the five envelope fields as published, so anyone holding the envelope rebuilds the same bytes. An entry MUST be at most 65,535 bytes.

The tree is RFC 9162's: SHA-256, leaf hash `SHA-256(0x00 || entry)`, interior node `SHA-256(0x01 || left || right)`, and the empty tree's root is `SHA-256("")`. Inclusion proofs (RFC 9162 section 2.1.3) and consistency proofs (section 2.1.4) are as RFC 9162 defines them.

## 3. Checkpoints

The log's state is a C2SP checkpoint ([c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint)):

```
trooth.co/witness-log/v1
<tree size, decimal>
<root hash, standard base64>
```

signed as a C2SP signed note ([c2sp.org/signed-note](https://c2sp.org/signed-note)) with an Ed25519 key named `trooth.co/witness-log/v1`, followed by any witness cosignatures (section 7). The signature line is an em dash (U+2014), a space, the key name, a space, and standard base64 of the 4-byte key hash followed by the 64-byte signature. The key hash is the first 4 bytes of `SHA-256(name || 0x0A || 0x01 || public key)`. The verifier key is written `<name>+<key hash, hex>+<base64(0x01 || public key)>`.

A checker MUST verify the signature with a log key it already holds before reading the size or root, and MUST refuse a checkpoint whose origin line is not `trooth.co/witness-log/v1`. `trooth` 0.9.0 and later carry the production log key in `bin/lib/log-trust.mjs`; the log also serves it at `/vkey`, which a checker SHOULD NOT rely on alone.

The log key signs checkpoints and COSE receipts (section 8), and nothing else. The two cannot be confused: a checkpoint signature covers text that begins with the origin line, and a COSE signature covers a CBOR array that begins with the string `Signature1`. It is not the key that signs statements. How it is made, held, rotated and revoked is in [KEY-CEREMONY.md](KEY-CEREMONY.md).

## 4. Receipts

A receipt ([schema](../schemas/log-receipt.schema.json)) is `{log, index, tree_size, root_hash, inclusion_proof, checkpoint}`. To check a receipt for a statement:

1. `log` MUST be `trooth.co/witness-log/v1`.
2. The checkpoint MUST verify against a log key the checker holds (section 3). Otherwise the result is **`checkpoint_invalid`**.
3. The checkpoint's size MUST equal `tree_size` and its root MUST equal `root_hash`.
4. Rebuild the entry (section 2) from the statement, hash it as a leaf, and verify `inclusion_proof` from that leaf at `index` to the root at `tree_size`.

If 3 or 4 fails the result is **`proof_invalid`**. If all hold the result is **`included`**.

## 5. The log in a statement check

`trooth verify` asks the log for the statement by its statement id and for any corrections naming it, then adds a `log` part to the result ([VERIFY.md](VERIFY.md) section 10):

| Log status | Meaning | Effect on the verdict |
|---|---|---|
| `included` | The receipt checks | None |
| `not_logged` | The log holds no entry for this statement | None in this version: statements published before October 6, 2026 enter the log at their next reading or by backfill |
| `unavailable` | The log could not be read | None; reported |
| `checkpoint_invalid`, `proof_invalid` | The log's answer does not check | The verdict becomes `mismatch` |

A valid correction (section 6) makes the verdict **`superseded`** unless the statement was already `signature_not_trusted` or `mismatch`.

## 6. Corrections

A correction is Trooth withdrawing or replacing a statement it signed. Its payload is `trooth.correction.v1` ([schema](../schemas/correction-payload.v1.schema.json)): `correction_id`, `supersedes` (the statement id it corrects), `subject_id`, `effect` (`withdrawn` with `replacement: null`, or `replaced` with a `replacement` statement id), `reason` (`code` and `explanation`), `issued_at` and `signer`.

The log refuses a correction whose `supersedes`, or whose `replacement`, is not already in the log as a witness statement. A checker relies on a correction only when all of these hold:

1. The envelope's `alg` is `Ed25519`, its `canonicalization` is `RFC8785`, and its payload bytes are their own RFC 8785 form.
2. `signer.key_id` equals the envelope's `key_id`, and `signer.issuer` is `trooth.co`.
3. `supersedes` equals the statement id of the statement being checked.
4. `reason.code` is one of `evaluator_defect`, `mapping_defect`, `source_misread`, `signing_key_compromised`, `dispute_upheld`, `withdrawn_by_trooth`, and `effect` agrees with `replacement`.
5. The signature checks with a key on the published key list that is trusted at `issued_at` ([VERIFY.md](VERIFY.md) section 3).
6. The correction has a receipt that checks (section 4), as kind `correction`.

A correction that fails any of these is reported and not relied on.

A company that disagrees with a reading asks Trooth to review it; if the dispute is upheld, Trooth issues a correction with `dispute_upheld`. A company cannot sign a correction to Trooth's statement, because the statement is Trooth's.

## 7. Witnesses

A witness is an independent party that keeps the latest checkpoint it has seen for each log it follows, and cosigns a new checkpoint only after checking a consistency proof from the old one ([c2sp.org/tlog-witness](https://c2sp.org/tlog-witness)). A checkpoint cosigned by several independent witnesses cannot have been shown to one reader while a different history was shown to another, unless every one of those witnesses was deceived or colluded.

The log asks the staging witnesses of the witness network ([witness-network.org](https://witness-network.org)) that cosign with Ed25519:

| Operator | Cosigner key |
|---|---|
| Geomys | `witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G` |
| Mullvad VPN AB | `witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv` |
| TrustFabric (transparency.dev) | `staging.witness.transparency.goog/ring-any-bells+2e1a8dc9+BG5JTpLc3FJtwzgh1Uv+Qelz9qeOH2bfWjS1s0s+y4rL` |

It sends `add-checkpoint` with a consistency proof when the tree has grown, and otherwise about once an hour so the newest cosignature carries a recent time: at most 144 requests a day to each witness. A witness answers 404 until the log is on a list it follows. The log applies to the witness network's staging list by the network's participation process; until a witness follows the log, the checkpoint carries no cosignature. `/witnesses` says, for each witness, what it last did.

A cosignature is a further signature line on the checkpoint ([c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature), the Ed25519 form): the cosigner's name, then base64 of the 4-byte key id `SHA-256(name || 0x0A || 0x04 || key)[:4]`, an 8-byte big-endian timestamp in seconds and the 64-byte signature over

```
cosignature/v1
time <timestamp>
<the checkpoint body: origin, size, root>
```

A checker MUST ignore lines by keys it does not hold, MUST NOT count a cosignature with a zero time, and SHOULD NOT count one dated more than an hour after its own clock. `trooth` 0.11.0 and later carry the three keys above in `bin/lib/log-trust.mjs`; `trooth log checkpoint` and `trooth log monitor` report which of them cosigned, and `--witnesses <n>` makes either command exit 9 when fewer than n did.

The log records a witness that answers with a larger tree of this log than the log holds (`witness_ahead`), or refuses a consistency proof (`proof_refused`), and reports it as an error: either is evidence of a split view or of lost entries.

A witness holds the log key it was given for the origin, so a witnessed log cannot change its key under the same origin ([KEY-CEREMONY.md](KEY-CEREMONY.md) section 4). A key change moves the log to a new origin, `trooth.co/witness-log/v2`, announced to the witness network first; the v1 log stays readable and its last checkpoint is entered in v2.

## 8. COSE receipts and the COSE key

For SCITT tooling the log also issues a receipt of inclusion as defined by RFC 9942 (COSE Receipts): a tagged COSE_Sign1 (RFC 9052) with

- protected header `{1 (alg): -8 (EdDSA), 4 (kid): <RFC 9679 thumbprint of the log key>, 395 (vds): 1 (RFC9162_SHA256)}`,
- unprotected header `{396 (vdp): {-1 (inclusion proofs): [bstr .cbor [tree_size, leaf_index, [path…]]]}}`,
- a detached (nil) payload, and
- an Ed25519 signature by the log key over `Sig_structure = ["Signature1", protected, h'', root]`.

To check one: rebuild the entry (section 2), hash it as a leaf, apply the inclusion proof to get the root, and check the signature over the Sig_structure with that root as the payload. `trooth log receipt <index>` does this and also confirms the published key set lists the key it checked with.

The log key is published as a COSE Key Set (`application/cbor`) at `https://api.trooth.co/.well-known/scitt-keys` (the key discovery resource of draft-ietf-scitt-scrapi), each key an OKP Ed25519 COSE_Key `{1: 1, -1: 6, -2: x, 2 (kid): thumbprint, 3 (alg): -8}`, and one key at `/.well-known/scitt-keys/<kid>` with the kid in base64url or hex. The thumbprint is SHA-256 over the deterministic CBOR of `{1: 1, -1: 6, -2: x}` (RFC 9679).

## 9. Monitoring

Anyone can check that the log only grows:

```
trooth log monitor --state trooth-log-state.json
```

The first run records the signed checkpoint. Each later run fetches the new checkpoint, verifies its signature, and asks for a consistency proof from the saved size. If the log shrank, shows two roots for one size, or cannot prove the new tree extends the saved one, the command exits 9 and leaves the saved state untouched. It also records which pinned witnesses cosigned. The trooth-cli repository runs this every hour in GitHub Actions (`.github/workflows/log-monitor.yml`) and keeps its state between runs.

Monitors and witnesses protect against different failures: a monitor that keeps checkpoints detects a rewritten history after the fact; witnesses refuse to cosign one, so a reader who requires cosignatures never accepts it.

## 10. Reading the log

All under `https://api.trooth.co/scan/log/v1`:

| Path | Returns |
|---|---|
| `/checkpoint` | The newest signed checkpoint with any witness cosignatures (text) |
| `/witnesses` | Each witness the log asks, its key, and what it last did (JSON) |
| `/receipt/<i>[?tree_size=<n>]` | An RFC 9942 COSE receipt for entry i (`application/cose`), against the newest checkpoint or size n |
| `/vkey` | The log's verifier key (text) |
| `/lookup?statement_id=trooth:statement:<hex>[&kind=correction\|public_record]` | The entry and a receipt against the newest checkpoint, or 404 |
| `/corrections?statement_id=…` | Every logged correction naming the statement, each with its receipt |
| `/proof/inclusion?index=<i>&tree_size=<n>` | An RFC 9162 inclusion proof |
| `/proof/consistency?first=<m>&second=<n>` | An RFC 9162 consistency proof |
| `/entries/<i>` | One entry |
| `/tile/<L>/<N>[.p/<W>]`, `/tile/entries/<N>[.p/<W>]` | C2SP tlog-tiles hash tiles and entry bundles ([c2sp.org/tlog-tiles](https://c2sp.org/tlog-tiles)) |

Every route reads. Nothing on this prefix accepts a write from the public. The COSE key set is at `https://api.trooth.co/.well-known/scitt-keys` (section 8).

## 11. Relation to other standards

The log follows Certificate Transparency's tree (RFC 9162) and the C2SP formats used by Go's checksum database, Sigstore's Rekor v2 and the transparency-dev ecosystem, so existing tools can read it, and it speaks the witness protocol of the witness network. Its receipts are also issued as RFC 9942 COSE receipts with the key at the SCRAPI key discovery path. It is not a full SCITT Transparency Service (RFC 9943): the statements it logs are Trooth's JSON envelopes, not COSE_Sign1 Signed Statements, and it takes no registrations from others.

## 12. Limits of this version

- One operator. The log runs on Trooth's infrastructure; witnesses and monitors detect or refuse a rewritten history, they do not run the log.
- Witness cosignatures begin when the witness network accepts the log onto its staging list; the witnesses are staging services, and the network has no production list yet.
- The time a checkpoint is signed is not in the checkpoint; the log keeps it, and it is Trooth's own clock. A cosignature's time is the witness's clock.
- The log key is held in software as an encrypted Worker secret, not yet in a hardware module, and is used by one person ([KEY-CEREMONY.md](KEY-CEREMONY.md)).
