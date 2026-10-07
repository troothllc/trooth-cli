# Trooth signing keys: ceremony, custody, rotation and revocation

Version 1.1, October 7, 2026. Version 1.1 records the first key drills (section 6), the rule for changing the key of a witnessed log (section 4), and the hardware custody plan in detail (section 5).

Trooth holds two kinds of signing key. This document says how each is made, where it is held, who can use it, and what happens when it is replaced or compromised. It describes what is in place now, and separately what is planned; nothing planned is described as done.

| Key | Signs | Published at |
|---|---|---|
| Statement key (`trooth-master-2026-09`) | Witness statements, corrections, directory receipts | `https://api.trooth.co/public/keys` |
| Log key (`trooth.co/witness-log/v1`) | Checkpoints of the witness statement log and its COSE receipts, and nothing else | `https://api.trooth.co/scan/log/v1/vkey`, as a COSE key at `https://api.trooth.co/.well-known/scitt-keys`, and pinned in `trooth` 0.9.0 and later |

Keeping them apart means a compromised log key cannot sign a statement, and a compromised statement key cannot rewrite the log's history.

## 1. Making the log key (ceremony v1)

Performed by the founder on the founder's own computer, by `~/dev/.trooth-publish-phase2.sh`:

1. An Ed25519 key pair is generated with Node.js `crypto.generateKeyPairSync('ed25519')`, from the operating system's random source.
2. The private key, as a JWK, is written to `~/.trooth/log-key/private.jwk` with mode 0600 in a directory with mode 0700. Nobody else, and no AI assistant, reads it.
3. It is sent to Cloudflare as the Worker secret `TROOTH_LOG_SIGNING_KEY` over standard input (`wrangler secret put`), never on a command line and never in a file in any repository.
4. The verifier key is derived locally and compared with the one the deployed log serves. The release stops if they differ.
5. The verifier key is written into `bin/lib/log-trust.mjs` and released in `trooth` 0.9.0.

The founder SHOULD keep one offline copy of `private.jwk` (an encrypted removable drive kept apart from the computer), so the log can keep its key if the computer is lost. Losing every copy does not lose the log: a new key is made (section 3) and the old checkpoints stay checkable with the old public key.

## 2. Custody

- **Use.** Only the log's Durable Object reads `TROOTH_LOG_SIGNING_KEY`, to sign a checkpoint after each append. No route returns it, logs it or signs anything chosen by a caller: a checkpoint's text is the log's own size and root.
- **Access.** Cloudflare account access is the founder's, with two-factor authentication. Worker secrets cannot be read back through Cloudflare's dashboard or API once set.
- **The statement key** is held the same way, as the Worker secret `TROOTH_MASTER_SIGNING_KEY`, and its lifecycle is published on the key list.

## 3. Rotation

The log key is rotated at least every 24 months, and whenever custody changes.

1. Make the new key as in section 1.
2. Publish the new verifier key in a new `trooth` release that pins both keys, and record it here with its date.
3. Switch the Worker to the new key. Checkpoints from then on are signed with it.
4. After every supported `trooth` release pins the new key, drop the old one from the pin list. Old checkpoints stay checkable with the old public key, which stays listed here.

The statement key follows the lifecycle on the key list: a retired key's signatures stay trusted for statements that carry a time before its retirement.

## 4. Compromise, and witnessed logs

If the log key is, or may be, compromised:

1. Make a new key and switch the Worker to it at once (section 3, steps 1 and 3).
2. Publish a `trooth` release that pins only the new key, and record here when the old key stopped being used.
3. Re-sign the current tree with the new key. The entries do not change, so every receipt's inclusion proof stays valid against the new checkpoint; only the checkpoint signature is new.
4. Ask monitors to compare their saved checkpoints with the log. A checkpoint signed with the old key after the recorded stop time is evidence of misuse.

**A witnessed log changes key by changing origin.** A witness keeps the key it was given for an origin and refuses a checkpoint signed by any other ([LOG.md](LOG.md) section 7); the witness network's lists cannot update a key once a witness has configured it. So once witnesses follow `trooth.co/witness-log/v1`, a rotation or a compromise is handled by starting `trooth.co/witness-log/v2` with the new key: it is announced to the witness network first, its first entry records the last v1 checkpoint, the v1 log stays readable, and a `trooth` release pins both. Drill 3 (section 6) showed a witness refusing a re-keyed checkpoint, which is what makes this rule necessary.

If the statement key is compromised, it is marked compromised on the key list with the time, which makes every checker stop relying on its signatures ([VERIFY.md](VERIFY.md) section 3). Trooth re-signs current readings with a new key and logs them.

## 5. Planned: hardware custody and two-person control

Two things are not in place, and this section says what each needs.

**Hardware custody.** The next ceremony moves the log key into a key service that generates Ed25519 keys in hardware and never releases them. AWS Key Management Service has offered Ed25519 signing (key spec `ECC_NIST_EDWARDS25519`, algorithm `ED25519_SHA_512`) since November 2025, in its hardware security modules; the log's signer would call it to sign each checkpoint and receipt, and the key could not be copied out. Because a witnessed log changes key only by changing origin (section 4), the hardware key becomes the key of `trooth.co/witness-log/v2`. It needs an AWS account that is Trooth's, an IAM identity for the Worker limited to `kms:Sign` on that one key, and the ceremony recorded here with the key's ARN, its public half and fingerprint, and the account's access controls.

**Two-person control.** Today one person, the founder, can use or change both keys. Two-person control needs a second named person with their own credentials: on the key service, a key policy under which changing or deleting the key needs a second approver; on Cloudflare, the Worker secrets and deploys of the log Worker require a second account's approval. Until a second person is named, the log's protection against its own operator is the witnesses and the monitors, not the operator's process.

## 6. Drills

The drills run on Trooth's own log code, in memory, with keys generated for the run and discarded, so production is never touched (`npm run drill:log-key` in trooth-scan-worker, `scripts/drill-log-key.mjs`). The founder's publisher runs them before each release that changes the log, and the result is recorded below.

1. **Key loss.** With the key gone, the log refuses to append (nothing is written that it cannot sign). A new key signs the same tree with the same root; the old checkpoint still checks with the old public half; every receipt's inclusion proof reaches the new root; the log grows again.
2. **Key compromise.** The tree is signed again with the new key at once. A checkpoint the stolen key signs still checks with the old public half, which is why the old key is unpinned at once; a monitor that kept a checkpoint sees two roots for one size signed by the old key, which is evidence of misuse; the new key does not open the forged checkpoint.
3. **Witnesses after a key change.** A witness that cosigned under the old key refuses (403) a checkpoint signed by the new one. This is the reason for the rule in section 4.

The runbook steps a drill does not exercise, because they need the real accounts, are sections 3 and 4: switching the Worker secret, publishing the release, and (for a witnessed log) announcing the new origin.

## Record

| Date | Key | Event |
|---|---|---|
| 2026-09-28 | Statement key `trooth-master-2026-09` | First listed on the key list |
| 2026-10-06 | Log key `trooth.co/witness-log/v1` | Generated (ceremony v1); verifier key `trooth.co/witness-log/v1+06471ca9+AY9UdmLMbCX5Ib3ksDeoE8x3CburcWGJE9eJiPiYP5sZ` |
| 2026-10-07 | Log key `trooth.co/witness-log/v1` | Drills 1 to 3 (section 6) run on the log code with throwaway keys: 12 of 12 steps held. Run again by the release publisher on the founder's computer before the release that added witnesses |
| 2026-10-07 | Log key `trooth.co/witness-log/v1` | Published as a COSE key at `https://api.trooth.co/.well-known/scitt-keys`; RFC 9679 thumbprint is its kid |
