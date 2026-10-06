# Trooth signing keys: ceremony, custody, rotation and revocation

Version 1.0, October 6, 2026.

Trooth holds two kinds of signing key. This document says how each is made, where it is held, who can use it, and what happens when it is replaced or compromised. It describes what is in place now, and separately what is planned; nothing planned is described as done.

| Key | Signs | Published at |
|---|---|---|
| Statement key (`trooth-master-2026-09`) | Witness statements, corrections, directory receipts | `https://api.trooth.co/public/keys` |
| Log key (`trooth.co/witness-log/v1`) | Checkpoints of the witness statement log, and nothing else | `https://api.trooth.co/scan/log/v1/vkey`, and pinned in `trooth` 0.9.0 and later |

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

## 4. Compromise

If the log key is, or may be, compromised:

1. Make a new key and switch the Worker to it at once (section 3, steps 1 and 3).
2. Publish a `trooth` release that pins only the new key, and record here when the old key stopped being used.
3. Re-sign the current tree with the new key. The entries do not change, so every receipt's inclusion proof stays valid against the new checkpoint; only the checkpoint signature is new.
4. Ask monitors to compare their saved checkpoints with the log. A checkpoint signed with the old key after the recorded stop time is evidence of misuse.

If the statement key is compromised, it is marked compromised on the key list with the time, which makes every checker stop relying on its signatures ([VERIFY.md](VERIFY.md) section 3). Trooth re-signs current readings with a new key and logs them.

## 5. Planned: hardware custody

The next ceremony moves both keys into a hardware-backed key store that supports Ed25519 and does not release private keys, so that signing requires the device and the key cannot be copied out. That ceremony will be recorded here with: the device or service, the attestation it gives, who was present, the key's public half and fingerprint, and the backup arrangement. Until then the keys are software keys held as described in section 2.

## Record

| Date | Key | Event |
|---|---|---|
| 2026-09-28 | Statement key `trooth-master-2026-09` | First listed on the key list |
| 2026-10-06 | Log key `trooth.co/witness-log/v1` | Generated (ceremony v1); verifier key `trooth.co/witness-log/v1+06471ca9+AY9UdmLMbCX5Ib3ksDeoE8x3CburcWGJE9eJiPiYP5sZ` |
