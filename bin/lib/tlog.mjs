// bin/lib/tlog.mjs - checking Trooth's witness statement log (docs/LOG.md).
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// The log is an append-only Merkle tree in the shape Certificate Transparency
// defined (RFC 9162, SHA-256, leaf prefix 0x00, node prefix 0x01), published
// as a C2SP checkpoint (c2sp.org/tlog-checkpoint) signed as a C2SP signed note
// (c2sp.org/signed-note) with an Ed25519 key, and as C2SP tiles
// (c2sp.org/tlog-tiles). This module only checks: it holds no log. The same
// rules are in sdk/python and sdk/go and in Trooth's log itself.

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { canonicalize } from './jcs.mjs';

export const LOG_ORIGIN = 'trooth.co/witness-log/v1';
export const ENTRY_KINDS = ['witness_statement', 'correction', 'public_record', 'mcp_tools'];

const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const ZERO = Buffer.from([0]);
const ONE = Buffer.from([1]);

/** RFC 9162 leaf hash: SHA-256(0x00 || entry bytes). */
export const leafHash = (entry) => sha256(ZERO, Buffer.from(entry));
/** RFC 9162 interior node: SHA-256(0x01 || left || right). */
export const nodeHash = (l, r) => sha256(ONE, l, r);
/** The root of the empty tree: SHA-256 of nothing. */
export const EMPTY_ROOT = sha256();

/**
 * The exact bytes of a log entry: RFC 8785 JSON of {kind, statement}, where
 * statement holds exactly the five envelope fields as published. Anyone with
 * the envelope rebuilds the same bytes, so the leaf hash names the statement.
 */
export function entryBytes(kind, statement) {
  if (!ENTRY_KINDS.includes(kind)) throw new Error(`unknown log entry kind: ${kind}`);
  const s = statement || {};
  for (const f of ['payload', 'signature', 'key_id', 'alg', 'canonicalization']) {
    if (typeof s[f] !== 'string') throw new Error(`the statement has no ${f}`);
  }
  return Buffer.from(canonicalize({ kind, statement: { alg: s.alg, canonicalization: s.canonicalization, key_id: s.key_id, payload: s.payload, signature: s.signature } }), 'utf8');
}

const lsb = (n) => (n & 1n) === 1n;

/** RFC 9162 section 2.1.3.2: does `proof` take leaf `index` of a tree of `size` to `root`? */
export function verifyInclusion(index, size, leaf, proof, root) {
  let fn = BigInt(index), sn = BigInt(size) - 1n;
  if (BigInt(index) >= BigInt(size) || BigInt(index) < 0n) return false;
  let r = Buffer.from(leaf);
  for (const pRaw of proof) {
    const p = Buffer.from(pRaw);
    if (p.length !== 32) return false;
    if (sn === 0n) return false;
    if (lsb(fn) || fn === sn) {
      r = nodeHash(p, r);
      if (!lsb(fn)) { while (!lsb(fn) && fn !== 0n) { fn >>= 1n; sn >>= 1n; } }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n && r.equals(Buffer.from(root));
}

/** RFC 9162 section 2.1.4.2: is the tree of `second` an append-only extension of the tree of `first`? */
export function verifyConsistency(first, second, firstRoot, secondRoot, proof) {
  const m = BigInt(first), n = BigInt(second);
  const fRoot = Buffer.from(firstRoot), sRoot = Buffer.from(secondRoot);
  if (m < 0n || m > n) return false;
  if (m === n) return proof.length === 0 && fRoot.equals(sRoot);
  if (m === 0n) return proof.length === 0;
  let path = proof.map((p) => Buffer.from(p));
  if (path.some((p) => p.length !== 32)) return false;
  if ((m & (m - 1n)) === 0n) path = [fRoot, ...path];
  if (path.length === 0) return false;
  let fn = m - 1n, sn = n - 1n;
  while (lsb(fn)) { fn >>= 1n; sn >>= 1n; }
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0n) return false;
    if (lsb(fn) || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      if (!lsb(fn)) { while (!lsb(fn) && fn !== 0n) { fn >>= 1n; sn >>= 1n; } }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n && fr.equals(fRoot) && sr.equals(sRoot);
}

/* ------------------------------------------------------- signed notes ---- */

/** The 4-byte key hash a signed-note Ed25519 key is named by: SHA-256(name || 0x0A || 0x01 || key)[0:4]. */
export function noteKeyHash(name, publicKey32) {
  return sha256(Buffer.from(name, 'utf8'), Buffer.from([0x0a, 0x01]), Buffer.from(publicKey32)).subarray(0, 4);
}

/** Parse a verifier key `<name>+<hash hex>+<base64(0x01 || key)>`. Throws when it is not one. */
export function parseVkey(vkey) {
  const m = /^([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})$/.exec(String(vkey).trim());
  if (!m) throw new Error('not a signed-note verifier key');
  const raw = Buffer.from(m[3], 'base64');
  if (raw.length !== 33 || raw[0] !== 0x01) throw new Error('the verifier key is not an Ed25519 key');
  const key = raw.subarray(1);
  const hash = noteKeyHash(m[1], key);
  if (hash.toString('hex') !== m[2]) throw new Error('the verifier key hash does not match its key');
  return { name: m[1], hash, key };
}

export function formatVkey(name, publicKey32) {
  return `${name}+${noteKeyHash(name, publicKey32).toString('hex')}+${Buffer.concat([Buffer.from([1]), Buffer.from(publicKey32)]).toString('base64')}`;
}

function ed25519Valid(key32, sig, msg) {
  if (key32.length !== 32 || sig.length !== 64) return false;
  try {
    return edVerify(null, msg, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(key32).toString('base64url') }, format: 'jwk' }), sig);
  } catch { return false; }
}

/**
 * Check a signed note against a verifier key. Returns {text} when a signature
 * line by that key verifies over the text, otherwise null. Lines by other keys
 * are ignored, as the format requires.
 */
export function verifyNote(note, vkey) {
  const v = typeof vkey === 'string' ? parseVkey(vkey) : vkey;
  const s = String(note);
  const split = s.lastIndexOf('\n\n');
  if (split < 0 || !s.endsWith('\n')) return null;
  const text = s.slice(0, split + 1);
  const sigs = s.slice(split + 2).split('\n').slice(0, -1);
  for (const line of sigs) {
    const m = /^— (\S+) ([A-Za-z0-9+/]+={0,2})$/.exec(line);
    if (!m || m[1] !== v.name) continue;
    const raw = Buffer.from(m[2], 'base64');
    if (raw.length !== 68 || !raw.subarray(0, 4).equals(v.hash)) continue;
    if (ed25519Valid(v.key, raw.subarray(4), Buffer.from(text, 'utf8'))) return { text };
  }
  return null;
}

/** Parse checkpoint text: origin, size, root hash and any extension lines. */
export function parseCheckpoint(text) {
  const lines = String(text).split('\n');
  if (lines.length < 4 || lines[lines.length - 1] !== '') throw new Error('the checkpoint is not three lines and a newline');
  const [origin, sizeStr, rootB64] = lines;
  if (!/^(0|[1-9][0-9]{0,18})$/.test(sizeStr)) throw new Error('the checkpoint size is not a decimal number');
  const root = Buffer.from(rootB64, 'base64');
  if (root.length !== 32 || root.toString('base64') !== rootB64) throw new Error('the checkpoint root is not 32 bytes of base64');
  return { origin, size: BigInt(sizeStr), root, extensions: lines.slice(3, -1) };
}

/** Verify a signed checkpoint: the signature by the vkey, then the body. Returns the parsed checkpoint or throws. */
export function openCheckpoint(note, vkey, origin = LOG_ORIGIN) {
  const v = typeof vkey === 'string' ? parseVkey(vkey) : vkey;
  const opened = verifyNote(note, v);
  if (!opened) throw new Error('the checkpoint signature does not check against the log key');
  const cp = parseCheckpoint(opened.text);
  if (cp.origin !== origin) throw new Error(`the checkpoint names the log ${cp.origin}, not ${origin}`);
  return cp;
}

const b64 = (h) => Buffer.from(h).toString('base64');
const unb64 = (s) => { const b = Buffer.from(String(s), 'base64'); return b.length === 32 && b.toString('base64') === s ? b : null; };

/**
 * Check a receipt (schemas/log-receipt.schema.json) for one statement:
 *   - the checkpoint is signed by one of `vkeys` and names this log,
 *   - its size and root are the receipt's,
 *   - the inclusion proof takes this statement's entry to that root.
 * Returns {status, index, tree_size, reason}. status: included | checkpoint_invalid | proof_invalid.
 */
export function checkReceipt({ kind = 'witness_statement', statement, receipt, vkeys }) {
  const out = (status, reason) => ({ status, index: receipt?.index ?? null, tree_size: receipt?.tree_size ?? null, reason });
  if (!receipt || typeof receipt !== 'object') return out('proof_invalid', 'no receipt');
  if (receipt.log !== LOG_ORIGIN) return out('proof_invalid', `the receipt names the log ${receipt.log}`);
  let cp = null, why = 'no log key to check against';
  for (const k of vkeys || []) { try { cp = openCheckpoint(receipt.checkpoint, k); break; } catch (e) { why = e.message; } }
  if (!cp) return out('checkpoint_invalid', why);
  if (!Number.isSafeInteger(receipt.index) || !Number.isSafeInteger(receipt.tree_size)) return out('proof_invalid', 'the receipt index or size is not an integer');
  if (cp.size !== BigInt(receipt.tree_size)) return out('proof_invalid', 'the receipt size is not the checkpoint size');
  if (receipt.root_hash !== b64(cp.root)) return out('proof_invalid', 'the receipt root is not the checkpoint root');
  const proof = (Array.isArray(receipt.inclusion_proof) ? receipt.inclusion_proof : []).map(unb64);
  if (proof.some((p) => !p)) return out('proof_invalid', 'a proof hash is not 32 bytes of base64');
  let leaf;
  try { leaf = leafHash(entryBytes(kind, statement)); } catch (e) { return out('proof_invalid', e.message); }
  if (!verifyInclusion(receipt.index, receipt.tree_size, leaf, proof, cp.root)) return out('proof_invalid', 'the inclusion proof does not reach the signed root');
  return out('included', `entry ${receipt.index} of a signed tree of ${receipt.tree_size}`);
}

/* ------------------------------------------------- tree building (tests) ---- */

/** The root of a list of leaf hashes (RFC 9162 MTH). For building tests and monitors' cross-checks. */
export function rootOf(leaves) {
  const n = leaves.length;
  if (n === 0) return EMPTY_ROOT;
  if (n === 1) return Buffer.from(leaves[0]);
  let k = 1; while (k * 2 < n) k *= 2;
  return nodeHash(rootOf(leaves.slice(0, k)), rootOf(leaves.slice(k)));
}

/** RFC 9162 PATH(m, D[n]). */
export function inclusionPath(m, leaves) {
  const n = leaves.length;
  if (n <= 1) return [];
  let k = 1; while (k * 2 < n) k *= 2;
  return m < k ? [...inclusionPath(m, leaves.slice(0, k)), rootOf(leaves.slice(k))] : [...inclusionPath(m - k, leaves.slice(k)), rootOf(leaves.slice(0, k))];
}

/** RFC 9162 PROOF(m, D[n]). */
export function consistencyPath(m, leaves) {
  const sub = (m2, d, b) => {
    const n = d.length;
    if (m2 === n) return b ? [] : [rootOf(d)];
    let k = 1; while (k * 2 < n) k *= 2;
    return m2 <= k ? [...sub(m2, d.slice(0, k), b), rootOf(d.slice(k))] : [...sub(m2 - k, d.slice(k), false), rootOf(d.slice(0, k))];
  };
  if (m === 0 || m === leaves.length) return [];
  return sub(m, leaves, true);
}

export const toB64 = b64;
export const fromB64 = unb64;
