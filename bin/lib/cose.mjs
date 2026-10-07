// bin/lib/cose.mjs - COSE receipts for Trooth's log (docs/LOG.md section 8):
// RFC 9942 receipts of inclusion over an RFC 9162 SHA-256 tree (vds 1),
// signed as a COSE_Sign1 (RFC 9052) with the log's Ed25519 key, payload
// detached. The key is published as a COSE Key Set at
// https://api.trooth.co/.well-known/scitt-keys.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { leafHash, nodeHash } from './tlog.mjs';

/** Decode one CBOR data item (RFC 8949), definite lengths only. Maps become Map. Throws on anything else. */
export function decodeCbor(bytes) {
  const b = Buffer.from(bytes);
  let i = 0;
  const need = (n) => { if (i + n > b.length) throw new Error('CBOR ends early'); };
  const item = (depth) => {
    if (depth > 16) throw new Error('CBOR nests too deep');
    need(1);
    const ib = b[i++], major = ib >> 5, ai = ib & 31;
    if (major === 7) {
      if (ib === 0xf6) return null;
      if (ib === 0xf5) return true;
      if (ib === 0xf4) return false;
      throw new Error('a CBOR simple value or float is not expected here');
    }
    let n;
    if (ai < 24) n = ai;
    else if (ai === 24) { need(1); n = b[i]; i += 1; }
    else if (ai === 25) { need(2); n = b.readUInt16BE(i); i += 2; }
    else if (ai === 26) { need(4); n = b.readUInt32BE(i); i += 4; }
    else if (ai === 27) { need(8); const v = b.readBigUInt64BE(i); i += 8; if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('a CBOR number is too large'); n = Number(v); }
    else throw new Error('indefinite-length CBOR is not expected here');
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { need(n); const v = b.subarray(i, i + n); i += n; return Buffer.from(v); }
      case 3: { need(n); const v = b.subarray(i, i + n).toString('utf8'); i += n; return v; }
      case 4: { const a = []; for (let k = 0; k < n; k++) a.push(item(depth + 1)); return a; }
      case 5: { const m = new Map(); for (let k = 0; k < n; k++) { const key = item(depth + 1); m.set(key, item(depth + 1)); } return m; }
      case 6: return { tag: n, value: item(depth + 1) };
    }
    throw new Error('unreachable');
  };
  const v = item(0);
  if (i !== b.length) throw new Error('bytes follow the CBOR item');
  return v;
}

const head = (major, n) => {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) { const x = Buffer.alloc(3); x[0] = (major << 5) | 25; x.writeUInt16BE(n, 1); return x; }
  const x = Buffer.alloc(5); x[0] = (major << 5) | 26; x.writeUInt32BE(n, 1); return x;
};
const bstr = (v) => Buffer.concat([head(2, v.length), v]);

/** Sig_structure for a COSE_Sign1 with empty external AAD: ["Signature1", protected, h'', payload]. */
export function sigStructure(protectedBytes, payload) {
  return Buffer.concat([Buffer.from([0x84]), head(3, 10), Buffer.from('Signature1'), bstr(protectedBytes), bstr(Buffer.alloc(0)), bstr(payload)]);
}

/** RFC 9679 thumbprint of an Ed25519 COSE_Key: SHA-256 over {1:1, -1:6, -2:x} in deterministic CBOR. */
export function coseKeyThumbprint(publicKey32) {
  return createHash('sha256').update(Buffer.concat([Buffer.from([0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20]), Buffer.from(publicKey32)])).digest();
}

/** The Ed25519 public keys in a COSE Key Set (only OKP Ed25519 keys are read). */
export function keysFromKeySet(bytes) {
  const set = decodeCbor(bytes);
  if (!Array.isArray(set)) throw new Error('a COSE Key Set is a CBOR array');
  return set.filter((k) => k instanceof Map && k.get(1) === 1 && k.get(-1) === 6 && Buffer.isBuffer(k.get(-2)) && k.get(-2).length === 32)
    .map((k) => ({ key: k.get(-2), kid: Buffer.isBuffer(k.get(2)) ? k.get(2) : null }));
}

/** Apply an RFC 9162 inclusion proof to a leaf hash. Returns the root, or null when the proof does not fit. */
export function rootFromInclusion(index, size, leaf, path) {
  if (!(index >= 0 && index < size)) return null;
  let r = Buffer.from(leaf), fn = BigInt(index), sn = BigInt(size) - 1n;
  for (const p of path) {
    if (!Buffer.isBuffer(p) || p.length !== 32 || sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) { r = nodeHash(p, r); if ((fn & 1n) === 0n) while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; } }
    else r = nodeHash(r, p);
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n ? r : null;
}

/**
 * Check a COSE receipt of inclusion for `entryBytes` against an Ed25519 log
 * public key. Returns {valid, index, tree_size, root, reason}.
 */
export function checkCoseReceipt(receiptBytes, entryBytes, publicKey32) {
  const out = (valid, reason, extra = {}) => ({ valid, reason, index: null, tree_size: null, root: null, ...extra });
  let top;
  try { top = decodeCbor(receiptBytes); } catch (e) { return out(false, `not CBOR: ${e.message}`); }
  if (!top || top.tag !== 18 || !Array.isArray(top.value) || top.value.length !== 4) return out(false, 'not a tagged COSE_Sign1');
  const [prot, unprot, payload, sig] = top.value;
  if (!Buffer.isBuffer(prot) || !(unprot instanceof Map) || payload !== null || !Buffer.isBuffer(sig) || sig.length !== 64) return out(false, 'not a COSE_Sign1 with a detached payload and an Ed25519 signature');
  let ph;
  try { ph = decodeCbor(prot); } catch { return out(false, 'the protected header is not CBOR'); }
  if (!(ph instanceof Map) || ph.get(1) !== -8 || ph.get(395) !== 1) return out(false, 'the protected header is not alg EdDSA with vds RFC9162_SHA256');
  const kid = ph.get(4);
  if (Buffer.isBuffer(kid) && !kid.equals(coseKeyThumbprint(publicKey32))) return out(false, "the receipt's kid is not this key's thumbprint");
  const proofs = unprot.get(396) instanceof Map ? unprot.get(396).get(-1) : null;
  if (!Array.isArray(proofs) || proofs.length !== 1 || !Buffer.isBuffer(proofs[0])) return out(false, 'the receipt carries no single inclusion proof');
  let proof;
  try { proof = decodeCbor(proofs[0]); } catch { return out(false, 'the inclusion proof is not CBOR'); }
  if (!Array.isArray(proof) || proof.length !== 3 || !Number.isSafeInteger(proof[0]) || !Number.isSafeInteger(proof[1]) || !Array.isArray(proof[2])) return out(false, 'the inclusion proof is not [tree_size, leaf_index, path]');
  const [size, index, path] = proof;
  const root = rootFromInclusion(index, size, leafHash(entryBytes), path);
  if (!root) return out(false, 'the inclusion proof does not fit a tree of that size', { index, tree_size: size });
  let ok = false;
  try { ok = edVerify(null, sigStructure(prot, root), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKey32).toString('base64url') }, format: 'jwk' }), sig); } catch { ok = false; }
  if (!ok) return out(false, 'the signature does not check over the root this entry and proof give', { index, tree_size: size });
  return out(true, `entry ${index} of a tree of ${size}, signed by the log key`, { index, tree_size: size, root: root.toString('base64') });
}
