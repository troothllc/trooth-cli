// bin/lib/witness.mjs - witness cosignatures on Trooth's log checkpoints
// (docs/LOG.md section 7): c2sp.org/tlog-cosignature, the Ed25519 form.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// A witness is an independent party that cosigns a log's checkpoint only
// after checking it is consistent with the last one it saw. A checkpoint
// cosigned by several independent witnesses cannot have been shown to one
// reader while a different history was shown to another, unless every one of
// those witnesses was deceived or colluded. This module only checks: it is
// given witness keys and a checkpoint, and says which cosignatures hold.

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };

/** SHA-256(<name> || "\n" || 0x04 || key)[:4]: the key id of an Ed25519 cosigner. */
export function cosignerKeyId(name, publicKey32) {
  return sha256(Buffer.from(name, 'utf8'), Buffer.from([0x0a, 0x04]), Buffer.from(publicKey32)).subarray(0, 4);
}

/** Parse a cosigner verifier key `<name>+<id hex>+base64(0x04 || key)`. Throws when it is not one. */
export function parseCosignerVkey(vkey) {
  const m = /^([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})$/.exec(String(vkey).trim());
  if (!m) throw new Error('not a verifier key');
  const raw = Buffer.from(m[3], 'base64');
  if (raw.length !== 33 || raw[0] !== 0x04) throw new Error('not an Ed25519 cosigner key (type 0x04)');
  const key = raw.subarray(1);
  const id = cosignerKeyId(m[1], key);
  if (id.toString('hex') !== m[2]) throw new Error("the cosigner key's id does not match its key");
  return { name: m[1], id, key };
}

/** The checkpoint body: every line up to the blank line, without signatures. */
export function noteBody(note) {
  const s = String(note);
  const i = s.indexOf('\n\n');
  if (i < 0) throw new Error('not a signed note');
  return s.slice(0, i + 1);
}

/**
 * The cosignatures in a signed checkpoint that check against `witnesses`
 * (each {vkey, operator?}). Returns one entry per witness: {name, operator,
 * valid, timestamp, time, reason}. A line by an unknown key is ignored, as
 * the format requires. A cosignature dated more than an hour after `now` is
 * not counted.
 */
export function checkCosignatures(note, witnesses, now = Date.now()) {
  const body = noteBody(note);
  const lines = String(note).slice(body.length + 1).split('\n').filter((l) => l.startsWith('— '));
  return witnesses.map((w) => {
    let c;
    try { c = parseCosignerVkey(w.vkey); } catch (e) { return { name: null, operator: w.operator ?? null, valid: false, timestamp: null, time: null, reason: e.message }; }
    const res = { name: c.name, operator: w.operator ?? null, valid: false, timestamp: null, time: null, reason: 'no cosignature from this witness' };
    for (const line of lines) {
      const m = /^— (\S+) ([A-Za-z0-9+/]+={0,2})$/.exec(line);
      if (!m || m[1] !== c.name) continue;
      const raw = Buffer.from(m[2], 'base64');
      if (raw.length !== 76 || !raw.subarray(0, 4).equals(c.id)) continue;
      const ts = raw.readBigUInt64BE(4);
      if (ts === 0n || ts > 0x7fffffffffffffffn) { res.reason = 'the cosignature carries no valid time'; continue; }
      const msg = Buffer.from(`cosignature/v1\ntime ${ts}\n${body}`, 'utf8');
      let ok = false;
      try { ok = edVerify(null, msg, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(c.key).toString('base64url') }, format: 'jwk' }), raw.subarray(12)); } catch { ok = false; }
      if (!ok) { res.reason = 'the cosignature does not check'; continue; }
      if (Number(ts) * 1000 > now + 3600e3) { res.reason = 'the cosignature is dated in the future'; continue; }
      return { ...res, valid: true, timestamp: Number(ts), time: new Date(Number(ts) * 1000).toISOString(), reason: null };
    }
    return res;
  });
}
