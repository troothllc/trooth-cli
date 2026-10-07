// tests/witness-cose.test.mjs - witness cosignatures (bin/lib/witness.mjs)
// and COSE receipts (bin/lib/cose.mjs) against tests/vectors/witness-cose.json,
// and the pinned witness keys.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkCosignatures, parseCosignerVkey, noteBody } from '../bin/lib/witness.mjs';
import { checkCoseReceipt, decodeCbor, coseKeyThumbprint, keysFromKeySet } from '../bin/lib/cose.mjs';
import { parseVkey, entryBytes } from '../bin/lib/tlog.mjs';
import { PINNED_WITNESSES, PINNED_LOG_VKEYS } from '../bin/lib/log-trust.mjs';
import { parseId, formatId } from '../bin/lib/ids.mjs';

const WC = JSON.parse(readFileSync(new URL('./vectors/witness-cose.json', import.meta.url), 'utf8'));
const LOG = JSON.parse(readFileSync(new URL('./vectors/log.json', import.meta.url), 'utf8'));
let n = 0;
const t = (name, fn) => { fn(); n++; console.log(`  ok  ${name}`); };

console.log('witness cosignatures');
for (const c of WC.cosignatures) {
  t(`cosignature vector ${c.name}`, () => {
    const [r] = checkCosignatures(c.checkpoint, [{ vkey: WC.witness_vkey, operator: 'test' }], Date.parse(WC.now));
    assert.equal(r.valid, c.expect.valid, r.reason);
    if (c.expect.timestamp) assert.equal(r.timestamp, c.expect.timestamp);
  });
}
t('the checkpoint body is the note without its signature lines', () => {
  assert.equal(noteBody(LOG.checkpoints['5']), LOG.checkpoints['5'].slice(0, LOG.checkpoints['5'].indexOf('\n\n') + 1));
});
t('every pinned witness key is an Ed25519 cosigner key, each a different cosigner', () => {
  assert.ok(PINNED_WITNESSES.length >= 3);
  const names = PINNED_WITNESSES.map((w) => parseCosignerVkey(w.vkey).name);
  assert.equal(new Set(names).size, names.length);
  assert.throws(() => parseCosignerVkey(PINNED_LOG_VKEYS[0]), /0x04/);
});

console.log('COSE receipts');
const logKey = parseVkey(WC.log_vkey).key;
t('the vectors name the log key by its RFC 9679 thumbprint', () => assert.equal(coseKeyThumbprint(logKey).toString('base64url'), WC.log_key_thumbprint));
for (const c of WC.cose_receipts) {
  t(`receipt vector ${c.name}`, () => {
    const e = LOG.entries[c.index];
    const r = checkCoseReceipt(Buffer.from(c.receipt, 'base64'), entryBytes(e.kind, e.statement), logKey);
    assert.equal(r.valid, c.expect.valid, r.reason);
    if (c.expect.tree_size) assert.equal(r.tree_size, c.expect.tree_size);
  });
}
t('the CBOR reader refuses trailing bytes, indefinite lengths and floats', () => {
  assert.throws(() => decodeCbor(Buffer.from([0x01, 0x02])), /follow/);
  assert.throws(() => decodeCbor(Buffer.from([0x9f, 0xff])), /indefinite/);
  assert.throws(() => decodeCbor(Buffer.from([0xf9, 0x3c, 0x00])), /float/);
  assert.deepEqual(decodeCbor(Buffer.from([0x83, 0x01, 0x20, 0xf6])), [1, -1, null]);
});
t('a COSE Key Set yields its Ed25519 keys and kids', () => {
  const set = Buffer.concat([Buffer.from([0x81, 0xa5, 0x01, 0x01, 0x02, 0x58, 0x20]), coseKeyThumbprint(logKey), Buffer.from([0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]), logKey]);
  const keys = keysFromKeySet(set);
  assert.equal(keys.length, 1);
  assert.ok(keys[0].key.equals(logKey));
  assert.ok(keys[0].kid.equals(coseKeyThumbprint(logKey)));
});

console.log('entity ids');
t('trooth:entity names a legal entity by its LEI or SEC CIK', () => {
  assert.deepEqual(parseId('trooth:entity:lei:HWUPKR0MPOU8FGXBT394'), { type: 'entity', value: 'lei:HWUPKR0MPOU8FGXBT394' });
  assert.deepEqual(parseId('trooth:entity:cik:0000320193'), { type: 'entity', value: 'cik:0000320193' });
  assert.equal(parseId('trooth:entity:00000000-0000-4000-8000-000000000000'), null, 'the reserved UUID form was never issued and is not an id');
  assert.equal(parseId('trooth:entity:lei:hwupkr0mpou8fgxbt394'), null);
  assert.equal(formatId('entity', 'cik:0000320193'), 'trooth:entity:cik:0000320193');
});
console.log(`\n${n} witness, COSE and id checks passed`);
