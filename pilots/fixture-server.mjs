// fixture-server.mjs - a local HTTP server for the Trooth-run guard pilots.
// It serves Trooth "worlds" built by tests/lib/guard-fixtures.mjs
// (makeWorld: Ed25519 keys generated for the run, signed statements, a real
// Merkle log, witness cosignatures). Nothing here is a Trooth key or a real
// record. Each world lives under a path prefix:
//   http://127.0.0.1:<port>/<world>/web/...  answers as trooth.co
//   http://127.0.0.1:<port>/<world>/api/...  answers as api.trooth.co
// The server writes its port, log verifier key and witness keys to
// logs/fixture-info.json, then serves until killed.
import http from 'node:http';
import { writeFileSync, mkdirSync } from 'node:fs';
import { makeWorld, keyEntry, K, DEFAULT_KEYS } from '../tests/lib/guard-fixtures.mjs';

// One fixed signing key for the log and the witnesses is shared by all worlds
// (K is module state), so one --log-vkey and one witness list serve every world.
const worlds = {
  main: makeWorld({
    cosignAt: Date.now() - 600000,
    keys: [...DEFAULT_KEYS(), keyEntry('test-guard-z', K.b, { status: 'revoked' })],
    domains: {
      // allow: every rule's claim is signed, logged, fresh
      'acme-payments.com': { witness: {}, public: {} },
      // deny SUBJECT_MISMATCH: the record served for this host is another domain's
      'spoofed-vendor.com': { projection: { domain: 'other-vendor.com' }, witness: {}, public: {} },
      // deny KEY_NOT_TRUSTED: signed with a key the key list marks revoked
      'revoked-key-vendor.com': { witness: { kid: 'test-guard-z', kp: K.b }, public: {}, signPublic: { kid: 'test-guard-z', kp: K.b } },
      // hold EVIDENCE_MISSING: the sanctions list has an entry with the same name
      'name-match-vendor.com': { witness: {}, public: { sanctionsMatches: [{ name: 'Acme Test Inc.', programs: 'SDGT' }] } },
      // allow for the data-export pilot
      'export-partner.com': { witness: {}, public: {} },
    },
  }),
  // deny NOT_IN_LOG: a forged inclusion proof (a wrong index)
  forged: makeWorld({
    cosignAt: Date.now() - 600000,
    domains: { 'forged-log-vendor.com': { witness: {}, public: {} } },
    forgeProof: (r) => ({ ...r, index: r.index === 0 ? 1 : 0 }),
  }),
};

const server = http.createServer(async (req, res) => {
  try {
    const m = /^\/([a-z]+)\/(web|api)(\/.*)$/.exec(req.url);
    const w = m && worlds[m[1]];
    if (!w) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{"error":"no such world"}'); return; }
    const upstream = (m[2] === 'web' ? w.web : w.api) + m[3];
    const r = await w.fetch(upstream, { method: req.method });
    const body = Buffer.from(await r.arrayBuffer());
    res.writeHead(r.status, { 'content-type': r.headers.get('content-type') || 'application/octet-stream', 'content-length': body.length });
    res.end(body);
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: String(e?.message ?? e) }));
  }
});

server.listen(Number(process.env.PORT || 0), '127.0.0.1', () => {
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  const info = {
    port, base,
    worlds: Object.fromEntries(Object.keys(worlds).map((k) => [k, { web: `${base}/${k}/web`, api: `${base}/${k}/api` }])),
    vkey: worlds.main.vkeys[0],
    witnesses: worlds.main.witnesses,
  };
  if (worlds.forged.vkeys[0] !== info.vkey) throw new Error('worlds disagree on the log key');
  mkdirSync(new URL('./logs/', import.meta.url), { recursive: true });
  writeFileSync(new URL('./logs/fixture-info.json', import.meta.url), JSON.stringify(info, null, 2));
  console.log(`fixture server on ${base}`);
});
