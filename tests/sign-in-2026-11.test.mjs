// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Trooth, LLC
// `trooth login` against the sign-in that connect.trooth.co uses since November 2026: the metadata address for a
// resource with no path, and a sign-in that ends when the password or two-step changes.
//   node tests/sign-in-2026-11.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { prmUrl, agentMain } from '../bin/lib/agent.mjs';

async function server(handler) {
  const seen = [];
  const s = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      seen.push({ url: req.url, auth: req.headers.authorization ?? null, body });
      const [status, out] = handler(req);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
    });
  });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, seen, close: () => { s.closeAllConnections(); s.close(); } };
}
const quietIo = (err) => ({ out: () => {}, diag: () => {}, errLine: (x) => err.push(x), emitJson: () => {}, outAlways: () => {}, asJson: false, quiet: false });

test('the metadata address follows RFC 9728: no trailing slash for a resource with no path', () => {
  assert.equal(prmUrl('https://mcp.trooth.co'), 'https://mcp.trooth.co/.well-known/oauth-protected-resource');
  assert.equal(prmUrl('https://mcp.trooth.co/'), 'https://mcp.trooth.co/.well-known/oauth-protected-resource');
  assert.equal(prmUrl('https://api.example.test/os/semanto/mcp'), 'https://api.example.test/.well-known/oauth-protected-resource/os/semanto/mcp');
});

test('login reaches the sign-in server when the resource has no path, as mcp.trooth.co does', async () => {
  let polls = 0;
  const s = await server((req) => {
    // Only the exact RFC address answers; the slashed one is 404, as on mcp.trooth.co.
    if (req.url === '/.well-known/oauth-protected-resource') return [200, { resource: 'x', authorization_servers: [`http://${req.headers.host}`] }];
    if (req.url === '/.well-known/oauth-authorization-server') return [200, { issuer: 'x', token_endpoint: `http://${req.headers.host}/token`, device_authorization_endpoint: `http://${req.headers.host}/device` }];
    if (req.url === '/device') return [200, { device_code: 'dc', user_code: 'MNPQ-RSTV', verification_uri: 'https://example.test/device', expires_in: 30, interval: 0.01 }];
    if (req.url === '/token') return ++polls < 2 ? [400, { error: 'authorization_pending' }] : [200, { access_token: 'at-root', refresh_token: 'rt-root', expires_in: 3600 }];
    return [404, {}];
  });
  const env = { TROOTH_SEMANTO_MCP: s.url, TROOTH_KEYCHAIN: 'memory', TROOTH_CLIENT_ID: 'client_test' };
  const err = [];
  assert.equal(await agentMain('login', [], quietIo(err), env), 0, err.join('\n'));
  assert.ok(!s.seen.some((x) => x.url === '/.well-known/oauth-protected-resource/'), 'no request to the slashed address');
  assert.match(globalThis.__troothKeychain.get(s.url), /"access_token":"at-root"/);
  globalThis.__troothKeychain.delete(s.url);
  s.close();
});

test('a refused refresh says the sign-in ended and removes the dead token', async () => {
  const s = await server((req) => {
    if (req.url === '/token') return [400, { error: 'invalid_grant' }];
    return [401, { error: 'unauthenticated' }];
  });
  const resource = `${s.url}/os/semanto/mcp`;
  globalThis.__troothKeychain ??= new Map();
  globalThis.__troothKeychain.set(resource, JSON.stringify({ access_token: 'old', refresh_token: 'rt-old', expires_at: Date.now() - 60_000, client_id: 'c', token_endpoint: `${s.url}/token` }));
  const env = { TROOTH_SEMANTO_MCP: resource, TROOTH_NETWORK_MCP: resource, TROOTH_KEYCHAIN: 'memory' };
  const err = [];
  const code = await agentMain('semanto', ['status', '--trooth-id', 'acme'], quietIo(err), env);
  assert.notEqual(code, 0);
  assert.match(err.join('\n'), /sign-in to 127\.0\.0\.1:\d+ ended: the password or two-step changed, or every session was signed out\. Run `trooth login`/);
  assert.equal(globalThis.__troothKeychain.get(resource), undefined, 'the dead token is gone');
  assert.ok(!s.seen.some((x) => x.auth === 'Bearer old'), 'the expired token is never sent');
  s.close();
});
