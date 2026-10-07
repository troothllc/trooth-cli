// bin/lib/mcp-tools.mjs - MCP tool description hashes (docs/EVIDENCE.md
// section 9): the hashes of one tool and of a manifest, the comparison of
// two tool lists, and a small MCP client that reads a server's tool list with
// no credentials, so `trooth mcp-tools <endpoint> --live` can compare what a
// server lists now with what Trooth logged.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
import { createHash } from 'node:crypto';
import { canonicalize } from './jcs.mjs';

const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

/** description_sha256 and definition_sha256 of one listed tool. */
export function hashTool(tool) {
  const description = typeof tool.description === 'string' ? tool.description : '';
  return { name: String(tool.name), description_sha256: sha(description), definition_sha256: sha(canonicalize(tool)) };
}

/** SHA-256 of the RFC 8785 bytes of [{name, definition_sha256}] sorted by name. */
export function manifestOf(tools) {
  const list = [...tools].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)).map((t) => ({ name: t.name, definition_sha256: t.definition_sha256 }));
  return sha(canonicalize(list));
}

/** Tool names added, removed and changed from `before` to `after`. */
export function diffTools(before, after) {
  const p = new Map(before.map((t) => [t.name, t.definition_sha256]));
  const n = new Map(after.map((t) => [t.name, t.definition_sha256]));
  return {
    added: [...n.keys()].filter((k) => !p.has(k)).sort(),
    removed: [...p.keys()].filter((k) => !n.has(k)).sort(),
    changed: [...n.keys()].filter((k) => p.has(k) && p.get(k) !== n.get(k)).sort(),
  };
}

/** The JSON-RPC answer with this id in a JSON or text/event-stream body. */
export function rpcMessage(contentType, text, id) {
  const parse = (t) => { try { return JSON.parse(t); } catch { return null; } };
  if (/text\/event-stream/i.test(contentType)) {
    for (const block of String(text).split(/\r?\n\r?\n/)) {
      const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
      const m = data ? parse(data) : null;
      if (m && m.id === id) return m;
    }
    return null;
  }
  const m = parse(text);
  if (Array.isArray(m)) return m.find((x) => x && x.id === id) || null;
  return m && m.id === id ? m : null;
}

/** Read a server's tools with no credentials: initialize, initialized, tools/list (paged). */
export async function listTools(endpoint, { fetchFn = fetch, timeoutMs = 15000, userAgent = 'trooth-cli' } = {}) {
  const session = { id: null, version: null };
  const call = async (id, method, params) => {
    const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'user-agent': userAgent };
    if (session.id) headers['mcp-session-id'] = session.id;
    if (session.version) headers['mcp-protocol-version'] = session.version;
    const msg = id === null ? { jsonrpc: '2.0', method, ...(params ? { params } : {}) } : { jsonrpc: '2.0', id, method, ...(params ? { params } : {}) };
    const res = await fetchFn(endpoint, { method: 'POST', headers, body: JSON.stringify(msg), redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    const sid = res.headers.get('mcp-session-id');
    if (sid) session.id = sid;
    const text = await res.text();
    if (id === null) return null;
    if (!res.ok) throw new Error(`${method} answered HTTP ${res.status}`);
    if (text.length > 4_000_000) throw new Error(`${method}: the answer is larger than 4 MB`);
    const m = rpcMessage(res.headers.get('content-type') || '', text, id);
    if (!m) throw new Error(`${method}: no JSON-RPC answer`);
    if (m.error) throw new Error(`${method}: ${String(m.error.message || 'error').slice(0, 200)}`);
    return m.result || {};
  };
  const init = await call(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'trooth-cli', version: '1' } });
  session.version = typeof init.protocolVersion === 'string' ? init.protocolVersion : '2025-06-18';
  await call(null, 'notifications/initialized');
  const tools = [];
  let cursor;
  for (let page = 0; page < 10; page++) {
    const r = await call(2 + page, 'tools/list', cursor ? { cursor } : undefined);
    for (const t of Array.isArray(r.tools) ? r.tools : []) if (t && typeof t.name === 'string') tools.push(t);
    cursor = typeof r.nextCursor === 'string' && r.nextCursor ? r.nextCursor : undefined;
    if (!cursor) break;
  }
  return { server: init.serverInfo || {}, protocol_version: session.version, tools };
}
