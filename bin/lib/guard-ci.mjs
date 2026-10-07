// bin/lib/guard-ci.mjs - CI mode of the guard (trooth guard ci, docs/GUARD.md
// section 7): find the external hosts a change adds to code and config, and
// report each one the policy's destinations.allowed does not list.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// Pure functions over text. It reads no network and sends nothing.

import { isIP } from 'node:net';
import { hostMatches, isDomainName } from './guard-policy.mjs';

/** Files that are prose, not code or config; a link in them is not a destination. HTML is code:
 *  a form action or a fetch() in a page is a destination. */
const PROSE = /(^|\/)(LICENSE|NOTICE|CHANGELOG|AUTHORS|CONTRIBUTORS)(\.[a-z]+)?$|\.(md|markdown|rst|txt|adoc|svg|lock)$/i;
/** File extensions that look like the last label of a host name in a bare string. */
const FILE_EXT = new Set(['json', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'md', 'yml', 'yaml', 'toml', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'css', 'scss', 'html', 'htm', 'py', 'rb', 'go', 'rs', 'java', 'kt', 'sh', 'lock', 'xml', 'csv', 'pdf', 'zip', 'gz', 'tgz', 'tar', 'wasm', 'map', 'log', 'env', 'ini', 'cfg', 'conf', 'tf', 'hcl', 'sql', 'php', 'swift', 'dart', 'vue', 'svelte', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'mp4', 'webp', 'avif', 'node', 'exe', 'dll', 'so', 'test', 'spec', 'min', 'd', 'local', 'internal', 'example', 'invalid', 'localhost']);
const RESERVED = /(^|\.)(example\.(com|net|org)|test|example|invalid|localhost|local|internal|home\.arpa)$/;

const URL_RE = /\bhttps?:\/\/([^\s/"'<>`)\]},;\\]+)/gi;
// A quoted string that is wholly a host name, or a config value (key: host, KEY=host).
const QUOTED_HOST = /["'`]((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})["'`]/gi;
const CONFIG_HOST = /(?:^|\s)[A-Za-z_][A-Za-z0-9_.-]*\s*(?:=|:)\s*((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\s*$/i;

function cleanHost(raw) {
  let h = String(raw).toLowerCase();
  h = h.replace(/^[^@]*@/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (h.startsWith('[')) return null;
  if (isIP(h)) return null;
  if (!isDomainName(h)) return null;
  if (RESERVED.test(h)) return null;
  const tld = h.split('.').pop();
  if (!/^[a-z]{2,63}$/.test(tld)) return null;
  return h;
}

/** The hosts one line names: URLs anywhere, bare hosts only as a quoted string or a config value. */
export function hostsInLine(line) {
  const out = new Set();
  for (const m of line.matchAll(URL_RE)) {
    if (/\$\{|\{\{|%s|<[a-z]/i.test(m[1])) continue;
    const h = cleanHost(m[1]);
    if (h) out.add(h);
  }
  for (const m of line.matchAll(QUOTED_HOST)) {
    const h = cleanHost(m[1]);
    if (h && !FILE_EXT.has(h.split('.').pop())) out.add(h);
  }
  const c = CONFIG_HOST.exec(line);
  if (c) { const h = cleanHost(c[1]); if (h && !FILE_EXT.has(h.split('.').pop())) out.add(h); }
  return [...out];
}

/** Added lines of a unified diff (git diff --unified=0): [{file, line, text}]. */
export function addedLines(diff) {
  const out = [];
  let file = null, line = 0;
  for (const l of String(diff).split('\n')) {
    if (l.startsWith('+++ ')) { const p = l.slice(4).trim(); file = p === '/dev/null' ? null : p.replace(/^b\//, ''); continue; }
    if (l.startsWith('--- ')) continue;
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(l);
    if (h) { line = Number(h[1]); continue; }
    if (file === null) continue;
    if (l.startsWith('+')) { out.push({ file, line, text: l.slice(1) }); line++; }
    else if (l.startsWith(' ')) line++;
  }
  return out;
}

/**
 * The findings: each added external host the policy does not allow and (when
 * the policy lists destinations.watch) a watch pattern covers.
 */
export function scanLines(lines, policy) {
  const findings = [];
  const allowed = [];
  for (const { file, line, text } of lines) {
    if (!file || PROSE.test(file)) continue;
    for (const host of hostsInLine(text)) {
      if (policy.destinations.allowed.some((p) => hostMatches(p, host))) { allowed.push({ file, line, host }); continue; }
      const watch = policy.destinations.watch;
      if (watch.length && !watch.some((p) => p === '*' || hostMatches(p, host) || host === p.replace(/^\*\./, ''))) continue;
      findings.push({ file, line, host });
    }
  }
  return { findings, allowed };
}
