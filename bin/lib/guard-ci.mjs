// bin/lib/guard-ci.mjs - CI mode of the guard (trooth guard ci, docs/GUARD.md
// section 7): find the external hosts a change adds to code and config, and
// report each one the policy's destinations.allowed does not list.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// Pure functions over text. It reads no network and sends nothing.
//
// What counts as a destination (since trooth 0.15.0):
//
//   (a) the host of an http, https, ws or wss URL, anywhere in a code or
//       config file, always;
//   (b) a bare host name only when it is the whole value of a host-like key
//       or argument (HOST_KEYS below: `host: api.vendor.io` in YAML,
//       `"host": "api.vendor.io"` in JSON, `host = "api.vendor.io"` in TOML,
//       `API_HOST=api.vendor.io` in .env, `{ baseURL: 'api.vendor.io' }` in a
//       JS object literal, `--host api.vendor.io` on a command line; in
//       source code the value must be quoted, since an unquoted value there
//       is an expression such as `to: msg.to`), and
//       only when it is written in lowercase letters, digits, dots and
//       hyphens, has at least two labels, and its last label is in
//       PUBLIC_SUFFIXES. A value with an uppercase letter (camelCase) or an
//       underscore is an identifier, not a host.
//
// A quoted dotted string on its own ("page.docs.cli.guardTitle",
// "lib.changelog.e2026.name", "x.open") is never a destination: before 0.15.0
// any quoted dotted string whose last label looked like a top-level domain
// counted, and i18n keys and dotted identifiers were reported as hosts.
//
// Prose files (Markdown, text, licenses, changelogs) are not read at all: a
// link in documentation is not a destination. IP literals, localhost and the
// reserved example names (example.com, .test, .example, .invalid, .localhost,
// .local, .internal, home.arpa) are never reported.

import { isIP } from 'node:net';
import { hostMatches, isDomainName } from './guard-policy.mjs';

/** Files that are prose, not code or config; a link in them is not a destination. HTML is code:
 *  a form action or a fetch() in a page is a destination. */
const PROSE = /(^|\/)(LICENSE|NOTICE|CHANGELOG|AUTHORS|CONTRIBUTORS)(\.[a-z]+)?$|\.(md|markdown|rst|txt|adoc|svg|lock)$/i;
const RESERVED = /(^|\.)(example\.(com|net|org)|test|example|invalid|localhost|local|internal|home\.arpa)$/;

/**
 * The last labels a bare host name may end in (rule b): a curated subset of
 * the public suffix list, the generic and country-code top-level domains most
 * used by services an application sends data or money to. It is deliberately
 * short, and it leaves out real top-level domains that are also common words
 * at the end of identifiers, i18n keys and property paths (name, link, open,
 * next, page, email, host, id, store, run, ws and the like), so that
 * `to: user.email` or `host: config.host` is not read as a host. A URL is a
 * destination whatever its top-level domain (rule a). To add a suffix, add it
 * here with a test in tests/guard-cli.test.mjs.
 */
export const PUBLIC_SUFFIXES = new Set([
  // generic
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
  'io', 'co', 'ai', 'dev', 'app', 'cloud', 'tech', 'info', 'biz', 'xyz', 'gg', 'sh', 'so', 'tv', 'cc', 'ly', 'to', 'la', 'is', 'me',
  // country codes
  'us', 'uk', 'de', 'fr', 'eu', 'ca', 'au', 'jp', 'in', 'ch', 'nl', 'se', 'no', 'fi', 'dk', 'es', 'it', 'pl', 'pt', 'br', 'mx', 'ar',
  'at', 'be', 'ie', 'lu', 'cz', 'sk', 'hu', 'ro', 'bg', 'gr', 'hr', 'si', 'ee', 'lv', 'lt', 'ua', 'tr', 'il', 'ae', 'sa', 'za', 'ng', 'ke', 'eg',
  'cn', 'hk', 'tw', 'kr', 'sg', 'th', 'vn', 'ph', 'nz', 'cl', 'pe', 'uy', 'ru', 'kz', 'pk', 'bd', 'lk', 'np',
  'fm', 'vc', 'nu', 'gl', 'bz', 'ag', 'li', 'mu', 'sc', 'ky', 'vg', 'cx',
]);

/** Key or argument names whose whole value may be a bare host. Matched against the
 *  last word of the key (API_HOST, webhook_host, baseURL, apiServer) or the whole key. */
export const HOST_KEYS = new Set(['host', 'hostname', 'domain', 'endpoint', 'url', 'base_url', 'baseurl', 'origin', 'webhook', 'to', 'from', 'redirect', 'server', 'api']);

const URL_RE = /\b(?:https?|wss?):\/\/([^\s/"'<>`)\]},;\\?#]+)/gi;
// key = value or key: value, where the value is the whole rest of the entry: a
// YAML or .env line, a JSON or TOML pair, a JS object property, a Python keyword.
const KEY_VALUE = /(?:^|[\s{,(])(["']?)([A-Za-z_$][A-Za-z0-9_$.-]*)\1\s*(?::|=(?!=))\s*(["'`]?)([^\s"'`,;{}()[\]]+)\3\s*(?=$|[,;})\]]|\s#|\s\/\/)/g;
// --flag value or --flag=value on a command line.
const FLAG = /(?:^|\s)--([a-z][a-z0-9-]*)(?:=|\s+)(["']?)([^\s"']+)\2(?=\s|$)/g;
/** Source files where an unquoted value is an expression (`to: msg.to`, `from: ws.me`), never a
 *  string: there a bare host counts only when it is quoted. */
const CODE = /\.(m?js|cjs|jsx?|tsx?|mts|cts|py|rb|go|java|kt|kts|scala|rs|php|swift|dart|cs|c|cc|cpp|h|hpp|vue|svelte|astro|html?)$/i;
const BARE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/** The words of a key: API_BASE_URL, apiBaseUrl, api-base-url and api.base.url all give api, base, url. */
function keyWords(key) {
  return key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toLowerCase().split(/[_.$-]+/).filter(Boolean);
}

/** Whether a key or argument name is host-like. */
export function hostLikeKey(key) {
  const words = keyWords(String(key));
  if (!words.length) return false;
  const last = words[words.length - 1];
  return HOST_KEYS.has(last) || HOST_KEYS.has(words.join('_')) || HOST_KEYS.has(words.join(''));
}

/** A host from a URL's authority: user info and port removed; null for an IP, a reserved name or a non-name. */
function urlHost(raw) {
  let h = String(raw).toLowerCase();
  h = h.replace(/^[^@]*@/, '').replace(/:\d*$/, '').replace(/\.$/, '');
  if (h.startsWith('[')) return null;
  if (isIP(h)) return null;
  if (!isDomainName(h)) return null;
  if (RESERVED.test(h)) return null;
  if (!/^[a-z]{2,63}$/.test(h.split('.').pop())) return null;
  return h;
}

/** Whether a value, exactly as written, is a bare host under rule (b). Returns the host or null. */
export function bareHost(value) {
  const v = String(value).replace(/:\d{1,5}$/, '').replace(/\.$/, '');
  if (!BARE.test(v)) return null; // uppercase (camelCase), underscores, or one label: an identifier
  if (isIP(v) || !isDomainName(v) || RESERVED.test(v)) return null;
  if (!PUBLIC_SUFFIXES.has(v.split('.').pop())) return null;
  return v;
}

/**
 * The hosts one line names: URLs anywhere; bare hosts only as the whole value
 * of a host-like key or argument. `file`, when given, decides whether an
 * unquoted value can be a host: not in source code, where it is an expression.
 */
export function hostsInLine(line, file = '') {
  const code = CODE.test(String(file));
  const out = new Set();
  const text = String(line);
  for (const m of text.matchAll(URL_RE)) {
    if (/\$\{|\{\{|%s|<[a-z]/i.test(m[1])) continue;
    const h = urlHost(m[1]);
    if (h) out.add(h);
  }
  for (const m of text.matchAll(KEY_VALUE)) {
    if (!hostLikeKey(m[2]) || (code && !m[3])) continue;
    const h = bareHost(m[4]);
    if (h) out.add(h);
  }
  for (const m of text.matchAll(FLAG)) {
    if (!hostLikeKey(m[1])) continue;
    const h = bareHost(m[3]);
    if (h) out.add(h);
  }
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
    for (const host of hostsInLine(text, file)) {
      if (policy.destinations.allowed.some((p) => hostMatches(p, host))) { allowed.push({ file, line, host }); continue; }
      const watch = policy.destinations.watch;
      if (watch.length && !watch.some((p) => p === '*' || hostMatches(p, host) || host === p.replace(/^\*\./, ''))) continue;
      findings.push({ file, line, host });
    }
  }
  return { findings, allowed };
}
