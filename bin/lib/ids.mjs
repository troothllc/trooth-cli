// bin/lib/ids.mjs - Trooth stable identifiers (docs/IDS.md).
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// One grammar, `trooth:<type>:<value>`, so a reference to a record, a reading,
// a key, a mapping or a statement means the same thing in a log entry, an SDK,
// a bundle and a citation, and never depends on a URL that could move.

import { createHash } from 'node:crypto';

/** Each type and the exact form its value takes. */
export const ID_TYPES = {
  domain: /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
  reading: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/,
  key: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/,
  mapping: /^\d+\.\d+\.\d+$/,
  statement: /^[0-9a-f]{64}$/,
  entity: /^(?:lei:[A-Z0-9]{18}[0-9]{2}|cik:[0-9]{10})$/,
  cik: /^[0-9]{10}$/,
  lei: /^[A-Z0-9]{18}[0-9]{2}$/,
  jurisdiction: /^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/,
  registry: /^[A-Z]{2}-[A-Z0-9]{1,3}:[A-Za-z0-9-]{1,40}$/,
  uei: /^[A-Z0-9]{12}$/,
  repo: /^(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)\/[a-z0-9_.-]{1,100}$/,
  api: /^(?=.{1,500}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}(?:\/[^\s?#]*)?$/,
  mcp: /^(?=.{1,500}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}(?:\/[^\s?#]*)?$/,
  contact: /^(?:mailto:[^\s?#@]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]|(?=.{1,500}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}(?:\/[^\s?#]*)?)$/,
};

/** Build an id; throws when the value is not in its type's form. */
export function formatId(type, value) {
  const re = ID_TYPES[type];
  if (!re) throw new Error(`unknown Trooth id type: ${type}`);
  const v = type === 'domain' ? String(value).toLowerCase().replace(/\.$/, '') : type === 'cik' ? String(value).padStart(10, '0') : type === 'lei' ? String(value).toUpperCase() : type === 'contact' ? contactValue(value) : String(value);
  if (!re.test(v)) throw new Error(`not a valid ${type} value for a Trooth id: ${value}`);
  return `trooth:${type}:${v}`;
}

/**
 * The canonical value of a `contact` id (docs/IDS.md 1.4): a mailto address with
 * the domain lowercased, or an https address as host and path, without scheme,
 * query, fragment or trailing slash. Anything else is returned as given, so the
 * pattern refuses it.
 *   mailto:Security@Example.COM?subject=x  ->  mailto:Security@example.com
 *   https://Example.com/Report/?a=1#b      ->  example.com/Report
 */
function contactValue(raw) {
  const c = String(raw).trim();
  const mail = /^mailto:([^?#\s@]{1,64})@([A-Za-z0-9.-]{1,253})(?:[?#].*)?$/i.exec(c);
  if (mail) return `mailto:${mail[1]}@${mail[2].toLowerCase().replace(/\.$/, '')}`;
  if (/^https:\/\//i.test(c)) {
    let u;
    try { u = new URL(c); } catch { return c; }
    if (u.username || u.password) return c;
    return `${u.hostname.toLowerCase()}${u.pathname}`.replace(/\/+$/, '');
  }
  return c;
}

/** Parse an id into {type, value}, or null when it is not one. */
export function parseId(id) {
  const m = /^trooth:([a-z]+):(.+)$/.exec(String(id));
  if (!m || !ID_TYPES[m[1]] || !ID_TYPES[m[1]].test(m[2])) return null;
  return { type: m[1], value: m[2] };
}

/** The content-addressed id of a signed statement: sha256 over its exact payload bytes. */
export function statementId(payload) {
  return `trooth:statement:${createHash('sha256').update(Buffer.from(String(payload), 'utf8')).digest('hex')}`;
}
