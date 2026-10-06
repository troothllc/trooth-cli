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
  entity: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
};

/** Build an id; throws when the value is not in its type's form. */
export function formatId(type, value) {
  const re = ID_TYPES[type];
  if (!re) throw new Error(`unknown Trooth id type: ${type}`);
  const v = type === 'domain' ? String(value).toLowerCase().replace(/\.$/, '') : String(value);
  if (!re.test(v)) throw new Error(`not a valid ${type} value for a Trooth id: ${value}`);
  return `trooth:${type}:${v}`;
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
