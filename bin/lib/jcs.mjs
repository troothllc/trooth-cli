// bin/lib/jcs.mjs - RFC 8785 JSON Canonicalization Scheme (JCS), as the
// trooth.witness-statement.v3 profile uses it.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// The profile (docs/VERIFY.md section 2.1) is JCS restricted to I-JSON values a
// Trooth payload actually carries: objects, arrays, strings, true, false, null
// and integers between -(2^53 - 1) and 2^53 - 1. A fraction, an exponent, a
// number outside that range or a string holding a lone surrogate is refused,
// so every implementation (this one, sdk/python, sdk/go) produces the same
// bytes or the same refusal. Object members are sorted by UTF-16 code units;
// strings are escaped exactly as ECMAScript's JSON.stringify escapes them.

export class CanonicalizationError extends Error {}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function str(s) {
  if (LONE_SURROGATE.test(s)) throw new CanonicalizationError('a string holds a lone surrogate');
  return JSON.stringify(s);
}

/** The canonical JSON text of a value, under the v3 profile. */
export function canonicalize(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'string') return str(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new CanonicalizationError(`the number ${value} is not an integer between -(2^53 - 1) and 2^53 - 1`);
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${str(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  throw new CanonicalizationError(`a ${typeof value} has no JSON form`);
}

/** Whether `text` is already the canonical form of the JSON it holds. */
export function isCanonical(text) {
  if (typeof text !== 'string') return false;
  let parsed;
  try { parsed = JSON.parse(text); } catch { return false; }
  try { return canonicalize(parsed) === text; } catch { return false; }
}

/**
 * RFC 8785 for a public record reading (docs/EVIDENCE.md section 5): the same
 * rules, but a finite number of any size is written in ECMAScript's shortest
 * form, which is what RFC 8785 specifies for numbers. Used only to recompute
 * the SHA-256 a public record statement names.
 */
export function canonicalizeRecord(value) {
  if (value === null || value === true || value === false || typeof value === 'string') return canonicalize(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalizationError('a number is not finite');
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeRecord).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${str(k)}:${canonicalizeRecord(value[k])}`).join(',')}}`;
  }
  throw new CanonicalizationError(`a ${typeof value} has no JSON form`);
}
