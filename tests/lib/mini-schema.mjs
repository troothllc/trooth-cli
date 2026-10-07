// tests/lib/mini-schema.mjs - the subset of JSON Schema 2020-12 that schemas/
// uses, validated with no dependency (the package keeps exactly one). It
// supports $ref (local and to a sibling file by name), type, const, enum,
// properties, required, additionalProperties, items, minItems, minLength,
// minimum, pattern, oneOf and anyOf, and takes format as an annotation only. A keyword outside that set is refused so a
// schema cannot quietly use something this validator ignores.
import { readFileSync, readdirSync } from 'node:fs';

const KNOWN = new Set(['$schema', '$id', '$defs', '$ref', 'title', 'description', 'type', 'const', 'enum', 'properties', 'required', 'additionalProperties', 'items', 'minItems', 'minLength', 'minimum', 'pattern', 'oneOf', 'anyOf', 'format']);

export function loadSchemas(dirUrl) {
  const out = {};
  for (const f of readdirSync(dirUrl)) if (f.endsWith('.json')) out[f] = JSON.parse(readFileSync(new URL(f, dirUrl), 'utf8'));
  return out;
}

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}

export function makeValidator(schemas) {
  function resolve(ref, file) {
    const [f, frag] = ref.split('#');
    const target = f ? f : file;
    let node = schemas[target];
    if (!node) throw new Error(`unresolved $ref ${ref}`);
    if (frag) for (const part of frag.split('/').filter(Boolean)) node = node[part];
    if (!node) throw new Error(`unresolved $ref ${ref}`);
    return { node, file: target };
  }
  function check(s, v, file, path, errs) {
    for (const k of Object.keys(s)) if (!KNOWN.has(k)) throw new Error(`${file}: keyword ${k} is outside the supported subset`);
    if (s.$ref) { const r = resolve(s.$ref, file); check(r.node, v, r.file, path, errs); }
    if (s.type) {
      const t = typeOf(v); const want = Array.isArray(s.type) ? s.type : [s.type];
      if (!want.includes(t) && !(t === 'integer' && want.includes('number'))) { errs.push(`${path}: is ${t}, expected ${want.join('|')}`); return; }
    }
    if ('const' in s && v !== s.const) errs.push(`${path}: is not ${JSON.stringify(s.const)}`);
    if (s.enum && !s.enum.includes(v)) errs.push(`${path}: ${JSON.stringify(v)} is not one of ${s.enum.join(', ')}`);
    if (typeof v === 'string') {
      if (s.minLength !== undefined && [...v].length < s.minLength) errs.push(`${path}: shorter than ${s.minLength}`);
      if (s.pattern && !new RegExp(s.pattern, 'u').test(v)) errs.push(`${path}: does not match ${s.pattern}`);
    }
    if (typeof v === 'number' && s.minimum !== undefined && v < s.minimum) errs.push(`${path}: below ${s.minimum}`);
    if (Array.isArray(v)) {
      if (s.minItems !== undefined && v.length < s.minItems) errs.push(`${path}: fewer than ${s.minItems} items`);
      if (s.items) v.forEach((x, i) => check(s.items, x, file, `${path}[${i}]`, errs));
    }
    if (typeOf(v) === 'object') {
      for (const r of s.required || []) if (!(r in v)) errs.push(`${path}: missing ${r}`);
      for (const [k, x] of Object.entries(v)) {
        if (s.properties && k in s.properties) check(s.properties[k], x, file, `${path}.${k}`, errs);
        else if (s.additionalProperties === false) errs.push(`${path}: unexpected ${k}`);
        else if (s.additionalProperties && typeof s.additionalProperties === 'object') check(s.additionalProperties, x, file, `${path}.${k}`, errs);
      }
    }
    if (s.oneOf) {
      const n = s.oneOf.filter((b) => { const e = []; check(b, v, file, path, e); return e.length === 0; }).length;
      if (n !== 1) errs.push(`${path}: matches ${n} of oneOf, expected exactly 1`);
    }
    if (s.anyOf && !s.anyOf.some((b) => { const e = []; check(b, v, file, path, e); return e.length === 0; })) errs.push(`${path}: matches none of anyOf`);
  }
  return (file, value) => { const errs = []; check(schemas[file], value, file, '$', errs); return errs; };
}
