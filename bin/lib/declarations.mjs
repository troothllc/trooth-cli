// What a declaration file says, read from its parsed tree.
// Copyright 2025-2026 Trooth, LLC. Apache-2.0.
//
// Every supported format is parsed first (HCL by ./hcl.mjs, JSON by
// JSON.parse, YAML by the maintained `yaml` package) and then read here from
// the tree, so a comment can never count, indentation cannot change a count,
// a minified file counts the same as a pretty one, and a file that does not
// parse is reported as invalid instead of being read.
//
// An unresolved expression ({ $expr: "..." }) is never promoted to a value.
// Where it decides a fact, the fact is reported as UNRESOLVED.

import { parseHcl, bodyToTree, HclParseError } from './hcl.mjs';
import { parseAllDocuments } from 'yaml';

export { HclParseError };

export const isExpr = (v) => !!v && typeof v === 'object' && !Array.isArray(v) && typeof v.$expr === 'string';

/* ------------------------------------------------------------ parsing ---- */

export class InvalidDeclaration extends Error {
  constructor(message) { super(message); this.name = 'InvalidDeclaration'; }
}

/** A string in Terraform's JSON syntax that holds a template is an expression. */
function tfJsonValue(v) {
  if (typeof v === 'string') {
    if (/[$%]\{/.test(v)) return { $expr: v };
    return v;
  }
  if (Array.isArray(v)) return v.map(tfJsonValue);
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = tfJsonValue(x);
    return o;
  }
  return v;
}

const each = (v, fn) => { if (Array.isArray(v)) v.forEach((x) => each(x, fn)); else if (v && typeof v === 'object') fn(v); };

/**
 * One file's units. Each unit: { type, name, address, tree, typed }.
 * `type` is a resource type or Kubernetes kind (null for everything else in the
 * file), `tree` is the parsed value, `address` is how other resources refer to
 * it. Throws InvalidDeclaration when the file does not parse.
 */
export function unitsOf(kind, text) {
  if (kind === 'terraform') {
    let items;
    try { items = parseHcl(text); } catch (e) { throw new InvalidDeclaration(e.message); }
    const units = [];
    const rest = [];
    for (const it of items) {
      if (it.kind === 'block' && it.type === 'resource') {
        if (it.labels.length !== 2) throw new InvalidDeclaration(`line ${it.line}: a resource block needs a type and a name`);
        const [type, name] = it.labels;
        units.push({ type, name, address: `${type}.${name}`, tree: bodyToTree(it.body), typed: true });
      } else rest.push(it);
    }
    if (rest.length) units.push({ type: null, name: null, address: null, tree: bodyToTree(rest), typed: false });
    return units;
  }
  if (kind === 'terraform-json') {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { throw new InvalidDeclaration(`not valid JSON: ${e.message}`); }
    if (!doc || typeof doc !== 'object') throw new InvalidDeclaration('a .tf.json file must hold a JSON object');
    const units = [];
    each(doc, (top) => each(top.resource, (byType) => {
      for (const [type, byName] of Object.entries(byType)) {
        if (!/^[a-z0-9_]+$/.test(type)) continue;
        each(byName, (names) => {
          for (const [name, body] of Object.entries(names)) {
            each(body, (b) => units.push({ type, name, address: `${type}.${name}`, tree: tfJsonValue(b), typed: true }));
          }
        });
      }
    }));
    if (!Array.isArray(doc)) {
      const rest = { ...doc }; delete rest.resource;
      if (Object.keys(rest).length) units.push({ type: null, name: null, address: null, tree: tfJsonValue(rest), typed: false });
    }
    return units;
  }
  if (kind === 'terraform-plan') {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { throw new InvalidDeclaration(`not valid JSON: ${e.message}`); }
    const units = [];
    const walkModule = (m) => {
      if (!m || typeof m !== 'object') return;
      for (const r of Array.isArray(m.resources) ? m.resources : []) {
        if (r && r.mode !== 'data' && typeof r.type === 'string') {
          units.push({ type: r.type, name: String(r.name ?? ''), address: r.address || `${r.type}.${r.name}`, tree: r.values ?? {}, typed: true, plan: true });
        }
      }
      for (const c of Array.isArray(m.child_modules) ? m.child_modules : []) walkModule(c);
    };
    if (doc && doc.planned_values && doc.planned_values.root_module) walkModule(doc.planned_values.root_module);
    else {
      for (const rc of Array.isArray(doc && doc.resource_changes) ? doc.resource_changes : []) {
        const after = rc && rc.change ? rc.change.after : null;
        if (rc && rc.mode !== 'data' && typeof rc.type === 'string' && after) {
          units.push({ type: rc.type, name: String(rc.name ?? ''), address: rc.address || `${rc.type}.${rc.name}`, tree: after, typed: true, plan: true });
        }
      }
    }
    return units;
  }
  if (kind === 'kubernetes') {
    const docs = parseAllDocuments(text, { strict: true, uniqueKeys: true, prettyErrors: false });
    const list = Array.isArray(docs) ? docs : [docs];
    const units = [];
    for (const d of list) {
      if (d.errors && d.errors.length) throw new InvalidDeclaration(`not valid YAML: ${d.errors[0].message.split('\n')[0]}`);
      const v = d.toJS({ maxAliasCount: 100 });
      if (v === null || v === undefined) continue;
      if (typeof v !== 'object' || Array.isArray(v)) throw new InvalidDeclaration('a Kubernetes document must be a mapping');
      const k = typeof v.kind === 'string' && /^[A-Za-z][A-Za-z0-9]*$/.test(v.kind) ? v.kind : null;
      if (!k || typeof v.apiVersion !== 'string') throw new InvalidDeclaration('a document in a Kubernetes file has no apiVersion and kind');
      units.push({ type: k, name: v.metadata && v.metadata.name ? String(v.metadata.name) : null, address: null, tree: v, typed: true });
    }
    return units;
  }
  if (kind === 'container') {
    return [{ type: null, name: null, address: null, tree: dockerfileTree(text), typed: false }];
  }
  throw new Error(`unknown kind ${kind}`);
}

/** A Dockerfile's ENV and ARG settings as a tree. Comment lines and line
 *  continuations are handled; every other instruction declares nothing lint
 *  counts. A value that uses $ is unresolved. */
function dockerfileTree(text) {
  const tree = {};
  const logical = [];
  let cur = '';
  for (const raw of text.split(/\r?\n/)) {
    if (/^\s*#/.test(raw) && !cur) continue;
    if (/\\\s*$/.test(raw)) { cur += raw.replace(/\\\s*$/, ' '); continue; }
    logical.push(cur + raw); cur = '';
  }
  if (cur) logical.push(cur);
  const val = (s) => {
    let v = s;
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    return /\$/.test(v) ? { $expr: v } : v;
  };
  for (const l of logical) {
    const m = /^\s*(ENV|ARG)\s+(.*)$/i.exec(l);
    if (!m) continue;
    const rest = m[2].trim();
    const pairs = rest.match(/[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)/g);
    if (pairs && pairs.join(' ').length >= rest.replace(/\s+/g, ' ').length - pairs.length) {
      for (const p of pairs) { const i = p.indexOf('='); tree[p.slice(0, i)] = val(p.slice(i + 1)); }
    } else {
      const sp = /^([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*))?$/.exec(rest);
      if (sp) tree[sp[1]] = sp[2] !== undefined ? val(sp[2].trim()) : { $expr: `ARG ${sp[1]}` };
    }
  }
  return tree;
}

/* ----------------------------------------------------------- reading ---- */

/** Every (key, value) pair in a tree, depth first. */
function* pairs(tree, parent = null) {
  if (Array.isArray(tree)) { for (const x of tree) yield* pairs(x, parent); return; }
  if (!tree || typeof tree !== 'object' || isExpr(tree)) return;
  for (const [k, v] of Object.entries(tree)) {
    yield [k, v, parent];
    yield* pairs(v, k);
  }
}

/** Every string (literal or expression source) in a tree. */
function* strings(tree) {
  if (typeof tree === 'string') { yield tree; return; }
  if (isExpr(tree)) { yield tree.$expr; return; }
  if (Array.isArray(tree)) { for (const x of tree) yield* strings(x); return; }
  if (tree && typeof tree === 'object') for (const v of Object.values(tree)) yield* strings(v);
}

const REGION_KEY = /^(region|location|availability_zone|aws_region|aws_default_region|zone)$/i;
const REGION_VALUE = /^[A-Za-z0-9][A-Za-z0-9._-]{2,40}$/;
const SECRET_KEY = /(password|passwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)/i;
const OPEN_CIDRS = new Set(['0.0.0.0/0', '::/0']);

export function regionsIn(tree) {
  const found = [];
  for (const [k, v] of pairs(tree)) if (REGION_KEY.test(k) && typeof v === 'string' && REGION_VALUE.test(v)) found.push(v);
  return found;
}

/** A credential literal: a secret-named key holding a literal string of at
 *  least eight characters. One count per key, wherever it sits in the file. */
export function credentialLiterals(tree) {
  let n = 0;
  for (const [k, v] of pairs(tree)) {
    if (!SECRET_KEY.test(k)) continue;
    if (typeof v === 'string' && v.length >= 8 && !/[$%]\{/.test(v)) n++;
  }
  return n;
}

export function opensToAnyAddress(tree) {
  for (const s of strings(tree)) if (OPEN_CIDRS.has(s.trim())) return true;
  return false;
}

export function markedPublic(tree) {
  for (const [k, v] of pairs(tree)) {
    if ((k === 'publicly_accessible' || k === 'public_network_access_enabled' || k === 'associate_public_ip_address') && (v === true || v === 'true')) return true;
    if (k === 'acl' && typeof v === 'string' && /^public-read/.test(v)) return true;
    if (k === 'type' && (v === 'LoadBalancer' || v === 'NodePort')) return true;
  }
  return false;
}

/* -------------------------------------------------------- encryption ---- */

// Keys whose value is the encryption switch itself.
const BOOL_KEY = /^(encrypted|storage_encrypted|encrypt_at_rest|encryption_enabled|enable_encryption|encrypted_at_rest|at_rest_encryption_enabled|encryption_at_rest_enabled)$/i;
// Keys that name the key or algorithm a store is encrypted with.
const KEY_KEY = /^(kms_key_id|kms_key_arn|kms_key_name|kms_key|kms_master_key_id|kms_key_self_link|encryption_key|encryption_key_name|disk_encryption_set_id|key_vault_key_id|sse_algorithm|default_kms_key_name)$/i;
// Blocks whose presence configures encryption, unless they switch it off.
const BLOCK_KEY = /^(server_side_encryption_configuration|server_side_encryption|encryption_configuration|encryption_config|encryption|encryption_at_rest|apply_server_side_encryption_by_default|disk_encryption|customer_managed_key)$/i;
// An expression that refers to a managed resource (aws_kms_key.main.arn) or a
// data source names a key that exists in the configuration; a variable, a
// local or anything else is unresolved.
const RESOURCE_REF = /^\$?\{?\s*(?:data\.)?[a-z][a-z0-9]*_[a-z0-9_]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_]+\s*\}?$/;

export const ENCRYPTION = Object.freeze({
  TRUE: 'declared',
  FALSE: 'declared_off',
  ABSENT: 'not_declared',
  UNRESOLVED: 'unresolved',
  UNSUPPORTED: 'unsupported',
});

function boolState(v) {
  if (v === true || v === 'true') return ENCRYPTION.TRUE;
  if (v === false || v === 'false') return ENCRYPTION.FALSE;
  if (isExpr(v)) return ENCRYPTION.UNRESOLVED;
  if (v === null) return ENCRYPTION.ABSENT;
  return ENCRYPTION.UNSUPPORTED;
}

function keyState(v) {
  if (v === null || v === '' || v === false) return ENCRYPTION.ABSENT;
  if (typeof v === 'string') return ENCRYPTION.TRUE;
  if (isExpr(v)) {
    const s = v.$expr.replace(/^"\$\{|\}"$/g, '').trim();
    return RESOURCE_REF.test(s) ? ENCRYPTION.TRUE : ENCRYPTION.UNRESOLVED;
  }
  return ENCRYPTION.UNSUPPORTED;
}

function blockState(v) {
  const blocks = Array.isArray(v) ? v : [v];
  let state = ENCRYPTION.ABSENT;
  for (const b of blocks) {
    if (!b || typeof b !== 'object' || isExpr(b)) { if (isExpr(b)) state = state === ENCRYPTION.TRUE ? state : ENCRYPTION.UNRESOLVED; continue; }
    if ('enabled' in b) {
      const s = boolState(b.enabled);
      if (s === ENCRYPTION.FALSE) return ENCRYPTION.FALSE;
      if (s === ENCRYPTION.UNRESOLVED) { state = ENCRYPTION.UNRESOLVED; continue; }
    }
    if (state !== ENCRYPTION.UNRESOLVED) state = ENCRYPTION.TRUE;
  }
  return state;
}

/**
 * What one store's tree declares about encryption at rest:
 *   declared      an explicit true, a key, or an encryption block
 *   declared_off  an explicit false (it wins over any other signal)
 *   not_declared  nothing about encryption (a comment is nothing)
 *   unresolved    decided by a variable, local or other expression
 *   unsupported   a value lint does not interpret (a number for a switch)
 * An explicit switch decides; keys and blocks decide only when no switch is set.
 */
export function encryptionState(tree) {
  const sw = [], other = [];
  for (const [k, v] of pairs(tree)) {
    if (BOOL_KEY.test(k)) sw.push(boolState(v));
    else if (KEY_KEY.test(k)) other.push(keyState(v));
    else if (BLOCK_KEY.test(k) && v && typeof v === 'object') other.push(blockState(v));
  }
  const decide = (list) => {
    if (list.includes(ENCRYPTION.FALSE)) return ENCRYPTION.FALSE;
    if (list.includes(ENCRYPTION.UNRESOLVED)) return ENCRYPTION.UNRESOLVED;
    if (list.includes(ENCRYPTION.UNSUPPORTED)) return ENCRYPTION.UNSUPPORTED;
    if (list.includes(ENCRYPTION.TRUE)) return ENCRYPTION.TRUE;
    return ENCRYPTION.ABSENT;
  };
  const s = decide(sw);
  if (s !== ENCRYPTION.ABSENT) return s;
  return decide(other);
}

/** Every string and expression source in a tree, joined, for finding a
 *  reference to another resource's address. */
export function referenceText(tree) {
  return [...strings(tree)].join('\n');
}
