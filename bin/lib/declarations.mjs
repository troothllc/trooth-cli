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
    // Terraform's JSON syntax requires an object at the root. An array is valid
    // JSON and not a valid declaration, so it is invalid, never read (T19).
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new InvalidDeclaration('Terraform JSON requires an object at the root');
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
    const rest = { ...doc }; delete rest.resource;
    if (Object.keys(rest).length) units.push({ type: null, name: null, address: null, tree: tfJsonValue(rest), typed: false });
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
    // Parsed BEFORE it is recognized (T16): flow style, quoted keys and several
    // documents are the same object to the parser, so they are the same object
    // here. A file none of whose documents is a manifest is not applicable; a
    // file that mixes manifests with other documents is invalid, as before.
    let list;
    try { list = parseAllDocuments(text, { strict: true, uniqueKeys: true, prettyErrors: false }); }
    catch (e) { throw new InvalidDeclaration(`not valid YAML: ${String(e && e.message).split('\n')[0]}`); }
    list = Array.isArray(list) ? list : [list];
    const looksLikeManifest = /["']?apiVersion["']?\s*:/.test(text) && /["']?kind["']?\s*:/.test(text);
    const values = [];
    for (const d of list) {
      if (d.errors && d.errors.length) {
        if (!looksLikeManifest) return Object.assign([], { notApplicable: true });
        throw new InvalidDeclaration(`not valid YAML: ${d.errors[0].message.split('\n')[0]}`);
      }
      // The alias limit stops expansion safely; it is reported against this
      // file with the rest of the read carrying on, never as a crash (T19).
      let v;
      try { v = d.toJS({ maxAliasCount: 100 }); }
      catch (e) {
        const m = String(e && e.message);
        throw new InvalidDeclaration(/alias/i.test(m) ? 'YAML alias expansion exceeds the limit of 100; the file was not read' : `not valid YAML: ${m.split('\n')[0]}`);
      }
      if (v !== null && v !== undefined) values.push(v);
    }
    const isManifest = (v) => v && typeof v === 'object' && !Array.isArray(v) && typeof v.apiVersion === 'string' && typeof v.kind === 'string' && /^[A-Za-z][A-Za-z0-9]*$/.test(v.kind);
    if (!values.some(isManifest)) return Object.assign([], { notApplicable: true });
    const units = [];
    let membersNotRead = 0;
    const add = (v, where) => {
      // A List (kind List, or any kind ending in List that holds items) is a
      // container, not a resource: each member is read with its own identity.
      if (/List$/.test(v.kind) && Array.isArray(v.items)) {
        v.items.forEach((it, i) => { if (isManifest(it)) add(it, `${where}.items[${i}]`); else membersNotRead++; });
        return;
      }
      units.push({ type: v.kind, name: v.metadata && v.metadata.name ? String(v.metadata.name) : null, address: where, tree: v, typed: true });
    };
    values.forEach((v, i) => {
      if (!isManifest(v)) {
        if (typeof v !== 'object' || Array.isArray(v)) throw new InvalidDeclaration('a Kubernetes document must be a mapping');
        throw new InvalidDeclaration('a document in a Kubernetes file has no apiVersion and kind');
      }
      add(v, `document[${i}]`);
    });
    return Object.assign(units, { membersNotRead });
  }
  if (kind === 'container') {
    const { tree, occurrences } = dockerfileTree(text);
    return [{ type: null, name: null, address: null, tree, occurrences, typed: false }];
  }
  throw new Error(`unknown kind ${kind}`);
}

/** A Dockerfile's ENV and ARG settings, twice: as a tree of effective values
 *  (the last assignment wins, as it does in a build) and as the ordered list of
 *  every assignment in the source. Credential literals are counted over the
 *  occurrences, so an earlier literal is not hidden by a later reference
 *  (T18); nothing else lint reports uses the occurrence list. Comment lines and
 *  line continuations are handled; a value that uses $ is unresolved. */
function dockerfileTree(text) {
  const tree = {};
  const occurrences = [];
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
      for (const p of pairs) { const i = p.indexOf('='); const k = p.slice(0, i), v = val(p.slice(i + 1)); tree[k] = v; occurrences.push([k, v]); }
    } else {
      const sp = /^([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*))?$/.exec(rest);
      if (sp) { const v = sp[2] !== undefined ? val(sp[2].trim()) : { $expr: `ARG ${sp[1]}` }; tree[sp[1]] = v; occurrences.push([sp[1], v]); }
    }
  }
  return { tree, occurrences };
}

/* ----------------------------------------------------------- reading ---- */

// Metadata a person writes about a resource: tags, labels, annotations and
// free-text descriptions. None of it configures anything, so none of it is read
// as configuration: a tag that says `encrypted = true` does not encrypt a
// volume, and a note that mentions 0.0.0.0/0 is not a network rule (T14).
const META_KEY = /^(tags|tags_all|default_tags|labels|annotations|description|descriptions|comment|comments|note|notes)$/i;

/** Every (key, value) pair in a tree, depth first, with metadata left out. */
function* pairs(tree, parent = null) {
  if (Array.isArray(tree)) { for (const x of tree) yield* pairs(x, parent); return; }
  if (!tree || typeof tree !== 'object' || isExpr(tree)) return;
  for (const [k, v] of Object.entries(tree)) {
    if (META_KEY.test(k)) continue;
    yield [k, v, parent];
    yield* pairs(v, k);
  }
}

/** Every string (literal or expression source) in a tree, metadata left out. */
function* strings(tree) {
  if (typeof tree === 'string') { yield tree; return; }
  if (isExpr(tree)) { yield tree.$expr; return; }
  if (Array.isArray(tree)) { for (const x of tree) yield* strings(x); return; }
  if (tree && typeof tree === 'object') for (const [k, v] of Object.entries(tree)) if (!META_KEY.test(k)) yield* strings(v);
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

// A secret-sounding name that is really an identifier, a location or a size:
// token_endpoint, secret_arn, kms_key_id, password_length. Excluded by the
// shape of the name, not by the length of the value (T17).
const NOT_SECRET_KEY = /(url|uri|endpoint|_arn|arn$|_ids?$|_name$|_names$|_type$|_length$|_path$|_file$|_ttl$|_version$|_count$|_ref$|_policy$|_enabled$|_rotation|rotation_|expir|_mode$|_format$|_algorithm$|_header$)/i;

/** A value that is written into the file, not a reference to one kept
 *  elsewhere. Empty strings, booleans, template and variable references are
 *  not literals. A URL is a literal credential only when it carries a password
 *  in its user information. */
function isLiteral(v) {
  if (typeof v !== 'string') return false;
  const s = v.trim();
  if (!s) return false;
  if (/[$%]\{/.test(s) || /\$\(/.test(s) || /^\$[A-Za-z_]/.test(s)) return false;
  if (/^(true|false|null|none|nil|undefined)$/i.test(s)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return /^[a-z][a-z0-9+.-]*:\/\/[^/@\s:]*:[^/@\s]+@/i.test(s);
  return true;
}

const isSecretKey = (k) => SECRET_KEY.test(k) && !NOT_SECRET_KEY.test(k);

/**
 * Credential literals in one unit, counted by SOURCE OCCURRENCE: each place a
 * credential is written into the file counts once. The forms read are
 *   a secret-named configuration key holding a literal value,
 *   a Kubernetes env entry whose name is secret-named and whose value is a literal,
 *   every value in a Kubernetes Secret's data and stringData,
 *   every ENV or ARG assignment in a Dockerfile, in source order.
 * The value itself is never returned, printed or hashed.
 */
export function credentialLiterals(unitOrTree) {
  const unit = unitOrTree && unitOrTree.tree !== undefined && ('typed' in unitOrTree) ? unitOrTree : { tree: unitOrTree };
  if (Array.isArray(unit.occurrences)) {
    return unit.occurrences.filter(([k, v]) => isSecretKey(k) && isLiteral(v)).length;
  }
  const tree = unit.tree;
  let n = 0;
  const isSecret = tree && typeof tree === 'object' && tree.kind === 'Secret' && typeof tree.apiVersion === 'string';
  const scan = (node) => {
    if (Array.isArray(node)) { node.forEach(scan); return; }
    if (!node || typeof node !== 'object' || isExpr(node)) return;
    // env: [{ name: API_TOKEN, value: ... }] and the same shape elsewhere.
    if (typeof node.name === 'string' && 'value' in node && isSecretKey(node.name) && isLiteral(node.value)) n++;
    for (const [k, v] of Object.entries(node)) {
      if (META_KEY.test(k)) continue;
      if (isSecret && node === tree && (k === 'data' || k === 'stringData')) {
        if (v && typeof v === 'object') for (const x of Object.values(v)) if (isLiteral(x)) n++;
        continue;
      }
      if (isSecretKey(k) && isLiteral(v)) n++;
      scan(v);
    }
  };
  scan(tree);
  return n;
}

// Keys that hold an address range in a network rule, in the providers and
// Kubernetes objects lint reads. An open range counts only here (T14).
const NET_KEY = /(cidr|source_ranges|sourceRanges|destination_ranges|address_prefix|addressPrefix|ip_ranges?|ipRanges?|source_ip|remote_ip_prefix|allowed_ips?|ip_address_range|loadBalancerSourceRanges|ipBlock)/i;

export function opensToAnyAddress(tree) {
  for (const [k, v] of pairs(tree)) {
    if (!NET_KEY.test(k)) continue;
    for (const s of strings(v)) if (OPEN_CIDRS.has(s.trim())) return true;
  }
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

// A block that is present but holds no setting lint recognizes. It is reported
// as unsupported rather than as declared: an empty `encryption {}` is not an
// encryption setting (T14). It never outranks a recognized setting elsewhere.
const UNRECOGNIZED_BLOCK = 'unrecognized_block';

function blockState(v) {
  const blocks = Array.isArray(v) ? v : [v];
  let state = ENCRYPTION.ABSENT;
  for (const b of blocks) {
    if (!b || typeof b !== 'object' || isExpr(b)) { if (isExpr(b)) state = state === ENCRYPTION.TRUE ? state : ENCRYPTION.UNRESOLVED; continue; }
    if ('enabled' in b) {
      const s = boolState(b.enabled);
      if (s === ENCRYPTION.FALSE) return ENCRYPTION.FALSE;
      if (s === ENCRYPTION.UNRESOLVED) { state = ENCRYPTION.UNRESOLVED; continue; }
      if (s === ENCRYPTION.TRUE) { if (state !== ENCRYPTION.UNRESOLVED) state = ENCRYPTION.TRUE; continue; }
    }
    // Otherwise the block declares encryption only through a recognized
    // setting inside it: a switch, a key or algorithm, or a nested block that
    // itself holds one.
    const inner = encryptionState(b, true);
    if (inner === ENCRYPTION.FALSE) return ENCRYPTION.FALSE;
    if (inner === ENCRYPTION.UNRESOLVED) { state = ENCRYPTION.UNRESOLVED; continue; }
    if (inner === ENCRYPTION.TRUE) { if (state !== ENCRYPTION.UNRESOLVED) state = ENCRYPTION.TRUE; continue; }
    if (state === ENCRYPTION.ABSENT) state = UNRECOGNIZED_BLOCK;
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
export function encryptionState(tree, inBlock = false) {
  const sw = [], other = [];
  let unrecognized = false;
  for (const [k, v] of pairs(tree)) {
    if (BOOL_KEY.test(k)) sw.push(boolState(v));
    else if (KEY_KEY.test(k)) other.push(keyState(v));
    else if (BLOCK_KEY.test(k) && v && typeof v === 'object') {
      const b = blockState(v);
      if (b === UNRECOGNIZED_BLOCK) unrecognized = true; else other.push(b);
    }
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
  const o = decide(other);
  if (o === ENCRYPTION.ABSENT && unrecognized && !inBlock) return ENCRYPTION.UNSUPPORTED;
  return o;
}

/** Every string and expression source in a tree, joined, for finding a
 *  reference to another resource's address. */
export function referenceText(tree) {
  return [...strings(tree)].join('\n');
}
