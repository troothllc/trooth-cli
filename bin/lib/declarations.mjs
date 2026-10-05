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

/** A string in Terraform's JSON syntax is a template. One with a live ${ } or
 *  %{ } is an expression; otherwise it is a constant, and its $${ and %%{
 *  escapes decode to the literal text ${ and %{ (N03). */
function tfJsonValue(v) {
  if (typeof v === 'string') {
    // Read left to right exactly as a quoted HCL string is (./hcl.mjs).
    let out = '';
    for (let i = 0; i < v.length; i++) {
      const c = v[i];
      if ((c === '$' || c === '%') && v[i + 1] === c && v[i + 2] === '{') { out += c + '{'; i += 2; continue; }
      if ((c === '$' || c === '%') && v[i + 1] === '{') return { $expr: v };
      out += c;
    }
    return out;
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

/** A block level in Terraform's JSON syntax is an object, or an array of
 *  objects (a repeated block). Anything else at a recognized declaration
 *  boundary is a malformed declaration, never an empty one (N01). The reason
 *  names the path of keys, never a value. */
function eachBlock(v, where, fn) {
  const objs = Array.isArray(v) ? v : [v];
  if (Array.isArray(v) && !v.length) throw new InvalidDeclaration(`${where} is an empty array; Terraform JSON needs an object here`);
  for (const o of objs) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) throw new InvalidDeclaration(`${where} must be an object${Array.isArray(v) ? ' or an array of objects' : ''}, found ${o === null ? 'null' : Array.isArray(o) ? 'an array' : typeof o}`);
    fn(o);
  }
}
const pathPart = (k) => (/^[A-Za-z0-9_-]{1,64}$/.test(k) ? k : '<key>');

/** The keys repeated within one JSON object, found from the source text,
 *  since JSON.parse silently keeps the last. Terraform rejects a repeated
 *  argument; reading either copy could credit a setting the file also
 *  switches off (N01). Returns the first repeated key, or null. */
function repeatedJsonKey(text) {
  const stack = [];
  let i = 0;
  const n = text.length;
  let expectKey = false;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1, raw = '';
      while (j < n && text[j] !== '"') { if (text[j] === '\\') { raw += text[j]; j++; } raw += text[j]; j++; }
      const top = stack[stack.length - 1];
      if (top && expectKey) {
        let key; try { key = JSON.parse(`"${raw}"`); } catch { key = raw; }
        if (top.has(key)) return key;
        top.add(key);
        expectKey = false;
      }
      i = j + 1; continue;
    }
    if (c === '{') { stack.push(new Set()); expectKey = true; }
    else if (c === '[') { stack.push(null); }
    else if (c === '}' || c === ']') { stack.pop(); }
    else if (c === ',') { expectKey = stack[stack.length - 1] instanceof Set; }
    i++;
  }
  return null;
}

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
        units.push({ type, name, address: `${type}.${name}`, tree: bodyToTree(it.body), typed: true, constants: true });
      } else rest.push(it);
    }
    if (rest.length) units.push({ type: null, name: null, address: null, tree: bodyToTree(rest), typed: false, constants: true });
    return units;
  }
  if (kind === 'terraform-json') {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { throw new InvalidDeclaration(`not valid JSON: ${e.message}`); }
    // Terraform's JSON syntax requires an object at the root. An array is valid
    // JSON and not a valid declaration, so it is invalid, never read (T19).
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new InvalidDeclaration('Terraform JSON requires an object at the root');
    const dup = repeatedJsonKey(text);
    if (dup !== null) throw new InvalidDeclaration(`the key ${JSON.stringify(pathPart(dup))} is repeated in one object; Terraform rejects a repeated argument`);
    const units = [];
    // Every recognized boundary is checked for shape (N01): `resource`, each
    // resource type and each resource body must be an object or an array of
    // objects. A "//" key is a comment in Terraform JSON at any level.
    if ('resource' in doc) {
      eachBlock(doc.resource, 'resource', (byType) => {
        for (const [type, byName] of Object.entries(byType)) {
          if (type === '//') continue;
          if (!/^[a-z0-9_]+$/.test(type)) continue;
          eachBlock(byName, `resource.${pathPart(type)}`, (names) => {
            for (const [name, body] of Object.entries(names)) {
              if (name === '//') continue;
              eachBlock(body, `resource.${pathPart(type)}.${pathPart(name)}`, (b) => units.push({ type, name, address: `${type}.${name}`, tree: tfJsonValue(b), typed: true, constants: true }));
            }
          });
        }
      });
    }
    const rest = { ...doc }; delete rest.resource;
    if (Object.keys(rest).length) units.push({ type: null, name: null, address: null, tree: tfJsonValue(rest), typed: false, constants: true });
    return units;
  }
  if (kind === 'terraform-plan') {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { throw new InvalidDeclaration(`not valid JSON: ${e.message}`); }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new InvalidDeclaration('a Terraform plan requires an object at the root');
    // WHAT IS NOT YET KNOWN (N02). A plan omits a value Terraform will only
    // learn at apply time from `after` and from planned_values, and marks it
    // `true` in change.after_unknown (and in proposed_unknown, when present).
    // Those marks are merged into each resource's tree as unresolved
    // expressions BEFORE anything is classified, so an unknown setting reads
    // as unresolved and never as not declared. Keyed by full address, so a
    // resource in module.a and one in module.b stay two resources.
    const unknownAt = new Map();
    const addUnknown = (address, marks) => {
      if (typeof address !== 'string' || marks === undefined || marks === null || marks === false) return;
      unknownAt.set(address, mergeMarks(unknownAt.get(address), marks));
    };
    const changes = Array.isArray(doc.resource_changes) ? doc.resource_changes : [];
    for (const rc of changes) if (rc && rc.change && typeof rc.change === 'object') addUnknown(rc.address, rc.change.after_unknown);
    const walkMarks = (m) => {
      if (!m || typeof m !== 'object') return;
      for (const r of Array.isArray(m.resources) ? m.resources : []) if (r && typeof r === 'object') addUnknown(r.address, r.values);
      for (const c of Array.isArray(m.child_modules) ? m.child_modules : []) walkMarks(c);
    };
    if (doc.proposed_unknown && typeof doc.proposed_unknown === 'object') walkMarks(doc.proposed_unknown.root_module);
    const withUnknown = (address, tree) => overlayUnknown(tree, unknownAt.get(address));

    const units = [];
    const walkModule = (m) => {
      if (!m || typeof m !== 'object') return;
      for (const r of Array.isArray(m.resources) ? m.resources : []) {
        if (r && r.mode !== 'data' && typeof r.type === 'string') {
          const address = r.address || `${r.type}.${r.name}`;
          units.push({ type: r.type, name: String(r.name ?? ''), address, tree: withUnknown(address, r.values ?? {}), typed: true, plan: true, constants: true });
        }
      }
      for (const c of Array.isArray(m.child_modules) ? m.child_modules : []) walkModule(c);
    };
    if (doc.planned_values && doc.planned_values.root_module) walkModule(doc.planned_values.root_module);
    else {
      for (const rc of changes) {
        const after = rc && rc.change ? rc.change.after : null;
        if (rc && rc.mode !== 'data' && typeof rc.type === 'string' && after) {
          const address = rc.address || `${rc.type}.${rc.name}`;
          units.push({ type: rc.type, name: String(rc.name ?? ''), address, tree: withUnknown(address, after), typed: true, plan: true, constants: true });
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
      // `kind: List`, or a *List kind that carries `items`, must hold an
      // array of items. Missing or non-array items is a malformed container,
      // reported as invalid, never read as an empty or complete one (N01).
      // An empty array is a valid, empty List.
      if (v.kind === 'List' || (/List$/.test(v.kind) && 'items' in v)) {
        if (!Array.isArray(v.items)) throw new InvalidDeclaration(`${where}: a ${pathPart(v.kind)} needs an items array, found ${v.items === undefined ? 'no items' : v.items === null ? 'null' : typeof v.items}`);
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
    return [{ type: null, name: null, address: null, tree, occurrences, typed: false, constants: true }];
  }
  throw new Error(`unknown kind ${kind}`);
}

/** `true` marks from after_unknown or proposed_unknown, merged: a leaf is
 *  unknown when either source says so. */
function mergeMarks(a, b) {
  if (a === true || b === true) return true;
  if (a === undefined || a === null || a === false) return b;
  if (b === undefined || b === null || b === false) return a;
  if (Array.isArray(a) && Array.isArray(b)) return Array.from({ length: Math.max(a.length, b.length) }, (_, i) => mergeMarks(a[i], b[i]));
  if (typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    const o = { ...a };
    for (const [k, v] of Object.entries(b)) o[k] = mergeMarks(a[k], v);
    return o;
  }
  return a;
}

const UNKNOWN = Object.freeze({ $expr: '(known after apply)' });

/** A planned value with every `true` mark replaced by an unresolved
 *  expression. Known values are kept as they are; nothing is evaluated. */
function overlayUnknown(value, marks) {
  if (marks === true) return UNKNOWN;
  if (!marks || typeof marks !== 'object') return value;
  if (Array.isArray(marks)) {
    const base = Array.isArray(value) ? [...value] : [];
    marks.forEach((m, i) => { const v = overlayUnknown(base[i], m); if (v !== undefined) base[i] = v; });
    return base;
  }
  const base = value && typeof value === 'object' && !Array.isArray(value) ? { ...value } : {};
  for (const [k, m] of Object.entries(marks)) {
    const v = overlayUnknown(base[k], m);
    if (v !== undefined) base[k] = v;
  }
  return base;
}

/**
 * A Dockerfile's logical lines, as BuildKit forms them (N04):
 *   parser directives are read only at the very top; `# escape=` sets the
 *   escape character to \ (the default) or `;
 *   a line ending in the escape character (trailing blanks allowed)
 *   continues on the next line, and the two are joined with NOTHING inserted;
 *   a full comment line or an empty line inside a continuation is dropped;
 *   CRLF and LF read the same.
 * Each logical line carries the physical line it started on.
 */
function dockerLogicalLines(text) {
  const physical = text.replace(/^﻿/, '').split(/\r?\n/);
  let escape = '\\';
  let k = 0;
  // Directives: `# name=value` lines before anything else. The first line
  // that is not one ends them, as BuildKit does.
  const seenDirective = new Set();
  for (; k < physical.length; k++) {
    const m = /^#[ \t]*([A-Za-z][A-Za-z0-9]*)[ \t]*=[ \t]*(\S*)[ \t]*$/.exec(physical[k]);
    if (!m) break;
    const name = m[1].toLowerCase();
    if (seenDirective.has(name)) throw new InvalidDeclaration(`line ${k + 1}: the parser directive ${name} is set twice`);
    seenDirective.add(name);
    if (name === 'escape') {
      if (m[2] !== '\\' && m[2] !== '`') throw new InvalidDeclaration(`line ${k + 1}: the escape directive accepts only \\ or \``);
      escape = m[2];
    }
  }
  const cont = new RegExp(`${escape === '\\' ? '\\\\' : '`'}[ \\t]*$`);
  const isComment = (l) => /^[ \t]*#/.test(l);
  const logical = [];
  for (let i = 0; i < physical.length; i++) {
    let raw = physical[i];
    if (i < k) continue; // a directive line
    const start = raw.replace(/^[ \t]+/, '');
    if (!start || start.startsWith('#')) continue;
    let line = start;
    const startLine = i + 1;
    while (cont.test(line)) {
      line = line.replace(cont, '');
      // Join the following physical lines, skipping comment and empty lines.
      let next = null;
      while (i + 1 < physical.length) {
        i++;
        const l = physical[i];
        if (isComment(l) || !l.trim()) continue;
        next = l; break;
      }
      if (next === null) break;
      line += next;
    }
    logical.push({ line, startLine });
  }
  return { logical, escape };
}

/** A Dockerfile word or value with its quotes and escapes removed, the way
 *  the build reads it. `expr` is true when an unescaped $ outside single
 *  quotes starts a variable reference, so the value is decided at build time.
 *  Throws on an unterminated quote. */
function dockerValue(s, escape, lineNo) {
  let out = '', expr = false, q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q === "'") { if (c === "'") q = null; else out += c; continue; }
    if (q === '"') {
      if (c === '"') { q = null; continue; }
      if (c === escape && i + 1 < s.length && ['"', '$', escape].includes(s[i + 1])) { out += s[++i]; continue; }
      if (c === '$' && /[A-Za-z_{]/.test(s[i + 1] || '')) expr = true;
      out += c; continue;
    }
    if (c === "'" || c === '"') { q = c; continue; }
    if (c === escape) { if (i + 1 < s.length) out += s[++i]; continue; }
    if (c === '$' && /[A-Za-z_{]/.test(s[i + 1] || '')) expr = true;
    out += c;
  }
  if (q) throw new InvalidDeclaration(`line ${lineNo}: an unterminated ${q === '"' ? 'double' : 'single'} quote in an ENV or ARG value`);
  return expr ? { $expr: s } : out;
}

/** Words split on unquoted, unescaped blanks, quotes and escapes kept. */
function dockerWords(s, escape, lineNo) {
  const words = [];
  let cur = '', q = null, inWord = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { cur += c; if (c === escape && q === '"' && i + 1 < s.length) cur += s[++i]; else if (c === q) q = null; continue; }
    if (c === ' ' || c === '\t') { if (inWord) { words.push(cur); cur = ''; inWord = false; } continue; }
    inWord = true;
    if (c === escape && i + 1 < s.length) { cur += c + s[++i]; continue; }
    if (c === '"' || c === "'") q = c;
    cur += c;
  }
  if (q) throw new InvalidDeclaration(`line ${lineNo}: an unterminated quote in an ENV or ARG instruction`);
  if (inWord) words.push(cur);
  return words;
}

const DOCKER_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A Dockerfile's ENV and ARG settings, twice: as a tree of effective values
 *  (the last assignment wins, as it does in a build) and as the ordered list of
 *  every assignment in the source. Credential literals are counted over the
 *  occurrences, so an earlier literal is not hidden by a later reference
 *  (T18); nothing else lint reports uses the occurrence list. Logical lines
 *  are formed first (N04), so a one-line instruction and the same instruction
 *  continued over several lines, with or without comments between, read the
 *  same. A value that refers to a variable is unresolved. An instruction lint
 *  cannot read as name=value pairs makes the file invalid, never silently
 *  skipped. Values never appear in a reason. */
function dockerfileTree(text) {
  const tree = {};
  const occurrences = [];
  const { logical, escape } = dockerLogicalLines(text);
  const record = (k, v) => { tree[k] = v; occurrences.push([k, v]); };
  let heredoc = null;
  for (const { line: l, startLine } of logical) {
    if (heredoc) { if (l.trim() === heredoc) heredoc = null; continue; }
    const m = /^(ENV|ARG)(?:[ \t]+(.*))?$/i.exec(l);
    if (!m) {
      // A heredoc body (RUN <<EOF ... EOF) is not instructions; skip to its end.
      const h = /^[A-Za-z]+\b.*<<-?(["']?)([A-Za-z_][A-Za-z0-9_]*)\1/.exec(l);
      if (h) heredoc = h[2];
      continue;
    }
    const instr = m[1].toUpperCase();
    const rest = (m[2] || '').trim();
    if (!rest) throw new InvalidDeclaration(`line ${startLine}: ${instr} has no name`);
    const words = dockerWords(rest, escape, startLine);
    if (!words[0].includes('=')) {
      // The legacy forms: `ENV NAME value with spaces` and `ARG NAME`.
      if (!DOCKER_NAME.test(words[0])) throw new InvalidDeclaration(`line ${startLine}: ${instr} names a variable lint cannot read`);
      if (instr === 'ARG') {
        if (words.length !== 1) throw new InvalidDeclaration(`line ${startLine}: ARG takes name or name=value pairs`);
        record(words[0], { $expr: `ARG ${words[0]}` });
        continue;
      }
      const value = rest.slice(words[0].length).replace(/^[ \t]+/, '');
      if (!value) throw new InvalidDeclaration(`line ${startLine}: ENV ${words[0]} has no value`);
      record(words[0], dockerValue(value, escape, startLine));
      continue;
    }
    for (const w of words) {
      const i = w.indexOf('=');
      const name = i < 0 ? w : w.slice(0, i);
      if (i < 0 && instr === 'ARG' && DOCKER_NAME.test(name)) { record(name, { $expr: `ARG ${name}` }); continue; }
      if (i < 0) throw new InvalidDeclaration(`line ${startLine}: ${instr} mixes name=value pairs with a word that has no =`);
      if (!DOCKER_NAME.test(name)) throw new InvalidDeclaration(`line ${startLine}: ${instr} names a variable lint cannot read`);
      record(name, dockerValue(w.slice(i + 1), escape, startLine));
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
function isLiteral(v, constants = false) {
  if (typeof v !== 'string') return false;
  const s = v.trim();
  if (!s) return false;
  // Where the parser already told a constant from an expression (HCL,
  // Terraform JSON, a plan, a Dockerfile), a string IS a constant, even when
  // its decoded text holds ${ or $ (N03). Only YAML strings, which carry no
  // such distinction, are read by their shape.
  if (!constants && (/[$%]\{/.test(s) || /\$\(/.test(s) || /^\$[A-Za-z_]/.test(s))) return false;
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
    return unit.occurrences.filter(([k, v]) => isSecretKey(k) && isLiteral(v, true)).length;
  }
  const tree = unit.tree;
  const constants = unit.constants === true;
  let n = 0;
  const isSecret = tree && typeof tree === 'object' && tree.kind === 'Secret' && typeof tree.apiVersion === 'string';
  const scan = (node) => {
    if (Array.isArray(node)) { node.forEach(scan); return; }
    if (!node || typeof node !== 'object' || isExpr(node)) return;
    // env: [{ name: API_TOKEN, value: ... }] and the same shape elsewhere.
    if (typeof node.name === 'string' && 'value' in node && isSecretKey(node.name) && isLiteral(node.value, constants)) n++;
    for (const [k, v] of Object.entries(node)) {
      if (META_KEY.test(k)) continue;
      if (isSecret && node === tree && (k === 'data' || k === 'stringData')) {
        if (v && typeof v === 'object') for (const x of Object.values(v)) if (isLiteral(x, constants)) n++;
        continue;
      }
      if (isSecretKey(k) && isLiteral(v, constants)) n++;
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
  // A whole planned object that is unknown until apply decides nothing yet.
  if (isExpr(tree)) return ENCRYPTION.UNRESOLVED;
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
