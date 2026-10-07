// bin/lib/yaml-lite.mjs - a small, strict YAML subset for guard policies.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// A guard policy decides whether an agent may act, so the file it is read
// from must mean one thing. This reader takes only the part of YAML 1.2 a
// policy needs and refuses everything else with a line number, instead of
// guessing:
//
//   accepted  block mappings, block lists (including lists of mappings),
//             flow lists [a, "b"] and flow maps {k: v} on one line, plain,
//             'single' and "double" quoted scalars, comments, decimal
//             integers, true, false, null and ~
//   refused   tabs in indentation, anchors (&), aliases (*), tags (!),
//             block scalars (| and >), multi-document streams, directives,
//             duplicate keys, fractions and exponents, a flow collection
//             that spans lines, and any line this reader cannot place
//
// It imports nothing.

export class YamlError extends Error {
  constructor(message, line) {
    super(line ? `line ${line}: ${message}` : message);
    this.line = line ?? null;
  }
}

const INT = /^[-+]?(0|[1-9][0-9]*)$/;
const FLOATISH = /^[-+]?(\.[0-9]+|[0-9]+\.[0-9]*|[0-9]+(\.[0-9]*)?[eE][-+]?[0-9]+|\.inf|\.Inf|\.INF|\.nan|\.NaN|\.NAN)$/;

/** Strip a comment: a # at the start or after whitespace, outside quotes. */
function stripComment(s, lineNo) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q === '"') {
      if (ch === '\\') { i++; continue; }
      if (ch === '"') q = null;
      continue;
    }
    if (q === "'") {
      if (ch === "'") { if (s[i + 1] === "'") { i++; continue; } q = null; }
      continue;
    }
    if (ch === '"' || ch === "'") {
      // A quote opens a quoted scalar only where a scalar can start.
      const prev = s.slice(0, i).trimEnd();
      if (prev === '' || /[:\-,\[{]$/.test(prev)) q = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trimEnd();
  }
  if (q) throw new YamlError('a quoted string is not closed on its line', lineNo);
  return s.trimEnd();
}

function scalar(raw, lineNo, inFlow = false) {
  const s = raw.trim();
  if (s === '') return null;
  if (s[0] === '"') {
    if (s.length < 2 || s[s.length - 1] !== '"') throw new YamlError(`a double-quoted string is not closed: ${s}`, lineNo);
    const body = s.slice(1, -1);
    // JSON escapes are the YAML double-quoted escapes a policy needs.
    if (/(^|[^\\])(\\\\)*"/.test(body)) throw new YamlError(`an unescaped quote inside a double-quoted string: ${s}`, lineNo);
    try { return JSON.parse(`"${body}"`); } catch { throw new YamlError(`an escape this reader does not accept in ${s}`, lineNo); }
  }
  if (s[0] === "'") {
    if (s.length < 2 || s[s.length - 1] !== "'") throw new YamlError(`a single-quoted string is not closed: ${s}`, lineNo);
    const body = s.slice(1, -1);
    if (/'(?!')/.test(body.replace(/''/g, ''))) throw new YamlError(`an unescaped quote inside a single-quoted string: ${s}`, lineNo);
    return body.replace(/''/g, "'");
  }
  if (/^[&*!|>%@`]/.test(s)) throw new YamlError(`"${s[0]}" (anchors, aliases, tags, block scalars, directives) is not accepted in a policy`, lineNo);
  if (/^[\[\]{}]/.test(s)) throw new YamlError(`a flow collection where a scalar was expected: ${s}`, lineNo);
  if (/: |:$/.test(s)) throw new YamlError(`a plain value holds ": "; quote it: ${s}`, lineNo);
  if (inFlow && /[,\[\]{}]/.test(s)) throw new YamlError(`a plain value in a flow collection holds , [ ] { or }; quote it: ${s}`, lineNo);
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~') return null;
  if (/^(True|TRUE|False|FALSE|Null|NULL|yes|no|Yes|No|YES|NO|on|off|On|Off|ON|OFF|y|n)$/.test(s)) throw new YamlError(`"${s}" means different things to different YAML readers; write true, false or a quoted string`, lineNo);
  if (INT.test(s)) {
    const n = Number(s);
    if (!Number.isSafeInteger(n)) throw new YamlError(`the integer ${s} is outside the safe range`, lineNo);
    return n;
  }
  if (FLOATISH.test(s) || /^0[0-9]+$/.test(s) || /^0[xXoObB]/.test(s)) throw new YamlError(`only decimal integers are accepted, not ${s}`, lineNo);
  return s;
}

/** Parse one flow collection that sits wholly on one line. */
function flow(text, lineNo) {
  let i = 0;
  const ws = () => { while (i < text.length && /\s/.test(text[i])) i++; };
  const fail = (m) => { throw new YamlError(m, lineNo); };
  function quoted() {
    const q = text[i];
    let j = i + 1;
    for (; j < text.length; j++) {
      if (q === '"' && text[j] === '\\') { j++; continue; }
      if (text[j] === q) { if (q === "'" && text[j + 1] === "'") { j++; continue; } break; }
    }
    if (j >= text.length) fail('a quoted string in a flow collection is not closed');
    const raw = text.slice(i, j + 1);
    i = j + 1;
    return scalar(raw, lineNo, true);
  }
  function plain(stops) {
    const start = i;
    while (i < text.length && !stops.includes(text[i])) {
      if (text[i] === ':' && (text[i + 1] === ' ' || stops.includes(text[i + 1]) || i + 1 === text.length) && stops.includes(':')) break;
      i++;
    }
    return scalar(text.slice(start, i), lineNo, true);
  }
  function value(stops) {
    ws();
    if (text[i] === '[') return list();
    if (text[i] === '{') return map();
    if (text[i] === '"' || text[i] === "'") return quoted();
    return plain(stops);
  }
  function list() {
    i++;
    const out = [];
    ws();
    if (text[i] === ']') { i++; return out; }
    for (;;) {
      ws();
      if (text[i] === ',' || text[i] === ']') fail('an empty entry in a flow list');
      out.push(value([',', ']']));
      ws();
      if (text[i] === ',') { i++; ws(); if (text[i] === ']') fail('a trailing comma in a flow list'); continue; }
      if (text[i] === ']') { i++; return out; }
      fail('a flow list is not closed with ] on its line');
    }
  }
  function map() {
    i++;
    const out = {};
    ws();
    if (text[i] === '}') { i++; return out; }
    for (;;) {
      ws();
      let key;
      if (text[i] === '"' || text[i] === "'") key = quoted();
      else key = plain([':', ',', '}']);
      if (typeof key !== 'string' || key === '') fail('a flow map key is not a string');
      ws();
      if (text[i] !== ':') fail(`the flow map key ${key} has no ":"`);
      i++;
      if (Object.prototype.hasOwnProperty.call(out, key)) fail(`the key ${key} appears twice`);
      // Assigning "__proto__" would set the object's prototype: its values would
      // be read as policy keys while staying out of Object.keys and the policy hash.
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') fail(`the key ${key} is not accepted`);
      const v = value([',', '}']);
      out[key] = v;
      ws();
      if (text[i] === ',') { i++; ws(); if (text[i] === '}') fail('a trailing comma in a flow map'); continue; }
      if (text[i] === '}') { i++; return out; }
      fail('a flow map is not closed with } on its line');
    }
  }
  const v = value([]);
  ws();
  if (i !== text.length) fail(`text after the end of a flow collection: ${text.slice(i)}`);
  return v;
}

function valueOf(rest, lineNo) {
  const s = rest.trim();
  if (s[0] === '[' || s[0] === '{') return flow(s, lineNo);
  return scalar(s, lineNo);
}

const KEY = /^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([A-Za-z0-9_][A-Za-z0-9_.\-/]*))[ ]*:(?:[ ]+(.*)|)$/;

/** Parse YAML subset text into plain JSON values. Throws YamlError. */
export function parseYaml(text) {
  if (typeof text !== 'string') throw new YamlError('the policy is not text');
  const src = text.replace(/^﻿/, '');
  const raw = src.split(/\r?\n/);
  const lines = [];
  let docStarted = false;
  for (let n = 0; n < raw.length; n++) {
    const lineNo = n + 1;
    const l = raw[n];
    const lead = /^[ \t]*/.exec(l)[0];
    if (lead.includes('\t')) throw new YamlError('a tab in indentation; indent with spaces', lineNo);
    const body = stripComment(l.slice(lead.length), lineNo);
    if (body === '') continue;
    if (lead.length === 0 && body === '---') {
      if (docStarted || lines.length) throw new YamlError('more than one document; a policy is one document', lineNo);
      docStarted = true;
      continue;
    }
    if (lead.length === 0 && (body === '...' || body.startsWith('%'))) throw new YamlError('document end markers and directives are not accepted', lineNo);
    lines.push({ indent: lead.length, text: body, lineNo });
  }
  if (!lines.length) throw new YamlError('the policy is empty');
  let pos = 0;

  function block(indent) {
    const first = lines[pos];
    if (first.indent !== indent) throw new YamlError('unexpected indentation', first.lineNo);
    if (first.text === '-' || first.text.startsWith('- ')) return seq(indent);
    if (first.text[0] === '[' || first.text[0] === '{') {
      pos++;
      const v = flow(first.text, first.lineNo);
      if (pos < lines.length && lines[pos].indent >= indent && indent > 0) throw new YamlError('a flow collection that spans lines is not accepted', lines[pos].lineNo);
      return v;
    }
    return map(indent);
  }

  function seq(indent) {
    const out = [];
    while (pos < lines.length && lines[pos].indent === indent && (lines[pos].text === '-' || lines[pos].text.startsWith('- '))) {
      const l = lines[pos];
      const rest = l.text === '-' ? '' : l.text.slice(2);
      const restTrim = rest.replace(/^ +/, '');
      if (restTrim === '') {
        pos++;
        if (pos < lines.length && lines[pos].indent > indent) out.push(block(lines[pos].indent));
        else out.push(null);
        continue;
      }
      const inner = indent + 2 + (rest.length - restTrim.length);
      if (KEY.test(restTrim) || restTrim.startsWith('- ') || restTrim === '-') {
        // "- key: value": the item is a mapping (or a list) whose first line starts after the dash.
        lines[pos] = { indent: inner, text: restTrim, lineNo: l.lineNo };
        out.push(block(inner));
      } else {
        pos++;
        out.push(valueOf(restTrim, l.lineNo));
        if (pos < lines.length && lines[pos].indent > indent) throw new YamlError('unexpected indentation after a list item', lines[pos].lineNo);
      }
    }
    if (pos < lines.length && lines[pos].indent > indent) throw new YamlError('unexpected indentation', lines[pos].lineNo);
    return out;
  }

  function map(indent) {
    const out = {};
    while (pos < lines.length && lines[pos].indent === indent) {
      const l = lines[pos];
      if (l.text === '-' || l.text.startsWith('- ')) throw new YamlError('a list item where a key was expected', l.lineNo);
      const m = KEY.exec(l.text);
      if (!m) throw new YamlError(`not a "key: value" line: ${l.text}`, l.lineNo);
      let key;
      if (m[1] !== undefined) { try { key = JSON.parse(`"${m[1]}"`); } catch { throw new YamlError('a quoted key holds an escape this reader does not accept', l.lineNo); } }
      else if (m[2] !== undefined) key = m[2].replace(/''/g, "'");
      else key = m[3];
      if (Object.prototype.hasOwnProperty.call(out, key)) throw new YamlError(`the key ${key} appears twice`, l.lineNo);
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') throw new YamlError(`the key ${key} is not accepted`, l.lineNo);
      pos++;
      const rest = m[4];
      if (rest === undefined || rest.trim() === '') {
        if (pos < lines.length && lines[pos].indent > indent) out[key] = block(lines[pos].indent);
        else if (pos < lines.length && lines[pos].indent === indent && (lines[pos].text === '-' || lines[pos].text.startsWith('- '))) out[key] = seq(indent);
        else out[key] = null;
      } else {
        out[key] = valueOf(rest, l.lineNo);
        if (pos < lines.length && lines[pos].indent > indent) throw new YamlError(`unexpected indentation after "${key}: ${rest.trim()}"`, lines[pos].lineNo);
      }
    }
    if (pos < lines.length && lines[pos].indent > indent) throw new YamlError('unexpected indentation', lines[pos].lineNo);
    return out;
  }

  const result = block(lines[0].indent);
  if (pos < lines.length) throw new YamlError('a line this reader cannot place (check its indentation)', lines[pos].lineNo);
  return result;
}
