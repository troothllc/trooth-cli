// A strict reader for the HCL native syntax Terraform uses (.tf files).
// Copyright 2025-2026 Trooth, LLC. Apache-2.0.
//
// WHY THIS EXISTS. Up to 0.4.4, `trooth lint` read .tf files with regular
// expressions. A regular expression cannot tell a comment from a setting or an
// indented block from a top-level one, and it cannot tell that a file is
// malformed, so `encrypted = false # off` and `# encrypted = true` both counted
// as declaring encryption and a broken file read as a successful one.
//
// This module tokenizes and parses the syntax into a tree. It does not
// evaluate anything: a variable, a function call, a conditional or a reference
// is kept as an UNRESOLVED EXPRESSION ({ $expr: "<source text>" }) and is never
// promoted to a value. Comments are dropped by the tokenizer, so nothing inside
// one can count. A file that does not parse throws HclParseError, and the
// caller reports it as invalid rather than as read.
//
// Supported: attributes, blocks with any number of labels, nested blocks,
// strings with escapes and ${ } / %{ } templates, heredocs (<<EOF and <<-EOF),
// numbers, true/false/null, tuples [ ], objects { }, and any other expression
// as unresolved source text. Not supported, and reported as unresolved rather
// than guessed: for-expressions, splat values, function results, conditionals.

export class HclParseError extends Error {
  constructor(message, line) {
    super(`line ${line}: ${message}`);
    this.name = 'HclParseError';
    this.line = line;
  }
}

const isIdentStart = (ch) => /[A-Za-z_]/.test(ch);
const isIdentChar = (ch) => /[A-Za-z0-9_-]/.test(ch);

/** Source text to tokens. Comments are skipped; newlines are kept because they
 *  end an attribute. Throws HclParseError on an unterminated string, comment or
 *  heredoc, or a character the syntax does not allow. */
export function tokenize(src) {
  const toks = [];
  let i = 0, line = 1;
  const n = src.length;
  const push = (t, v, extra) => toks.push({ t, v, line, ...extra });
  while (i < n) {
    const ch = src[i];
    if (ch === '\n') { push('nl', '\n'); line++; i++; continue; }
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '﻿') { i++; continue; }
    if (ch === '#' || (ch === '/' && src[i + 1] === '/')) {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end < 0) throw new HclParseError('unterminated /* comment', line);
      for (let k = i; k < end; k++) if (src[k] === '\n') line++;
      i = end + 2;
      continue;
    }
    if (ch === '"') {
      const startLine = line;
      let j = i + 1, value = '', interp = false, depth = 0;
      for (;;) {
        if (j >= n) throw new HclParseError('unterminated string', startLine);
        const c = src[j];
        if (c === '\n' && depth === 0) throw new HclParseError('newline inside a quoted string', startLine);
        if (c === '\n') line++;
        if (c === '\\' && depth === 0) {
          const e = src[j + 1];
          const map = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\' };
          if (e in map) { value += map[e]; j += 2; continue; }
          if (e === 'u' || e === 'U') { value += '\\' + e; j += 2; continue; }
          throw new HclParseError(`invalid escape \\${e}`, line);
        }
        if ((c === '$' || c === '%') && src[j + 1] === '{' && depth === 0) {
          if (src[j - 1] === c && src[j - 2] !== c) { value += '{'; j += 2; continue; } // $${ escapes
          interp = true; depth = 1; value += c + '{'; j += 2; continue;
        }
        if (depth > 0) {
          if (c === '{') depth++;
          else if (c === '}') depth--;
          else if (c === '"') {
            // a quoted string nested inside a template expression
            let k = j + 1;
            while (k < n && src[k] !== '"') { if (src[k] === '\\') k++; if (src[k] === '\n') throw new HclParseError('unterminated string', startLine); k++; }
            if (k >= n) throw new HclParseError('unterminated string', startLine);
            value += src.slice(j, k + 1); j = k + 1; continue;
          }
          value += c; j++; continue;
        }
        if (c === '"') break;
        value += c; j++;
      }
      push('str', value, { interp, raw: src.slice(i, j + 1) });
      i = j + 1;
      continue;
    }
    if (ch === '<' && src[i + 1] === '<' && /[-A-Za-z_]/.test(src[i + 2] || '')) {
      const m = /^<<(-?)([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n/.exec(src.slice(i));
      if (m) {
        const startLine = line;
        const marker = m[2];
        let j = i + m[0].length;
        line++;
        const lines = [];
        let closed = false;
        while (j <= n) {
          let e = src.indexOf('\n', j);
          if (e < 0) e = n;
          const l = src.slice(j, e).replace(/\r$/, '');
          if (l.trim() === marker) { closed = true; j = e; break; }
          lines.push(l);
          if (e >= n) break;
          line++;
          j = e + 1;
        }
        if (!closed) throw new HclParseError(`unterminated heredoc <<${marker}`, startLine);
        const value = lines.join('\n');
        push('str', value, { interp: /[$%]\{/.test(value), raw: src.slice(i, j), heredoc: true });
        i = j;
        continue;
      }
    }
    if (/[0-9]/.test(ch)) {
      const m = /^[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(src.slice(i));
      push('num', Number(m[0]), { raw: m[0] });
      i += m[0].length;
      continue;
    }
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < n && isIdentChar(src[j])) j++;
      push('ident', src.slice(i, j), { raw: src.slice(i, j) });
      i = j;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (['==', '!=', '<=', '>=', '&&', '||', '=>', '...'].includes(src.slice(i, i + 3)) || ['==', '!=', '<=', '>=', '&&', '||', '=>'].includes(two)) {
      const op = src.slice(i, i + 3) === '...' ? '...' : two;
      push('op', op, { raw: op }); i += op.length; continue;
    }
    if ('{}[]()=:,.?!+-*/%<>'.includes(ch)) { push(ch, ch, { raw: ch }); i++; continue; }
    throw new HclParseError(`unexpected character ${JSON.stringify(ch)}`, line);
  }
  push('eof', '');
  return toks;
}

const OPEN = { '{': '}', '[': ']', '(': ')' };

class Parser {
  constructor(toks) { this.toks = toks; this.p = 0; }
  peek(k = 0) { return this.toks[this.p + k]; }
  next() { return this.toks[this.p++]; }
  skipNl() { while (this.peek().t === 'nl') this.p++; }
  error(msg, tok = this.peek()) { throw new HclParseError(msg, tok.line); }

  /** A body: attributes and blocks until `}` (nested) or end of file (top). */
  body(nested) {
    const items = [];
    for (;;) {
      this.skipNl();
      const tok = this.peek();
      if (tok.t === 'eof') { if (nested) this.error('unclosed block: a } is missing'); return items; }
      if (tok.t === '}') { if (!nested) this.error('unexpected }'); this.next(); return items; }
      if (tok.t !== 'ident') this.error(`expected an attribute or block name, found ${JSON.stringify(tok.v)}`);
      const name = this.next().v;
      if (this.peek().t === '=' ) {
        this.next();
        const exprToks = this.collectExpr(tok.line);
        items.push({ kind: 'attr', key: name, value: exprValue(exprToks), line: tok.line });
        continue;
      }
      const labels = [];
      while (this.peek().t === 'str' || this.peek().t === 'ident') {
        const l = this.next();
        if (l.t === 'str' && l.interp) this.error('a block label cannot be a template', l);
        labels.push(l.v);
      }
      if (this.peek().t !== '{') this.error(`expected = or { after ${name}`);
      this.next();
      const inner = this.body(true);
      items.push({ kind: 'block', type: name, labels, body: inner, line: tok.line });
      // a block ends at a newline or the end of the enclosing body
      const after = this.peek().t;
      if (after !== 'nl' && after !== 'eof' && after !== '}') this.error('expected a newline after a block');
    }
  }

  /** The tokens of one expression, up to the newline that ends it at depth 0. */
  collectExpr(line) {
    const out = [];
    const stack = [];
    for (;;) {
      const tok = this.peek();
      if (tok.t === 'eof') {
        if (stack.length) this.error(`unclosed ${stack[stack.length - 1]}`, tok);
        break;
      }
      if (!stack.length && (tok.t === 'nl' || tok.t === '}')) break;
      this.next();
      if (OPEN[tok.t]) stack.push(OPEN[tok.t]);
      else if (tok.t === '}' || tok.t === ']' || tok.t === ')') {
        if (stack.pop() !== tok.t) this.error(`mismatched ${tok.t}`, tok);
      }
      out.push(tok);
    }
    const meaningful = out.filter((t) => t.t !== 'nl');
    if (!meaningful.length) throw new HclParseError('an attribute has no value', line);
    return out;
  }
}

const sourceOf = (toks) => toks.filter((t) => t.t !== 'nl').map((t) => (t.raw !== undefined ? t.raw : String(t.v))).join(' ')
  .replace(/ ?\. ?/g, '.').replace(/\[ /g, '[').replace(/ \]/g, ']').replace(/\( /g, '(').replace(/ \)/g, ')');

/** Split tokens on a separator at depth 0 (commas and newlines inside a tuple
 *  or object). */
function splitTop(toks, isSep) {
  const parts = [];
  let cur = [], depth = 0;
  for (const t of toks) {
    if (OPEN[t.t]) depth++;
    else if (t.t === '}' || t.t === ']' || t.t === ')') depth--;
    if (depth === 0 && isSep(t)) { if (cur.some((x) => x.t !== 'nl')) parts.push(cur); cur = []; continue; }
    cur.push(t);
  }
  if (cur.some((x) => x.t !== 'nl')) parts.push(cur);
  return parts;
}

/** Tokens of an expression to a value. Literals become JS values; tuples and
 *  objects become arrays and objects when every member parses; anything else
 *  becomes { $expr: source }. Nothing is evaluated. */
export function exprValue(toks) {
  const ts = toks.filter((t) => t.t !== 'nl');
  if (ts.length === 1) {
    const t = ts[0];
    if (t.t === 'ident') {
      if (t.v === 'true') return true;
      if (t.v === 'false') return false;
      if (t.v === 'null') return null;
      return { $expr: t.v };
    }
    if (t.t === 'num') return t.v;
    if (t.t === 'str') return t.interp ? { $expr: t.raw } : t.v;
  }
  if (ts.length === 2 && ts[0].t === '-' && ts[1].t === 'num') return -ts[1].v;
  const first = ts[0], last = ts[ts.length - 1];
  if (first.t === '[' && last.t === ']' && closesAt(ts, 0) === ts.length - 1) {
    const inner = toks.slice(toks.indexOf(first) + 1, toks.lastIndexOf(last));
    if (inner.some((t) => t.t === 'ident' && t.v === 'for')) return { $expr: sourceOf(ts) };
    return splitTop(inner, (t) => t.t === ',').map(exprValue);
  }
  if (first.t === '{' && last.t === '}' && closesAt(ts, 0) === ts.length - 1) {
    const inner = toks.slice(toks.indexOf(first) + 1, toks.lastIndexOf(last));
    if (inner.some((t) => t.t === 'ident' && t.v === 'for')) return { $expr: sourceOf(ts) };
    const obj = {};
    for (const member of splitTop(inner, (t) => t.t === ',' || t.t === 'nl')) {
      const m = member.filter((t) => t.t !== 'nl');
      const eq = m.findIndex((t) => t.t === '=' || t.t === ':');
      if (eq !== 1 || !(m[0].t === 'ident' || (m[0].t === 'str' && !m[0].interp))) return { $expr: sourceOf(ts) };
      obj[m[0].v] = exprValue(m.slice(2));
    }
    return obj;
  }
  return { $expr: sourceOf(ts) };
}

function closesAt(ts, start) {
  let depth = 0;
  for (let k = start; k < ts.length; k++) {
    if (OPEN[ts[k].t]) depth++;
    else if (ts[k].t === '}' || ts[k].t === ']' || ts[k].t === ')') { depth--; if (depth === 0) return k; }
  }
  return -1;
}

/** Parse a whole file. Returns the list of top-level items. */
export function parseHcl(src) {
  return new Parser(tokenize(src)).body(false);
}

/** A block's items as a plain object tree: attributes become keys, nested
 *  blocks become objects (an array of them when a block type repeats). */
export function bodyToTree(items) {
  const tree = {};
  for (const it of items) {
    if (it.kind === 'attr') { tree[it.key] = it.value; continue; }
    const v = bodyToTree(it.body);
    const key = it.type;
    if (key in tree) tree[key] = Array.isArray(tree[key]) && tree[`__blocks_${key}`] ? [...tree[key], v] : [tree[key], v];
    else tree[key] = v;
    if (Array.isArray(tree[key])) Object.defineProperty(tree, `__blocks_${key}`, { value: true, enumerable: false, configurable: true });
  }
  return tree;
}
