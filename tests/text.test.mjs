// tests/text.test.mjs - the linear string helpers that replaced the regular
// expressions GitHub code scanning flagged (CodeQL js/polynomial-redos).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { stripTrailingSlashes, quotedStrings, replaceFirst } from '../bin/lib/text.mjs';
import { txtValue } from '../bin/lib/declaration.mjs';

test('stripTrailingSlashes matches the old /\\/+$/ replace', () => {
  for (const s of ['', '/', '///', 'https://api.trooth.co', 'https://api.trooth.co/', 'https://api.trooth.co///', 'a/b/', '/a']) {
    assert.equal(stripTrailingSlashes(s), s.replace(/\/+$/, ''));
  }
});

test('txtValue keeps its answers: joined quoted strings, escapes undone, raw text when unquoted', () => {
  assert.equal(txtValue('"trooth-key=abc"'), 'trooth-key=abc');
  assert.equal(txtValue('"a" "b"'), 'ab');
  assert.equal(txtValue('"say \\"hi\\""'), 'say "hi"');
  assert.equal(txtValue('plain'), 'plain');
  assert.deepEqual(quotedStrings('"x" junk "y" "unterminated'), ['x', 'y']);
});

test('linear on the inputs that were quadratic', () => {
  const t0 = performance.now();
  stripTrailingSlashes('a' + '/'.repeat(200000) + 'b');
  quotedStrings('"' + '\\"'.repeat(100000));
  assert.ok(performance.now() - t0 < 1000, 'both finish well under a second');
});

test('replaceFirst replaces one occurrence, literally', () => {
  assert.equal(replaceFirst('{a}{b}', '{', '[$&'), '[$&a}{b}');
  assert.equal(replaceFirst('abc', 'z', 'y'), 'abc');
});
