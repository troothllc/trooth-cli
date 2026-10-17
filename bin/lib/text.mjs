// bin/lib/text.mjs - small string helpers that run in linear time.
//
// GitHub code scanning (CodeQL js/polynomial-redos, 2026-10) flagged
// `.replace(/\/+$/, '')` and the quoted-string pattern in txtValue: on a long
// run of the repeated character a backtracking engine retries the match from
// every position, which is quadratic. A base URL or a DNS answer can come from
// outside, so these are plain loops instead of regular expressions.

/** The string with every trailing "/" removed. */
export function stripTrailingSlashes(value) {
  const s = String(value);
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--;
  return s.slice(0, end);
}

/**
 * The "..."-quoted strings in a DNS TXT answer ("a" "b"), each unescaped
 * (\x becomes x), in order. One pass, no backtracking. Text outside quotes is
 * ignored; an unterminated final string is dropped, as the old pattern did.
 */
export function quotedStrings(value) {
  const s = String(value);
  const out = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') { i++; continue; }
    let j = i + 1, buf = '', closed = false;
    while (j < s.length) {
      const c = s[j];
      if (c === '\\' && j + 1 < s.length) { buf += s[j + 1]; j += 2; continue; }
      if (c === '"') { closed = true; break; }
      buf += c; j++;
    }
    if (!closed) break;
    out.push(buf);
    i = j + 1;
  }
  return out;
}

/** The string with the first occurrence of `find` replaced by `replacement` (no pattern, no $-substitution). */
export function replaceFirst(value, find, replacement) {
  const s = String(value);
  const at = s.indexOf(find);
  return at === -1 ? s : s.slice(0, at) + replacement + s.slice(at + find.length);
}
