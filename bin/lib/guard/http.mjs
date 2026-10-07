// bin/lib/guard/http.mjs - the Trooth guard around a fetch function.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// Followed, read on October 7, 2026: the WHATWG Fetch standard,
// https://fetch.spec.whatwg.org/#fetch-method (fetch(input, init); input is a
// string, a URL or a Request), as Node 18 and later implement it.
//
//   const guardedFetch = guardFetch(fetch, guard);
//   await guardedFetch('https://api.example-bank.com/v1/payouts', { method: 'POST', body });
//
// A request the policy covers (applies_to.http: [{ method, host }], host a glob
// where * matches any characters, including dots) is decided on its
// destination host before it is sent. allow -> the request goes out unchanged.
// hold -> GuardHold is thrown; deny -> GuardDeny is thrown. Both carry the
// Decision, and the request is not sent. A request the policy does not cover
// goes out unchanged. The guard sees the method and the host only: the body,
// headers, path and query are never given to it and never sent anywhere.

import { decideSafely, errorFor } from './errors.mjs';

function globToRegExp(glob) {
  const esc = String(glob).toLowerCase().split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${esc}$`);
}

/** The applies_to.http rules of the guard's policy, compiled. */
export function httpRules(guard) {
  const list = guard?.policy?.applies_to?.http;
  if (!Array.isArray(list)) return [];
  return list.filter((r) => r && typeof r.host === 'string').map((r) => ({
    method: r.method ? String(r.method).toUpperCase() : '*',
    host: globToRegExp(r.host),
  }));
}

/** Method and lowercase host (no port, no trailing dot) of a fetch call; null when it has no usable URL. */
export function requestTarget(input, init) {
  let url;
  let method = init?.method;
  try {
    if (typeof input === 'string' || input instanceof URL) url = new URL(String(input));
    else if (input && typeof input.url === 'string') { url = new URL(input.url); method = method ?? input.method; }
    // fetch() turns any other input into a string (a URL object from another
    // realm or a polyfill, anything with toString), so the guard reads the same string.
    else if (input !== null && input !== undefined) url = new URL(String(input));
    else return null;
  } catch {
    return null;
  }
  return { method: String(method ?? 'GET').toUpperCase(), host: url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '') };
}

/** Whether the guard's policy covers a request with this method and host. */
export function coversRequest(rules, target) {
  return !!target && rules.some((r) => (r.method === '*' || r.method === target.method) && r.host.test(target.host));
}

/**
 * Wrap a fetch function. opts.onDecision sees every Decision. The policy's
 * rules are read once, when guardFetch is called.
 */
export function guardFetch(fetchFn, guard, { onDecision } = {}) {
  if (typeof fetchFn !== 'function') throw new TypeError('guardFetch needs a fetch function');
  if (!guard || typeof guard.decide !== 'function') throw new TypeError('guardFetch needs a guard from createGuard');
  const rules = httpRules(guard);
  return async function guardedFetch(input, init) {
    const target = requestTarget(input, init);
    if (!coversRequest(rules, target)) return fetchFn(input, init);
    const decision = await decideSafely(guard, { tool: `http:${target.method}`, host: target.host, args: { method: target.method } });
    if (onDecision) onDecision(decision);
    const err = errorFor(decision);
    if (err) throw err;
    return fetchFn(input, init);
  };
}
