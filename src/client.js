'use strict';

/**
 * Minimal HTTP client for the Trooth API.
 * Uses the built-in fetch (Node 18+) so the CLI has zero network dependencies.
 *
 * The production API surface is at https://api.trooth.co. During the pre-launch
 * window (before August 2, 2026), calls return a scaffold-mode response so the
 * CLI runs cleanly in CI pipelines.
 */

const pkg = require('../package.json');

function getApiKey(options) {
  const key = (options && options.apiKey) || process.env.TROOTH_API_KEY || '';
  if (!key) {
    throw new Error('No API key. Pass --api-key or set TROOTH_API_KEY. Get one free at https://www.trooth.co.');
  }
  return key;
}

function getHost(options) {
  return (options && options.host) || process.env.TROOTH_HOST || 'https://api.trooth.co';
}

async function request(method, path, options, body) {
  const apiKey = getApiKey(options);
  const host = getHost(options);
  const url = host.replace(/\/+$/, '') + path;

  const headers = {
    'Authorization': 'Bearer ' + apiKey,
    'Content-Type': 'application/json',
    'User-Agent': '@trooth/cli/' + pkg.version
  };

  let response;
  try {
    response = await fetch(url, {
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (err) {
    return { scaffold: true, reason: 'unavailable' };
  }

  if (response.status === 404 || response.status === 502 || response.status === 503) {
    return { scaffold: true, reason: 'unavailable' };
  }

  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    return { scaffold: true, reason: 'unavailable' };
  }

  if (!response.ok) {
    throw new Error('API returned ' + response.status + ': ' + (json.message || text));
  }

  return json;
}

module.exports = {
  request: request,
  getApiKey: getApiKey,
  getHost: getHost
};
