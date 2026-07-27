'use strict';

const client = require('../client');

async function status(options) {
  const result = await client.request('GET', '/v1/status', options);

  if (result.scaffold) {
    const message = 'Trooth API not yet available (' + result.reason + '). Scaffold mode. Status will be live August 2, 2026.';
    if (options.json) {
      process.stdout.write(JSON.stringify({ status: 'scaffold', reason: result.reason }, null, 2) + '\n');
    } else {
      process.stdout.write(message + '\n');
    }
    return;
  }

  if (options.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  process.stdout.write('Trust Score:        ' + (result.score || 'unknown') + '\n');
  process.stdout.write('Tier:               ' + (result.tier || 'unknown') + '\n');
  process.stdout.write('Last scan:          ' + (result.lastScanAt || 'never') + '\n');
  process.stdout.write('Drift status:       ' + (result.driftStatus || 'unknown') + '\n');

  if (result.publicProfileUrl) {
    process.stdout.write('Public Trust Profile: ' + result.publicProfileUrl + '\n');
  }
}

module.exports = status;
