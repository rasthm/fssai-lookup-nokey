import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { formatResult } from '../bin/fssai.js';

const CLI = fileURLToPath(new URL('../bin/fssai.js', import.meta.url));

function run(...args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

test('prints usage and exits 2 without a number', () => {
  const r = run();
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Usage: node bin\/fssai\.js <fssai-number>/);
});

test('--help exits 0', () => {
  assert.equal(run('--help').status, 0);
});

test('rejects an invalid number without touching the network', () => {
  const r = run('12345');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /not a valid FSSAI number/);
});

test('formatResult prints only the fields that are present', () => {
  const text = formatResult({
    fssaiNumber: '12421012003663',
    companyName: 'ACME FOODS',
    address: null,
    status: 'Active',
    products: [{ productName: 'Biscuits' }],
  });
  assert.match(text, /FSSAI number\s+: 12421012003663/);
  assert.match(text, /Company\s+: ACME FOODS/);
  assert.doesNotMatch(text, /Address/);
  assert.match(text, /Products \(1\)\n {2}- Biscuits/);
});
