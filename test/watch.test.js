import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runWatch, fingerprintBundle, describeSchemeChange, extractBundleUrls, samePem } from '../scripts/watch-foscos.mjs';

const pem = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });

const BUNDLE = `x=function(){var c=["a"];return{k:"Content-Type",h:"x-encrypted-key",m:"RSA-OAEP",s:"csrf",e:"encryptedPayload"}};
md.sha256 encryptedResponse getsearchapplicationdetails mode.CBC {keyWordArray:M(32),ivWordArray:M(16)} /auth/csrf-token`;
const HOME = '<html><script src="main.abc123.bundle.js"></script></html>';

function setup({ enc = pem(), res = pem(), bundle = BUNDLE } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', 'foscos-encryption-public.pem'), enc);
  fs.writeFileSync(path.join(root, 'src', 'foscos-response-public.pem'), res);
  const site = { '/assets/keys/encPublic.pem': enc, '/assets/keys/resPublic.pem': res, '/': HOME, '/main.abc123.bundle.js': bundle };
  const fetch = async (url) => {
    const body = site[new URL(url).pathname];
    return body === undefined ? new Response('nope', { status: 404 }) : new Response(body);
  };
  return { root, site, fetch };
}
const ok = async () => ({ companyName: ' ACME ' });

test('first run records the scheme fingerprint and reports status updated', async () => {
  const { root, fetch } = setup();
  const r = await runWatch({ root, fetch, lookup: ok });
  assert.equal(r.status, 'updated');
  assert.equal(r.exitCode, 0);
  assert.deepEqual(r.keysChanged, []);
  assert.ok(fs.existsSync(path.join(root, 'state', 'foscos-scheme.json')));
});

test('an unchanged site gives status ok and touches nothing', async () => {
  const { root, fetch } = setup();
  await runWatch({ root, fetch, lookup: ok });
  const r = await runWatch({ root, fetch, lookup: ok });
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.files, []);
});

test('a rotated key is written into src/ and the self-test receives the new keys', async () => {
  const { root, site, fetch } = setup();
  await runWatch({ root, fetch, lookup: ok });
  const newEnc = pem();
  site['/assets/keys/encPublic.pem'] = newEnc;
  let seen;
  const r = await runWatch({ root, fetch, lookup: async (keys) => ((seen = keys), { companyName: 'X' }) });
  assert.deepEqual(r.keysChanged, ['encryption']);
  assert.equal(r.status, 'updated');
  assert.ok(samePem(fs.readFileSync(path.join(root, 'src', 'foscos-encryption-public.pem'), 'utf8'), newEnc));
  assert.ok(samePem(seen.encryption, newEnc));
  assert.deepEqual(r.files, [path.join('src', 'foscos-encryption-public.pem')]);
});

test('a vanished encryption marker plus a failing self-test needs attention', async () => {
  const { root, site, fetch } = setup();
  await runWatch({ root, fetch, lookup: ok });
  site['/main.abc123.bundle.js'] = BUNDLE.replace('x-encrypted-key', 'x-something-else');
  const r = await runWatch({
    root,
    fetch,
    lookup: async () => {
      throw Object.assign(new Error('FoSCoS returned HTTP 500 for /x: post:ResponseEncryptionFilter'), { code: 'HTTP_ERROR' });
    },
  });
  assert.equal(r.status, 'needs-attention');
  assert.equal(r.exitCode, 2);
  assert.match(r.schemeNotes.join('\n'), /marker disappeared: x-encrypted-key header/);
});

test('maintenance (503) is "unavailable", not a scheme problem', async () => {
  const { root, fetch } = setup();
  await runWatch({ root, fetch, lookup: ok });
  const r = await runWatch({
    root,
    fetch,
    lookup: async () => {
      throw Object.assign(new Error('FoSCoS returned HTTP 503: System is under maintenance'), { code: 'HTTP_ERROR' });
    },
  });
  assert.equal(r.status, 'unavailable');
  assert.equal(r.exitCode, 3);
});

test('HTML served in place of a key is rejected rather than written to src/', async () => {
  const { root, site, fetch } = setup();
  site['/assets/keys/encPublic.pem'] = '<html>Service unavailable</html>';
  await assert.rejects(runWatch({ root, fetch, lookup: ok }), /not a public key/);
});

test('helpers: bundle url, fingerprint and change notes', () => {
  assert.deepEqual(extractBundleUrls(HOME), ['main.abc123.bundle.js']);
  const f = fingerprintBundle(BUNDLE);
  assert.equal(f.markers['AES-CBC mode'], true);
  assert.equal(describeSchemeChange(null, f).length, 0);
  const g = fingerprintBundle(BUNDLE.replace('RSA-OAEP', 'RSA-PKCS1'));
  assert.ok(describeSchemeChange(f, g).length >= 1);
});
