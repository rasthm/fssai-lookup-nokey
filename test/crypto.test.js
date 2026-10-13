import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createSession, wrapSessionKey, encryptPayload, decryptResponse, verifySignature } from '../src/crypto.js';

test('the session key is wrapped with RSA-OAEP (SHA-256) as {k, iv} in base64', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const session = createSession();
  assert.equal(session.key.length, 32);
  assert.equal(session.iv.length, 16);
  const wrapped = wrapSessionKey(session, publicKey.export({ type: 'spki', format: 'pem' }));
  const plain = crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(wrapped, 'base64'),
  );
  assert.deepEqual(JSON.parse(plain.toString()), { k: session.key.toString('base64'), iv: session.iv.toString('base64') });
});

test('payload encryption round-trips with the session key', () => {
  const session = createSession();
  const body = JSON.stringify({ flrsLicenseNo: '12421012003663' });
  const encrypted = encryptPayload(body, session);
  assert.match(encrypted, /^[A-Za-z0-9+/]+=*$/);
  assert.equal(decryptResponse(encrypted, session), body);
});

test('responses are decrypted with the iv FoSCoS sends back', () => {
  const session = createSession();
  const iv = crypto.randomBytes(16);
  const encrypted = encryptPayload('{"ok":true}', session, iv);
  assert.equal(decryptResponse(encrypted, session, iv.toString('base64')), '{"ok":true}');
});

test('signature check accepts a good signature and rejects tampering', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const enc = 'QUJDREVGRw==';
  const sig = crypto.sign('sha256', Buffer.from(enc), privateKey).toString('base64');
  assert.equal(verifySignature(enc, sig, pem), true);
  assert.equal(verifySignature('A' + enc.slice(1), sig, pem), false);
  assert.equal(verifySignature(enc, 'not-a-signature', pem), false);
});
