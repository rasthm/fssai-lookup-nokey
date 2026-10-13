// FoSCoS wraps its JSON traffic in a per-request AES-256-CBC session key.
// The browser makes a random key + IV, encrypts {k, iv} with FoSCoS's RSA public key
// (RSA-OAEP, SHA-256) and sends it in the `x-encrypted-key` header. POST bodies are
// AES-encrypted with that key; replies come back encrypted with the same key and a
// fresh IV (`iv` in the body), signed with RSA-SHA256.
// Both public keys are served by the public FoSCoS frontend; they are not secrets.
import crypto from 'node:crypto';
import fs from 'node:fs';

const readKey = (name) => fs.readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');

// Served by FoSCoS at /assets/keys/encPublic.pem (wraps the session key)
export const ENCRYPTION_PUBLIC_KEY = readKey('foscos-encryption-public.pem');
// Served by FoSCoS at /assets/keys/resPublic.pem (checks response signatures)
export const RESPONSE_PUBLIC_KEY = readKey('foscos-response-public.pem');

export function createSession() {
  return { key: crypto.randomBytes(32), iv: crypto.randomBytes(16) };
}

// Value for the x-encrypted-key header.
export function wrapSessionKey(session, publicKey = ENCRYPTION_PUBLIC_KEY) {
  const json = JSON.stringify({ k: session.key.toString('base64'), iv: session.iv.toString('base64') });
  return crypto
    .publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(json))
    .toString('base64');
}

export function encryptPayload(text, session, iv = session.iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', session.key, iv);
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]).toString('base64');
}

export function decryptResponse(base64, session, ivBase64) {
  const iv = ivBase64 ? Buffer.from(ivBase64, 'base64') : session.iv;
  const decipher = crypto.createDecipheriv('aes-256-cbc', session.key, iv);
  return Buffer.concat([decipher.update(base64, 'base64'), decipher.final()]).toString('utf8');
}

export function verifySignature(encryptedResponse, signature, publicKey = RESPONSE_PUBLIC_KEY) {
  try {
    return crypto.verify(
      'sha256',
      Buffer.from(encryptedResponse, 'utf8'),
      publicKey,
      Buffer.from(signature, 'base64'),
    );
  } catch {
    return false;
  }
}
