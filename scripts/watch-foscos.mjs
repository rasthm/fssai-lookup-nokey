#!/usr/bin/env node
// Daily watcher for FoSCoS's request-encryption scheme.
//
//   node scripts/watch-foscos.mjs [--commit] [--push] [--no-selftest] [--number <14 digits>]
//
// What it does, in order:
//   1. Downloads the two public keys FoSCoS serves (/assets/keys/*.pem). If either changed,
//      it rewrites src/*.pem so the library ships the new key.
//   2. Downloads the site's main JavaScript bundle and fingerprints the encryption code
//      (which markers are present, plus a hash of the string literals around it). A change
//      here means FSSAI may have changed the SCHEME, not just a key.
//   3. Runs a real lookup as a self-test with the new keys.
//   4. With --commit it commits the changed key/fingerprint files (only if the self-test
//      passed); with --push it also pushes.
//
// Exit codes: 0 ok (nothing or only keys changed, self-test passed or skipped),
//             2 NEEDS ATTENTION (self-test failed and the scheme looks changed: code must be updated),
//             3 FoSCoS unreachable / under maintenance (try again later),
//             1 the watcher itself failed.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FoscosClient, BASE_URL, KEY_PATHS } from '../src/foscos.js';

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
const DEFAULT_TEST_NUMBER = '12421012003663';
const ROOT = fileURLToPath(new URL('..', import.meta.url));

// Things that must appear in the FoSCoS frontend for our request/response scheme to still apply.
export const MARKERS = {
  'x-encrypted-key header': /x-encrypted-key/,
  'RSA-OAEP key wrapping': /RSA-OAEP/,
  'sha256 for OAEP': /md\.sha256/,
  'encryptedPayload body': /encryptedPayload/,
  'encryptedResponse reply': /encryptedResponse/,
  'search endpoint': /getsearchapplicationdetails/,
  'AES-CBC mode': /mode\.CBC/,
  '32-byte session key': /keyWordArray:\w+\(32\)/,
  '16-byte iv': /ivWordArray:\w+\(16\)/,
  'csrf-token endpoint': /auth\/csrf-token/,
};

export const samePem = (a, b) => String(a).replace(/\s+/g, '') === String(b).replace(/\s+/g, '');

export function extractBundleUrls(html) {
  return [...html.matchAll(/(?:src|href)="([^"]*\bmain\.[0-9a-f]+\.bundle\.js)"/g)].map((m) => m[1]);
}

// Fingerprint of the encryption code that survives minifier renames: which markers exist,
// and a hash of the string literals found around the x-encrypted-key interceptor.
export function fingerprintBundle(text) {
  const markers = Object.fromEntries(Object.entries(MARKERS).map(([name, re]) => [name, re.test(text)]));
  const at = text.indexOf('x-encrypted-key');
  let literalsHash = null;
  if (at >= 0) {
    const region = text.slice(Math.max(0, at - 1500), at + 600);
    const literals = [...region.matchAll(/"([^"\\]{2,80})"/g)].map((m) => m[1]);
    literalsHash = crypto.createHash('sha256').update(literals.join('\n')).digest('hex').slice(0, 16);
  }
  return { markers, literalsHash };
}

export function describeSchemeChange(prev, next) {
  if (!prev) return [];
  const notes = [];
  for (const [name, present] of Object.entries(next.markers)) {
    if (prev.markers?.[name] && !present) notes.push(`marker disappeared: ${name}`);
    if (!prev.markers?.[name] && present) notes.push(`marker appeared: ${name}`);
  }
  if (prev.literalsHash && next.literalsHash && prev.literalsHash !== next.literalsHash) {
    notes.push('string literals around the encryption interceptor changed');
  }
  return notes;
}

const isPublicKey = (pem) => {
  try {
    crypto.createPublicKey(pem);
    return true;
  } catch {
    return false;
  }
};

async function getText(fetchImpl, url, timeoutMs) {
  const res = await fetchImpl(url, {
    headers: { 'User-Agent': USER_AGENT, Referer: `${BASE_URL}/` },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.text();
}

const readIfExists = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null);

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

/**
 * One watcher pass. Everything that touches the outside world is injectable so it can be tested.
 * Returns { status, exitCode, keysChanged: string[], schemeNotes: string[], selfTest, ... }.
 */
export async function runWatch({
  root = ROOT,
  baseUrl = BASE_URL,
  fetch: fetchImpl = globalThis.fetch,
  timeoutMs = 60_000,
  selfTest = true,
  number = DEFAULT_TEST_NUMBER,
  lookup = null, // (keys) => Promise<record|null>; defaults to a real FoscosClient lookup
  now = () => new Date(),
} = {}) {
  const srcDir = path.join(root, 'src');
  const keyFiles = {
    encryption: path.join(srcDir, 'foscos-encryption-public.pem'),
    response: path.join(srcDir, 'foscos-response-public.pem'),
  };
  const schemeFile = path.join(root, 'state', 'foscos-scheme.json');
  const result = { checkedAt: now().toISOString(), keysChanged: [], schemeNotes: [], files: [] };

  // 1. keys
  const keys = {};
  for (const [kind, urlPath] of Object.entries(KEY_PATHS)) {
    const pem = await getText(fetchImpl, `${baseUrl}${urlPath}`, timeoutMs);
    if (!isPublicKey(pem)) throw new Error(`${urlPath} is not a public key (got: ${pem.slice(0, 80)})`);
    keys[kind] = pem.endsWith('\n') ? pem : `${pem}\n`;
    const current = readIfExists(keyFiles[kind]);
    if (current === null || !samePem(current, pem)) {
      fs.writeFileSync(keyFiles[kind], keys[kind]);
      result.keysChanged.push(kind);
      result.files.push(path.relative(root, keyFiles[kind]));
    }
  }

  // 2. scheme fingerprint
  const home = await getText(fetchImpl, `${baseUrl}/`, timeoutMs);
  const bundleUrls = extractBundleUrls(home);
  if (!bundleUrls.length) throw new Error('could not find the main bundle in the FoSCoS home page');
  const bundleUrl = new URL(bundleUrls[0], `${baseUrl}/`).href;
  const bundle = await getText(fetchImpl, bundleUrl, Math.max(timeoutMs, 120_000));
  const fingerprint = { bundle: path.basename(bundleUrl), ...fingerprintBundle(bundle) };
  const previous = JSON.parse(readIfExists(schemeFile) ?? 'null');
  result.schemeNotes = describeSchemeChange(previous, fingerprint);
  result.bundle = fingerprint.bundle;
  if (!previous || JSON.stringify(previous) !== JSON.stringify(fingerprint)) {
    writeJson(schemeFile, fingerprint);
    result.files.push(path.relative(root, schemeFile));
  }

  // 3. self-test with the freshly downloaded keys
  result.selfTest = { ran: false };
  if (selfTest) {
    result.selfTest.ran = true;
    try {
      const record = lookup
        ? await lookup(keys)
        : await new FoscosClient({
            baseUrl,
            fetch: fetchImpl,
            timeoutMs: 30_000,
            encryptionKey: keys.encryption,
            publicKey: keys.response,
            fetchKeys: false,
          }).lookup(number);
      result.selfTest.ok = Boolean(record);
      if (!record) result.selfTest.error = `no record for ${number}`;
      else result.selfTest.company = record.companyName?.trim() ?? null;
    } catch (err) {
      result.selfTest.ok = false;
      result.selfTest.error = err.message;
      result.selfTest.code = err.code ?? null;
    }
  }

  // 4. verdict
  const st = result.selfTest;
  const unavailable = !st.ok && (/HTTP 50[234]|maintenance|Timed out|Could not reach/i.test(st.error ?? '') || st.code === 'TIMEOUT' || st.code === 'NETWORK');
  if (!st.ran || st.ok) {
    result.status = result.files.length || result.schemeNotes.length ? 'updated' : 'ok';
    result.exitCode = 0;
  } else if (unavailable && !/HTTP 500/.test(st.error) && !result.schemeNotes.length) {
    result.status = 'unavailable';
    result.exitCode = 3;
  } else {
    result.status = 'needs-attention';
    result.exitCode = 2;
  }
  return result;
}

function git(root, ...args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

export function commitChanges(root, result, { push = false } = {}) {
  if (!result.files.length) return { committed: false, reason: 'nothing to commit' };
  if (result.status === 'needs-attention' || result.status === 'unavailable') {
    return { committed: false, reason: `not committing while status is ${result.status}` };
  }
  git(root, 'add', '--', ...result.files);
  const parts = [];
  if (result.keysChanged.length) parts.push(`rotated ${result.keysChanged.join(' + ')} key`);
  if (result.schemeNotes.length) parts.push('scheme fingerprint changed');
  const message = `chore(watch): FoSCoS ${parts.join(', ') || 'fingerprint updated'} (${result.bundle})\n\n${result.schemeNotes.map((n) => `- ${n}`).join('\n')}`.trim();
  git(root, 'commit', '-m', message);
  let pushed = false;
  let pushError = null;
  if (push) {
    try {
      git(root, 'push', 'origin', 'HEAD');
      pushed = true;
    } catch (err) {
      pushError = String(err.stderr || err.message).trim();
    }
  }
  return { committed: true, pushed, pushError };
}

function log(root, line) {
  const file = path.join(root, 'logs', 'watch.log');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${line}\n`);
  console.log(line);
}

async function main(argv) {
  const flag = (name) => argv.includes(name);
  const number = argv.includes('--number') ? argv[argv.indexOf('--number') + 1] : process.env.FSSAI_TEST_NUMBER || DEFAULT_TEST_NUMBER;
  let result;
  try {
    result = await runWatch({ selfTest: !flag('--no-selftest'), number });
  } catch (err) {
    log(ROOT, `[${new Date().toISOString()}] watcher failed: ${err.message}`);
    return 1;
  }
  const bits = [`status=${result.status}`, `bundle=${result.bundle}`];
  if (result.keysChanged.length) bits.push(`keys changed: ${result.keysChanged.join(', ')}`);
  if (result.schemeNotes.length) bits.push(`scheme: ${result.schemeNotes.join('; ')}`);
  if (result.selfTest.ran) bits.push(result.selfTest.ok ? `self-test ok (${result.selfTest.company ?? 'record'})` : `self-test FAILED: ${result.selfTest.error}`);
  log(ROOT, `[${result.checkedAt}] ${bits.join(' | ')}`);

  writeJson(path.join(ROOT, 'logs', 'last-run.json'), result);
  const attention = path.join(ROOT, 'logs', 'NEEDS-ATTENTION.txt');
  if (result.status === 'needs-attention') {
    fs.writeFileSync(
      attention,
      `FoSCoS lookup is broken as of ${result.checkedAt}.\n${bits.join('\n')}\n\nThe encryption scheme probably changed: src/crypto.js and src/foscos.js need to be updated by hand.\nCompare the bundle's interceptor (search for "x-encrypted-key") with src/crypto.js.\n`,
    );
  } else if (fs.existsSync(attention) && result.status !== 'unavailable') {
    fs.rmSync(attention);
  }

  if (flag('--commit') || flag('--push')) {
    const c = commitChanges(ROOT, result, { push: flag('--push') });
    log(ROOT, `  commit: ${JSON.stringify(c)}`);
  }
  return result.exitCode;
}

const isEntryPoint = process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntryPoint) process.exitCode = await main(process.argv.slice(2));
