# fssai-lookup-nokey

Look up an FSSAI licence or registration number on FoSCoS (foscos.fssai.gov.in), the same data the
public "FBO Search" page shows. **No API key, no paid provider, no dependencies.** Node 20+.

It also ships a **daily watcher** that notices when FSSAI changes the keys or the encryption scheme
FoSCoS uses, updates the bundled keys, and tells you when the code itself needs a fix.

Based on [sajithamma/fssai-core](https://github.com/sajithamma/fssai-core), updated for FoSCoS's
current per-request encryption (the original used fixed keys, which FoSCoS no longer accepts).

```
$ node bin/fssai.js 12421012003663
FSSAI number     : 12421012003663
Company          : Sapphire Foods India Limited (KFC)
Address          : 2-C, Vinayaga Nagar
District         : Madurai
State            : Tamil Nadu
Pincode          : 625020
Licence type     : State License
Status           : License Issued
FoSCoS ref ID    : 108052332
```

## CLI

```bash
node bin/fssai.js 12421012003663
node bin/fssai.js 12421012003663 --products   # also list licensed food products
node bin/fssai.js 12421012003663 --json       # full result incl. the raw FoSCoS record
```

Exit codes: `0` found, `1` no record, `2` bad input, `3` network/server error.

## Library

```js
import { lookupFssai, FoscosClient } from 'fssai-lookup-nokey';

const info = await lookupFssai('12421012003663', { products: true });
// { fssaiNumber, companyName, address, district, state, pincode, licenseCategory, status,
//   kindOfBusiness, issuedOn, validUpto, refId, raw, products? }  or null if FoSCoS has no record

const client = new FoscosClient({ timeoutMs: 20000 }); // reuse for many lookups
```

What FoSCoS returns varies. In practice the public search gives name, address, district, state,
pincode, licence type, status and the licensed products. **It does not return the expiry date,
issue date or kind of business**, so `validUpto`, `issuedOn` and `kindOfBusiness` are usually `null`.
The untouched record is always in `raw`.

Errors are `FoscosError` with a `code`: `INVALID_NUMBER`, `TIMEOUT`, `NETWORK`, `HTTP_ERROR`,
`BAD_RESPONSE`, `BAD_SIGNATURE`.

## How it works

FoSCoS wraps its traffic in a per-request session key. The library does what the FoSCoS web page does:

1. Fetches FoSCoS's two public keys (`/assets/keys/encPublic.pem` and `resPublic.pem`). If that
   fails it uses the copies bundled in `src/`.
2. `GET /gateway/api/auth/csrf-token` for the session cookie.
3. For every request it makes a random AES-256 key and IV, wraps `{k, iv}` with the encryption
   public key (RSA-OAEP, SHA-256) and sends it in the `x-encrypted-key` header.
4. `POST …/getsearchapplicationdetails/1` with `{"encryptedPayload": AES-256-CBC(query)}`.
5. The reply is `{encryptedResponse, signature, iv}`: the RSA-SHA256 signature is checked against
   the response public key, then the body is AES-decrypted with the same session key.

The site's captcha is enforced only in the browser; this library does not solve or fake captchas.
Keep usage gentle: it talks to a public government service, so look up one number at a time, not in bulk.

## Keeping up with FSSAI: the daily watcher

FSSAI changes things on FoSCoS from time to time. `scripts/watch-foscos.mjs` guards against that:

```bash
node scripts/watch-foscos.mjs                 # check, update keys if they changed, run a self-test
node scripts/watch-foscos.mjs --commit        # also git-commit changed key files
node scripts/watch-foscos.mjs --commit --push # …and push to origin
node scripts/watch-foscos.mjs --no-selftest   # skip the live lookup
```

Each run:

1. Downloads both public keys. If one changed, it rewrites `src/*.pem`.
2. Downloads the site's main JavaScript bundle and fingerprints the encryption code
   (`state/foscos-scheme.json`): which markers exist (`x-encrypted-key`, RSA-OAEP, AES-CBC, 32-byte key,
   and so on) and a hash of the strings around it. The fingerprint survives the minifier renaming variables.
3. Runs a real lookup with the new keys as a self-test (default number `12421012003663`; override with
   `--number` or `FSSAI_TEST_NUMBER`).
4. With `--commit`, commits the changed files, but only when the self-test passed.

| Exit | Status | Meaning |
|---|---|---|
| 0 | `ok` / `updated` | Working. `updated` means a key or the fingerprint changed and was saved. |
| 2 | `needs-attention` | The self-test failed and FoSCoS responded in a way that suggests the scheme changed. `src/crypto.js` and `src/foscos.js` need updating by hand. A note is written to `logs/NEEDS-ATTENTION.txt`. |
| 3 | `unavailable` | FoSCoS is down or under maintenance. Nothing is changed. Try again later. |
| 1 | – | The watcher itself failed (for example it could not reach the site). |

A **key rotation** fixes itself: the library fetches the current keys at runtime, and the watcher keeps
the bundled copies fresh. A **scheme change** (a different cipher, header or endpoint) cannot be patched
automatically, because the new code has to be written. The watcher detects it the day it happens and flags it.

Logs: `logs/watch.log` (every run) and `logs/last-run.json`. Both are git-ignored.

### Email alerts

The watcher emails you when something worth knowing happens: a key was rotated, the site's encryption
code changed, or the lookup is broken. It does not email for "all fine", for the first baseline run, or
for FoSCoS maintenance, and it does not repeat the same alert every day.

1. Copy `.env.example` to `.env` (git-ignored).
2. Fill in `MAIL_USER` and `MAIL_APP_PASSWORD`. For Gmail, turn on 2-step verification and create an
   app password at https://myaccount.google.com/apppasswords. `MAIL_TO` defaults to `MAIL_USER`.

Without these the watcher still works and logs `mail: NOT SENT`. Mail is sent with a small built-in SMTP
client (`scripts/mailer.mjs`), so there are no dependencies.

### Run it every day (Windows)

FoSCoS normally only answers Indian IP addresses, so run the watcher from a machine in India, not from
GitHub Actions. Register a daily task at 03:35 that also runs after a missed start (PC was off):

```powershell
$node   = (Get-Command node).Source
$action = New-ScheduledTaskAction -Execute $node -Argument 'scripts\watch-foscos.mjs --commit --push' -WorkingDirectory 'C:\path\to\fssai-lookup-nokey'
$trigger  = New-ScheduledTaskTrigger -Daily -At 3:35am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName 'FoSCoS key watcher' -Action $action -Trigger $trigger -Settings $settings
```

On Linux/macOS use cron: `35 3 * * * cd /path/to/fssai-lookup-nokey && node scripts/watch-foscos.mjs --commit --push`.

## Geo-blocking

FoSCoS normally only answers Indian IP addresses. From outside India, use an Indian proxy:

```bash
NODE_USE_ENV_PROXY=1 HTTPS_PROXY=http://user:pass@in-proxy:port node bin/fssai.js 12421012003663
```

## Tests

```bash
npm test
```

All tests are offline (a fake FoSCoS server stands in for the real one).

## Notes and limits

- This is an unofficial client for a public government website. It is not affiliated with or endorsed by
  FSSAI. FSSAI can change or block it at any time, and it may stop working until the code is updated.
- The data is whatever FoSCoS shows publicly. Always check the official site before relying on it for
  anything that matters.
- Be considerate: one lookup at a time, no bulk scraping.

## License

MIT. See [LICENSE](LICENSE).
