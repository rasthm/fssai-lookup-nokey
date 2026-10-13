import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { sendMail, buildMessage, mailConfigFromEnv } from '../scripts/mailer.mjs';
import { alertFor } from '../scripts/watch-foscos.mjs';

// A tiny fake SMTP server that records what the client says.
function fakeSmtp({ rejectPassword = false } = {}) {
  const seen = { commands: [], data: '' };
  const server = net.createServer((sock) => {
    sock.setEncoding('utf8');
    let inData = false;
    let buf = '';
    sock.write('220 fake ESMTP\r\n');
    sock.on('data', (chunk) => {
      buf += chunk;
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (inData) {
          if (line === '.') {
            inData = false;
            sock.write('250 queued\r\n');
          } else seen.data += `${line}\n`;
          continue;
        }
        seen.commands.push(line);
        if (line.startsWith('EHLO')) sock.write('250-fake\r\n250 AUTH LOGIN\r\n');
        else if (line === 'AUTH LOGIN') sock.write('334 VXNlcm5hbWU6\r\n');
        else if (seen.commands.at(-2) === 'AUTH LOGIN') sock.write('334 UGFzc3dvcmQ6\r\n');
        else if (seen.commands.at(-3) === 'AUTH LOGIN') sock.write(rejectPassword ? '535 bad credentials\r\n' : '235 ok\r\n');
        else if (line.startsWith('MAIL FROM') || line.startsWith('RCPT TO')) sock.write('250 ok\r\n');
        else if (line === 'DATA') {
          inData = true;
          sock.write('354 go\r\n');
        } else if (line === 'QUIT') sock.end('221 bye\r\n');
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, port: server.address().port })));
}

test('sends a message through an SMTP conversation with AUTH LOGIN', async () => {
  const { server, seen, port } = await fakeSmtp();
  await sendMail({ host: '127.0.0.1', port, secure: false, user: 'me@example.com', pass: 'secret', to: 'me@example.com', subject: 'Hello', text: 'line one\n.starts with dot' });
  server.close();
  assert.ok(seen.commands.includes('MAIL FROM:<me@example.com>'));
  assert.ok(seen.commands.includes('RCPT TO:<me@example.com>'));
  assert.match(seen.data, /Subject: Hello/);
  assert.match(seen.data, /\.\.starts with dot/); // dot-stuffed
  assert.ok(seen.commands.includes(Buffer.from('secret').toString('base64')));
});

test('a rejected login surfaces the server error', async () => {
  const { server, port } = await fakeSmtp({ rejectPassword: true });
  await assert.rejects(
    sendMail({ host: '127.0.0.1', port, secure: false, user: 'a@b.c', pass: 'wrong', to: 'a@b.c', subject: 's', text: 't' }),
    /535 bad credentials/,
  );
  server.close();
});

test('non-ASCII subjects are encoded', () => {
  assert.match(buildMessage({ from: 'a@b.c', to: 'd@e.f', subject: 'हिन्दी', text: 'x' }), /Subject: =\?UTF-8\?B\?/);
});

test('mail config comes from env and strips spaces from the app password', () => {
  assert.equal(mailConfigFromEnv({}), null);
  const c = mailConfigFromEnv({ MAIL_USER: 'me@gmail.com', MAIL_APP_PASSWORD: 'abcd efgh ijkl mnop' });
  assert.equal(c.pass, 'abcdefghijklmnop');
  assert.equal(c.to, 'me@gmail.com');
  assert.equal(c.host, 'smtp.gmail.com');
});

const base = { checkedAt: 't', bundle: 'main.x.js', keysChanged: [], schemeNotes: [], files: [], selfTest: { ran: true, ok: true } };

test('alerts: key rotation, broken lookup, and quiet cases', () => {
  assert.match(alertFor({ ...base, status: 'updated', keysChanged: ['encryption'], files: ['x'] }).subject, /rotated its key/);
  assert.match(alertFor({ ...base, status: 'needs-attention', selfTest: { ran: true, ok: false, error: 'HTTP 500' } }).subject, /BROKEN/);
  assert.equal(alertFor({ ...base, status: 'ok' }), null);
  assert.equal(alertFor({ ...base, status: 'updated', files: ['state/foscos-scheme.json'] }), null); // first baseline
  assert.equal(alertFor({ ...base, status: 'unavailable', selfTest: { ran: true, ok: false, error: 'HTTP 503' } }), null);
});
