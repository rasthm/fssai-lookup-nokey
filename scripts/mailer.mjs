// Minimal SMTP client (no dependencies) so the watcher can email you when FoSCoS changes.
// Works with Gmail: smtp.gmail.com:465 (implicit TLS) and an app password.
import net from 'node:net';
import tls from 'node:tls';

export function buildMessage({ from, to, subject, text, date = new Date() }) {
  const encodedSubject = /^[\x20-\x7e]*$/.test(subject) ? subject : `=?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`;
  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${encodedSubject}`,
    `Date: ${date.toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
  ];
  // CRLF line ends, and a leading "." on a line is doubled so it cannot end the DATA section.
  const body = text.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
  return `${headers.join('\r\n')}\r\n\r\n${body}\r\n`;
}

/**
 * Sends one plain-text email. Resolves when the server accepts it, rejects with a readable error.
 * options: { host, port, secure, user, pass, from, to, subject, text, timeoutMs }
 */
export function sendMail({ host, port = 465, secure = true, user, pass, from = user, to, subject, text, timeoutMs = 30_000 }) {
  return new Promise((resolve, reject) => {
    const socket = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
    socket.setEncoding('utf8');
    socket.setTimeout(timeoutMs, () => fail(new Error('SMTP timed out')));

    let buffer = '';
    let waiting = null;
    let done = false;

    function fail(err) {
      if (done) return;
      done = true;
      socket.destroy();
      reject(err);
    }

    socket.on('error', fail);
    socket.on('data', (chunk) => {
      buffer += chunk;
      // A reply is complete at a line like "250 text" (a space after the code); "250-text" continues.
      const lines = buffer.split('\r\n');
      const last = lines.filter(Boolean).at(-1);
      if (waiting && last && /^\d{3} /.test(last) && buffer.endsWith('\r\n')) {
        const reply = buffer;
        buffer = '';
        const cb = waiting;
        waiting = null;
        cb(reply);
      }
    });

    const expect = (okCodes) =>
      new Promise((res, rej) => {
        waiting = (reply) => (okCodes.includes(reply.slice(0, 3)) ? res(reply) : rej(new Error(`SMTP error: ${reply.trim()}`)));
      });
    const send = async (line, okCodes) => {
      const reply = expect(okCodes);
      socket.write(`${line}\r\n`);
      return reply;
    };

    (async () => {
      await expect(['220']);
      await send('EHLO fssai-lookup-nokey', ['250']);
      if (user) {
        await send('AUTH LOGIN', ['334']);
        await send(Buffer.from(user).toString('base64'), ['334']);
        await send(Buffer.from(pass).toString('base64'), ['235']);
      }
      await send(`MAIL FROM:<${from.match(/<([^>]+)>/)?.[1] ?? from}>`, ['250']);
      await send(`RCPT TO:<${to}>`, ['250', '251']);
      await send('DATA', ['354']);
      await send(`${buildMessage({ from, to, subject, text })}.`, ['250']);
      await send('QUIT', ['221']).catch(() => {});
      done = true;
      socket.end();
      resolve();
    })().catch(fail);
  });
}

// Mail settings come from the environment (the watcher loads .env first).
export function mailConfigFromEnv(env = process.env) {
  const user = env.MAIL_USER;
  const pass = env.MAIL_APP_PASSWORD;
  const to = env.MAIL_TO || user;
  if (!user || !pass || !to) return null;
  return {
    host: env.MAIL_HOST || 'smtp.gmail.com',
    port: Number(env.MAIL_PORT) || 465,
    secure: env.MAIL_SECURE !== '0',
    user,
    pass: pass.replace(/\s+/g, ''), // Google shows app passwords in groups of four
    from: `FoSCoS watcher <${user}>`,
    to,
  };
}
