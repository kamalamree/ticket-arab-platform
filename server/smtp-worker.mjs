import { connect } from 'cloudflare:sockets';
import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';

const encoder = new TextEncoder();
const clean = (value) => String(value ?? '').replace(/[\r\n\0]/g, ' ').trim();
const b64 = (value) => Buffer.from(String(value), 'utf8').toString('base64').replace(/.{1,76}/g, '$&\r\n').trimEnd();

function parseAddress(value) {
  if (typeof value !== 'string') return { email: clean(value?.address || value?.email), name: clean(value?.name) };
  const match = value.match(/^(.*?)\s*<([^<>]+)>$/);
  return match
    ? { name: clean(match[1].replace(/^\"|\"$/g, '')), email: clean(match[2]) }
    : { email: clean(value) };
}

function headerText(value) {
  const text = clean(value);
  return /^[\x20-\x7e]*$/.test(text) ? text : `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`;
}

function formatAddress(address) {
  if (!address.email || !/^[^\s<>@]+@[^\s<>@]+$/.test(address.email)) throw new Error('عنوان البريد غير صالح.');
  return address.name ? `${headerText(address.name)} <${address.email}>` : address.email;
}

function mimeMessage(message, sender, recipients) {
  const headers = [
    `From: ${formatAddress(sender)}`,
    `To: ${recipients.map(formatAddress).join(', ')}`,
    `Subject: ${headerText(message.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${randomUUID()}@${sender.email.split('@')[1]}>`,
    'MIME-Version: 1.0',
  ];
  if (message.replyTo?.address) headers.push(`Reply-To: ${formatAddress(parseAddress(message.replyTo))}`);

  const text = String(message.text || '');
  const html = String(message.html || '');
  const attachments = message.attachments || [];
  const alternativeBoundary = `=_ticket_alt_${randomUUID().replaceAll('-', '')}`;
  const mixedBoundary = `=_ticket_mix_${randomUUID().replaceAll('-', '')}`;
  const body = [
    `--${alternativeBoundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64(text),
    `--${alternativeBoundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64(html),
    `--${alternativeBoundary}--`,
  ];

  if (!attachments.length) {
    headers.push(`Content-Type: multipart/alternative; boundary="${alternativeBoundary}"`);
    return `${headers.join('\r\n')}\r\n\r\n${body.join('\r\n')}\r\n`;
  }

  headers.push(`Content-Type: multipart/mixed; boundary="${mixedBoundary}"`);
  const parts = [`--${mixedBoundary}`, `Content-Type: multipart/alternative; boundary="${alternativeBoundary}"`, '', ...body];
  for (const file of attachments) {
    const filename = clean(file.filename || file.name || 'attachment.bin').slice(0, 180) || 'attachment.bin';
    const fallback = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
    const contentType = clean(file.contentType || file.content_type || 'application/octet-stream').replace(/[^\w.+\-/]/g, '') || 'application/octet-stream';
    const content = Buffer.isBuffer(file.content) ? file.content : Buffer.from(file.content || '');
    parts.push(
      `--${mixedBoundary}`,
      `Content-Type: ${contentType}; name="${fallback}"`,
      `Content-Disposition: attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
      'Content-Transfer-Encoding: base64',
      ...(file.cid ? [`Content-ID: <${clean(file.cid).replace(/[<>]/g, '')}>`] : []),
      '',
      content.toString('base64').replace(/.{1,76}/g, '$&\r\n').trimEnd(),
    );
  }
  parts.push(`--${mixedBoundary}--`);
  return `${headers.join('\r\n')}\r\n\r\n${parts.join('\r\n')}\r\n`;
}

class SmtpSocket {
  constructor(socket) {
    this.socket = socket;
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
    this.pending = '';
  }

  async readResponse() {
    let response = '';
    const deadline = Date.now() + 12000;
    while (Date.now() < deadline) {
      const end = this.pending.indexOf('\r\n');
      if (end >= 0) {
        const line = this.pending.slice(0, end);
        this.pending = this.pending.slice(end + 2);
        response += `${line}\n`;
        const match = line.match(/^(\d{3})([ -])/);
        if (!match) throw new Error('استجابة SMTP غير مفهومة.');
        if (match[2] === ' ') return { code: Number(match[1]), text: response.trim() };
        continue;
      }
      const remaining = deadline - Date.now();
      let timeout;
      const result = await Promise.race([
        this.reader.read(),
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('انتهت مهلة اتصال SMTP.')), remaining); }),
      ]).finally(() => clearTimeout(timeout));
      if (result.done) throw new Error('أغلق خادم SMTP الاتصال قبل اكتمال العملية.');
      this.pending += new TextDecoder().decode(result.value, { stream: true });
      if (this.pending.length > 65536) throw new Error('استجابة خادم SMTP أطول من الحد المسموح.');
    }
    throw new Error('انتهت مهلة اتصال SMTP.');
  }

  async command(value, expected) {
    await this.writer.write(encoder.encode(`${value}\r\n`));
    const response = await this.readResponse();
    if (!expected.includes(response.code)) throw new Error(`SMTP ${response.code}: ${response.text.slice(0, 400)}`);
    return response;
  }

  async upgradeTls() {
    this.reader.releaseLock();
    this.writer.releaseLock();
    this.socket = this.socket.startTls();
    this.reader = this.socket.readable.getReader();
    this.writer = this.socket.writable.getWriter();
    this.pending = '';
  }

  async close() {
    try { this.reader.releaseLock(); } catch {}
    try { this.writer.releaseLock(); } catch {}
    try { await this.socket.close(); } catch {}
  }
}

export async function sendCustomSmtp(settings, message) {
  const hostname = clean(settings.smtpHost);
  const port = Number(settings.smtpPort || 587);
  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535 || port === 25) {
    throw new Error('أدخل خادم SMTP صالحًا. Cloudflare Workers لا يسمح بالاتصال على المنفذ 25؛ استخدم 465 أو 587 أو منفذ إرسال آمنًا يدعمه مزودك.');
  }
  const sender = parseAddress(message.from || settings.mailFrom);
  const recipients = (Array.isArray(message.to) ? message.to : [message.to]).map(parseAddress);
  if (!sender.email || !recipients.length || recipients.some((item) => !item.email)) throw new Error('أدخل عنوان مرسل ومستلم صالحين.');
  if (!message.subject || /[\r\n]/.test(message.subject)) throw new Error('عنوان الرسالة غير صالح.');

  const mode = settings.smtpTlsMode || 'auto';
  const implicitTls = mode === 'tls' || (mode === 'auto' && (port === 465 || (port !== 587 && Boolean(settings.smtpSecure))));
  const socket = connect({ hostname, port }, { secureTransport: implicitTls ? 'on' : 'starttls' });
  let smtp;
  try {
    await socket.opened;
    smtp = new SmtpSocket(socket);
    const greeting = await smtp.readResponse();
    if (greeting.code !== 220) throw new Error(`SMTP ${greeting.code}: ${greeting.text.slice(0, 400)}`);
    const clientName = (settings.smtpEhloName || 'ticketarab.com').replace(/[^a-zA-Z0-9.-]/g, '') || 'localhost';
    let capabilities = await smtp.command(`EHLO ${clientName}`, [250]);

    const wantsStartTls = mode === 'starttls' || (mode === 'auto' && !implicitTls);
    if (!implicitTls && wantsStartTls) {
      const lines = capabilities.text.split('\n').map((line) => line.slice(4).trim().toUpperCase());
      if (!lines.some((line) => line.startsWith('STARTTLS'))) throw new Error('خادم SMTP لا يعلن دعم STARTTLS. اختر TLS ضمن إعدادات الاتصال أو استخدم بيانات مزود تدعم التشفير.');
      await smtp.command('STARTTLS', [220]);
      await smtp.upgradeTls();
      capabilities = await smtp.command(`EHLO ${clientName}`, [250]);
    }

    const capabilityLines = capabilities.text.split('\n').map((line) => line.slice(4).trim().toUpperCase());
    const authLine = capabilityLines.find((line) => line.startsWith('AUTH ')) || '';
    if (settings.smtpUser) {
      if (authLine.includes('PLAIN')) {
        const token = Buffer.from(`\0${settings.smtpUser}\0${settings.smtpPassword}`, 'utf8').toString('base64');
        await smtp.command(`AUTH PLAIN ${token}`, [235, 503]);
      } else if (authLine.includes('LOGIN')) {
        await smtp.command('AUTH LOGIN', [334]);
        await smtp.command(Buffer.from(settings.smtpUser, 'utf8').toString('base64'), [334]);
        await smtp.command(Buffer.from(settings.smtpPassword, 'utf8').toString('base64'), [235]);
      } else {
        throw new Error('خادم SMTP لا يعلن دعم تسجيل الدخول بكلمة المرور عبر AUTH PLAIN أو AUTH LOGIN.');
      }
    }

    await smtp.command(`MAIL FROM:<${sender.email}>`, [250]);
    for (const recipient of recipients) await smtp.command(`RCPT TO:<${recipient.email}>`, [250, 251]);
    await smtp.command('DATA', [354]);
    const rawMessage = mimeMessage(message, sender, recipients).replace(/\r?\n/g, '\r\n');
    const dotStuffed = rawMessage.replace(/(^|\r\n)\./g, '$1..');
    await smtp.writer.write(encoder.encode(`${dotStuffed}\r\n.\r\n`));
    const accepted = await smtp.readResponse();
    if (accepted.code !== 250) throw new Error(`SMTP ${accepted.code}: ${accepted.text.slice(0, 400)}`);
    await smtp.command('QUIT', [221]);
    return { accepted: recipients.map((item) => item.email), response: accepted.text, provider: settings.smtpProviderName || 'Custom SMTP' };
  } finally {
    if (smtp) await smtp.close();
    else try { await socket.close(); } catch {}
  }
}
