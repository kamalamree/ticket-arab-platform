const crypto = require('node:crypto');
const express = require('express');
const { Pool, Client } = require('pg');
const bcrypt = require('bcryptjs');
// Select PDFKit's Node build explicitly. Wrangler's Worker bundler otherwise
// selects its browser ESM build, whose import.meta.url asset lookup throws at
// module initialization inside Workers.
const PDFDocument = require('./node_modules/pdfkit/js/pdfkit.js');
const { render: shapeArabicBidi } = require('bidi-shaper');
const invoiceFont = Buffer.from(require('./noto-naskh-arabic-400-ttf-base64.json'), 'base64');
const defaultEmailTemplates = require('./email-templates.json');
if (process.env.CLOUDFLARE_WORKER !== '1') require('dotenv').config();

const app = express();
const cloudflareWorker = process.env.CLOUDFLARE_WORKER === '1';
const pool = cloudflareWorker ? {
  async query(...args) {
    const client = new Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();
    try { return await client.query(...args); } finally { await client.end(); }
  },
  async connect() {
    const client = new Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();
    client.release = () => client.end();
    return client;
  }
} : new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
const PORT = Number(process.env.PORT || 3000);
if (!process.env.SESSION_SECRET || Buffer.byteLength(process.env.SESSION_SECRET) < 32) throw new Error('Set SESSION_SECRET to at least 32 random bytes before starting the API.');
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY);
app.use(express.json({ limit: '12mb', verify: (req, _res, buffer) => { req.rawBody = Buffer.from(buffer); } }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (process.env.FRONTEND_ORIGIN && req.headers.origin === process.env.FRONTEND_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_ORIGIN);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const escapeXml = value => String(value || '').replace(/[<>&"']/g, char => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[char]);
const publicSeoSettings = seo => {
  const siteUrl = new URL(seo.siteUrl || 'https://www.ticketarab.com').origin;
  const publicAsset = (value, fallback) => { if (!value) return fallback; if (value.startsWith('/') && !value.startsWith('//')) return value; try { return new URL(value, `${siteUrl}/`).href; } catch { return fallback; } };
  return { ...seo, siteUrl, canonical: `${siteUrl}/`, socialImage: publicAsset(seo.socialImage, '/social-preview.png?v=2'), faviconUrl: publicAsset(seo.faviconUrl, '/favicon-32.png?v=2'), appleIconUrl: publicAsset(seo.appleIconUrl, '/apple-touch-icon.png?v=2') };
};
const cookieName = 'ticket_admin';
const sign = value => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('base64url');
function issueSession(adminId, version = 0) {
  const payload = Buffer.from(JSON.stringify({ sub: adminId, version: Number(version || 0), exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}
function readSession(value) {
  if (!value || !process.env.SESSION_SECRET) return null;
  const [payload, signature] = value.split('.');
  const expected = sign(payload || '');
  const a = Buffer.from(signature || ''); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const data = JSON.parse(Buffer.from(payload, 'base64url').toString()); return data.exp > Date.now() ? data : null; } catch { return null; }
}
async function requireAdmin(req, res, next) {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=').map(decodeURIComponent)));
  const session = readSession(cookies[cookieName]);
  if (!session) return res.status(401).json({ error: 'سجّل الدخول للمتابعة' });
  const { rows } = await pool.query('SELECT id,email,session_version FROM admins WHERE id=$1', [session.sub]);
  if (rows[0] && Number(rows[0].session_version || 0) !== Number(session.version || 0)) return res.status(401).json({ error: 'Session expired' });
  if (!rows[0]) return res.status(401).json({ error: 'انتهت الجلسة' });
  req.admin = rows[0]; next();
}
const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' && process.env.FRONTEND_ORIGIN ? 'None' : 'Strict', path: '/', maxAge: 8 * 60 * 60 * 1000 };
const encryptionKey = () => {
  if (!process.env.DATA_ENCRYPTION_KEY || Buffer.byteLength(process.env.DATA_ENCRYPTION_KEY) < 32) throw new Error('Set DATA_ENCRYPTION_KEY to at least 32 random bytes to manage credentials in the admin panel.');
  return crypto.createHash('sha256').update(process.env.DATA_ENCRYPTION_KEY).digest();
};
function encryptSettings(value) {
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: encrypted.toString('base64') };
}
function decryptSettings(value) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(value.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(value.data, 'base64')), decipher.final()]).toString('utf8'));
}
async function getIntegrationSettings() {
  const { rows } = await pool.query("SELECT encrypted_value FROM admin_settings WHERE settings_key='integrations'");
  const stored = rows[0] ? decryptSettings(rows[0].encrypted_value) : {};
  const emailTemplates = { ...defaultEmailTemplates, ...(stored.emailTemplates || {}) };
  for (const key of ['test','invoice','ticket']) {
    const saved = stored.emailTemplates?.[key];
    if (saved && /\?{2,}|\uFFFD/.test(`${saved.subject || ''}\n${saved.html || ''}`)) emailTemplates[key] = defaultEmailTemplates[key];
  }
  const brevoApiKey = stored.brevoApiKey || process.env.BREVO_API_KEY || '';
  const smtp2goApiKey = stored.smtp2goApiKey || process.env.SMTP2GO_API_KEY || '';
  const resendApiKey = stored.resendApiKey || process.env.RESEND_API_KEY || '';
  const configuredEmailProvider = stored.emailProvider || ((stored.smtpHost || process.env.SMTP_HOST) ? 'smtp' : ((stored.smtp2goApiKey || process.env.SMTP2GO_API_KEY) ? 'smtp2go' : ((stored.resendApiKey || process.env.RESEND_API_KEY) ? 'resend' : 'brevo')));
  const emailProvider = configuredEmailProvider;
  const legacySubjects = {
    test: 'اختبار البريد — Ticket Arab',
    ticket: 'تذاكرك جاهزة — {{orderNumber}}'
  };
  for (const key of Object.keys(legacySubjects)) {
    const saved = stored.emailTemplates?.[key];
    if (saved?.subject === legacySubjects[key] && String(saved.html || '').length < 2000 && /font-family:Arial,sans-serif;line-height:1\.8/.test(saved.html || '')) emailTemplates[key] = defaultEmailTemplates[key];
  }
  const ticketTemplate = emailTemplates.ticket;
  let ticketHtml = String(ticketTemplate?.html || '');
  const ticketCodesMarker = '{{{ticketCodes}}}';
  const ticketCodesAt = ticketHtml.indexOf(ticketCodesMarker);
  if (ticketCodesAt >= 0) {
    const headingStart = ticketHtml.lastIndexOf('<h2', ticketCodesAt);
    const headingEnd = headingStart >= 0 ? ticketHtml.indexOf('</h2>', headingStart) + 5 : -1;
    const sectionStart = headingEnd >= 0 ? ticketHtml.indexOf('<div', headingEnd) : -1;
    const sectionEnd = ticketHtml.indexOf('</div>', ticketCodesAt) + 6;
    if (headingStart >= 0 && headingEnd > headingStart && sectionStart >= headingEnd && sectionEnd > sectionStart) ticketHtml = ticketHtml.slice(0, headingStart) + ticketHtml.slice(sectionEnd);
    else ticketHtml = ticketHtml.replaceAll(ticketCodesMarker, '');
  }
  ticketHtml = ticketHtml.replace(/<div\b[^>]*>[^<]*QR[^<]*<\/div>/gi, '');
  emailTemplates.ticket = { ...ticketTemplate, html: ticketHtml };
  return {
    paypalClientId: stored.paypalClientId || process.env.PAYPAL_CLIENT_ID || '',
    paypalClientSecret: stored.paypalClientSecret || process.env.PAYPAL_CLIENT_SECRET || '',
    paypalEnv: stored.paypalEnv || process.env.PAYPAL_ENV || 'sandbox',
    paypalCardButtonText: String(stored.paypalCardButtonText || 'Visa').trim().slice(0, 32) || 'Visa',
    paypalApplePayDomainFile: stored.paypalApplePayDomainFile || '',
    paypalEnabled: stored.paypalEnabled ?? true,
    paypalWalletButtonEnabled: stored.paypalWalletButtonEnabled ?? true,
    paypalPayLaterButtonEnabled: stored.paypalPayLaterButtonEnabled ?? true,
    paypalCardButtonEnabled: stored.paypalCardButtonEnabled ?? true,
    paymegateEnabled: stored.paymegateEnabled ?? false,
    paymegateApiKey: stored.paymegateApiKey || process.env.PAYMEGATE_API_KEY || '',
    paymegateWebhookSecret: stored.paymegateWebhookSecret || process.env.PAYMEGATE_WEBHOOK_SECRET || '',
    lemonSqueezyEnabled: stored.lemonSqueezyEnabled ?? false,
    lemonSqueezyApiKey: stored.lemonSqueezyApiKey || process.env.LEMON_SQUEEZY_API_KEY || '',
    lemonSqueezyStoreId: stored.lemonSqueezyStoreId || process.env.LEMON_SQUEEZY_STORE_ID || '',
    lemonSqueezyVariantId: stored.lemonSqueezyVariantId || process.env.LEMON_SQUEEZY_VARIANT_ID || '',
    lemonSqueezyWebhookSecret: stored.lemonSqueezyWebhookSecret || process.env.LEMON_SQUEEZY_WEBHOOK_SECRET || '',
    heleketEnabled: stored.heleketEnabled ?? false,
    heleketMerchantId: stored.heleketMerchantId || process.env.HELEKET_MERCHANT_ID || '',
    heleketPaymentApiKey: stored.heleketPaymentApiKey || process.env.HELEKET_PAYMENT_API_KEY || '',
    smtpHost: stored.smtpHost || process.env.SMTP_HOST || '', smtpPort: stored.smtpPort || process.env.SMTP_PORT || '587',
    smtpProviderName: stored.smtpProviderName || process.env.SMTP_PROVIDER_NAME || '',
    smtpTlsMode: stored.smtpTlsMode || process.env.SMTP_TLS_MODE || 'auto',
    smtpSecure: stored.smtpSecure ?? process.env.SMTP_SECURE === 'true', smtpUser: stored.smtpUser || process.env.SMTP_USER || '',
    smtpPassword: stored.smtpPassword || process.env.SMTP_PASSWORD || '', mailFrom: stored.mailFrom || process.env.MAIL_FROM || '',
    brevoApiKey,
    smtp2goApiKey,
    resendApiKey,
    emailProvider,
    supportEmail: stored.supportEmail || process.env.SUPPORT_EMAIL || '',
    emailTemplates,
    paypalLogo: stored.paypalLogo || '', paymegateLogo: stored.paymegateLogo || '', lemonSqueezyLogo: stored.lemonSqueezyLogo || '', heleketLogo: stored.heleketLogo || '',
    seo: {
      siteName: stored.seo?.siteName || 'Ticket Arab',
      title: stored.seo?.title || 'Ticket Arab | تذاكر حفلات لا تُنسى',
      description: stored.seo?.description || 'اكتشف أجمل الحفلات واحجز تذكرتك بسهولة وأمان مع Ticket Arab.',
      siteUrl: stored.seo?.siteUrl || 'https://www.ticketarab.com',
      socialImage: stored.seo?.socialImage || '',
      faviconUrl: stored.seo?.faviconUrl || '',
      appleIconUrl: stored.seo?.appleIconUrl || '',
      keywords: stored.seo?.keywords || '',
      twitterHandle: stored.seo?.twitterHandle || '',
      allowIndex: stored.seo?.allowIndex ?? true
    }
  };
}
const hasEmailTransport = settings => Boolean(settings.mailFrom && (
  (settings.emailProvider === 'brevo' && settings.brevoApiKey)
  || (settings.emailProvider === 'smtp2go' && settings.smtp2goApiKey)
  || (settings.emailProvider === 'resend' && settings.resendApiKey)
  || (settings.emailProvider === 'smtp' && settings.smtpHost && Number(settings.smtpPort) > 0 && Number(settings.smtpPort) !== 25)
));
const emailRuntimeError = () => '\u0623\u0643\u0645\u0644 \u0625\u0639\u062f\u0627\u062f \u0645\u0632\u0648\u062f \u0627\u0644\u0628\u0631\u064a\u062f \u0648\u0628\u064a\u0627\u0646\u0627\u062a\u0647 \u0648\u0639\u0646\u0648\u0627\u0646 \u0627\u0644\u0645\u0631\u0633\u0644 \u0641\u064a \u0644\u0648\u062d\u0629 \u0627\u0644\u0625\u062f\u0627\u0631\u0629.';
const renderEmailTemplate = (template, values) => String(template || '').replace(/\{\{\{([A-Za-z0-9_]+)\}\}\}|\{\{([A-Za-z0-9_]+)\}\}/g, (match, rawKey, escapedKey) => {
  const key = rawKey || escapedKey; const value = String(values[key] ?? ''); return rawKey ? value : escapeHtml(value);
});
const emailHtmlFromText = value => `<div dir="rtl" style="margin:0;padding:28px 12px;background:#f2f4f7;color:#17212b;font-family:Tahoma,Arial,sans-serif"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;margin:0 auto;background:#fff;border:1px solid #e5e9ee;border-radius:14px;overflow:hidden"><tr><td style="padding:22px 26px;background:#101b29;color:#fff;border-bottom:4px solid #d6ad5b;font-size:20px;font-weight:800">TICKET <span style="color:#e4bd70">ARAB</span></td></tr><tr><td style="padding:26px;text-align:right;line-height:1.9;color:#344252;font-size:14px">${escapeHtml(value).replace(/\r?\n/g, '<br>')}</td></tr><tr><td style="padding:16px;background:#f8fafb;border-top:1px solid #e5e9ee;color:#7a8794;text-align:center;font-size:11px">رسالة آلية من Ticket Arab</td></tr></table></div>`;
const emailTextFromHtml = value => String(value || '')
  .replace(/<\s*(br|\/p|\/div|\/li|\/tr|\/h[1-6])\b[^>]*>/gi, '\n')
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>|<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
  .replace(/<[^>]*>/g, ' ')
  .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
  .replace(/[ \t]+/g, ' ').replace(/\n\s+/g, '\n').trim();
async function sendEmail(settings, message) {
  const normalizedMessage = { ...message };
  normalizedMessage.text = String(message.text || emailTextFromHtml(message.html || ''));
  normalizedMessage.html = String(message.html || emailHtmlFromText(normalizedMessage.text));
  if (!normalizedMessage.subject || !normalizedMessage.to) throw new Error('Recipient and message subject are required.');
  if (!hasEmailTransport(settings)) throw new Error(emailRuntimeError(settings));
  const fromValue = normalizedMessage.from || settings.mailFrom;
  const fromText = typeof fromValue === 'string' ? fromValue : String(fromValue?.email || fromValue?.address || '');
  const fromEmail = fromText.match(/<([^<>]+)>/)?.[1] || fromText;
  if (/@(?:[a-z0-9-]+\.)*workers\.dev$/i.test(fromEmail)) throw new Error('استخدم عنوان مرسلًا من نطاق تملكه وتم التحقق منه لدى مزود البريد، وليس عنوان workers.dev.');
  if (settings.emailProvider === 'smtp') {
    const sendCustomSmtp = globalThis.__ticketArabSendCustomSmtp;
    if (typeof sendCustomSmtp !== 'function') throw new Error('الإرسال عبر SMTP المخصص متاح عند تشغيل الموقع على Cloudflare Workers.');
    return sendCustomSmtp(settings, normalizedMessage);
  }
  const parseAddress = value => {
    if (typeof value !== 'string') return { email: value?.address || value?.email, name: value?.name };
    const match = value.match(/^(.*?)\s*<([^<>]+)>$/);
    return match ? { name: match[1].replace(/^\"|\"$/g, ''), email: match[2] } : { email: value.trim() };
  };
  const sender = parseAddress(normalizedMessage.from || settings.mailFrom);
  const recipients = (Array.isArray(normalizedMessage.to) ? normalizedMessage.to : [normalizedMessage.to]).map(parseAddress).filter(item => item.email);
  if (!sender.email || !recipients.length) throw new Error('A valid sender and recipient are required.');
  const attachments = (normalizedMessage.attachments || []).map(file => ({ name: file.filename || file.name || 'attachment.bin', content: Buffer.isBuffer(file.content) ? file.content.toString('base64') : Buffer.from(file.content || '').toString('base64') }));
  const htmlContent = normalizedMessage.html.replace(/<img\b[^>]*>/gi, tag => {
    const cid = tag.match(/\bsrc\s*=\s*([\"'])cid:([^\"']+)\1/i)?.[2];
    if (!cid) return tag;
    const file = (normalizedMessage.attachments || []).find(item => item.cid === cid);
    return `<p>QR image is attached as ${escapeHtml(file?.filename || file?.name || 'ticket-qr.png')}.</p>`;
  });
  const senderValue = sender.name ? { name: sender.name, email: sender.email } : { email: sender.email };
  const recipientAddresses = recipients.map(item => item.email);
  const attachmentContent = normalizedMessage.attachments || [];
  let endpoint; let headers; let payload; let provider;
  if (settings.emailProvider === 'brevo') {
    endpoint = 'https://api.brevo.com/v3/smtp/email';
    headers = { 'api-key': settings.brevoApiKey, 'Content-Type': 'application/json', Accept: 'application/json' };
    payload = { sender: senderValue, to: recipients, subject: normalizedMessage.subject, textContent: normalizedMessage.text, htmlContent,
      ...(attachments.length ? { attachment: attachments } : {}),
      ...(normalizedMessage.replyTo?.address ? { replyTo: { email: normalizedMessage.replyTo.address, name: normalizedMessage.replyTo.name } } : {}) };
    provider = 'Brevo API';
  } else if (settings.emailProvider === 'smtp2go') {
    endpoint = 'https://api.smtp2go.com/v3/email/send';
    headers = { 'X-Smtp2go-Api-Key': settings.smtp2goApiKey, 'Content-Type': 'application/json', Accept: 'application/json' };
    payload = { sender: sender.name ? `${sender.name} <${sender.email}>` : sender.email, to: recipientAddresses, subject: normalizedMessage.subject, text_body: normalizedMessage.text, html_body: htmlContent, fastaccept: true,
      ...(attachments.length ? { attachments: attachmentContent.map(file => ({ filename: file.filename || file.name || 'attachment.bin', fileblob: Buffer.isBuffer(file.content) ? file.content.toString('base64') : Buffer.from(file.content || '').toString('base64'), mimetype: file.contentType || file.content_type || 'application/octet-stream' })) } : {}),
      ...(normalizedMessage.replyTo?.address ? { custom_headers: [{ header: 'Reply-To', value: normalizedMessage.replyTo.name ? `${normalizedMessage.replyTo.name} <${normalizedMessage.replyTo.address}>` : normalizedMessage.replyTo.address }] } : {}) };
    provider = 'SMTP2GO API';
  } else if (settings.emailProvider === 'resend') {
    endpoint = 'https://api.resend.com/emails';
    headers = { Authorization: `Bearer ${settings.resendApiKey}`, 'Content-Type': 'application/json', Accept: 'application/json' };
    payload = { from: sender.name ? `${sender.name} <${sender.email}>` : sender.email, to: recipientAddresses, subject: normalizedMessage.subject, text: normalizedMessage.text, html: htmlContent,
      ...(attachments.length ? { attachments: attachmentContent.map(file => ({ filename: file.filename || file.name || 'attachment.bin', content: Buffer.isBuffer(file.content) ? file.content.toString('base64') : Buffer.from(file.content || '').toString('base64'), content_type: file.contentType || file.content_type || 'application/octet-stream', ...(file.cid ? { content_id: file.cid } : {}) })) } : {}),
      ...(normalizedMessage.replyTo?.address ? { reply_to: normalizedMessage.replyTo.name ? `${normalizedMessage.replyTo.name} <${normalizedMessage.replyTo.address}>` : normalizedMessage.replyTo.address } : {}) };
    provider = 'Resend API';
  } else {
    throw new Error('Unsupported email provider.');
  }
  const response = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(20000) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(String(result.message || result.error || result.code || result.data?.error || `${provider} returned HTTP ${response.status}`).slice(0, 240));
  if (settings.emailProvider === 'smtp2go' && (Number(result.data?.failed || 0) > 0 || Number(result.data?.succeeded || 0) < 1)) {
    throw new Error(String(result.data?.failures?.[0]?.error || result.data?.error || 'SMTP2GO did not accept the message.').slice(0, 240));
  }
  const messageId = result.messageId || result.id || result.data?.email_id || result.request_id;
  return { accepted: recipientAddresses, response: String(messageId || `Accepted by ${provider}`), provider, queued: settings.emailProvider === 'smtp2go' };
}
const usdRateCache = new Map();
async function getUsdRate(currency) {
  const base = String(currency || '').trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(base)) throw new Error('Invalid currency code');
  if (base === 'USD') return { rate: 1, date: new Date().toISOString().slice(0, 10) };
  const cached = usdRateCache.get(base);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  try {
    const response = await fetch(`https://api.frankfurter.dev/v2/rate/${base.toLowerCase()}/usd`, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`Frankfurter returned HTTP ${response.status}`);
    const data = await response.json();
    const rate = Number(data.rate);
    if (String(data.base).toUpperCase() !== base || String(data.quote).toUpperCase() !== 'USD' || !Number.isFinite(rate) || rate <= 0 || !data.date) throw new Error('Invalid Frankfurter exchange rate response');
    const value = { rate, date: data.date, source: 'Frankfurter' };
    usdRateCache.set(base, { value, expiresAt: Date.now() + 12 * 60 * 60 * 1000 });
    return value;
  } catch (primaryError) {
    try {
      // Daily, no-key fallback. One USD-based snapshot serves every supported currency.
      const cacheKey = '__exchange_rate_api_usd';
      let snapshot = usdRateCache.get(cacheKey);
      if (!snapshot || snapshot.expiresAt <= Date.now()) {
        const response = await fetch('https://open.er-api.com/v6/latest/USD', { signal: AbortSignal.timeout(5000) });
        if (!response.ok) throw new Error(`ExchangeRate-API returned HTTP ${response.status}`);
        const data = await response.json();
        const updatedAt = Number(data.time_last_update_unix);
        if (data.result !== 'success' || String(data.base_code).toUpperCase() !== 'USD' || !Number.isFinite(updatedAt) || Date.now() / 1000 - updatedAt > 7 * 24 * 60 * 60) throw new Error('Invalid or stale fallback exchange-rate response');
        snapshot = { data, date: new Date(updatedAt * 1000).toISOString().slice(0, 10), expiresAt: Date.now() + 12 * 60 * 60 * 1000 };
        usdRateCache.set(cacheKey, snapshot);
      }
      const localPerUsd = Number(snapshot.data.rates?.[base]);
      if (!Number.isFinite(localPerUsd) || localPerUsd <= 0) throw new Error(`Fallback does not support ${base}`);
      const value = { rate: 1 / localPerUsd, date: snapshot.date, source: 'ExchangeRate-API' };
      usdRateCache.set(base, { value, expiresAt: snapshot.expiresAt });
      return value;
    } catch (fallbackError) {
      console.error('Exchange-rate providers failed:', String(primaryError?.message || primaryError), String(fallbackError?.message || fallbackError));
      throw new Error('No current exchange rate is available for this currency');
    }
  }
}
function requestDetails(req) {
  const userAgent = String(req.get('user-agent') || '').slice(0, 500);
  const referrer = req.get('referer'); let referrerOrigin = null;
  try { if (referrer) referrerOrigin = new URL(referrer).origin; } catch {}
  const deviceType = /bot|crawler|spider/i.test(userAgent) ? 'bot' : /ipad|tablet/i.test(userAgent) ? 'tablet' : /mobile|android|iphone/i.test(userAgent) ? 'mobile' : userAgent ? 'desktop' : 'unknown';
  const trustedCloudflare = cloudflareWorker || Boolean(process.env.TRUST_PROXY);
  const forwardedIp = trustedCloudflare ? req.get('cf-connecting-ip') : '';
  const ip = String(forwardedIp || req.ip || req.socket.remoteAddress || '').slice(0, 80);
  const countryCode = trustedCloudflare ? String(req.get('x-edge-country') || req.get('cf-ipcountry') || '').toUpperCase().slice(0, 2) : '';
  const country = /^[A-Z]{2}$/.test(countryCode) ? countryCode : null;
  const countryName = country ? new Intl.DisplayNames(['ar'],{type:'region'}).of(country) : null;
  return { ip, userAgent, referrerOrigin, deviceType, countryCode: country, countryName, region:trustedCloudflare?String(req.get('x-edge-region')||'').slice(0,120):null, city:trustedCloudflare?String(req.get('x-edge-city')||'').slice(0,120):null };
}
let featureSchemaPromise;
const INVOICE_PDF_VERSION = 11;
const INVOICE_ARABIC_FEATURES = Object.freeze({
  ccmp: false, locl: false, rlig: false, liga: false, clig: false, calt: false,
  kern: false, mark: false, mkmk: false, rtla: false, rtlm: false,
  init: false, medi: false, fina: false, isol: false, fin2: false, fin3: false,
  med2: false, mset: false, rclt: false, curs: false, rvrn: false,
  ltra: false, ltrm: false, frac: false, numr: false, dnom: false
});
function ensureFeatureSchema() {
  featureSchemaPromise ||= (async () => {
    await pool.query('ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS viewed_at timestamptz');
    await pool.query('ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS archived_at timestamptz');
    await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_pdf bytea');
    await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_pdf_sha256 text');
    await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_pdf_version integer NOT NULL DEFAULT 0');
    await pool.query('ALTER TABLE payments ADD COLUMN IF NOT EXISTS country_code char(2)');
    await pool.query('ALTER TABLE payments ADD COLUMN IF NOT EXISTS country_name text');
    await pool.query('ALTER TABLE payments ADD COLUMN IF NOT EXISTS region text');
    await pool.query('ALTER TABLE payments ADD COLUMN IF NOT EXISTS city text');
    await pool.query(`CREATE TABLE IF NOT EXISTS visitor_events (
      id bigserial PRIMARY KEY, ip_address text NOT NULL, country_code char(2), country_name text,
      region text, city text, path text NOT NULL, referrer_origin text, device_type text NOT NULL DEFAULT 'unknown',
      user_agent text, created_at timestamptz NOT NULL DEFAULT now())`);
    await pool.query('CREATE INDEX IF NOT EXISTS visitor_events_created_idx ON visitor_events(created_at DESC)');
    await pool.query('CREATE INDEX IF NOT EXISTS visitor_events_country_idx ON visitor_events(country_code,created_at DESC)');
  })().catch(error => { featureSchemaPromise = null; throw error; });
  return featureSchemaPromise;
}
const loginAttempts = new Map();
function limitAdminLogin(req, res, next) {
  const key = req.ip; const now = Date.now(); const state = loginAttempts.get(key) || { count: 0, reset: now + 15 * 60 * 1000 };
  if (state.reset <= now) { state.count = 0; state.reset = now + 15 * 60 * 1000; }
  if (state.count >= 8) return res.status(429).json({ error: 'محاولات كثيرة. حاول مجددًا بعد قليل.' });
  state.count++; loginAttempts.set(key, state); next();
}

app.get('/api/health', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1'); res.json({ ok: true });
}));
app.get('/api/payment-methods',asyncRoute(async(_req,res)=>{
  const s=await getIntegrationSettings();
  const paypal=s.paypalEnabled&&Boolean(s.paypalClientId&&s.paypalClientSecret)&&(s.paypalWalletButtonEnabled||s.paypalPayLaterButtonEnabled||s.paypalCardButtonEnabled);
  let paypalClientToken='';
  if(paypal)try{
    const pp=await paypalToken(s);
    const tokenResponse=await fetch(`${pp.base}/v1/identity/generate-token`,{method:'POST',headers:{Authorization:`Bearer ${pp.token}`,'Accept-Language':'en_US','Content-Type':'application/json'},signal:AbortSignal.timeout(10000)});
    const tokenData=await tokenResponse.json();
    if(tokenResponse.ok&&tokenData.client_token)paypalClientToken=tokenData.client_token;
    else console.warn('PayPal client token request failed:',tokenData.name||tokenData.message||tokenResponse.status);
  }catch(error){console.warn('PayPal client token setup failed:',String(error?.message||error).slice(0,250));}
  res.set('Cache-Control','no-store').json({paypal,paypalClientId:paypal?s.paypalClientId:'',paypalClientToken,paypalSandbox:s.paypalEnv!=='live',paypalCardButtonText:s.paypalCardButtonText||'Visa',paypalFunding:{paypal:paypal&&s.paypalWalletButtonEnabled,paylater:paypal&&s.paypalPayLaterButtonEnabled,card:paypal&&s.paypalCardButtonEnabled},paymegate:s.paymegateEnabled&&Boolean(s.paymegateApiKey&&s.paymegateWebhookSecret&&process.env.FRONTEND_ORIGIN?.startsWith('https://')),heleket:s.heleketEnabled&&Boolean(s.heleketMerchantId&&s.heleketPaymentApiKey&&process.env.FRONTEND_ORIGIN?.startsWith('https://')),logos:{paypal:s.paypalLogo,paymegate:s.paymegateLogo,heleket:s.heleketLogo}});
}));
app.get('/api/public/seo',asyncRoute(async(_req,res)=>{const settings=await getIntegrationSettings();res.set('Cache-Control','no-store');res.json(publicSeoSettings(settings.seo));}));
app.get('/robots.txt',asyncRoute(async(_req,res)=>{const settings=await getIntegrationSettings();const seo=publicSeoSettings(settings.seo);res.type('text/plain').set('Cache-Control','public, max-age=300').send(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\nDisallow: /webhooks/\nDisallow: /support\nDisallow: /checkout/\n${seo.allowIndex?'Sitemap: '+seo.siteUrl+'/sitemap.xml\n':'# Indexing disabled by site owner\n'}`);}));
app.get('/sitemap.xml',asyncRoute(async(_req,res)=>{const settings=await getIntegrationSettings();const seo=publicSeoSettings(settings.seo);const body=seo.allowIndex?`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${escapeXml(seo.canonical)}</loc><changefreq>daily</changefreq><priority>1.0</priority></url></urlset>`:`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`;res.type('application/xml').set('Cache-Control','public, max-age=300').send(body);}));
app.get('/.well-known/apple-developer-merchantid-domain-association',asyncRoute(async(_req,res)=>{const settings=await getIntegrationSettings();if(!settings.paypalApplePayDomainFile)return res.sendStatus(404);res.status(200).type('application/octet-stream').set('Cache-Control','public, max-age=3600').send(settings.paypalApplePayDomainFile);}));
app.get('/api/quote',asyncRoute(async(req,res)=>{const amount=Number(req.query.amount);const currency=String(req.query.currency||'').trim().toUpperCase();if(!Number.isFinite(amount)||amount<=0||amount>10000000||!/^[A-Z]{3}$/.test(currency))return res.status(400).json({error:'Invalid amount or currency'});const fx=await getUsdRate(currency);res.json({usd_amount:Number((amount*fx.rate).toFixed(2)),currency,exchange_rate:fx.rate,exchange_rate_date:fx.date,source:fx.source});}));
app.post('/api/visit',asyncRoute(async(req,res)=>{await ensureFeatureSchema();const detail=requestDetails(req);const path=String(req.body?.path||'/').slice(0,300);if(!detail.ip)return res.status(204).end();await pool.query('INSERT INTO visitor_events(ip_address,country_code,country_name,region,city,path,referrer_origin,device_type,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[detail.ip,detail.countryCode,detail.countryName,detail.region,detail.city,path,detail.referrerOrigin,detail.deviceType,detail.userAgent]);res.status(204).end();}));
app.get('/api/admin/analytics',requireAdmin,asyncRoute(async(req,res)=>{await ensureFeatureSchema();const range=['day','week','month'].includes(req.query.range)?req.query.range:'week';const interval=range==='day'?'24 hours':range==='week'?'7 days':'30 days';const bucket=range==='day'?'hour':'day';const page=Math.max(1,Number.parseInt(req.query.page,10)||1);const pageSize=30;const [totals,series,countries,places,ipCount,ips]=await Promise.all([
  pool.query(`SELECT count(*)::int visits,count(DISTINCT ip_address)::int visitors FROM visitor_events WHERE created_at>=now()-$1::interval`,[interval]),
  pool.query(`SELECT date_trunc('${bucket}',created_at) bucket,count(*)::int visits,count(DISTINCT ip_address)::int visitors FROM visitor_events WHERE created_at>=now()-$1::interval GROUP BY 1 ORDER BY 1`,[interval]),
  pool.query(`SELECT country_code,COALESCE(country_name,country_code,'غير معروف') name,count(*)::int visits,count(DISTINCT ip_address)::int visitors FROM visitor_events WHERE created_at>=now()-$1::interval GROUP BY country_code,country_name ORDER BY visits DESC LIMIT 12`,[interval]),
  pool.query(`SELECT concat_ws('، ',city,region,country_name) name,count(*)::int visits,count(DISTINCT ip_address)::int visitors FROM visitor_events WHERE created_at>=now()-$1::interval AND (city IS NOT NULL OR region IS NOT NULL) GROUP BY 1 ORDER BY visits DESC LIMIT 12`,[interval]),
  pool.query(`SELECT count(DISTINCT ip_address)::int total FROM visitor_events WHERE created_at>=now()-$1::interval`,[interval]),
  pool.query(`SELECT * FROM (SELECT DISTINCT ON (ip_address) ip_address,country_code,country_name,region,city,device_type,path,created_at FROM visitor_events WHERE created_at>=now()-$1::interval ORDER BY ip_address,created_at DESC) recent ORDER BY created_at DESC LIMIT $2 OFFSET $3`,[interval,pageSize,(page-1)*pageSize])
]);res.json({range,totals:totals.rows[0],series:series.rows,countries:countries.rows,places:places.rows,ips:ips.rows,ip_total:ipCount.rows[0].total,ip_page:page,ip_page_size:pageSize});}));
app.get('/api/events', asyncRoute(async (_req, res) => {
  const { rows } = await pool.query(`SELECT e.*, COALESCE((SELECT json_agg(json_build_object('id',t.id,'name',t.name,'price',t.price,'currency',t.currency,'available',GREATEST(t.quantity_available-t.quantity_sold-t.quantity_reserved,0)) ORDER BY CASE t.name WHEN 'Bronze' THEN 1 WHEN 'Regular' THEN 1 WHEN 'Silver' THEN 2 WHEN 'Gold' THEN 3 WHEN 'Diamond / Fan Pit' THEN 4 WHEN 'Platinum' THEN 4 WHEN 'Premium' THEN 5 WHEN 'Premium Diamond' THEN 6 WHEN 'Premium VIP' THEN 6 WHEN 'VIP' THEN 7 ELSE 99 END,t.price) FROM ticket_types t WHERE t.event_id=e.id AND t.is_active=true AND e.is_active=true),'[]') ticket_types FROM events e WHERE e.is_active=true AND e.event_date>now() ORDER BY e.event_date`);
  res.json({ events: rows });
}));
app.post('/api/admin/login', limitAdminLogin, asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT id,email,password_hash,session_version FROM admins WHERE email=$1', [email]);
  if (!rows[0] || !await bcrypt.compare(password, rows[0].password_hash)) return res.status(401).json({ error: 'البريد أو كلمة المرور غير صحيحة' });
  res.cookie(cookieName, issueSession(rows[0].id, rows[0].session_version), cookieOptions);
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)', [rows[0].id, 'login', JSON.stringify({ email })]);
  res.json({ admin: { id: rows[0].id, email: rows[0].email } });
}));
app.post('/api/admin/logout', (_req, res) => res.clearCookie(cookieName, { ...cookieOptions, maxAge: undefined }).json({ ok: true }));
app.get('/api/admin/me', requireAdmin, (req, res) => res.json({ admin: req.admin }));
const passwordResetAttempts = new Map();
app.post('/api/admin/password/forgot', asyncRoute(async (req, res) => {
  const email=String(req.body?.email||'').trim().toLowerCase();
  const detail=requestDetails(req);const now=Date.now();const attempt=passwordResetAttempts.get(detail.ip)||{count:0,until:now+60*60*1000};
  if(attempt.until<=now){attempt.count=0;attempt.until=now+60*60*1000;}if(attempt.count>=5)return res.json({ok:true});attempt.count++;passwordResetAttempts.set(detail.ip,attempt);
  const admin=(await pool.query('SELECT id,email FROM admins WHERE email=$1',[email])).rows[0];
  if(admin){
    const token=crypto.randomBytes(32).toString('base64url');const tokenHash=crypto.createHash('sha256').update(token).digest('hex');
    await pool.query('DELETE FROM admin_password_resets WHERE admin_id=$1 OR expires_at<=now()',[admin.id]);
    await pool.query('INSERT INTO admin_password_resets(admin_id,token_hash,expires_at) VALUES($1,$2,now()+interval \'1 hour\')',[admin.id,tokenHash]);
    const origin=String(process.env.FRONTEND_ORIGIN||'http://localhost:5173').replace(/\/$/,'');
    const url=`${origin}/admin/reset-password?token=${encodeURIComponent(token)}`;const settings=await getIntegrationSettings();
    try{await sendEmail(settings,{from:settings.mailFrom,to:admin.email,subject:'إعادة تعيين كلمة مرور Ticket Arab',text:`طلبت إعادة تعيين كلمة مرور لوحة الإدارة. افتح الرابط التالي خلال ساعة واحدة لإتمام العملية:\n${url}\n\nإذا لم تطلب ذلك، تجاهل هذه الرسالة.`});}
    catch(err){console.error('Admin password reset email failed:',err.message);}
  }
  res.json({ok:true,message:'إذا كان البريد مسجلًا، فستصلك رسالة لاستعادة كلمة المرور.'});
}));
app.post('/api/admin/password/reset', asyncRoute(async (req, res) => {
  const token=String(req.body?.token||'');const password=String(req.body?.password||'');
  if(token.length<32||password.length<12)return res.status(400).json({error:'الرابط غير صالح أو انتهت صلاحيته، وكلمة المرور الجديدة يجب أن تكون 12 حرفًا على الأقل.'});
  const tokenHash=crypto.createHash('sha256').update(token).digest('hex');const client=await pool.connect();
  try{
    await client.query('BEGIN');const reset=(await client.query('SELECT id,admin_id FROM admin_password_resets WHERE token_hash=$1 AND expires_at>now() FOR UPDATE',[tokenHash])).rows[0];
    if(!reset){await client.query('ROLLBACK');return res.status(400).json({error:'الرابط غير صالح أو انتهت صلاحيته. اطلب رابطًا جديدًا.'});}
    const hash=await bcrypt.hash(password,12);await client.query('UPDATE admins SET password_hash=$1,session_version=session_version+1 WHERE id=$2',[hash,reset.admin_id]);
    await client.query('DELETE FROM admin_password_resets WHERE admin_id=$1',[reset.admin_id]);await client.query('COMMIT');
  }catch(err){await client.query('ROLLBACK');throw err;}finally{await client.release();}
  res.clearCookie(cookieName,{...cookieOptions,maxAge:undefined}).json({ok:true});
}));
app.put('/api/admin/account',requireAdmin,asyncRoute(async(req,res)=>{
  const email=String(req.body?.email||'').trim().toLowerCase();const currentPassword=String(req.body?.currentPassword||'');const newPassword=String(req.body?.newPassword||'');
  if(!/^\S+@\S+\.\S+$/.test(email)||!currentPassword)return res.status(400).json({error:'أدخل بريدًا صحيحًا وكلمة المرور الحالية.'});
  if(newPassword&&newPassword.length<12)return res.status(400).json({error:'كلمة المرور الجديدة يجب أن تكون 12 حرفًا على الأقل.'});
  const admin=(await pool.query('SELECT id,email,password_hash,session_version FROM admins WHERE id=$1',[req.admin.id])).rows[0];
  if(!admin||!await bcrypt.compare(currentPassword,admin.password_hash))return res.status(403).json({error:'كلمة المرور الحالية غير صحيحة.'});
  if(email===admin.email&&!newPassword)return res.status(400).json({error:'لا توجد تغييرات لحفظها.'});
  const passwordHash=newPassword?await bcrypt.hash(newPassword,12):admin.password_hash;const version=Number(admin.session_version||0)+(newPassword?1:0);
  try{await pool.query('UPDATE admins SET email=$1,password_hash=$2,session_version=$3 WHERE id=$4',[email,passwordHash,version,admin.id]);}
  catch(err){if(err.code==='23505')return res.status(409).json({error:'هذا البريد مستخدم بالفعل.'});throw err;}
  if(newPassword)res.cookie(cookieName,issueSession(admin.id,version),cookieOptions);
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[admin.id,'admin.account.update',JSON.stringify({email_changed:email!==admin.email,password_changed:Boolean(newPassword)})]);
  res.json({ok:true,admin:{id:admin.id,email}});
}));
app.get('/api/admin/summary', requireAdmin, asyncRoute(async (_req, res) => {
  await ensureFeatureSchema();
  const [orders, revenue, events, tickets, unreadSupport, pendingTicketDeliveries] = await Promise.all([
    pool.query("SELECT count(*)::int count FROM orders WHERE status='paid'"),
    pool.query("SELECT COALESCE(sum(amount),0) amount FROM payments WHERE status='completed' AND currency='USD'"),
    pool.query('SELECT count(*)::int count FROM events WHERE is_active=true'),
    pool.query('SELECT count(*)::int count FROM tickets WHERE status=\'valid\''),
    pool.query("SELECT count(*)::int count FROM support_messages WHERE viewed_at IS NULL AND archived_at IS NULL"),
    pool.query("SELECT COALESCE(sum(oi.quantity),0)::int count FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.status='paid' AND o.ticket_delivery_status IN ('waiting','failed')")
  ]);
  const latest = await pool.query('SELECT id,order_number,buyer_name,buyer_email,total_amount,currency,status,created_at FROM orders ORDER BY created_at DESC LIMIT 12');
  res.json({ stats: { orders: orders.rows[0].count, revenue: revenue.rows[0].amount, events: events.rows[0].count, tickets: tickets.rows[0].count, unreadSupport: unreadSupport.rows[0].count, pendingTicketDeliveries: pendingTicketDeliveries.rows[0].count }, orders: latest.rows });
}));
app.get('/api/admin/events', requireAdmin, asyncRoute(async (req, res) => {
  const page=Math.max(1,Number.parseInt(req.query.page,10)||1);const pageSize=25;
  const [count,result]=await Promise.all([
    pool.query('SELECT count(*)::int total FROM events'),
    pool.query('SELECT e.*, COALESCE(json_agg(json_build_object(\'id\',t.id,\'name\',t.name,\'price\',t.price,\'currency\',t.currency,\'quantity_available\',t.quantity_available,\'quantity_sold\',t.quantity_sold,\'quantity_reserved\',t.quantity_reserved,\'is_active\',t.is_active)) FILTER (WHERE t.id IS NOT NULL),\'[]\') ticket_types FROM events e LEFT JOIN ticket_types t ON t.event_id=e.id GROUP BY e.id ORDER BY event_date LIMIT $1 OFFSET $2',[pageSize,(page-1)*pageSize])
  ]);
  res.json({ events: result.rows,total:count.rows[0].total,page,page_size:pageSize });
}));
app.post('/api/admin/events', requireAdmin, asyncRoute(async (req, res) => {
  const { title, description = '', venue, city, country, event_date, image_url = '', ticket_types = [] } = req.body;
  if (!title || !venue || !city || !country || !event_date || !Array.isArray(ticket_types) || !ticket_types.length) return res.status(400).json({ error: 'أكمل بيانات الحفلة ونوع تذكرة واحدًا على الأقل' });
  if (ticket_types.some(t => !/^[A-Z]{3}$/.test(String(t.currency || 'USD').trim().toUpperCase()))) return res.status(400).json({ error: 'اكتب رمز العملة الدولي المكوّن من 3 أحرف، مثل EGP أو USD.' });
  if (new Set(ticket_types.map(t=>String(t.currency||'USD').trim().toUpperCase())).size > 1) return res.status(400).json({ error: 'يجب استخدام عملة واحدة لجميع فئات الحفلة.' });
  if (ticket_types.some(t => !String(t.name || '').trim() || !Number.isFinite(Number(t.price)) || Number(t.price) < 0 || !Number.isInteger(Number(t.quantity_available)) || Number(t.quantity_available) < 1)) return res.status(400).json({ error: 'تحقق من اسم التذكرة والسعر والكمية المتاحة.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const event = (await client.query('INSERT INTO events(title,description,venue,city,country,event_date,image_url) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *', [title, description, venue, city, country, event_date, image_url])).rows[0];
    for (const t of ticket_types) await client.query('INSERT INTO ticket_types(event_id,name,price,currency,quantity_available) VALUES($1,$2,$3,$4,$5)', [event.id, String(t.name).trim(), Number(t.price), String(t.currency || 'USD').toUpperCase(), Number(t.quantity_available)]);
    await client.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)', [req.admin.id, 'event.create', JSON.stringify({ event_id: event.id })]);
    await client.query('COMMIT'); res.status(201).json({ event });
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { await client.release(); }
}));
app.post('/api/admin/events/:id/ticket-types', requireAdmin, asyncRoute(async (req,res) => {
  const name=String(req.body.name||'').trim().slice(0,100);const price=Number(req.body.price);const currency=String(req.body.currency||'').trim().toUpperCase();const quantity=Number(req.body.quantity_available);
  if(!name||!Number.isFinite(price)||price<0||!/^[A-Z]{3}$/.test(currency)||!Number.isInteger(quantity)||quantity<1)return res.status(400).json({error:'تحقق من اسم الفئة والسعر والعملة والكمية.'});
  const client=await pool.connect();try{await client.query('BEGIN');const event=(await client.query('SELECT id FROM events WHERE id=$1 AND is_active FOR UPDATE',[req.params.id])).rows[0];if(!event){await client.query('ROLLBACK');return res.status(404).json({error:'الحفلة غير موجودة أو مؤرشفة.'});}const currencies=(await client.query('SELECT DISTINCT currency FROM ticket_types WHERE event_id=$1 AND is_active',[event.id])).rows;if(currencies.some(row=>String(row.currency).trim().toUpperCase()!==currency)){await client.query('ROLLBACK');return res.status(400).json({error:'يجب استخدام عملة واحدة لكل فئات الحفلة.'});}const ticket=(await client.query('INSERT INTO ticket_types(event_id,name,price,currency,quantity_available) VALUES($1,$2,$3,$4,$5) RETURNING *',[event.id,name,price,currency,quantity])).rows[0];await client.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'ticket_type.create',JSON.stringify({event_id:event.id,ticket_type_id:ticket.id})]);await client.query('COMMIT');res.status(201).json({ticket_type:ticket});}catch(err){await client.query('ROLLBACK');throw err;}finally{await client.release();}
}));
app.put('/api/admin/ticket-types/:id', requireAdmin, asyncRoute(async (req, res) => {
  const price = Number(req.body.price);
  const currency = String(req.body.currency || '').trim().toUpperCase();
  const quantity = Number(req.body.quantity_available);
  if (!Number.isFinite(price) || price < 0 || !/^[A-Z]{3}$/.test(currency) || !Number.isInteger(quantity) || quantity < 0) return res.status(400).json({ error: 'تحقق من السعر والعملة والكمية المتاحة.' });
  const { rows } = await pool.query('UPDATE ticket_types SET price=$2,currency=$3,quantity_available=$4 WHERE id=$1 AND quantity_sold+quantity_reserved<=$4 RETURNING id,event_id,name,price,currency,quantity_available,quantity_sold', [req.params.id, price, currency, quantity]);
  if (!rows[0]) {
    const exists = await pool.query('SELECT id FROM ticket_types WHERE id=$1', [req.params.id]);
    if (!exists.rowCount) return res.status(404).json({ error: 'فئة التذكرة غير موجودة.' });
    return res.status(400).json({ error: 'لا يمكن ضبط الكمية بأقل من التذاكر المباعة أو المحجوزة.' });
  }
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)', [req.admin.id, 'ticket_type.update', JSON.stringify({ ticket_type_id: rows[0].id, event_id: rows[0].event_id, quantity_available: quantity, currency })]);
  res.json({ ticket_type: rows[0] });
}));
app.get('/api/admin/events/:id', requireAdmin, asyncRoute(async(req,res)=>{
  const {rows}=await pool.query(`SELECT e.*,COALESCE((SELECT json_agg(json_build_object('id',t.id,'name',t.name,'price',t.price,'currency',t.currency,'quantity_available',t.quantity_available,'quantity_sold',t.quantity_sold,'quantity_reserved',t.quantity_reserved,'is_active',t.is_active) ORDER BY t.price) FROM ticket_types t WHERE t.event_id=e.id),'[]') ticket_types FROM events e WHERE e.id=$1`,[req.params.id]);
  if(!rows[0])return res.status(404).json({error:'الحفلة غير موجودة'});res.json({event:rows[0]});
}));
app.put('/api/admin/events/:id', requireAdmin, asyncRoute(async (req, res) => {
  const { title, description, venue, city, country, event_date, image_url, is_active } = req.body;
  const { rows } = await pool.query('UPDATE events SET title=COALESCE($1,title),description=COALESCE($2,description),venue=COALESCE($3,venue),city=COALESCE($4,city),country=COALESCE($5,country),event_date=COALESCE($6,event_date),image_url=COALESCE($7,image_url),is_active=COALESCE($8,is_active),updated_at=now() WHERE id=$9 RETURNING *', [title, description, venue, city, country, event_date, image_url, is_active, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'الحفلة غير موجودة' });
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)', [req.admin.id, 'event.update', JSON.stringify({ event_id: req.params.id })]); res.json({ event: rows[0] });
}));
app.delete('/api/admin/events/:id', requireAdmin, asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('UPDATE events SET is_active=false,updated_at=now() WHERE id=$1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'الحفلة غير موجودة' });
  await pool.query('UPDATE ticket_types SET is_active=false WHERE event_id=$1', [req.params.id]);
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)', [req.admin.id, 'event.archive', JSON.stringify({ event_id: req.params.id })]); res.json({ ok: true });
}));

app.get('/api/admin/settings', requireAdmin, asyncRoute(async (_req, res) => {
  const settings = await getIntegrationSettings();
  res.json({ paypal: { configured: Boolean(settings.paypalClientId && settings.paypalClientSecret), enabled: settings.paypalEnabled, walletButtonEnabled: settings.paypalWalletButtonEnabled, payLaterButtonEnabled: settings.paypalPayLaterButtonEnabled, cardButtonEnabled: settings.paypalCardButtonEnabled, mode: settings.paypalEnv, cardButtonText: settings.paypalCardButtonText || 'Visa', clientIdHint: settings.paypalClientId ? `••••${settings.paypalClientId.slice(-4)}` : '', logo: settings.paypalLogo, applePayDomainConfigured: Boolean(settings.paypalApplePayDomainFile) }, paymegate: { configured: Boolean(settings.paymegateApiKey && settings.paymegateWebhookSecret), enabled: settings.paymegateEnabled, logo: settings.paymegateLogo }, heleket: { configured: Boolean(settings.heleketMerchantId && settings.heleketPaymentApiKey), enabled: settings.heleketEnabled, merchantId: settings.heleketMerchantId, logo: settings.heleketLogo }, email: { configured: hasEmailTransport(settings), provider: settings.emailProvider, apiConfigured: Boolean(settings.brevoApiKey), smtp2goConfigured: Boolean(settings.smtp2goApiKey), resendConfigured: Boolean(settings.resendApiKey), smtpConfigured: Boolean(settings.smtpHost && settings.mailFrom), smtpSupported: true, host: settings.smtpHost, port: settings.smtpPort, providerName: settings.smtpProviderName, tlsMode: settings.smtpTlsMode, secure: settings.smtpSecure, user: settings.smtpUser, from: settings.mailFrom, templates: settings.emailTemplates }, supportEmail: settings.supportEmail, seo: publicSeoSettings(settings.seo) });
}));
app.post('/api/admin/cache/clear',requireAdmin,asyncRoute(async(req,res)=>{
  const cleared=usdRateCache.size;usdRateCache.clear();
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'cache.clear',JSON.stringify({scope:'worker-runtime-exchange-rates',entries:cleared})]);
  res.json({ok:true,cleared,scope:'worker-runtime-exchange-rates'});
}));
app.post('/api/admin/data/transactions/clear',requireAdmin,asyncRoute(async(req,res)=>{
  if(req.body?.confirmation!=='DELETE ALL TRANSACTIONS')return res.status(400).json({error:'اكتب عبارة التأكيد المطلوبة قبل حذف سجل المعاملات.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const payments=await client.query('SELECT count(*)::int count FROM payments');
    const orders=await client.query('SELECT count(*)::int count FROM orders');
    await client.query('DELETE FROM ticket_deliveries');
    await client.query('DELETE FROM tickets');
    await client.query('DELETE FROM order_items');
    await client.query('DELETE FROM payments');
    await client.query('DELETE FROM payment_webhook_events');
    await client.query('DELETE FROM orders');
    await client.query('UPDATE ticket_types SET quantity_sold=0,quantity_reserved=0');
    await client.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'transactions.clear',JSON.stringify({orders:orders.rows[0].count,payments:payments.rows[0].count})]);
    await client.query('COMMIT');
    res.json({ok:true,orders:orders.rows[0].count,payments:payments.rows[0].count});
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}));
app.put('/api/admin/settings', requireAdmin, asyncRoute(async (req, res) => {
  const current = await getIntegrationSettings(); const body = req.body || {};
  const next = { ...current };
  if (body.seo && typeof body.seo === 'object' && !Array.isArray(body.seo)) {
    const value = body.seo;
    const siteName = String(value.siteName ?? current.seo.siteName).trim().slice(0, 100);
    const title = String(value.title ?? current.seo.title).trim().slice(0, 180);
    const description = String(value.description ?? current.seo.description).trim().slice(0, 320);
    let siteUrl;
    try { const parsed = new URL(String(value.siteUrl ?? current.seo.siteUrl).trim()); if (parsed.protocol !== 'https:' || parsed.username || parsed.password || !['', '/'].includes(parsed.pathname) || parsed.search || parsed.hash) throw new Error(); siteUrl = parsed.origin; }
    catch { return res.status(400).json({ error: '???? ????? ?????? ??????? ????? HTTPS ?????? ??? https://www.ticketarab.com' }); }
    const assetUrl = (input, field) => {
      const raw = String(input ?? current.seo[field] ?? '').trim(); if (!raw) return '';
      try { const parsed = new URL(raw, `${siteUrl}/`); if (parsed.protocol !== 'https:') throw new Error(); if (raw.startsWith('/') && !raw.startsWith('//')) return `${parsed.pathname}${parsed.search}${parsed.hash}`; return parsed.href; }
      catch { throw new Error(`??? ?? ???? ???? ${field === 'socialImage' ? '?????? ?????????' : '????????'} ???? HTTPS ??????.`); }
    };
    try {
      next.seo = { siteName, title, description, siteUrl, socialImage: assetUrl(value.socialImage, 'socialImage'),
        faviconUrl: assetUrl(value.faviconUrl, 'faviconUrl'), appleIconUrl: assetUrl(value.appleIconUrl, 'appleIconUrl'),
        keywords: String(value.keywords ?? current.seo.keywords).trim().slice(0, 500),
        twitterHandle: String(value.twitterHandle ?? current.seo.twitterHandle).trim().replace(/^@/, '').slice(0, 30),
        allowIndex: value.allowIndex === undefined ? current.seo.allowIndex : Boolean(value.allowIndex) };
    } catch (error) { return res.status(400).json({ error: error.message }); }
    if (!siteName || !title || !description) return res.status(400).json({ error: '??? ?????? ???????? ?????? ???? ??????.' });
  }
  for (const key of ['paypalClientId','paypalClientSecret','paypalApplePayDomainFile','paymegateApiKey','paymegateWebhookSecret','lemonSqueezyApiKey','lemonSqueezyStoreId','lemonSqueezyVariantId','lemonSqueezyWebhookSecret','heleketMerchantId','heleketPaymentApiKey','smtpHost','smtpUser','smtpPassword','mailFrom','supportEmail','brevoApiKey','smtp2goApiKey','resendApiKey']) if (typeof body[key] === 'string' && body[key].trim()) next[key] = body[key].trim();
  for (const key of ['paypalLogo','paymegateLogo','lemonSqueezyLogo','heleketLogo']) if (typeof body[key] === 'string') {
    if (body[key] && (!/^data:image\/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(body[key]) || body[key].length > 220000)) return res.status(400).json({ error: 'ارفع شعارًا بصيغة PNG أو JPG أو WEBP أو SVG وحجم أقل من 160 كيلوبايت.' });
    next[key] = body[key];
  }
  if (body.paypalApplePayDomainFile && body.paypalApplePayDomainFile.length > 100000) return res.status(400).json({ error: 'Apple Pay domain association file is too large.' });
  if (body.clearPaypal === true) { next.paypalClientId = ''; next.paypalClientSecret = ''; }
  if (body.clearApplePayDomainFile === true) next.paypalApplePayDomainFile = '';
  if (body.clearEmail === true) { next.smtpHost = ''; next.smtpProviderName = ''; next.smtpTlsMode = 'auto'; next.smtpUser = ''; next.smtpPassword = ''; next.brevoApiKey = ''; next.smtp2goApiKey = ''; next.resendApiKey = ''; next.mailFrom = ''; }
  if (['sandbox','live'].includes(body.paypalEnv)) next.paypalEnv = body.paypalEnv;
  if (typeof body.paypalCardButtonText === 'string') { const label = body.paypalCardButtonText.trim().slice(0, 32); next.paypalCardButtonText = label || 'Visa'; }
  for (const key of ['paypalEnabled','paymegateEnabled','lemonSqueezyEnabled','heleketEnabled']) if (typeof body[key] === 'boolean') next[key] = body[key];
  for (const key of ['paypalWalletButtonEnabled','paypalPayLaterButtonEnabled','paypalCardButtonEnabled']) if (typeof body[key] === 'boolean') next[key] = body[key];
  if (body.clearPaymegate === true) { next.paymegateApiKey = ''; next.paymegateWebhookSecret = ''; }
  if (body.clearHeleket === true) { next.heleketMerchantId = ''; next.heleketPaymentApiKey = ''; next.heleketEnabled = false; }
  if (body.clearLemonSqueezy === true) { next.lemonSqueezyApiKey = ''; next.lemonSqueezyStoreId = ''; next.lemonSqueezyVariantId = ''; next.lemonSqueezyWebhookSecret = ''; next.lemonSqueezyEnabled = false; }
  if (next.heleketEnabled && (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(next.heleketMerchantId) || !next.heleketPaymentApiKey || !process.env.FRONTEND_ORIGIN?.startsWith('https://'))) return res.status(400).json({ error: 'Enter the Heleket merchant UUID and payment API key, and set FRONTEND_ORIGIN to a public HTTPS URL before enabling Heleket.' });
  if (next.lemonSqueezyEnabled && (!next.lemonSqueezyApiKey || !/^\d+$/.test(next.lemonSqueezyStoreId) || !/^\d+$/.test(next.lemonSqueezyVariantId) || !next.lemonSqueezyWebhookSecret || !process.env.FRONTEND_ORIGIN?.startsWith('https://'))) return res.status(400).json({ error: 'أكمل مفتاح API ومعرّف المتجر والنسخة وسر Webhook، واضبط FRONTEND_ORIGIN على عنوان HTTPS قبل تفعيل Lemon Squeezy.' });
  if (typeof body.smtpProviderName === 'string') next.smtpProviderName = body.smtpProviderName.trim().slice(0, 80);
  if (Number(body.smtpPort) === 25) return res.status(400).json({ error: 'Cloudflare يحظر SMTP على المنفذ 25. استخدم المنفذ 587 أو 465.' });
  if (Number.isInteger(Number(body.smtpPort)) && Number(body.smtpPort) >= 1 && Number(body.smtpPort) <= 65535) next.smtpPort = String(Number(body.smtpPort));
  if (typeof body.smtpSecure === 'boolean') next.smtpSecure = body.smtpSecure;
  if (['auto','starttls','tls'].includes(body.smtpTlsMode)) next.smtpTlsMode = body.smtpTlsMode;
  if (['brevo','smtp2go','resend','smtp'].includes(body.emailProvider)) next.emailProvider = body.emailProvider;
  if (body.emailProvider && body.emailProvider !== current.emailProvider && !hasEmailTransport(next)) {
    return res.status(400).json({ error: 'لا يمكن تبديل مزود البريد قبل اكتمال إعداداته. أدخل مفتاح API أو بيانات SMTP وبريد المرسل أولًا.' });
  }
  if (body.emailTemplates && typeof body.emailTemplates === 'object') {
    const templates = {};
    for (const key of ['test','invoice','ticket']) {
      const item = body.emailTemplates[key]; if (!item) continue;
      const subject = String(item.subject || '').trim(); const html = String(item.html || '');
      if (!subject || subject.length > 240 || !html.trim() || html.length > 50000) return res.status(400).json({ error: 'تحقق من عنوان القالب ومحتواه؛ حد HTML هو 50 ألف حرف.' });
      templates[key] = { subject, html };
    }
    next.emailTemplates = { ...defaultEmailTemplates, ...templates };
  }
  if (next.paypalClientId && next.paypalClientSecret && (body.paypalClientId || body.paypalClientSecret || (body.paypalEnv && body.paypalEnv !== current.paypalEnv))) await paypalToken(next);
  // Save credentials independently from network verification. SMTP socket/TLS
  // verification is unreliable inside Workers and used to reject valid settings.
  await pool.query(`INSERT INTO admin_settings(settings_key,encrypted_value,updated_by) VALUES('integrations',$1,$2)
    ON CONFLICT(settings_key) DO UPDATE SET encrypted_value=EXCLUDED.encrypted_value,updated_by=EXCLUDED.updated_by,updated_at=now()`, [encryptSettings(next), req.admin.id]);
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)', [req.admin.id, 'settings.update', JSON.stringify({ paypal: Boolean(next.paypalClientId), paymegate: Boolean(next.paymegateApiKey), email: Boolean(next.smtpHost) })]);
  res.json({ ok: true });
}));
app.post('/api/admin/email/test',requireAdmin,asyncRoute(async(req,res)=>{
  const to=String(req.body.to||'').trim();if(!/^\S+@\S+\.\S+$/.test(to))return res.status(400).json({error:'اكتب بريدًا إلكترونيًا صحيحًا لاستقبال رسالة الاختبار.'});
  const settings=await getIntegrationSettings();if(!hasEmailTransport(settings))return res.status(503).json({error:emailRuntimeError(settings)});
  const template=settings.emailTemplates.test;const html=renderEmailTemplate(template.html,{});let info;try{info=await sendEmail(settings,{from:settings.mailFrom,to,subject:renderEmailTemplate(template.subject,{}),text:emailTextFromHtml(html),html});}catch(err){
    const detail=String(err.message||'');const code=String(err.code||'').slice(0,40);console.error('Email test message failed:',code||'send_error',detail.slice(0,240));
    await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'email.test.failed',JSON.stringify({to,provider:settings.emailProvider,code})]).catch(()=>{});
    if(/timeout|ETIMEDOUT|ECONNECTION|ESOCKET|TLS|certificate/i.test(`${code} ${detail}`))return res.status(502).json({error:'انتهت مهلة الاتصال بخادم البريد أو تعذر إنشاء TLS. راجع عنوان الخادم والمنفذ وبيانات الاعتماد؛ استخدم 587 مع STARTTLS أو 465 مع TLS مباشر.'});
    const providerName = ({ brevo: 'Brevo API', smtp2go: 'SMTP2GO API', resend: 'Resend API', smtp: 'Custom SMTP' })[settings.emailProvider] || 'Email';
    return res.status(502).json({error:`${providerName} send failed: ${detail.slice(0,200)}`});
  }
  const accepted=Array.isArray(info.accepted)&&info.accepted.some(address=>String(address).toLowerCase()===to.toLowerCase());
  const provider=info.provider||'Custom SMTP';const queued=info.queued===true;
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'email.test',JSON.stringify({to,accepted,provider,queued,response:String(info.response||info.messageId||'').slice(0,300)})]);
  res.json({ok:true,accepted,queued,provider,response:String(info.response||info.messageId||'').slice(0,300)});
}));

const supportAttempts = new Map();
app.post('/api/support', asyncRoute(async (req, res) => {
  const detail = requestDetails(req); const now = Date.now(); const state = supportAttempts.get(detail.ip) || { count: 0, until: now + 60 * 60 * 1000 };
  if (state.until < now) { state.count = 0; state.until = now + 60 * 60 * 1000; }
  if (state.count >= 5) return res.status(429).json({ error: 'وصلنا لعدد الرسائل المسموح به مؤقتًا. حاول لاحقًا.' });
  state.count++; supportAttempts.set(detail.ip, state);
  const { sender_name, sender_email, subject, message, order_number } = req.body || {};
  if (!String(sender_name || '').trim() || !/^\S+@\S+\.\S+$/.test(String(sender_email || '')) || !String(subject || '').trim() || String(message || '').trim().length < 10 || String(message).length > 5000) return res.status(400).json({ error: 'أكمل الاسم والبريد والموضوع، واكتب رسالة من 10 إلى 5000 حرف.' });
  const { rows } = await pool.query('INSERT INTO support_messages(order_number,sender_name,sender_email,subject,message) VALUES($1,$2,$3,$4,$5) RETURNING id,created_at', [String(order_number || '').slice(0,80) || null, String(sender_name).trim().slice(0,160), String(sender_email).trim().slice(0,320), String(subject).trim().slice(0,180), String(message).trim()]);
  const settings = await getIntegrationSettings();
  if (hasEmailTransport(settings) && settings.supportEmail) sendEmail(settings,{ from: settings.mailFrom, to: settings.supportEmail, replyTo: { address: String(sender_email).trim(), name: String(sender_name).trim().slice(0,160) }, subject: `رسالة دعم جديدة: ${String(subject).replace(/[\r\n]/g,' ').trim().slice(0,180)}`, text: `من: ${sender_name} <${sender_email}>\nرقم الطلب: ${order_number || 'غير مذكور'}\n\n${String(message).trim()}` }).catch(err => console.error('Support notification failed:', err.message));
  res.status(201).json({ success: true, reference: rows[0].id });
}));
app.get('/api/admin/support', requireAdmin, asyncRoute(async (req, res) => {
  await ensureFeatureSchema();
  const status = ['open','replied','closed','archived'].includes(req.query.status) ? req.query.status : null;
  const page=Math.max(1,Number.parseInt(req.query.page,10)||1);const pageSize=25;
  const filter = `($1::text IS NULL AND archived_at IS NULL) OR ($1='archived' AND archived_at IS NOT NULL) OR ($1 IN ('open','replied','closed') AND status=$1 AND archived_at IS NULL)`;
  const [count,result,unread]=await Promise.all([
    pool.query(`SELECT count(*)::int total FROM support_messages WHERE ${filter}`,[status]),
    pool.query(`SELECT id,order_number,sender_name,sender_email,subject,message,status,admin_reply,replied_at,viewed_at,archived_at,created_at FROM support_messages WHERE ${filter} ORDER BY created_at DESC LIMIT $2 OFFSET $3`,[status,pageSize,(page-1)*pageSize]),
    pool.query('SELECT count(*)::int unread FROM support_messages WHERE viewed_at IS NULL AND archived_at IS NULL')
  ]);
  res.json({ messages: result.rows,total:count.rows[0].total,unread:unread.rows[0].unread,page,page_size:pageSize });
}));
app.post('/api/admin/support/:id/view', requireAdmin, asyncRoute(async (req,res)=>{await ensureFeatureSchema();const {rows}=await pool.query('UPDATE support_messages SET viewed_at=COALESCE(viewed_at,now()) WHERE id=$1 RETURNING id,viewed_at',[req.params.id]);if(!rows[0])return res.status(404).json({error:'رسالة الدعم غير موجودة'});res.json({ok:true,viewed_at:rows[0].viewed_at});}));
app.post('/api/admin/support/:id/reply', requireAdmin, asyncRoute(async (req, res) => {
  await ensureFeatureSchema();
  const reply = String(req.body.reply || '').trim(); if (!reply || reply.length > 5000) return res.status(400).json({ error: 'اكتب ردًا من 1 إلى 5000 حرف.' });
  const { rows } = await pool.query("UPDATE support_messages SET admin_reply=$1,status='replied',replied_at=now() WHERE id=$2 AND archived_at IS NULL RETURNING *", [reply, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'رسالة الدعم غير موجودة' });
  const settings = await getIntegrationSettings(); let emailSent = false;
  if (hasEmailTransport(settings)) {
    try { await sendEmail(settings,{ from: settings.mailFrom, to: rows[0].sender_email, subject: `رد الدعم: ${rows[0].subject.replace(/[\r\n]/g,' ')}`, text: reply }); emailSent = true; }
    catch (err) { console.error('Support reply email failed:', err.message); }
  }
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)', [req.admin.id, 'support.reply', JSON.stringify({ message_id: rows[0].id, email_sent: emailSent })]);
  res.json({ success: true, email_sent: emailSent });
}));
app.post('/api/admin/support/:id/close', requireAdmin, asyncRoute(async (req,res)=>{const {rowCount}=await pool.query("UPDATE support_messages SET status='closed' WHERE id=$1 AND archived_at IS NULL",[req.params.id]);if(!rowCount)return res.status(404).json({error:'رسالة الدعم غير موجودة أو مؤرشفة'});await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'support.close',JSON.stringify({message_id:req.params.id})]);res.json({ok:true});}));
app.post('/api/admin/support/:id/archive', requireAdmin, asyncRoute(async (req,res)=>{await ensureFeatureSchema();const {rowCount}=await pool.query('UPDATE support_messages SET archived_at=COALESCE(archived_at,now()),viewed_at=COALESCE(viewed_at,now()) WHERE id=$1',[req.params.id]);if(!rowCount)return res.status(404).json({error:'رسالة الدعم غير موجودة'});await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'support.archive',JSON.stringify({message_id:req.params.id})]);res.json({ok:true});}));
app.post('/api/admin/support/:id/restore', requireAdmin, asyncRoute(async (req,res)=>{const {rowCount}=await pool.query('UPDATE support_messages SET archived_at=NULL WHERE id=$1 AND archived_at IS NOT NULL',[req.params.id]);if(!rowCount)return res.status(404).json({error:'الرسالة المؤرشفة غير موجودة'});await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'support.restore',JSON.stringify({message_id:req.params.id})]);res.json({ok:true});}));
app.delete('/api/admin/support/:id', requireAdmin, asyncRoute(async (req,res)=>{const client=await pool.connect();try{await client.query('BEGIN');const found=(await client.query('SELECT id FROM support_messages WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];if(!found){await client.query('ROLLBACK');return res.status(404).json({error:'رسالة الدعم غير موجودة'});}await client.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'support.delete',JSON.stringify({message_id:req.params.id})]);await client.query('DELETE FROM support_messages WHERE id=$1',[req.params.id]);await client.query('COMMIT');res.json({ok:true});}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}));
app.get('/api/admin/payments', requireAdmin, asyncRoute(async (req, res) => {
  const status = ['created','creating','completed','failed'].includes(req.query.status) ? req.query.status : null;
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1); const pageSize = 10;
  const [count, result] = await Promise.all([
    pool.query("SELECT count(*)::int total FROM payments p WHERE $1::text IS NULL OR ($1='created' AND p.status IN ('created','creating')) OR p.status=$1", [status]),
    pool.query(`SELECT p.id,p.id transaction_id,p.order_id,o.order_number,o.buyer_name,o.buyer_email,o.buyer_phone,p.provider,p.provider_order_id,p.provider_capture_id,p.status,p.amount,p.currency,p.display_amount,p.display_currency,p.exchange_rate,p.exchange_rate_date,p.client_ip,p.country_code,p.country_name,p.region,p.city,p.user_agent,p.referrer_origin,p.device_type,p.failure_reason,p.created_at,p.updated_at,o.ticket_delivery_status,
      (SELECT COALESCE(json_agg(json_build_object('event',e.title,'ticket_type',tt.name,'quantity',oi.quantity,'line_total',oi.total_price)),'[]'::json) FROM order_items oi JOIN ticket_types tt ON tt.id=oi.ticket_type_id JOIN events e ON e.id=tt.event_id WHERE oi.order_id=o.id) items
      FROM payments p JOIN orders o ON o.id=p.order_id WHERE $1::text IS NULL OR ($1='created' AND p.status IN ('created','creating')) OR p.status=$1 ORDER BY p.created_at DESC LIMIT $2 OFFSET $3`, [status,pageSize,(page-1)*pageSize])
  ]);
  res.json({ payments: result.rows, total: count.rows[0].total, page, page_size: pageSize });
}));
app.delete('/api/admin/payments/:id',requireAdmin,asyncRoute(async(req,res)=>{const client=await pool.connect();try{await client.query('BEGIN');const payment=(await client.query("SELECT p.id,p.order_id,p.status,p.created_at,o.status order_status,o.expires_at FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.id=$1 FOR UPDATE OF p,o",[req.params.id])).rows[0];if(!payment){await client.query('ROLLBACK');return res.status(404).json({error:'المعاملة غير موجودة'});}if(!['failed','created','creating'].includes(payment.status)||payment.order_status==='paid'){await client.query('ROLLBACK');return res.status(409).json({error:'لا يمكن حذف معاملة ناجحة أو غير مؤهلة للحذف'});}if(Date.now()-new Date(payment.created_at).getTime()<12*60*60*1000){await client.query('ROLLBACK');return res.status(409).json({error:'يمكن حذف المعاملات الفاشلة أو المعلقة بعد مرور 12 ساعة فقط'});}await client.query("UPDATE ticket_types t SET quantity_reserved=GREATEST(0,t.quantity_reserved-x.quantity) FROM (SELECT ticket_type_id,sum(quantity)::int quantity FROM order_items WHERE order_id=$1 GROUP BY ticket_type_id) x WHERE t.id=x.ticket_type_id AND EXISTS(SELECT 1 FROM orders WHERE id=$1 AND status='pending' AND expires_at>now())",[payment.order_id]);await client.query('DELETE FROM payments WHERE id=$1',[payment.id]);await client.query("UPDATE orders SET status='cancelled',updated_at=now() WHERE id=$1 AND status<>'paid'",[payment.order_id]);await client.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'payment.delete',JSON.stringify({payment_id:payment.id,order_id:payment.order_id})]);await client.query('COMMIT');res.json({ok:true});}catch(error){await client.query('ROLLBACK');throw error;}finally{await client.release();}}));
app.get('/api/admin/orders', requireAdmin, asyncRoute(async(req,res)=>{
  const status=['paid','pending','cancelled','refunded'].includes(req.query.status)?req.query.status:'paid';const delivery=['waiting','sent','failed'].includes(req.query.delivery_status)?req.query.delivery_status:null;const page=Math.max(1,Number.parseInt(req.query.page,10)||1);const pageSize=50;
  const args=[status,delivery];const where='o.status=$1 AND ($2::text IS NULL OR o.ticket_delivery_status=$2)';
  const [count,result]=await Promise.all([pool.query(`SELECT count(*)::int total FROM orders o WHERE ${where}`,args),pool.query(`SELECT o.id,o.order_number,o.buyer_name,o.buyer_email,o.total_amount,o.currency,o.status,o.ticket_delivery_status,o.invoice_sent_at,o.created_at,(SELECT count(*)::int FROM order_items oi WHERE oi.order_id=o.id) item_count FROM orders o WHERE ${where} ORDER BY o.created_at DESC LIMIT $3 OFFSET $4`,[...args,pageSize,(page-1)*pageSize])]);
  res.json({orders:result.rows,total:count.rows[0].total,page,page_size:pageSize});
}));

async function paypalToken(settings) {
  settings ||= await getIntegrationSettings();
  const base = settings.paypalEnv === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const auth = Buffer.from(`${settings.paypalClientId}:${settings.paypalClientSecret}`).toString('base64');
  const response = await fetch(`${base}/v1/oauth2/token`, { method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=client_credentials' });
  const data = await response.json(); if (!response.ok) throw new Error('PayPal authentication failed'); return { token: data.access_token, base };
}
function drawInvoiceText(doc, value, x, y, options = {}) {
  const { size = 10, color = '#263445', maxWidth = 490, align = 'left' } = options;
  const raw = String(value ?? '').normalize('NFC').replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  const hasArabic = /\p{Script=Arabic}/u.test(raw);
  doc.font('Invoice').fontSize(size).fillColor(color);
  const shaped = hasArabic ? shapeArabicBidi(raw, { direction: 'rtl' }) : raw;
  const font = doc._font.font;
  const originalLayout = font.layout;
  if (hasArabic) {
    // bidi-shaper already converted Arabic to presentation forms and visual
    // order. Fontkit otherwise detects Arabic and reverses the glyph run again.
    // Force LTR layout and disable Arabic substitutions for these pre-shaped glyphs.
    font.layout = function (text, features, script, language) {
      return originalLayout.call(this, text, features, script, language, 'ltr');
    };
  }
  try {
    const features = hasArabic ? { ...INVOICE_ARABIC_FEATURES } : [];
    const width = Math.max(1, Math.min(maxWidth, doc.widthOfString(shaped, { features })));
    const boxWidth = Math.max(width, Math.min(maxWidth, options.boxWidth || maxWidth));
    const drawX = align === 'center' ? x - boxWidth / 2 : align === 'right' ? x - boxWidth : x;
    doc.text(shaped, drawX, y, {
      width: boxWidth,
      align,
      lineBreak: false,
      features
    });
  } finally {
    if (hasArabic) font.layout = originalLayout;
  }
  return y + size * 1.8;
}
async function createInvoicePdf(order, items) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 0, compress: true, font: null, info: { Title: 'Ticket Arab - Payment Receipt', Author: 'Ticket Arab', Subject: 'Payment confirmation' } });
    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('error', reject);
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.registerFont('Invoice', invoiceFont);

    const pageWidth = 595.28;
    const left = 52;
    const right = 543;
    const muted = '#687789';
    const ink = '#17283a';
    const gold = '#bd984d';
    const arabic = {
      receipt: '\u0625\u064a\u0635\u0627\u0644 \u062f\u0641\u0639',
      confirmation: '\u062a\u0623\u0643\u064a\u062f \u0639\u0645\u0644\u064a\u0629 \u0627\u0644\u0634\u0631\u0627\u0621',
      continued: '\u0625\u064a\u0635\u0627\u0644 \u062f\u0641\u0639 \u2014 \u062a\u0627\u0628\u0639',
      verified: '\u0646\u0633\u062e\u0629 \u0645\u0648\u062b\u0642\u0629',
      paid: '\u062a\u0645 \u0627\u0644\u062f\u0641\u0639 \u0628\u0646\u062c\u0627\u062d',
      transaction: '\u0631\u0642\u0645 \u0627\u0644\u0645\u0639\u0627\u0645\u0644\u0629',
      date: '\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u062f\u0641\u0639 (UTC)',
      customer: '\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u0634\u062a\u0631\u064a',
      name: '\u0627\u0644\u0627\u0633\u0645',
      email: '\u0627\u0644\u0628\u0631\u064a\u062f \u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a',
      phone: '\u0627\u0644\u0647\u0627\u062a\u0641',
      tickets: '\u062a\u0641\u0627\u0635\u064a\u0644 \u0627\u0644\u062a\u0630\u0627\u0643\u0631',
      ticketType: '\u0627\u0644\u062d\u0641\u0644\u0629 / \u0641\u0626\u0629 \u0627\u0644\u062a\u0630\u0643\u0631\u0629',
      quantity: '\u0627\u0644\u0639\u062f\u062f',
      amount: '\u0627\u0644\u0645\u0628\u0644\u063a',
      orderTotal: '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u0637\u0644\u0628',
      charged: '\u0627\u0644\u0645\u0628\u0644\u063a \u0627\u0644\u0645\u062e\u0635\u0648\u0645',
      exchange: '\u0633\u0639\u0631 \u0627\u0644\u0635\u0631\u0641',
      reference: '\u0645\u0631\u062c\u0639 \u0627\u0644\u062f\u0641\u0639',
      notice: '\u062a\u0646\u0648\u064a\u0647 \u0647\u0627\u0645',
      nonRefundable: '\u0628\u0639\u062f \u0625\u062a\u0645\u0627\u0645 \u0627\u0644\u0634\u0631\u0627\u0621 \u0628\u0646\u062c\u0627\u062d\u060c \u0627\u0644\u062a\u0630\u0627\u0643\u0631 \u063a\u064a\u0631 \u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u0627\u0633\u062a\u0631\u062f\u0627\u062f \u0623\u0648 \u0627\u0644\u0625\u0644\u063a\u0627\u0621.',
      footer: '\u0623\u064f\u0635\u062f\u0631 \u0647\u0630\u0627 \u0627\u0644\u0625\u064a\u0635\u0627\u0644 \u0628\u0639\u062f \u0646\u062c\u0627\u062d \u0627\u0644\u062f\u0641\u0639. \u062a\u0635\u0644 \u0627\u0644\u062a\u0630\u0643\u0631\u0629 \u0625\u0644\u0649 \u0628\u0631\u064a\u062f\u0643 \u0628\u0639\u062f \u062a\u062c\u0647\u064a\u0632\u0647\u0627.'
    };
    const money = (amount, currency) => `${String(currency || 'USD').toUpperCase()} ${Number(amount || 0).toFixed(2)}`;
    let pageNumber = 1;
    const seal = () => {
      doc.save();
      doc.fillOpacity(0.055).strokeOpacity(0.14);
      doc.circle(pageWidth / 2, 452, 77).lineWidth(2).stroke(gold);
      doc.circle(pageWidth / 2, 452, 68).lineWidth(0.8).stroke(gold);
      drawInvoiceText(doc, 'TICKET ARAB', pageWidth / 2, 426, { size: 14, color: gold, align: 'center', boxWidth: 180 });
      drawInvoiceText(doc, arabic.verified, pageWidth / 2, 450, { size: 13, color: gold, align: 'center', boxWidth: 180 });
      drawInvoiceText(doc, 'ticketarab.com', pageWidth / 2, 474, { size: 8, color: gold, align: 'center', boxWidth: 180 });
      doc.restore();
    };
    const brand = (continued = false) => {
      doc.rect(0, 0, pageWidth, 112).fill('#102033');
      seal();
      drawInvoiceText(doc, 'TICKET ARAB', left, 27, { size: 22, color: '#ffffff' });
      drawInvoiceText(doc, continued ? arabic.continued : arabic.receipt, right, 31, { size: 18, color: '#ffffff', align: 'right' });
      drawInvoiceText(doc, arabic.confirmation, right, 66, { size: 9, color: '#e2c47e', align: 'right' });
      doc.moveTo(left, 129).lineTo(right, 129).lineWidth(1).stroke('#e1e6eb');
    };
    const footer = () => {
      doc.moveTo(left, 796).lineTo(right, 796).lineWidth(1).stroke('#e1e6eb');
      drawInvoiceText(doc, arabic.footer, right, 808, { size: 8, color: muted, align: 'right', maxWidth: 390 });
      drawInvoiceText(doc, `ticketarab.com  |  ${pageNumber}`, left, 808, { size: 8, color: muted });
    };
    const newPage = () => {
      footer();
      doc.addPage({ size: 'A4', margin: 0 });
      pageNumber += 1;
      brand(true);
    };
    const labelValue = (label, value, y, opts = {}) => {
      drawInvoiceText(doc, label, right, y, { size: 8, color: muted, align: 'right', maxWidth: 175 });
      drawInvoiceText(doc, value, left, y, { size: opts.size || 10, color: opts.color || ink, maxWidth: 330 });
    };
    const sectionTitle = (label, y) => {
      drawInvoiceText(doc, label, right, y, { size: 11, color: gold, align: 'right' });
    };

    brand();
    let y = 151;
    doc.roundedRect(right - 160, y - 4, 160, 27, 7).fill('#e9f5ee');
    drawInvoiceText(doc, arabic.paid, right - 80, y + 3, { size: 10, color: '#19734a', align: 'center', boxWidth: 160 });
    y += 33;
    labelValue(arabic.transaction, order.order_number || '?', y, { size: 9 }); y += 25;
    const paidAt = order.updated_at ? new Date(order.updated_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '?';
    labelValue(arabic.date, paidAt, y, { size: 8 }); y += 26;
    doc.moveTo(left, y).lineTo(right, y).lineWidth(1).stroke('#e1e6eb'); y += 17;

    sectionTitle(arabic.customer, y); y += 21;
    labelValue(arabic.name, order.buyer_name || '?', y); y += 21;
    labelValue(arabic.email, order.buyer_email || '?', y, { size: 9 }); y += 21;
    if (order.buyer_phone) { labelValue(arabic.phone, order.buyer_phone, y, { size: 9 }); y += 21; }
    doc.moveTo(left, y).lineTo(right, y).lineWidth(1).stroke('#e1e6eb'); y += 17;

    sectionTitle(arabic.tickets, y); y += 22;
    drawInvoiceText(doc, arabic.ticketType, right, y, { size: 8, color: muted, align: 'right', maxWidth: 260 });
    drawInvoiceText(doc, arabic.quantity, 424, y, { size: 8, color: muted, align: 'center', boxWidth: 44 });
    drawInvoiceText(doc, arabic.amount, left, y, { size: 8, color: muted }); y += 17;
    for (const item of items) {
      if (y > 590) { newPage(); y = 153; sectionTitle(arabic.tickets, y); y += 22; }
      drawInvoiceText(doc, `${item.event_title || 'Event'}  /  ${item.ticket_name || 'Ticket'}`, right, y, { size: 9, maxWidth: 275, align: 'right' });
      drawInvoiceText(doc, String(item.quantity), 424, y, { size: 9, align: 'center', boxWidth: 44 });
      drawInvoiceText(doc, money(item.total_price, order.display_currency || order.currency), left, y, { size: 9 });
      y += 20;
    }
    if (y > 635) { newPage(); y = 153; }
    y += 5;
    doc.moveTo(left, y).lineTo(right, y).lineWidth(1).stroke('#e1e6eb'); y += 16;
    labelValue(arabic.orderTotal, money(order.display_amount ?? order.total_amount, order.display_currency || order.currency), y, { size: 10, color: ink }); y += 22;
    labelValue(arabic.charged, money(order.charged_amount ?? order.total_amount, order.charged_currency || order.currency), y, { size: 12, color: '#19734a' }); y += 21;
    if (order.exchange_rate) {
      labelValue(arabic.exchange, `1 ${order.display_currency} = ${order.exchange_rate} ${order.charged_currency || 'USD'}`, y, { size: 8 }); y += 19;
    }
    if (order.provider_capture_id) {
      labelValue(arabic.reference, order.provider_capture_id, y, { size: 8 }); y += 19;
    }
    if (y > 705) { newPage(); y = 153; }
    y += 4;
    doc.roundedRect(left, y, right - left, 64, 7).fillAndStroke('#fff8e9', '#e5cf9c');
    doc.roundedRect(right - 6, y, 6, 64, 3).fill('#bd984d');
    drawInvoiceText(doc, arabic.notice, right - 18, y + 10, { size: 10, color: '#785b25', align: 'right' });
    drawInvoiceText(doc, arabic.nonRefundable, right - 18, y + 32, { size: 9, color: '#473c28', align: 'right', maxWidth: right - left - 36 });
    footer();
    doc.end();
  });
}
async function loadInvoiceData(orderId) {
  const order=(await pool.query(`SELECT o.*,p.provider,p.provider_capture_id,p.amount charged_amount,p.currency charged_currency,p.display_amount,p.display_currency,p.exchange_rate,p.exchange_rate_date FROM orders o LEFT JOIN payments p ON p.order_id=o.id AND p.status='completed' WHERE o.id=$1 AND o.status='paid' ORDER BY p.updated_at DESC LIMIT 1`,[orderId])).rows[0];if(!order)throw new Error('Paid order not found');
  const items=(await pool.query(`SELECT e.title event_title,t.name ticket_name,oi.quantity,oi.total_price FROM order_items oi JOIN ticket_types t ON t.id=oi.ticket_type_id JOIN events e ON e.id=t.event_id WHERE oi.order_id=$1 ORDER BY e.title,t.name`,[orderId])).rows;return {order,items};
}
async function getOrCreateInvoicePdf(orderId) {
  await ensureFeatureSchema();
  const existing = (await pool.query("SELECT invoice_pdf,invoice_pdf_sha256,invoice_pdf_version FROM orders WHERE id=$1 AND status='paid'", [orderId])).rows[0];
  if (!existing) throw new Error('Paid order not found');
  if (existing.invoice_pdf && Number(existing.invoice_pdf_version) === INVOICE_PDF_VERSION) return { pdf: Buffer.from(existing.invoice_pdf), sha256: existing.invoice_pdf_sha256 || crypto.createHash('sha256').update(existing.invoice_pdf).digest('hex') };
  const { order, items } = await loadInvoiceData(orderId);
  const pdf = await createInvoicePdf(order, items);
  const sha256 = crypto.createHash('sha256').update(pdf).digest('hex');
  const saved = (await pool.query("UPDATE orders SET invoice_pdf=$1,invoice_pdf_sha256=$2,invoice_pdf_version=$3 WHERE id=$4 AND (invoice_pdf IS NULL OR invoice_pdf_version<$3) AND status='paid' RETURNING invoice_pdf,invoice_pdf_sha256", [pdf, sha256, INVOICE_PDF_VERSION, orderId])).rows[0];
  if (saved) return { pdf: Buffer.from(saved.invoice_pdf), sha256: saved.invoice_pdf_sha256 };
  const raced = (await pool.query("SELECT invoice_pdf,invoice_pdf_sha256,invoice_pdf_version FROM orders WHERE id=$1 AND status='paid'", [orderId])).rows[0];
  if (!raced?.invoice_pdf) throw new Error('Unable to save paid invoice');
  return { pdf: Buffer.from(raced.invoice_pdf), sha256: raced.invoice_pdf_sha256 };
}
async function sendInvoice(orderId) {
  const settings = await getIntegrationSettings();
  if (!hasEmailTransport(settings)) throw new Error(emailRuntimeError(settings));
  const { order } = await loadInvoiceData(orderId);
  const { pdf } = await getOrCreateInvoicePdf(orderId);
  const template = settings.emailTemplates.invoice;
  const values = { buyerName: order.buyer_name, orderNumber: order.order_number, displayAmount: order.display_amount, displayCurrency: order.display_currency, chargedAmount: order.charged_amount, chargedCurrency: order.charged_currency, provider: order.provider };
  const html = renderEmailTemplate(template.html, values);
  await sendEmail(settings, { from: { name: 'Ticket Arab', email: settings.mailFrom }, replyTo: settings.supportEmail || undefined, to: order.buyer_email, subject: renderEmailTemplate(template.subject, values), text: emailTextFromHtml(html), html, attachments: [{ filename: `invoice-${order.order_number}.pdf`, content: pdf, contentType: 'application/pdf' }] });
  await pool.query('UPDATE orders SET invoice_sent_at=now() WHERE id=$1', [orderId]);
}
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]); }
async function sendTicketDelivery(orderId) {
  const settings = await getIntegrationSettings(); if (!hasEmailTransport(settings)) throw new Error(emailRuntimeError(settings));
  const { order, items } = await loadInvoiceData(orderId);
  const delivery = (await pool.query('SELECT * FROM ticket_deliveries WHERE order_id=$1', [orderId])).rows[0];
  if (!delivery) throw new Error('Save ticket content before sending it');
  const fileAttachments = (delivery.attachments || []).map(file => ({ filename: file.name, content: Buffer.from(file.data, 'base64'), contentType: file.type }));
  const ticketList=`<ul>${items.map(item=>`<li>${escapeHtml(item.event_title)} — ${escapeHtml(item.ticket_name)} × ${item.quantity}</li>`).join('')}</ul>`;
  const template=settings.emailTemplates.ticket;const values={buyerName:order.buyer_name,orderNumber:order.order_number,message:`<p>${escapeHtml(delivery.body).replace(/\n/g,'<br/>')}</p>`,ticketList,ticketCodes:''};const html=renderEmailTemplate(template.html,values);
  await sendEmail(settings,{ from: { name: 'Ticket Arab', email: settings.mailFrom }, replyTo: settings.supportEmail || undefined, to: order.buyer_email, subject: renderEmailTemplate(delivery.subject||template.subject,values), text: `${delivery.body}\n\n${items.map(item => `${item.event_title} — ${item.ticket_name} x ${item.quantity}`).join('\n')}`, html, attachments: fileAttachments });
  await pool.query("UPDATE ticket_deliveries SET status='sent',sent_at=now(),last_error=NULL,updated_at=now() WHERE order_id=$1", [orderId]);
  await pool.query("UPDATE orders SET ticket_delivery_status='sent' WHERE id=$1", [orderId]);
}
function recordRequest(req) {
  const details = requestDetails(req);
  return [details.ip, details.countryCode, details.countryName, details.region, details.city, details.userAgent, details.referrerOrigin, details.deviceType];
}
async function failPayment(paymentId, reason) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const p = (await client.query('SELECT p.order_id,o.status FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.id=$1 FOR UPDATE OF p,o', [paymentId])).rows[0];
    if (!p) { await client.query('ROLLBACK'); return; }
    await client.query("UPDATE payments SET status='failed',failure_reason=$1,updated_at=now() WHERE id=$2", [String(reason || 'Payment did not complete').slice(0,500), paymentId]);
    if (p.status === 'pending') {
      await client.query('UPDATE ticket_types t SET quantity_reserved=GREATEST(t.quantity_reserved-oi.quantity,0) FROM order_items oi WHERE oi.order_id=$1 AND t.id=oi.ticket_type_id', [p.order_id]);
      await client.query("UPDATE orders SET status='cancelled',updated_at=now() WHERE id=$1", [p.order_id]);
    }
    await client.query('COMMIT');
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { await client.release(); }
}
async function completePaymegatePayment(orderNumber,providerOrderId,event,eventId) {
  const client=await pool.connect();let orderId;let payId;
  try {
    await client.query('BEGIN');
    const received=await client.query('INSERT INTO payment_webhook_events(provider,event_id,order_uuid,transaction_uuid) VALUES($1,$2,$3,$4) ON CONFLICT(provider,event_id) DO NOTHING RETURNING event_id',['paymegate',eventId,String(event.orderUUID),String(event.transactionUUID)]);
    if(!received.rowCount){await client.query('COMMIT');return {duplicate:true};}
    const pay=(await client.query("SELECT p.*,o.id order_id,o.status order_status,o.expires_at FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.provider='paymegate' AND o.order_number=$1 AND p.provider_order_id=$2 FOR UPDATE OF p,o",[orderNumber,providerOrderId])).rows[0];
    if(!pay){await client.query('ROLLBACK');return {notFound:true};}orderId=pay.order_id;payId=pay.id;
    if(pay.order_status==='paid'&&pay.status==='completed'){await client.query('COMMIT');return {orderId,alreadyPaid:true};}
    if(event.status!=='PAID'||Number(event.amount).toFixed(2)!==Number(pay.amount).toFixed(2)||String(event.currency||'').toUpperCase()!==String(pay.currency).trim().toUpperCase())throw new Error('Paymegate amount/currency/status did not match');
    if(pay.order_status!=='pending'||new Date(pay.expires_at)<=new Date())throw new Error('Order reservation expired before Paymegate confirmation');
    const items=(await client.query('SELECT oi.*,t.quantity_reserved,t.id ticket_type_id FROM order_items oi JOIN ticket_types t ON t.id=oi.ticket_type_id WHERE oi.order_id=$1 FOR UPDATE OF t',[orderId])).rows;
    if(!items.length||items.some(item=>Number(item.quantity_reserved)<Number(item.quantity)))throw new Error('Inventory reservation unavailable');
    for(const item of items){
      await client.query('UPDATE ticket_types SET quantity_sold=quantity_sold+$1,quantity_reserved=GREATEST(quantity_reserved-$1,0) WHERE id=$2',[item.quantity,item.ticket_type_id]);
      for(let i=0;i<Number(item.quantity);i++)await client.query('INSERT INTO tickets(order_id,ticket_type_id,code) VALUES($1,$2,$3)',[orderId,item.ticket_type_id,crypto.randomUUID()]);
    }
    await client.query("UPDATE orders SET status='paid',ticket_delivery_status='waiting',updated_at=now() WHERE id=$1",[orderId]);
    await client.query("UPDATE payments SET status='completed',provider_capture_id=$1,updated_at=now() WHERE id=$2",[String(event.transactionUUID),payId]);
    await client.query('COMMIT');
  } catch(err){await client.query('ROLLBACK');throw err;}finally{await client.release();}
  await sendInvoice(orderId).catch(err=>console.error('Paymegate invoice email failed:',err.message));return {orderId};
}
app.post(['/api/paymegate/webhook','/webhooks/paymegate'], asyncRoute(async(req,res)=>{
  const settings=await getIntegrationSettings();
  const timestamp=String(req.get('x-paymegate-timestamp')||'');
  const signature=String(req.get('x-paymegate-signature')||'');
  const eventHeader=String(req.get('x-paymegate-event')||'');
  const eventId=String(req.get('x-paymegate-event-id')||'');
  const raw=req.rawBody;
  if(!settings.paymegateWebhookSecret||!raw||eventHeader!=='order.paid'||!eventId||!/^\d+$/.test(timestamp)||Math.abs(Date.now()-Number(timestamp)*1000)>5*60*1000) return res.status(403).json({error:'Invalid Paymegate webhook'});
  const expected=crypto.createHmac('sha256',settings.paymegateWebhookSecret).update(`${timestamp}.`).update(raw).digest('base64url');
  const a=Buffer.from(expected);const b=Buffer.from(signature);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(403).json({error:'Invalid Paymegate webhook signature'});
  const event=req.body;
  if(event?.type!=='order.paid'||event?.status!=='PAID'||!event.orderUUID||!event.externalId||!event.transactionUUID)return res.status(400).json({error:'Invalid paid-order event'});
  const result=await completePaymegatePayment(String(event.externalId),String(event.orderUUID),event,eventId);
  if(result.notFound)return res.status(404).json({error:'Payment not found'});
  res.sendStatus(200);
}));
async function completeLemonSqueezyPayment(event) {
  const attributes=event?.data?.attributes||{};const custom=event?.meta?.custom_data||{};const orderId=String(custom.order_id||'');const providerOrderId=String(event?.data?.id||'');const eventId=providerOrderId;
  if(!/^\d+$/.test(providerOrderId)||!orderId||!custom.order_number||attributes.status!=='paid')throw new Error('Invalid paid Lemon Squeezy order event');
  if(attributes.store_id&&String(attributes.store_id)!==String((await getIntegrationSettings()).lemonSqueezyStoreId))throw new Error('Lemon Squeezy store ID did not match');
  const client=await pool.connect();let paymentId;
  try {
    await client.query('BEGIN');
    const received=await client.query('INSERT INTO payment_webhook_events(provider,event_id,order_uuid,transaction_uuid) VALUES($1,$2,$3,$4) ON CONFLICT(provider,event_id) DO NOTHING RETURNING event_id',['lemon_squeezy',eventId,orderId,providerOrderId]);
    if(!received.rowCount){await client.query('COMMIT');return {duplicate:true};}
    const pay=(await client.query("SELECT p.*,o.id order_id,o.order_number,o.status order_status,o.expires_at FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.provider='lemon_squeezy' AND o.id=$1 AND o.order_number=$2 FOR UPDATE OF p,o",[orderId,String(custom.order_number)])).rows[0];
    if(!pay){await client.query('ROLLBACK');return {notFound:true};}paymentId=pay.id;
    if(pay.order_status==='paid'&&pay.status==='completed'){await client.query('COMMIT');return {alreadyPaid:true};}
    const totalCents=Number(attributes.total);const expectedCents=Math.round(Number(pay.amount)*100);
    if(!Number.isSafeInteger(totalCents)||totalCents!==expectedCents||String(attributes.currency||'').toUpperCase()!==String(pay.currency).trim().toUpperCase())throw new Error('Lemon Squeezy amount or currency did not match the order');
    if(pay.order_status!=='pending'||new Date(pay.expires_at)<=new Date())throw new Error('Order reservation expired before Lemon Squeezy confirmation');
    const items=(await client.query('SELECT oi.*,t.quantity_reserved,t.id ticket_type_id FROM order_items oi JOIN ticket_types t ON t.id=oi.ticket_type_id WHERE oi.order_id=$1 FOR UPDATE OF t',[pay.order_id])).rows;
    if(!items.length||items.some(item=>Number(item.quantity_reserved)<Number(item.quantity)))throw new Error('Inventory reservation unavailable');
    for(const item of items){await client.query('UPDATE ticket_types SET quantity_sold=quantity_sold+$1,quantity_reserved=GREATEST(quantity_reserved-$1,0) WHERE id=$2',[item.quantity,item.ticket_type_id]);for(let i=0;i<Number(item.quantity);i++)await client.query('INSERT INTO tickets(order_id,ticket_type_id,code) VALUES($1,$2,$3)',[pay.order_id,item.ticket_type_id,crypto.randomUUID()]);}
    await client.query("UPDATE orders SET status='paid',ticket_delivery_status='waiting',updated_at=now() WHERE id=$1",[pay.order_id]);
    await client.query("UPDATE payments SET status='completed',provider_order_id=$1,provider_capture_id=$1,updated_at=now() WHERE id=$2",[providerOrderId,pay.id]);
    await client.query('COMMIT');
  } catch(error){await client.query('ROLLBACK');throw error;}finally{await client.release();}
  if(paymentId)await sendInvoice(String(event.meta.custom_data.order_id)).catch(error=>console.error('Lemon Squeezy invoice email failed:',error.message));
  return {ok:true};
}
function heleketBodyAndSign(payload, apiKey) {
  const body = JSON.stringify(payload).replace(/\//g, '\\/');
  return { body, sign: crypto.createHash('md5').update(Buffer.from(body, 'utf8').toString('base64') + apiKey).digest('hex') };
}
async function completeHeleketPayment(event) {
  const orderNumber=String(event?.order_id||'');const uuid=String(event?.uuid||'');const status=String(event?.status||'').toLowerCase();
  if(!orderNumber||!uuid||!status)throw new Error('Invalid Heleket payment notification');
  const client=await pool.connect();let orderId;let paymentId;
  try{
    await client.query('BEGIN');
    const eventId=`${uuid}:${status}`;
    const received=await client.query('INSERT INTO payment_webhook_events(provider,event_id,order_uuid,transaction_uuid) VALUES($1,$2,$3,$4) ON CONFLICT(provider,event_id) DO NOTHING RETURNING event_id',['heleket',eventId,orderNumber,uuid]);
    if(!received.rowCount){await client.query('COMMIT');return {duplicate:true};}
    const pay=(await client.query("SELECT p.*,o.id order_id,o.status order_status,o.expires_at FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.provider='heleket' AND replace(o.id::text,'-','')=$1 AND p.provider_order_id=$2 FOR UPDATE OF p,o",[orderNumber,uuid])).rows[0];
    if(!pay){await client.query('ROLLBACK');return {notFound:true};}orderId=pay.order_id;paymentId=pay.id;
    if(pay.order_status==='paid'&&pay.status==='completed'){await client.query('COMMIT');return {alreadyPaid:true};}
    if(status==='paid'||status==='paid_over'){
      if(Number(event.amount).toFixed(2)!==Number(pay.amount).toFixed(2)||String(event.currency||'').toUpperCase()!==String(pay.currency).trim().toUpperCase())throw new Error('Heleket amount or currency did not match the order');
      if(pay.order_status!=='pending'||new Date(pay.expires_at)<=new Date())throw new Error('Order reservation expired before Heleket confirmation');
      const items=(await client.query('SELECT oi.*,t.quantity_reserved,t.id ticket_type_id FROM order_items oi JOIN ticket_types t ON t.id=oi.ticket_type_id WHERE oi.order_id=$1 FOR UPDATE OF t',[orderId])).rows;
      if(!items.length||items.some(item=>Number(item.quantity_reserved)<Number(item.quantity)))throw new Error('Inventory reservation unavailable');
      for(const item of items){await client.query('UPDATE ticket_types SET quantity_sold=quantity_sold+$1,quantity_reserved=GREATEST(quantity_reserved-$1,0) WHERE id=$2',[item.quantity,item.ticket_type_id]);for(let i=0;i<Number(item.quantity);i++)await client.query('INSERT INTO tickets(order_id,ticket_type_id,code) VALUES($1,$2,$3)',[orderId,item.ticket_type_id,crypto.randomUUID()]);}
      await client.query("UPDATE orders SET status='paid',ticket_delivery_status='waiting',updated_at=now() WHERE id=$1",[orderId]);
      await client.query("UPDATE payments SET status='completed',provider_capture_id=$1,updated_at=now() WHERE id=$2",[String(event.txid||uuid),paymentId]);
    }else if(['fail','cancel','system_fail','wrong_amount'].includes(status)&&pay.order_status==='pending'){
      await client.query('UPDATE ticket_types t SET quantity_reserved=GREATEST(t.quantity_reserved-oi.quantity,0) FROM order_items oi WHERE oi.order_id=$1 AND t.id=oi.ticket_type_id',[orderId]);
      await client.query("UPDATE orders SET status='cancelled',updated_at=now() WHERE id=$1",[orderId]);
      await client.query("UPDATE payments SET status='failed',failure_reason=$1,updated_at=now() WHERE id=$2",[`Heleket payment status: ${status}`,paymentId]);
    }
    await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK');throw error;}finally{await client.release();}
  if(['paid','paid_over'].includes(status))await sendInvoice(orderId).catch(error=>console.error('Heleket invoice email failed:',error.message));
  return {ok:true};
}
app.post(['/api/heleket/webhook','/webhooks/heleket'],asyncRoute(async(req,res)=>{
  const settings=await getIntegrationSettings();const event=req.body||{};const supplied=String(event.sign||'').toLowerCase();
  if(!settings.heleketPaymentApiKey||!/^[\da-f]{32}$/.test(supplied))return res.status(403).json({error:'Invalid Heleket webhook'});
  const payload={...event};delete payload.sign;const {sign}=heleketBodyAndSign(payload,settings.heleketPaymentApiKey);
  const a=Buffer.from(sign);const b=Buffer.from(supplied);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(403).json({error:'Invalid Heleket webhook signature'});
  if(event.type!=='payment')return res.sendStatus(200);
  const result=await completeHeleketPayment(event);if(result.notFound)return res.status(404).json({error:'Payment not found'});return res.sendStatus(200);
}));
app.post(['/api/lemonsqueezy/webhook','/webhooks/lemonsqueezy'],asyncRoute(async(req,res)=>{
  const settings=await getIntegrationSettings();const signature=String(req.get('x-signature')||'').trim();const raw=req.rawBody;
  if(!settings.lemonSqueezyWebhookSecret||!raw||!/^[\da-f]{64}$/i.test(signature))return res.status(403).json({error:'Invalid Lemon Squeezy webhook'});
  const expected=crypto.createHmac('sha256',settings.lemonSqueezyWebhookSecret).update(raw).digest('hex');const a=Buffer.from(expected.toLowerCase());const b=Buffer.from(signature.toLowerCase());
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(403).json({error:'Invalid Lemon Squeezy webhook signature'});
  const event=req.body||{};const eventName=String(event?.meta?.event_name||'').trim();const headerEventName=String(req.get('x-event-name')||'').trim();const objectId=String(event?.data?.id||'').trim();
  if(!eventName||!/^[a-z][a-z0-9_]{1,80}$/.test(eventName)||!objectId||(headerEventName&&headerEventName!==eventName))return res.status(400).json({error:'Invalid Lemon Squeezy event'});
  // Acknowledge and record every signed event chosen in the Lemon Squeezy dashboard.
  // Only a correlated, paid order_created event may complete a ticket order.
  if(eventName!=='order_created'||!event?.meta?.custom_data?.order_id||!event?.meta?.custom_data?.order_number){
    await pool.query('INSERT INTO payment_webhook_events(provider,event_id,order_uuid,transaction_uuid) VALUES($1,$2,$3,$4) ON CONFLICT(provider,event_id) DO NOTHING',['lemon_squeezy',`${eventName}:${objectId}`,eventName,objectId]);
    await pool.query('INSERT INTO admin_logs(action,details) VALUES($1,$2)',['lemon_squeezy.webhook.received',JSON.stringify({event:eventName,object_id:objectId})]);
    return res.sendStatus(200);
  }
  const result=await completeLemonSqueezyPayment(event);if(result.notFound)return res.status(404).json({error:'Payment not found'});return res.sendStatus(200);
}));
app.get('/api/checkout/status',asyncRoute(async(req,res)=>{
  const number=String(req.query.order_number||'');const token=String(req.query.invoice_token||'');const provider=['paymegate','heleket','lemon_squeezy'].includes(String(req.query.provider))?String(req.query.provider):'paymegate';if(!number||token.length<32)return res.status(400).json({error:'Order reference is required'});
  const row=(await pool.query('SELECT o.status,o.order_number,o.total_amount,o.currency,o.invoice_token_hash,p.status payment_status FROM orders o JOIN payments p ON p.order_id=o.id WHERE o.order_number=$1 AND p.provider=$2 ORDER BY p.created_at DESC LIMIT 1',[number,provider])).rows[0];
  const hash=crypto.createHash('sha256').update(token).digest('hex');if(!row||!row.invoice_token_hash||!crypto.timingSafeEqual(Buffer.from(hash),Buffer.from(row.invoice_token_hash)))return res.status(404).json({error:'Order not found'});
  res.json({status:row.status,payment_status:row.payment_status,order_number:row.order_number,invoice_token:token,total_amount:row.total_amount,currency:row.currency});
}));
app.post('/api/checkout', asyncRoute(async (req, res) => {
  const { buyer_name, buyer_email, buyer_phone } = req.body || {}; const requestedProvider = req.body?.provider; const paypalMethod=String(req.body?.paypal_method||'card');
  const buyerName=String(buyer_name||'').trim();const buyerEmail=String(buyer_email||'').trim();
  if (requestedProvider && !['paypal','paymegate','heleket'].includes(requestedProvider)) return res.status(400).json({ error: 'Payment provider is not supported' });
  const provider = requestedProvider || 'paypal';
  if(provider==='paypal'&&!['card','paypal','paylater','googlepay','applepay'].includes(paypalMethod)) return res.status(400).json({error:'PayPal payment method is not supported'});
  const inputs = Array.isArray(req.body?.ticket_items) ? req.body.ticket_items : [{ ticket_type_id: req.body?.ticket_type_id, quantity: req.body?.quantity }];
  const requestedItems = inputs.map(item => ({ id: String(item.ticket_type_id || ''), quantity: Number(item.quantity) })).filter(item => item.quantity > 0);
  const totalQuantity = requestedItems.reduce((sum, item) => sum + item.quantity, 0);
  if (!buyerName || buyerName.length>160 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(buyerEmail) || buyerEmail.length>320 || !requestedItems.length || requestedItems.length > 20 || requestedItems.some(item => !item.id || !Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 8) || totalQuantity > 8 || new Set(requestedItems.map(item=>item.id)).size !== requestedItems.length) return res.status(400).json({ error: 'تحقق من الاسم والبريد الإلكتروني الصحيح وأن مجموع التذاكر بين 1 و8.' });
  const settings = await getIntegrationSettings();
  if (provider === 'paypal' && (!settings.paypalEnabled || !settings.paypalClientId || !settings.paypalClientSecret)) return res.status(503).json({ error: 'PayPal غير مفعّل أو بياناته غير مُعدة بعد' });
  if (provider === 'paypal' && !settings.paypalWalletButtonEnabled && !settings.paypalPayLaterButtonEnabled && !settings.paypalCardButtonEnabled) return res.status(503).json({ error: 'لا توجد وسيلة PayPal مفعّلة حاليًا.' });
  if (provider === 'paypal' && ((paypalMethod === 'card' && !settings.paypalCardButtonEnabled) || (paypalMethod === 'paylater' && !settings.paypalPayLaterButtonEnabled) || (paypalMethod === 'paypal' && !settings.paypalWalletButtonEnabled))) return res.status(503).json({ error: 'وسيلة الدفع هذه غير مفعّلة حاليًا.' });
  if (provider === 'paymegate' && (!settings.paymegateEnabled || !settings.paymegateApiKey || !settings.paymegateWebhookSecret || !process.env.FRONTEND_ORIGIN?.startsWith('https://'))) return res.status(503).json({ error: 'Paymegate غير مفعّل أو غير مكتمل. أضف مفتاح API وسر Webhook واضبط FRONTEND_ORIGIN على عنوان HTTPS عام.' });
  if (provider === 'heleket' && (!settings.heleketEnabled || !settings.heleketMerchantId || !settings.heleketPaymentApiKey || !process.env.FRONTEND_ORIGIN?.startsWith('https://'))) return res.status(503).json({ error: 'Heleket is not enabled or its merchant credentials are incomplete.' });
  if (!hasEmailTransport(settings)) return res.status(503).json({ error: emailRuntimeError(settings) });
  const ids = requestedItems.map(item=>item.id);
  const listed = (await pool.query('SELECT t.id,t.event_id,t.price,t.currency FROM ticket_types t JOIN events e ON e.id=t.event_id WHERE t.id=ANY($1::uuid[]) AND t.is_active AND e.is_active AND e.event_date>now()', [ids])).rows;
  if (listed.length !== requestedItems.length) return res.status(409).json({ error: 'انتهى موعد الحفل أو لم تعد فئة التذكرة متاحة. حدّث الصفحة واختر حفلًا قادمًا.' });
  const displayCurrency = String(listed[0].currency).trim().toUpperCase();
  if (listed.some(row=>row.event_id!==listed[0].event_id||String(row.currency).trim().toUpperCase()!==displayCurrency)) return res.status(400).json({ error: 'يجب أن تكون التذاكر المختارة من الحفلة نفسها وبالعملة نفسها.' });
  let fx; const chargeCurrency = 'USD';
  try { fx = await getUsdRate(displayCurrency); }
  catch { return res.status(503).json({ error: 'تعذر جلب سعر صرف موثوق لهذه العملة الآن. حاول مرة أخرى لاحقًا.' }); }
  const client = await pool.connect(); let order; let payment; let displayAmount; let chargeAmount; const invoiceToken = crypto.randomBytes(32).toString('base64url'); const details = recordRequest(req);
  try {
    await client.query('BEGIN');
    await client.query(`WITH expired AS (UPDATE orders SET status='cancelled',updated_at=now() WHERE status='pending' AND expires_at<=now() RETURNING id), released AS (SELECT oi.ticket_type_id,sum(oi.quantity)::int quantity FROM order_items oi JOIN expired e ON e.id=oi.order_id GROUP BY oi.ticket_type_id) UPDATE ticket_types t SET quantity_reserved=GREATEST(t.quantity_reserved-released.quantity,0) FROM released WHERE t.id=released.ticket_type_id`);
    const tickets=(await client.query('SELECT t.*,e.title FROM ticket_types t JOIN events e ON e.id=t.event_id WHERE t.id=ANY($1::uuid[]) AND t.is_active AND e.is_active AND e.event_date>now() ORDER BY t.id FOR UPDATE OF t',[ids])).rows;
    const byId=new Map(tickets.map(ticket=>[ticket.id,ticket])); let subtotal=0;
    for(const requested of requestedItems){const ticket=byId.get(requested.id);if(!ticket||Number(ticket.quantity_available)-Number(ticket.quantity_sold)-Number(ticket.quantity_reserved)<requested.quantity){await client.query('ROLLBACK');return res.status(409).json({error:'الكمية المطلوبة من إحدى فئات التذاكر غير متاحة.'});}if(String(ticket.currency).trim().toUpperCase()!==displayCurrency){await client.query('ROLLBACK');return res.status(409).json({error:'تغيرت عملة التذاكر. حدّث الصفحة وحاول مرة أخرى.'});}subtotal+=Number(ticket.price)*requested.quantity;}
    displayAmount=subtotal.toFixed(2);chargeAmount=(Math.round(Number(displayAmount)*fx.rate*100)/100).toFixed(2);
    if(Number(chargeAmount)<=0){await client.query('ROLLBACK');return res.status(400).json({error:'السعر بعد التحويل أقل من الحد الأدنى للتحصيل.'});}
    const orderNo=`TA-${crypto.randomUUID().toUpperCase()}`;
    order=(await client.query("INSERT INTO orders(order_number,buyer_name,buyer_email,buyer_phone,total_amount,currency,status,invoice_token_hash) VALUES($1,$2,$3,$4,$5,$6,'pending',$7) RETURNING *",[orderNo,buyerName,buyerEmail,String(buyer_phone||'').trim().slice(0,80)||null,displayAmount,displayCurrency,crypto.createHash('sha256').update(invoiceToken).digest('hex')])).rows[0];
    for(const requested of requestedItems){const ticket=byId.get(requested.id);const lineTotal=(Number(ticket.price)*requested.quantity).toFixed(2);await client.query('INSERT INTO order_items(order_id,ticket_type_id,quantity,unit_price,total_price) VALUES($1,$2,$3,$4,$5)',[order.id,ticket.id,requested.quantity,ticket.price,lineTotal]);await client.query('UPDATE ticket_types SET quantity_reserved=quantity_reserved+$1 WHERE id=$2',[requested.quantity,ticket.id]);}
    payment=(await client.query("INSERT INTO payments(order_id,provider,status,amount,currency,display_amount,display_currency,exchange_rate,exchange_rate_date,client_ip,country_code,country_name,region,city,user_agent,referrer_origin,device_type) VALUES($1,$2,'creating',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id,amount",[order.id,provider,chargeAmount,chargeCurrency,displayAmount,displayCurrency,fx.rate,fx.date,...details])).rows[0];
    await client.query('COMMIT');
  } catch(e) { await client.query('ROLLBACK'); throw e; } finally { await client.release(); }  try {
    if (provider === 'paymegate') {
      const frontendOrigin=process.env.FRONTEND_ORIGIN.replace(/\/$/,'');
      const backUrl=`${frontendOrigin}/?paymegate_return=${encodeURIComponent(order.order_number)}&invoice_token=${encodeURIComponent(invoiceToken)}`;
      const response=await fetch('https://api.paymegate.com/v1/orders',{method:'POST',headers:{'X-API-Key':settings.paymegateApiKey,'Content-Type':'application/json'},body:JSON.stringify({externalId:order.order_number,amount:String(payment.amount),currency:'USD',paymentMethodsKeys:['*'],backUrl,customer:{email:String(buyer_email).trim(),fullName:String(buyer_name).trim().slice(0,160)},metadata:{orderNumber:order.order_number}}),signal:AbortSignal.timeout(15000)});
      let result;try{result=await response.json();}catch{result=null;}const remoteOrder=result?.data;
      const checkoutUrl=typeof remoteOrder?.checkoutUrl==='string'?new URL(remoteOrder.checkoutUrl):null;
      if(!response.ok||result?.success!==true||!remoteOrder?.orderUUID||!checkoutUrl||checkoutUrl.origin!=='https://www.paymegate.com')throw new Error(String(result?.error?.message||result?.message||`Paymegate order API returned HTTP ${response.status}`).slice(0,300));
      await pool.query("UPDATE payments SET provider_order_id=$1,status='created',updated_at=now() WHERE id=$2",[String(remoteOrder.orderUUID),payment.id]);
      await pool.query("UPDATE orders SET expires_at=now()+interval '45 minutes',updated_at=now() WHERE id=$1 AND status='pending'",[order.id]);
      return res.json({provider:'paymegate',checkout_url:remoteOrder.checkoutUrl,invoice_token:invoiceToken,order_number:order.order_number,display_amount:order.total_amount,display_currency:order.currency,charge_amount:payment.amount,charge_currency:payment.currency,exchange_rate:fx.rate,exchange_rate_date:fx.date});
    }
    if (provider === 'heleket') {
      const frontendOrigin=process.env.FRONTEND_ORIGIN.replace(/\/$/,'');
      const returnUrl=`${frontendOrigin}/?heleket_return=${encodeURIComponent(order.order_number)}&invoice_token=${encodeURIComponent(invoiceToken)}`;
      const gatewayOrderId=String(order.id).replace(/-/g,'');
      const requestBody={amount:String(payment.amount),currency:String(payment.currency).trim().toUpperCase(),order_id:gatewayOrderId,url_callback:`${frontendOrigin}/webhooks/heleket`,url_return:returnUrl,url_success:returnUrl,lifetime:2700,accuracy_payment_percent:0,is_payment_multiple:false,additional_data:String(order.order_number)};
      const signed=heleketBodyAndSign(requestBody,settings.heleketPaymentApiKey);
      const response=await fetch('https://api.heleket.com/v1/payment',{method:'POST',headers:{merchant:settings.heleketMerchantId,sign:signed.sign,'Content-Type':'application/json'},body:signed.body,signal:AbortSignal.timeout(15000)});
      let result;try{result=await response.json();}catch{result=null;}const invoice=result?.result;let checkoutUrl;try{checkoutUrl=new URL(invoice?.url||'');}catch{}
      if(!response.ok||result?.state!==0||!invoice?.uuid||!checkoutUrl||checkoutUrl.protocol!=='https:'||checkoutUrl.hostname!=='pay.heleket.com')throw new Error(String(result?.message||result?.errors?.amount?.[0]||`Heleket invoice API returned HTTP ${response.status}`).slice(0,300));
      await pool.query("UPDATE payments SET provider_order_id=$1,status='created',updated_at=now() WHERE id=$2",[String(invoice.uuid),payment.id]);
      await pool.query("UPDATE orders SET expires_at=now()+interval '45 minutes',updated_at=now() WHERE id=$1 AND status='pending'",[order.id]);
      return res.json({provider:'heleket',checkout_url:checkoutUrl.href,invoice_token:invoiceToken,order_number:order.order_number,display_amount:order.total_amount,display_currency:order.currency,charge_amount:payment.amount,charge_currency:payment.currency,exchange_rate:fx.rate,exchange_rate_date:fx.date});
    }
    const pp = await paypalToken(settings);
    const tokenResponse = await fetch(`${pp.base}/v1/identity/generate-token`, { method:'POST',headers:{Authorization:`Bearer ${pp.token}`,'Accept-Language':'en_US','Content-Type':'application/json'} });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.client_token) throw new Error('PayPal client token generation failed');
    const paypalOrderBody={intent:'CAPTURE',...(paypalMethod==='card'?{payment_source:{card:{attributes:{verification:{method:'SCA_ALWAYS'}},experience_context:{shipping_preference:'NO_SHIPPING'}}}}:{}),purchase_units:[{reference_id:order.id,custom_id:String(order.id),amount:{currency_code:'USD',value:payment.amount},invoice_id:order.order_number,description:String(buyer_name).slice(0,100)}]};
    const response = await fetch(`${pp.base}/v2/checkout/orders`, { method:'POST',headers:{Authorization:`Bearer ${pp.token}`,'Content-Type':'application/json'},body:JSON.stringify(paypalOrderBody) });
    const paypal = await response.json(); if (!response.ok) throw new Error(paypal.message || paypal.details?.map(detail => detail.description).filter(Boolean).join('; ') || paypal.name || 'PayPal rejected the order');
    await pool.query("UPDATE payments SET provider_order_id=$1,status='created',updated_at=now() WHERE id=$2",[paypal.id,payment.id]);
    res.json({order_id:order.id,order_number:order.order_number,payment_id:payment.id,paypal_order_id:paypal.id,client_id:settings.paypalClientId,client_token:tokenData.client_token,paypal_sandbox:settings.paypalEnv!=='live',invoice_token:invoiceToken,display_amount:order.total_amount,display_currency:order.currency,usd_amount:payment.amount,exchange_rate:fx.rate,exchange_rate_date:fx.date});
  } catch (err) { const providerError=String(err.message||err).slice(0,500); console.error(`${provider} checkout initialization failed:`,providerError); await failPayment(payment.id,providerError); const paymegateMessage=/EVM payout wallet/i.test(providerError)?'إعداد محفظة التاجر في Paymegate غير مكتمل: أضف عنوان محفظة EVM صالحًا لاستلام التسويات من لوحة Paymegate، ثم أعد المحاولة.':'تعذر إنشاء طلب الدفع لدى Paymegate. تحقّق من مفتاح API وإعدادات التاجر ثم حاول مجددًا.'; res.status(502).json({error:provider==='paymegate'?paymegateMessage:'تعذر بدء عملية الدفع. حاول مرة أخرى.'}); }
}));
app.post('/api/checkout/failure', asyncRoute(async (req,res) => {
  const paypalId=String(req.body.paypal_order_id||''); const invoiceToken=String(req.body.invoice_token||'');
  if(!paypalId||invoiceToken.length<32) return res.status(400).json({error:'Payment reference is required'});
  const row=(await pool.query('SELECT p.id,o.invoice_token_hash FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.provider_order_id=$1 AND p.status IN (\'created\',\'creating\')',[paypalId])).rows[0];
  if(row) {
    const tokenHash=crypto.createHash('sha256').update(invoiceToken).digest('hex');
    if(!row.invoice_token_hash||!crypto.timingSafeEqual(Buffer.from(tokenHash),Buffer.from(row.invoice_token_hash))) return res.status(403).json({error:'Invalid payment token'});
    await failPayment(row.id,String(req.body.reason||'Card payment was not approved'));
  }
  res.json({ok:true});
}));
app.post('/api/checkout/capture', asyncRoute(async (req, res) => {
  const paypalId=String(req.body.paypal_order_id||''); const invoiceToken=String(req.body.invoice_token||'');
  if(!paypalId||invoiceToken.length<32) return res.status(400).json({error:'Payment reference is required'});
  let captureAttempted=false; let capturedAtProvider=false; let paymentId; let orderNumber;
  try {
    // Never keep a Hyperdrive/Postgres transaction open while waiting for PayPal.
    const pay=(await pool.query('SELECT p.*,o.status order_status,o.order_number,o.expires_at,o.invoice_token_hash FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.provider_order_id=$1 AND p.provider=$2',[paypalId,'paypal'])).rows[0];
    if(!pay) return res.status(404).json({error:'Payment not found'});
    paymentId=pay.id; orderNumber=pay.order_number;
    const tokenHash=crypto.createHash('sha256').update(invoiceToken).digest('hex');
    if(!pay.invoice_token_hash||!crypto.timingSafeEqual(Buffer.from(tokenHash),Buffer.from(pay.invoice_token_hash))) return res.status(403).json({error:'Invalid checkout token'});
    if(pay.order_status==='paid') return res.json({success:true,order_number:orderNumber,invoice_token:invoiceToken});
    if(pay.order_status!=='pending'||new Date(pay.expires_at)<=new Date()) {
      await failPayment(pay.id,'Reservation expired before PayPal capture');
      return res.status(409).json({error:'Reservation expired. Please start a new checkout.'});
    }

    const settings=await getIntegrationSettings(); const pp=await paypalToken(settings);
    const detailResponse=await fetch(`${pp.base}/v2/checkout/orders/${encodeURIComponent(paypalId)}`,{headers:{Authorization:`Bearer ${pp.token}`} });
    const detail=await detailResponse.json();
    if(!detailResponse.ok) throw new Error(detail.message||'PayPal could not verify the payment');
    const cardSource=detail.payment_source?.card;
    const walletSource=detail.payment_source?.paypal||detail.payment_source?.google_pay||detail.payment_source?.apple_pay;
    if(!cardSource&&!walletSource) throw new Error('PayPal did not confirm an approved card or wallet source');
    const liabilityShift=String(cardSource?.authentication_result?.liability_shift||walletSource?.card?.authentication_result?.liability_shift||'').toUpperCase();
    if((cardSource||liabilityShift)&&['NO','UNKNOWN'].includes(liabilityShift)) throw new Error(`PayPal 3-D Secure liability shift was ${liabilityShift}`);

    let capture=detail;
    if(detail.status!=='COMPLETED') {
      captureAttempted=true;
      const response=await fetch(`${pp.base}/v2/checkout/orders/${encodeURIComponent(paypalId)}/capture`,{
        method:'POST',headers:{Authorization:`Bearer ${pp.token}`,'Content-Type':'application/json','PayPal-Request-Id':String(pay.id)}
      });
      capture=await response.json();
      if(!response.ok||capture.status!=='COMPLETED') {
        await failPayment(pay.id,capture.message||'PayPal capture declined');
        return res.status(402).json({error:'Payment was not completed'});
      }
    }
    capturedAtProvider=true;
    const captureRecord=capture.purchase_units?.[0]?.payments?.captures?.[0];
    const paidAmount=captureRecord?.amount||capture.purchase_units?.[0]?.amount;
    if(capture.status!=='COMPLETED'||(captureRecord&&captureRecord.status!=='COMPLETED')||!paidAmount||Number(paidAmount.value)!==Number(pay.amount)||String(paidAmount.currency_code).trim().toUpperCase()!==String(pay.currency).trim().toUpperCase()) {
      throw new Error('PayPal capture status, amount, or currency did not match the order');
    }

    const client=await pool.connect(); let orderId;
    try {
      await client.query('BEGIN');
      const locked=(await client.query('SELECT p.id,p.order_id,p.status payment_status,o.status order_status,o.order_number,o.invoice_token_hash FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.provider=$1 AND p.provider_order_id=$2 FOR UPDATE OF p,o',['paypal',paypalId])).rows[0];
      if(!locked) { await client.query('ROLLBACK'); return res.status(404).json({error:'Payment not found'}); }
      const lockedHash=crypto.createHash('sha256').update(invoiceToken).digest('hex');
      if(!locked.invoice_token_hash||!crypto.timingSafeEqual(Buffer.from(lockedHash),Buffer.from(locked.invoice_token_hash))) { await client.query('ROLLBACK'); return res.status(403).json({error:'Invalid checkout token'}); }
      orderId=locked.order_id; orderNumber=locked.order_number;
      if(locked.order_status==='paid') { await client.query('COMMIT'); return res.json({success:true,order_number:orderNumber,invoice_token:invoiceToken}); }
      if(locked.order_status!=='pending'||['failed','refunded'].includes(locked.payment_status)) throw new Error('Captured PayPal payment is not in a fulfillable local state');
      const items=(await client.query('SELECT oi.*,t.quantity_reserved,t.id ticket_type_id FROM order_items oi JOIN ticket_types t ON t.id=oi.ticket_type_id WHERE oi.order_id=$1 FOR UPDATE OF t',[orderId])).rows;
      if(!items.length||items.some(item=>Number(item.quantity_reserved)<Number(item.quantity))) throw new Error('Inventory reservation unavailable after PayPal capture');
      for(const item of items) {
        await client.query('UPDATE ticket_types SET quantity_sold=quantity_sold+$1,quantity_reserved=GREATEST(quantity_reserved-$1,0) WHERE id=$2',[item.quantity,item.ticket_type_id]);
        for(let i=0;i<Number(item.quantity);i++) await client.query('INSERT INTO tickets(order_id,ticket_type_id,code) VALUES($1,$2,$3)',[orderId,item.ticket_type_id,crypto.randomUUID()]);
      }
      await client.query("UPDATE orders SET status='paid',ticket_delivery_status='waiting',updated_at=now() WHERE id=$1",[orderId]);
      await client.query("UPDATE payments SET status='completed',provider_capture_id=$1,updated_at=now() WHERE id=$2",[captureRecord?.id||null,locked.id]);
      await client.query('COMMIT');
    } catch(error) { await client.query('ROLLBACK').catch(()=>{}); throw error; }
    finally { await client.release(); }
    const invoiceEmailSent=await sendInvoice(orderId).then(()=>true).catch(err=>{console.error('Invoice email failed:',err.message);return false;});
    return res.json({success:true,order_number:orderNumber,invoice_token:invoiceToken,invoice_email_sent:invoiceEmailSent,ticket_status:'waiting'});
  } catch(error) {
    // A timeout can happen after PayPal captured the funds. Keep that order retryable
    // and let a retried request reconcile PayPal's completed order before changing state.
    if(paymentId&&!captureAttempted&&!capturedAtProvider) await failPayment(paymentId,error.message).catch(()=>{});
    if(capturedAtProvider) console.error('PayPal captured payment needs local reconciliation:',{orderNumber,paymentId,error:String(error?.message||error).slice(0,300)});
    throw error;
  }
}));
app.get('/api/invoices/:orderNumber.pdf', asyncRoute(async(req,res)=>{
  const token=String(req.query.t||'');const rows=(await pool.query("SELECT id,invoice_token_hash FROM orders WHERE order_number=$1 AND status='paid'",[req.params.orderNumber])).rows;if(!rows[0]||!rows[0].invoice_token_hash||token.length<32)return res.status(404).send('Invoice not found');const a=Buffer.from(crypto.createHash('sha256').update(token).digest('hex'));const b=Buffer.from(rows[0].invoice_token_hash);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(404).send('Invoice not found');const {order}=await loadInvoiceData(rows[0].id);const {pdf,sha256}=await getOrCreateInvoicePdf(rows[0].id);res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="invoice-${order.order_number}.pdf"`);res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-SHA256',sha256);res.send(pdf);
}));
app.get('/api/admin/orders/:id/invoice.pdf', requireAdmin, asyncRoute(async(req,res)=>{
  try {
    const row=(await pool.query("SELECT id,order_number FROM orders WHERE id=$1 AND status='paid'",[req.params.id])).rows[0];
    if(!row)return res.status(404).json({error:'الفاتورة غير موجودة'});
    const {pdf,sha256}=await getOrCreateInvoicePdf(row.id);const download=req.query.download==='1';
    res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`${download?'attachment':'inline'}; filename="invoice-${row.order_number}.pdf"`);res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-SHA256',sha256);res.send(pdf);
  } catch(error) {
    console.error('Admin invoice generation failed:', error);
    res.status(500).json({error:'تعذر تجهيز ملف الفاتورة.',details:String(error?.message||'خطأ غير معروف').slice(0,240)});
  }
}));
app.get('/api/admin/orders/:id', requireAdmin, asyncRoute(async(req,res)=>{
  const order=(await pool.query('SELECT id,order_number,buyer_name,buyer_email,buyer_phone,total_amount,currency,status,created_at,updated_at,invoice_sent_at,ticket_delivery_status FROM orders WHERE id=$1',[req.params.id])).rows[0];if(!order)return res.status(404).json({error:'Order not found'});
  const [items,tickets,delivery]=await Promise.all([pool.query('SELECT e.title event_title,t.name ticket_name,oi.quantity,oi.total_price FROM order_items oi JOIN ticket_types t ON t.id=oi.ticket_type_id JOIN events e ON e.id=t.event_id WHERE oi.order_id=$1',[order.id]),pool.query('SELECT code,status FROM tickets WHERE order_id=$1 ORDER BY created_at,id',[order.id]),pool.query('SELECT subject,body,status,sent_at,last_error FROM ticket_deliveries WHERE order_id=$1',[order.id])]);
  res.json({order,items:items.rows,tickets:tickets.rows,delivery:delivery.rows[0]||null});
}));
app.post('/api/admin/orders/:id/invoice/resend',requireAdmin,asyncRoute(async(req,res)=>{const order=(await pool.query("SELECT id FROM orders WHERE id=$1 AND status='paid'",[req.params.id])).rows[0];if(!order)return res.status(404).json({error:'Paid order not found'});try{await sendInvoice(order.id);}catch(err){return res.status(502).json({error:`Could not send invoice: ${String(err.message||'mail error').slice(0,240)}`});}await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'invoice.resend',JSON.stringify({order_id:order.id})]);res.json({ok:true});}));
app.put('/api/admin/orders/:id/delivery', requireAdmin, asyncRoute(async(req,res)=>{
  const order=(await pool.query("SELECT id,buyer_email,status FROM orders WHERE id=$1 AND status='paid'",[req.params.id])).rows[0];if(!order)return res.status(404).json({error:'Paid order not found'});
  const subject=String(req.body.subject||'').replace(/[\r\n]/g,' ').trim().slice(0,180);const body=String(req.body.body||'').trim().slice(0,5000);const files=Array.isArray(req.body.attachments)?req.body.attachments:null;
  if(!subject||!body)return res.status(400).json({error:'اكتب عنوان الرسالة ومحتوى التذكرة.'});
  const attachments=[];let bytes=0;
  for(const file of (files||[]).slice(0,5)){const data=String(file.data||'').replace(/^data:[^;]+;base64,/,'');const type=String(file.type||'');if(!['application/pdf','image/png','image/jpeg','image/webp','text/plain'].includes(type))return res.status(400).json({error:'نوع ملف غير مسموح.'});bytes+=Buffer.byteLength(data,'base64');if(bytes>8*1024*1024)return res.status(413).json({error:'الحد الإجمالي للمرفقات 8 ميجابايت.'});attachments.push({name:String(file.name||'ticket-file').replace(/[\\/\r\n]/g,'_').slice(0,160),type,data});}
  await pool.query(`INSERT INTO ticket_deliveries(order_id,subject,body,attachments,status) VALUES($1,$2,$3,COALESCE($4::jsonb,'[]'::jsonb),'draft') ON CONFLICT(order_id) DO UPDATE SET subject=EXCLUDED.subject,body=EXCLUDED.body,attachments=COALESCE($4::jsonb,ticket_deliveries.attachments),status='draft',last_error=NULL,updated_at=now()`,[order.id,subject,body,files?JSON.stringify(attachments):null]);
  if(req.body.send===true){try{await sendTicketDelivery(order.id);}catch(err){await pool.query("UPDATE ticket_deliveries SET status='failed',last_error=$1,updated_at=now() WHERE order_id=$2",[String(err.message).slice(0,500),order.id]);await pool.query("UPDATE orders SET ticket_delivery_status='failed' WHERE id=$1",[order.id]);const detail=String(err.message||'تعذر إرسال الرسالة').slice(0,240); await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'ticket.send.failed',JSON.stringify({order_id:order.id,provider:(await getIntegrationSettings()).emailProvider,detail})]).catch(()=>{}); return res.status(502).json({error:'حُفظت الرسالة لكن تعذر إرسالها.',details:detail});}await pool.query("UPDATE orders SET ticket_delivery_status='sent' WHERE id=$1",[order.id]);}
  else await pool.query("UPDATE orders SET ticket_delivery_status='waiting' WHERE id=$1",[order.id]);
  await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,req.body.send===true?'ticket.send':'ticket.draft',JSON.stringify({order_id:order.id})]);res.json({ok:true,status:req.body.send===true?'sent':'draft'});
}));
app.post('/api/admin/orders/:id/delivery/resend', requireAdmin, asyncRoute(async(req,res)=>{try{await sendTicketDelivery(req.params.id);}catch(err){return res.status(502).json({error:err.message});}await pool.query("UPDATE orders SET ticket_delivery_status='sent' WHERE id=$1",[req.params.id]);await pool.query('INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)',[req.admin.id,'ticket.resend',JSON.stringify({order_id:req.params.id})]);res.json({ok:true});}));
app.use((err, _req, res, _next) => { console.error(err.message); res.status(500).json({ error: 'حدث خطأ في الخادم' }); });
if (process.env.CLOUDFLARE_WORKER !== '1') app.listen(PORT, () => console.log(`Ticket Arab API listening on ${PORT}`));
module.exports = app;
