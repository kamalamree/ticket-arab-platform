import { createServer } from 'node:http';
import { httpServerHandler } from 'cloudflare:node';
import { sendCustomSmtp } from './smtp-worker.mjs';

globalThis.__ticketArabSendCustomSmtp = sendCustomSmtp;

let apiHandlerPromise;
const runtimeVariables = [
  'SESSION_SECRET',
  'DATA_ENCRYPTION_KEY',
  'BREVO_API_KEY',
  'SMTP2GO_API_KEY',
  'RESEND_API_KEY',
  'SMTP_PROVIDER_NAME',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_SECURE',
  'SMTP_TLS_MODE',
  'SMTP_USER',
  'SMTP_PASSWORD',
  'MAIL_FROM',
  'TRUST_PROXY',
  'PAYPAL_ENV',
  'PAYPAL_CLIENT_ID',
  'PAYPAL_CLIENT_SECRET',
  'PAYMEGATE_API_KEY',
  'PAYMEGATE_WEBHOOK_SECRET',
  'HELEKET_MERCHANT_ID',
  'HELEKET_PAYMENT_API_KEY',
  'LEMON_SQUEEZY_API_KEY',
  'LEMON_SQUEEZY_STORE_ID',
  'LEMON_SQUEEZY_VARIANT_ID',
  'LEMON_SQUEEZY_WEBHOOK_SECRET',
  'SUPPORT_EMAIL',
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const isApi = url.pathname.startsWith('/api/') || url.pathname.startsWith('/webhooks/') || ['/robots.txt', '/sitemap.xml'].includes(url.pathname);
    const isHtml = request.method === 'GET' && (url.pathname === '/' || url.pathname.endsWith('/index.html') || !/\.[a-z0-9]{1,8}$/i.test(url.pathname));
    if (!isApi && !isHtml) return env.ASSETS.fetch(request);

    process.env.CLOUDFLARE_WORKER = '1';
    // PDFKit's CommonJS Node entry expects Node's __filename global. Workers
    // provide node compatibility APIs but do not define this module global.
    globalThis.__filename ||= '/worker.js';
    globalThis.__dirname ||= '/';
    process.env.DATABASE_URL = env.HYPERDRIVE.connectionString;
    const configuredFrontendOrigin = env.FRONTEND_ORIGIN || '';
    process.env.FRONTEND_ORIGIN = configuredFrontendOrigin.startsWith('https://') ? configuredFrontendOrigin : url.origin;
    for (const name of runtimeVariables) {
      if (env[name] !== undefined) process.env[name] = String(env[name]);
    }

    apiHandlerPromise ||= import('./index.js').then(({ default: app }) =>
      httpServerHandler(createServer(app)),
    );
    const handler = await apiHandlerPromise;
    const forwardedHeaders = new Headers(request.headers);
    if (request.cf?.country) forwardedHeaders.set('x-edge-country', request.cf.country);
    if (request.cf?.city) forwardedHeaders.set('x-edge-city', request.cf.city);
    if (request.cf?.region) forwardedHeaders.set('x-edge-region', request.cf.region);
    if (isApi) return handler.fetch(new Request(request, { headers: forwardedHeaders }), env, ctx);

    const page = await env.ASSETS.fetch(request);
    if (!page.ok || !page.headers.get('content-type')?.includes('text/html')) return page;
    try {
      const seoResponse = await handler.fetch(new Request(`${url.origin}/api/public/seo`, { headers: forwardedHeaders }), env, ctx);
      if (!seoResponse.ok) return page;
      const seo = await seoResponse.json();
      const isPrivate = url.pathname.startsWith('/admin') || url.pathname === '/support' || url.pathname.startsWith('/checkout/') || url.searchParams.has('paymegate_return') || url.searchParams.has('error');
      const privateLabel = url.pathname.startsWith('/admin') ? 'لوحة الإدارة' : url.pathname === '/support' ? 'الدعم' : 'إتمام الحجز';
      const title = isPrivate ? `${privateLabel} | ${seo.siteName}` : seo.title;
      const description = seo.description;
      const canonical = `${seo.siteUrl}/`;
      const assetUrl = value => new URL(value, url.origin).href;
      const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
      const tags = [
        `<meta name="description" content="${escape(description)}">`,
        ...(seo.keywords ? [`<meta name="keywords" content="${escape(seo.keywords)}">`] : []),
        `<meta name="robots" content="${isPrivate || !seo.allowIndex ? 'noindex, nofollow' : 'index, follow'}">`,
        ...(isPrivate ? [] : [`<link rel="canonical" href="${escape(canonical)}">`]),
        `<meta property="og:site_name" content="${escape(seo.siteName)}">`,
        `<meta property="og:locale" content="ar_AR">`,
        `<meta property="og:type" content="website">`,
        `<meta property="og:title" content="${escape(title)}">`,
        `<meta property="og:description" content="${escape(description)}">`,
        `<meta property="og:image" content="${escape(assetUrl(seo.socialImage))}">`,
        `<meta property="og:image:alt" content="${escape(seo.siteName)}">`,
        ...(!isPrivate ? [`<meta property="og:url" content="${escape(canonical)}">`] : []),
        `<meta name="twitter:card" content="summary_large_image">`,
        `<meta name="twitter:title" content="${escape(title)}">`,
        `<meta name="twitter:description" content="${escape(description)}">`,
        `<meta name="twitter:image" content="${escape(seo.socialImage)}">`,
        ...(seo.twitterHandle ? [`<meta name="twitter:site" content="@${escape(seo.twitterHandle)}">`] : []),
        `<link rel="icon" type="image/png" sizes="32x32" href="${escape(assetUrl(seo.faviconUrl))}">`,
        `<link rel="apple-touch-icon" href="${escape(assetUrl(seo.appleIconUrl))}">`,
        ...(!isPrivate && seo.allowIndex ? [`<script type="application/ld+json">${JSON.stringify({ '@context': 'https://schema.org', '@type': 'WebSite', name: seo.siteName, url: canonical, description }).replace(/</g, '\\u003c')}</script>`] : []),
      ].join('');
      let html = await page.text();
      html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escape(title)}</title>`)
        .replace(/<meta\s+name=["']description["'][^>]*>/gi, '')
        .replace(/<meta\s+name=["']robots["'][^>]*>/gi, '')
        .replace(/<meta\s+name=["']keywords["'][^>]*>/gi, '')
        .replace(/<meta\s+property=["']og:[^"']+["'][^>]*>/gi, '')
        .replace(/<meta\s+name=["']twitter:[^"']+["'][^>]*>/gi, '')
        .replace(/<link\s+rel=["']canonical["'][^>]*>/gi, '')
        .replace(/<link\s+rel=["'](?:icon|apple-touch-icon)["'][^>]*>/gi, '')
        .replace('</head>', `${tags}</head>`);
      const headers = new Headers(page.headers);
      headers.delete('Content-Length');
      headers.delete('Content-Encoding');
      headers.delete('ETag');
      headers.set('Content-Type', 'text/html; charset=utf-8');
      headers.set('Cache-Control', 'public, max-age=0, must-revalidate');
      return new Response(html, { status: page.status, statusText: page.statusText, headers });
    } catch (error) {
      console.error('SEO metadata injection failed:', error);
      return page;
    }
  },
};
