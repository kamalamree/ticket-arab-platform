# Ticket Arab

Arabic RTL concert ticket storefront built with React, Vite, TypeScript, Tailwind CSS and Lucide. The Express API uses PostgreSQL on Neon, password-hashed admin accounts, signed HTTP-only admin cookies, PayPal hosted card fields and Paymegate hosted checkout, QR tickets and email delivery.

## Local setup

1. Rotate any Neon database password that was shared in chat or another public place. Create `server/.env` from `server/.env.example` and add the rotated connection string, a random `SESSION_SECRET`, a separate random `DATA_ENCRYPTION_KEY` (at least 32 bytes), and sandbox PayPal credentials. `DATA_ENCRYPTION_KEY` encrypts provider and mail credentials managed from the dashboard; keep it backed up and stable or saved credentials cannot be decrypted. Configure Brevo API or SMTP in the admin email settings to enable support notifications and ticket delivery. Brevo keys may also be set with BREVO_API_KEY.
2. Install frontend and server dependencies: run `npm install` in the project root and `npm install` in `server/`.
3. Create or update the schema with `npm run db:setup` from `server/`.
4. Create the first administrator with `npm run admin:create` from `server/`. Use a strong unique password. This command stores a bcrypt hash.
5. Start the API with `npm run dev` from `server/` and the storefront with `npm run dev` from the project root. Vite proxies `/api` to the local API.

## Checkout and admin workflow

PayPal hosted card fields load after the server creates a PayPal order in USD. Card details go directly to PayPal and are not stored by this service. Ticket prices remain displayed and stored in the currency selected for the event; at checkout the server converts that amount to USD using the latest available Frankfurter reference rate, shows the USD charge and quote date, and stores the rate with the payment. Rates are published daily and are indicative; the card issuer may apply its own conversion fees. Checkout stops safely if a current rate cannot be obtained. Keep `PAYPAL_ENV=sandbox` for development. Switch to live credentials and `PAYPAL_ENV=live` only when the PayPal account is approved for Advanced Card Payments.


Paymegate is an optional hosted checkout. Add its live API key and webhook signing secret from the admin integration page, then configure the public HTTPS `https://www.ticketarab.com/webhooks/paymegate` URL (route this path to the Node API server) in the Paymegate merchant dashboard. The server verifies the timestamped HMAC signature and matches the order UUID, external order number, amount, and currency before marking a payment paid. Paymegate's documented live order API does not accept test API keys, so a complete checkout test creates a real provider order and must be done with a low-value payment. The API key stays server-side. See [Paymegate Merchant API](https://www.paymegate.com/developers/api).

Outgoing email supports Brevo API v3, SMTP2GO API, Resend API, and a built-in custom SMTP sender. The HTTPS APIs work from Cloudflare Workers; add each provider key in admin email settings or as a Worker secret. The custom SMTP option accepts settings for any external SMTP host: provider name, host, port, username/password, sender, and automatic/TLS/STARTTLS mode. It sends SMTP directly over Cloudflare TCP sockets without Nodemailer; port 25 is blocked by Cloudflare, so use 465 (implicit TLS), 587 (STARTTLS), or another secure submission port supported by your provider. Some hosts behind Cloudflare proxy IPs or private addresses cannot be reached from Workers. Credentials saved in the admin panel are encrypted in Neon. The admin page includes a test-email action; success means the SMTP server accepted the message, while provider delivery logs determine final inbox or bounce status.

After payment, the customer gets a unique TA transaction number, a downloadable PDF invoice and an invoice email when SMTP is configured. The invoice says the ticket is being prepared. Paid orders appear in the admin ticket-preparation page, where an administrator can prepare the email and attach PDF, image or text ticket files. The system adds each ticket QR code and emails the prepared ticket. Failed and completed attempts appear in the payment log with request IP, user agent, device category and referrer origin when available. It does not collect GPS location or card details.

Visitors can use the support page to send a message to the admin inbox. Replies can be emailed to the visitor. Payment credentials, SMTP settings and the support email can be updated in the admin integration settings; secrets are encrypted in Neon with DATA_ENCRYPTION_KEY and never returned to the browser. Set TRUST_PROXY only to the exact trusted proxy configuration used by the deployment so logged client IP addresses are accurate.

Ticket prices entered in the admin dashboard use a three-letter ISO currency code such as EGP, SAR, EUR or USD. See [Frankfurter rate documentation](https://frankfurter.dev/) for available currency pairs and daily reference rates. PayPal and Paymegate charge in USD.

## Database

`server/schema.sql` creates the admins, events, ticket types, orders, order items, tickets, payments, support inbox, ticket delivery drafts, encrypted admin settings and admin audit log tables. Run `npm run db:seed-events` from `server/` to import the checked upcoming listings represented in `/example`; the event currency codes are preserved. Seeded ticket quantities start at zero because verified sale inventory was not supplied, so the booking buttons stay disabled until inventory is assigned from **الحفلات والتذاكر** in the admin dashboard. The seed command preserves any ticket price and stock already present in the database when it is run again.

## Deployment

### Cloudflare Workers

The Worker serves the Vite site as Static Assets and runs the Express API. Neon connects through the existing Hyperdrive binding in `wrangler.jsonc`. Cloudflare builds and deploys both parts from the repository root.

#### One-time Cloudflare setup

1. Confirm the Cloudflare account has the `ticket-arab` Worker and the Hyperdrive configuration referenced in `wrangler.jsonc`. The Hyperdrive connection string must point to the production Neon database; never put that URL in GitHub.
2. In **Workers & Pages → ticket-arab → Settings → Variables and Secrets**, add `SESSION_SECRET` and `DATA_ENCRYPTION_KEY` as secrets. Use separate random values with at least 32 bytes each. Keep `DATA_ENCRYPTION_KEY` backed up and stable: changing it prevents the app from decrypting credentials saved in Neon.
3. Add optional provider credentials as Worker secrets only if you want them supplied through environment variables. Payment and email credentials can instead be entered in the admin settings, where they are encrypted in Neon.
4. Apply `server/schema.sql` and migrations to Neon and create the initial admin before sending production traffic. For the existing database, use the private local `server/.env` and the documented server scripts.
5. Configure the production custom domain on the Worker once in Cloudflare. This repository deployment does not change Worker routes or custom domains.

#### GitHub automatic deployment

The workflow in `.github/workflows/deploy-cloudflare.yml` runs on pull requests to `main` to check the production build, and deploys on pushes to `main`.

1. Push this project to a GitHub repository using the `main` branch.
2. Create a Cloudflare API token for CI/CD with **Workers Editor** access scoped to the existing `ticket-arab` Worker. If the Worker has not been created yet, the first deployment needs account-level Workers Admin access to create it. See Cloudflare's [Workers permissions](https://developers.cloudflare.com/workers/authorization/workers/) and [GitHub Actions guide](https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/).
3. In GitHub, open **Settings → Secrets and variables → Actions** and add the token as `CLOUDFLARE_API_TOKEN`. The Cloudflare account ID and Worker name are already in `wrangler.jsonc`; they are identifiers, not credentials.
4. Confirm the required Cloudflare Worker secrets and Hyperdrive binding are set, then merge or push to `main`. The workflow installs both lockfile-based dependency sets, builds the storefront, and deploys with Wrangler. Pull requests build but do not deploy.

For SMTP mail delivery, run the API as a regular Node.js service; SMTP delivery is unavailable in the Cloudflare Worker runtime. Never commit `.env`, `.dev.vars`, database URLs, provider keys, or SMTP credentials. The repository has not been uploaded to GitHub from this workspace.
