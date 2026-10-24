CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS admins (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  session_version integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE admins ADD COLUMN IF NOT EXISTS session_version integer NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS admin_password_resets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id uuid NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS admin_password_resets_expiry_idx ON admin_password_resets(expires_at);
CREATE TABLE IF NOT EXISTS events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  venue text NOT NULL,
  city text NOT NULL,
  country text NOT NULL,
  event_date timestamptz NOT NULL,
  image_url text NOT NULL DEFAULT '',
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ticket_types (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES events(id),
  name text NOT NULL,
  price numeric(12,2) NOT NULL CHECK(price >= 0),
  currency char(3) NOT NULL DEFAULT 'USD',
  quantity_available integer NOT NULL CHECK(quantity_available >= 0),
  quantity_sold integer NOT NULL DEFAULT 0 CHECK(quantity_sold >= 0),
  quantity_reserved integer NOT NULL DEFAULT 0 CHECK(quantity_reserved >= 0),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_number text NOT NULL UNIQUE,
  buyer_name text NOT NULL,
  buyer_email text NOT NULL,
  buyer_phone text,
  total_amount numeric(12,2) NOT NULL CHECK(total_amount >= 0),
  currency char(3) NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','cancelled','refunded')),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '15 minutes'),
  invoice_token_hash text,
  invoice_sent_at timestamptz,
  ticket_delivery_status text NOT NULL DEFAULT 'waiting',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS order_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL REFERENCES orders(id),
  ticket_type_id uuid NOT NULL REFERENCES ticket_types(id),
  quantity integer NOT NULL CHECK(quantity > 0),
  unit_price numeric(12,2) NOT NULL,
  total_price numeric(12,2) NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL REFERENCES orders(id),
  ticket_type_id uuid NOT NULL REFERENCES ticket_types(id),
  code uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  status text NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','used','cancelled')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS payments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL REFERENCES orders(id),
  provider text NOT NULL,
  provider_order_id text UNIQUE,
  provider_capture_id text,
  status text NOT NULL DEFAULT 'created',
  amount numeric(12,2) NOT NULL,
  currency char(3) NOT NULL,
  display_amount numeric(12,2),
  display_currency char(3),
  exchange_rate numeric(20,10),
  exchange_rate_date date,
  client_ip text,
  country_code char(2),
  country_name text,
  region text,
  city text,
  user_agent text,
  referrer_origin text,
  device_type text,
  failure_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS admin_logs (
  id bigserial PRIMARY KEY,
  admin_id uuid REFERENCES admins(id),
  action text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS payment_webhook_events (
  provider text NOT NULL,
  event_id text NOT NULL,
  order_uuid text NOT NULL,
  transaction_uuid text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, event_id)
);
CREATE TABLE IF NOT EXISTS support_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_number text,
  sender_name text NOT NULL,
  sender_email text NOT NULL,
  subject text NOT NULL,
  message text NOT NULL,
  status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','replied','closed')),
  admin_reply text,
  replied_at timestamptz,
  viewed_at timestamptz,
  archived_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS viewed_at timestamptz;
ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS archived_at timestamptz;
CREATE TABLE IF NOT EXISTS visitor_events (
  id bigserial PRIMARY KEY,
  ip_address text NOT NULL,
  country_code char(2),
  country_name text,
  region text,
  city text,
  path text NOT NULL,
  referrer_origin text,
  device_type text NOT NULL DEFAULT 'unknown',
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ticket_deliveries (
  order_id uuid PRIMARY KEY REFERENCES orders(id),
  subject text NOT NULL,
  body text NOT NULL,
  attachments jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sent','failed')),
  sent_at timestamptz,
  last_error text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS admin_settings (
  settings_key text PRIMARY KEY,
  encrypted_value jsonb NOT NULL,
  updated_by uuid REFERENCES admins(id),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE ticket_types ADD COLUMN IF NOT EXISTS quantity_reserved integer NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS expires_at timestamptz NOT NULL DEFAULT (now() + interval '15 minutes');
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_token_hash text;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_sent_at timestamptz;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS ticket_delivery_status text NOT NULL DEFAULT 'waiting';
ALTER TABLE payments ADD COLUMN IF NOT EXISTS client_ip text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS country_code char(2);
ALTER TABLE payments ADD COLUMN IF NOT EXISTS country_name text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS region text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS city text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS user_agent text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS referrer_origin text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS device_type text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS failure_reason text;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS display_amount numeric(12,2);
ALTER TABLE payments ADD COLUMN IF NOT EXISTS display_currency char(3);
ALTER TABLE payments ADD COLUMN IF NOT EXISTS exchange_rate numeric(20,10);
ALTER TABLE payments ADD COLUMN IF NOT EXISTS exchange_rate_date date;
CREATE INDEX IF NOT EXISTS events_date_idx ON events(event_date) WHERE is_active=true;
CREATE INDEX IF NOT EXISTS orders_created_idx ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_order_idx ON tickets(order_id);
CREATE INDEX IF NOT EXISTS support_messages_created_idx ON support_messages(created_at DESC);
CREATE INDEX IF NOT EXISTS payment_webhook_events_received_idx ON payment_webhook_events(received_at DESC);
CREATE INDEX IF NOT EXISTS payments_created_idx ON payments(created_at DESC);
CREATE INDEX IF NOT EXISTS visitor_events_created_idx ON visitor_events(created_at DESC);
CREATE INDEX IF NOT EXISTS visitor_events_country_idx ON visitor_events(country_code,created_at DESC);

