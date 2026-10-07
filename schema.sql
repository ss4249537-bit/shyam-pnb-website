CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname='user_role') THEN CREATE TYPE user_role AS ENUM ('ADMIN','OPERATOR','VIEWER','CUSTOMER'); END IF;
  BEGIN ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'CUSTOMER'; EXCEPTION WHEN duplicate_object THEN NULL; END;
END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname='day_status') THEN CREATE TYPE day_status AS ENUM ('OPEN','CLOSED','LOCKED'); END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname='pending_status') THEN CREATE TYPE pending_status AS ENUM ('PENDING','DEPOSITED','CANCELLED'); END IF; END $$;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(80) UNIQUE NOT NULL,
  display_name VARCHAR(160),
  password_hash TEXT NOT NULL,
  role user_role NOT NULL DEFAULT 'OPERATOR',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  failed_login_count INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS customers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(160) NOT NULL,
  mobile VARCHAR(20),
  account_ref VARCHAR(120),
  aadhaar_last4 CHAR(4),
  aadhaar_encrypted TEXT,
  notes TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(160);
CREATE INDEX IF NOT EXISTS idx_customers_mobile ON customers(mobile);
CREATE INDEX IF NOT EXISTS idx_customers_account_ref ON customers(account_ref);

CREATE TABLE IF NOT EXISTS business_days (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  record_date DATE UNIQUE NOT NULL,
  operator_id UUID REFERENCES users(id),
  counter_name VARCHAR(120),
  opening_cash NUMERIC(14,2) NOT NULL DEFAULT 0,
  physical_cash NUMERIC(14,2) NOT NULL DEFAULT 0,
  short_excess NUMERIC(14,2) NOT NULL DEFAULT 0,
  difference_reason TEXT,
  status day_status NOT NULL DEFAULT 'OPEN',
  closed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  business_day_id UUID NOT NULL REFERENCES business_days(id) ON DELETE CASCADE,
  customer_id UUID REFERENCES customers(id),
  transaction_type VARCHAR(30) NOT NULL CHECK (transaction_type IN ('DEPOSIT','WITHDRAWAL','SERVICE')),
  amount NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
  account_ref VARCHAR(120),
  description TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_transactions_day ON transactions(business_day_id);

CREATE TABLE IF NOT EXISTS pending_cash (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  business_day_id UUID NOT NULL REFERENCES business_days(id) ON DELETE CASCADE,
  customer_id UUID REFERENCES customers(id),
  amount NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
  due_date DATE,
  status pending_status NOT NULL DEFAULT 'PENDING',
  deposited_at TIMESTAMPTZ,
  notes TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pending_status_due ON pending_cash(status,due_date);

CREATE TABLE IF NOT EXISTS cash_denominations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  business_day_id UUID NOT NULL REFERENCES business_days(id) ON DELETE CASCADE,
  denomination INTEGER NOT NULL,
  quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
  UNIQUE(business_day_id, denomination)
);

CREATE TABLE IF NOT EXISTS service_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  business_day_id UUID NOT NULL REFERENCES business_days(id) ON DELETE CASCADE,
  customer_id UUID REFERENCES customers(id),
  service_name VARCHAR(120) NOT NULL,
  amount NUMERIC(14,2) NOT NULL DEFAULT 0,
  status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
  reference_no VARCHAR(120),
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  action VARCHAR(80) NOT NULL,
  entity_type VARCHAR(80),
  entity_id UUID,
  ip_address INET,
  user_agent TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS app_backups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_by UUID REFERENCES users(id),
  backup_version INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE business_days ADD COLUMN IF NOT EXISTS expected_cash NUMERIC(14,2) NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_business_date ON business_days(record_date);
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(160);
CREATE INDEX IF NOT EXISTS idx_customers_mobile ON customers(mobile);
CREATE INDEX IF NOT EXISTS idx_customers_account ON customers(account_ref);
ALTER TABLE customers ADD COLUMN IF NOT EXISTS aadhaar_encrypted TEXT;


DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname='subscription_status') THEN CREATE TYPE subscription_status AS ENUM ('PENDING_PAYMENT','TRIAL','ACTIVE','PAST_DUE','CANCELLED','EXPIRED'); END IF; END $$;
CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_code VARCHAR(40) NOT NULL DEFAULT 'PRO_MONTHLY',
  trial_amount_paise INTEGER NOT NULL DEFAULT 100,
  recurring_amount_paise INTEGER NOT NULL DEFAULT 2900,
  trial_started_at TIMESTAMPTZ,
  trial_ends_at TIMESTAMPTZ,
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  status subscription_status NOT NULL DEFAULT 'TRIAL',
  auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
  last_payment_id VARCHAR(100),
  last_payment_status VARCHAR(40),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id)
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status, current_period_end);
CREATE TABLE IF NOT EXISTS subscription_payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID REFERENCES subscriptions(id) ON DELETE CASCADE,
  provider VARCHAR(30) NOT NULL DEFAULT 'PAYTM_QR',
  provider_payment_id VARCHAR(120),
  provider_event_id VARCHAR(160),
  amount_paise INTEGER NOT NULL,
  currency CHAR(3) NOT NULL DEFAULT 'INR',
  status VARCHAR(40) NOT NULL,
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(provider, provider_payment_id),
  UNIQUE(provider, provider_event_id)
);
CREATE INDEX IF NOT EXISTS idx_subscription_payments_sub ON subscription_payments(subscription_id, created_at DESC);

-- Central website configuration for Admin-controlled changes that automatically appear for all users.
CREATE TABLE IF NOT EXISTS app_settings (
  key VARCHAR(120) PRIMARY KEY,
  value JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_by UUID REFERENCES users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO app_settings(key,value) VALUES
('public_contact', '"9621543891"'::jsonb),
('site_title', '"SHYAM PNB PRO"'::jsonb)
ON CONFLICT(key) DO NOTHING;

-- SHYAM PNB PRO final hardening / Paytm QR manual verification migration
-- One operator can have one record per date; different operators may use the same date.
ALTER TABLE business_days DROP CONSTRAINT IF EXISTS business_days_record_date_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_business_days_operator_date ON business_days(operator_id, record_date);

-- Public signup creates Operators. Existing legacy CUSTOMER accounts are migrated to Operator accounts.
UPDATE users SET role='OPERATOR' WHERE role='CUSTOMER';

ALTER TABLE subscription_payments ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE subscription_payments ADD COLUMN IF NOT EXISTS payment_time TIMESTAMPTZ;
ALTER TABLE subscription_payments ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE subscription_payments ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE subscription_payments ADD COLUMN IF NOT EXISTS verified_by UUID REFERENCES users(id);
ALTER TABLE subscription_payments ADD COLUMN IF NOT EXISTS admin_note TEXT;
UPDATE subscription_payments SET user_id=s.user_id FROM subscriptions s WHERE subscription_payments.subscription_id=s.id AND subscription_payments.user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_subscription_payments_user ON subscription_payments(user_id,submitted_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_subscription_payments_utr ON subscription_payments(LOWER(provider),LOWER(provider_payment_id)) WHERE provider_payment_id IS NOT NULL;

-- Paytm QR is the only payment method in this release. Remove obsolete gateway columns if upgrading an older database.
ALTER TABLE subscriptions DROP COLUMN IF EXISTS razorpay_customer_id;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS razorpay_subscription_id;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS razorpay_plan_id;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS razorpay_order_id;
UPDATE subscription_payments SET provider='PAYTM_QR' WHERE provider='RAZORPAY';
ALTER TABLE subscription_payments ALTER COLUMN provider SET DEFAULT 'PAYTM_QR';
DELETE FROM app_settings WHERE key IN ('razorpay','payment_gateway');
ALTER TABLE service_records ADD COLUMN IF NOT EXISTS mobile VARCHAR(20);
ALTER TABLE service_records ADD COLUMN IF NOT EXISTS account_ref VARCHAR(120);
ALTER TABLE service_records ADD COLUMN IF NOT EXISTS mode VARCHAR(40);
