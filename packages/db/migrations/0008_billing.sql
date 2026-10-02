-- 0008: usage ledger, period seals, conflict reports, invoices for services/billing (docs/adr/0018). ADDITIVE: new tables only.
-- Every table carries tenant_id and FORCED RLS, and is INSERT-ONLY for the app role AND for everyone else (forbid_mutation triggers):
-- corrections are compensating entries, a closed period is a sealed row, an invoice is never edited.

CREATE TABLE usage_events (
  tenant_id           uuid NOT NULL REFERENCES tenants (id),
  id                  uuid NOT NULL DEFAULT gen_random_uuid(),
  idempotency_key     text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 512),
  payload_hash        text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  entry_type          text NOT NULL CHECK (entry_type IN ('usage', 'adjustment')),
  meter               text NOT NULL CHECK (meter IN ('tokens_in', 'tokens_out', 'runtime_seconds', 'tool_executions',
                                                     'voice_minutes', 'storage_gb_hours', 'marketplace_installs')),
  quantity            bigint NOT NULL CHECK (quantity BETWEEN -9007199254740991 AND 9007199254740991),
  event_time          timestamptz NOT NULL,
  recorded_at         timestamptz NOT NULL DEFAULT now(),
  period_id           text NOT NULL CHECK (period_id ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  original_period_id  text CHECK (original_period_id ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  dimensions          jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(dimensions) = 'object'),
  source              text NOT NULL CHECK (length(source) BETWEEN 1 AND 64),
  reason              text,
  actor               text,
  corrects_key        text,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key),
  CHECK ((entry_type = 'usage' AND quantity >= 0)
      OR (entry_type = 'adjustment' AND quantity <> 0 AND reason IS NOT NULL AND length(reason) >= 3 AND actor IS NOT NULL))
);
CREATE INDEX usage_events_period_idx ON usage_events (tenant_id, period_id, meter);
CREATE INDEX usage_events_time_idx ON usage_events (tenant_id, event_time);

-- A closed period: hash-chained per tenant (seq/prev_seal_hash) and signed. One row per (tenant, period), never changed.
CREATE TABLE billing_period_seals (
  tenant_id        uuid NOT NULL REFERENCES tenants (id),
  period_id        text NOT NULL CHECK (period_id ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  seq              integer NOT NULL CHECK (seq >= 1),
  prev_seal_hash   text NOT NULL CHECK (prev_seal_hash ~ '^[0-9a-f]{64}$'),
  seal_hash        text NOT NULL CHECK (seal_hash ~ '^[0-9a-f]{64}$'),
  signature        text NOT NULL,
  key_id           text NOT NULL,
  event_count      bigint NOT NULL CHECK (event_count >= 0),
  rows_digest      text NOT NULL CHECK (rows_digest ~ '^[0-9a-f]{64}$'),
  totals           jsonb NOT NULL,
  closed_at        timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, period_id),
  UNIQUE (tenant_id, seq)
);

-- Defence in depth for "closed periods are immutable": an entry can never be inserted into a sealed period, whatever the caller computed.
-- The shared advisory lock orders inserts against the sealer, which takes the exclusive lock (see PgUsageLedger.closePeriod).
CREATE FUNCTION axis.usage_period_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock_shared(727280, pg_catalog.hashtext(NEW.tenant_id::pg_catalog.text));
  IF EXISTS (SELECT 1 FROM public.billing_period_seals s WHERE s.tenant_id = NEW.tenant_id AND s.period_id = NEW.period_id) THEN
    RAISE EXCEPTION 'billing period % is sealed', NEW.period_id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER usage_period_guard BEFORE INSERT ON usage_events FOR EACH ROW EXECUTE FUNCTION axis.usage_period_guard();

-- Same idempotency key, different payload: rejected and recorded here for review. Never overwrites the original.
CREATE TABLE usage_conflicts (
  tenant_id              uuid NOT NULL REFERENCES tenants (id),
  id                     uuid NOT NULL DEFAULT gen_random_uuid(),
  idempotency_key        text NOT NULL,
  existing_payload_hash  text NOT NULL,
  offered_payload_hash   text NOT NULL,
  source                 text NOT NULL,
  detected_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key, offered_payload_hash)
);

-- A rated invoice. Never edited: a re-rating is a new revision.
CREATE TABLE invoices (
  tenant_id     uuid NOT NULL REFERENCES tenants (id),
  id            uuid NOT NULL DEFAULT gen_random_uuid(),
  period_id     text NOT NULL CHECK (period_id ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  revision      integer NOT NULL CHECK (revision >= 1),
  plan_id       text NOT NULL,
  price_book    text NOT NULL,
  currency      text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  lines         jsonb NOT NULL,
  total_micro   bigint NOT NULL,
  invoice_hash  text NOT NULL CHECK (invoice_hash ~ '^[0-9a-f]{64}$'),
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, period_id, revision)
);

CREATE TABLE invoice_provider_links (
  tenant_id            uuid NOT NULL REFERENCES tenants (id),
  invoice_id           uuid NOT NULL,
  provider             text NOT NULL,
  provider_invoice_id  text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, invoice_id, provider),
  UNIQUE (tenant_id, provider, provider_invoice_id),
  FOREIGN KEY (tenant_id, invoice_id) REFERENCES invoices (tenant_id, id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['usage_events', 'billing_period_seals', 'usage_conflicts', 'invoices', 'invoice_provider_links'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation()', t || '_append_only', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION axis.forbid_mutation()', t || '_no_truncate', t);
    PERFORM axis.enable_tenant_rls(t, 'tenant_id', 'SELECT, INSERT');
  END LOOP;
END $$;
