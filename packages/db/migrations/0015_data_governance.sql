-- 0015: data governance for services/data-governance (docs/adr/0080-0083). ADDITIVE: new tables, one new role, and replacement of
-- three "append-only" guard functions so that ONE database role (axis_governance) can scrub/pseudonymise subject data. audit_events,
-- audit_checkpoints and every audit trigger are untouched: the audit chain is never rewritten (ADR-0080).
--
-- axis_governance: NOLOGIN, NOBYPASSRLS. It is granted to the data-governance service's login role by ops; every table keeps FORCED RLS, so
-- even this role sees one tenant per transaction. A trigger decides by current_user, so application code running as axis_app cannot
-- reach the scrub paths by setting a GUC.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'axis_governance') THEN
    CREATE ROLE axis_governance NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
GRANT USAGE ON SCHEMA axis TO axis_governance;
GRANT EXECUTE ON FUNCTION axis.current_tenant(), axis.set_tenant(uuid) TO axis_governance;

-- ---- governance tables ----------------------------------------------------------------------------------------------------------

-- A data subject is an opaque random id. Which person it is lives ONLY in governance_subject_identifiers (keyed HMAC lookups).
CREATE TABLE governance_subjects (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  subject_id  uuid NOT NULL DEFAULT gen_random_uuid(),
  -- Per-subject random salt mixed into the pseudonyms written to retained rows. Setting it to NULL (shred) makes those pseudonyms
  -- unrecomputable from an identifier even for a holder of the tenant key.
  salt        bytea CHECK (salt IS NULL OR octet_length(salt) = 32),
  shredded_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject_id),
  CHECK ((salt IS NULL) = (shredded_at IS NOT NULL))
);
SELECT axis.enable_tenant_rls('governance_subjects', 'tenant_id', 'SELECT');

-- lookup_hmac = HMAC-SHA256(per-tenant lookup key, kind || 0x00 || normalised value). Deleting these rows is the crypto-shred: after it
-- nothing maps an identifier to the subject id that audit events carry (ADR-0080).
CREATE TABLE governance_subject_identifiers (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  lookup_hmac  text NOT NULL CHECK (lookup_hmac ~ '^[0-9a-f]{64}$'),
  subject_id   uuid NOT NULL,
  kind         text NOT NULL CHECK (length(kind) BETWEEN 1 AND 40),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, lookup_hmac),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES governance_subjects (tenant_id, subject_id)
);
CREATE INDEX governance_subject_identifiers_subject_idx ON governance_subject_identifiers (tenant_id, subject_id);
SELECT axis.enable_tenant_rls('governance_subject_identifiers', 'tenant_id', 'SELECT');

-- Data-subject requests. `sealed_identifiers` is AES-256-GCM ciphertext (tenant key) so a crashed erase can resume; it is NULLed when the
-- request completes. `subject_ref` is the keyed pseudonym used in audit events.
CREATE TABLE governance_requests (
  tenant_id          uuid NOT NULL REFERENCES tenants (id),
  id                 uuid NOT NULL,
  kind               text NOT NULL CHECK (kind IN ('export', 'erase', 'restrict')),
  subject_id         uuid NOT NULL,
  subject_ref        text NOT NULL CHECK (subject_ref ~ '^sub_[0-9a-f]{32}$'),
  status             text NOT NULL CHECK (status IN ('received', 'verified', 'processing', 'completed', 'rejected', 'cancelled')),
  received_at        timestamptz NOT NULL,
  due_at             timestamptz NOT NULL,
  extended_until     timestamptz,
  extension_reason   text,
  verified_at        timestamptz,
  verified_method    text,
  requested_by       text NOT NULL,
  destination_region text,
  sealed_identifiers bytea,
  result             jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(result) = 'object'),
  rev                integer NOT NULL DEFAULT 1,
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX governance_requests_due_idx ON governance_requests (tenant_id, status, due_at);
SELECT axis.enable_tenant_rls('governance_requests', 'tenant_id', 'SELECT');

-- One row per (request, provider, phase): the resume point. Re-running a completed step is a no-op.
CREATE TABLE governance_steps (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  request_id  uuid NOT NULL,
  provider    text NOT NULL,
  phase       text NOT NULL CHECK (phase IN ('export', 'erase', 'verify')),
  status      text NOT NULL CHECK (status IN ('done', 'failed')),
  result      jsonb NOT NULL DEFAULT '{}',
  at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id, provider, phase),
  FOREIGN KEY (tenant_id, request_id) REFERENCES governance_requests (tenant_id, id)
);
SELECT axis.enable_tenant_rls('governance_steps', 'tenant_id', 'SELECT');

-- Legal holds (suspend purge/erase of the matching data) and restrictions (Art. 18: stop processing). Identifiers are sealed.
CREATE TABLE governance_holds (
  tenant_id          uuid NOT NULL REFERENCES tenants (id),
  id                 uuid NOT NULL,
  kind               text NOT NULL CHECK (kind IN ('legal_hold', 'restriction')),
  scope              text NOT NULL CHECK (scope IN ('tenant', 'subject', 'case')),
  subject_id         uuid,
  case_ref           text CHECK (case_ref IS NULL OR length(case_ref) <= 200),
  data_classes       text[],
  reason             text NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
  sealed_identifiers bytea,
  placed_by          text NOT NULL,
  placed_at          timestamptz NOT NULL,
  released_by        text,
  released_at        timestamptz,
  PRIMARY KEY (tenant_id, id),
  CHECK ((scope = 'subject') = (subject_id IS NOT NULL)),
  CHECK (kind = 'legal_hold' OR scope = 'subject')
);
CREATE INDEX governance_holds_active_idx ON governance_holds (tenant_id, kind) WHERE released_at IS NULL;
SELECT axis.enable_tenant_rls('governance_holds', 'tenant_id', 'SELECT');

CREATE TABLE governance_retention_policies (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  data_class  text NOT NULL CHECK (data_class ~ '^[a-z_]{2,30}$'),
  days        integer NOT NULL CHECK (days BETWEEN 1 AND 36500),
  updated_by  text NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, data_class)
);
SELECT axis.enable_tenant_rls('governance_retention_policies', 'tenant_id', 'SELECT');

CREATE TABLE governance_retention_runs (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  id           uuid NOT NULL,
  dry_run      boolean NOT NULL,
  started_at   timestamptz NOT NULL,
  finished_at  timestamptz,
  report       jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, id)
);
SELECT axis.enable_tenant_rls('governance_retention_runs', 'tenant_id', 'SELECT');

GRANT SELECT, INSERT, UPDATE, DELETE ON governance_subjects, governance_subject_identifiers, governance_requests, governance_steps,
  governance_holds, governance_retention_policies, governance_retention_runs TO axis_governance;
REVOKE DELETE ON governance_subjects, governance_requests, governance_steps, governance_holds, governance_retention_policies,
  governance_retention_runs FROM axis_governance;

-- ---- subject-data privileges for the governance role -----------------------------------------------------------------------------
GRANT SELECT, UPDATE, DELETE ON memory_chunks, memory_documents, members TO axis_governance;
GRANT SELECT, UPDATE ON sessions, api_keys TO axis_governance;
GRANT SELECT ON knowledge_bases, tenants TO axis_governance;
GRANT SELECT, UPDATE, DELETE ON end_users, channel_identities, conversations, conversation_threads, conversation_messages, link_challenges
  TO axis_governance;
GRANT SELECT, UPDATE ON runs, run_events, approvals, usage_events, eval_hub_docs TO axis_governance;
GRANT DELETE ON eval_hub_docs TO axis_governance;
GRANT SELECT ON invoices, audit_events TO axis_governance; -- audit read only (nothing else is granted on it)

-- ---- guard functions ---------------------------------------------------------------------------------------------------------------

-- run_events / usage_events: the governance role may rewrite ONLY the named columns (UPDATE); nobody may delete. Everyone else: unchanged
-- forbid_mutation semantics. TG_ARGV[0] = comma-separated columns the governance role may change.
CREATE FUNCTION axis.governance_scrub_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE cols text[] := string_to_array(TG_ARGV[0], ',');
        o jsonb; n jsonb; c text;
BEGIN
  IF TG_OP = 'UPDATE' AND current_user = 'axis_governance' THEN
    o := to_jsonb(OLD); n := to_jsonb(NEW);
    FOREACH c IN ARRAY cols LOOP o := o - c; n := n - c; END LOOP;
    IF o = n THEN RETURN NEW; END IF;
  END IF;
  RAISE EXCEPTION '% on % is forbidden: table is append-only', TG_OP, TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;

DROP TRIGGER run_events_append_only ON run_events;
CREATE TRIGGER run_events_append_only BEFORE UPDATE OR DELETE ON run_events
  FOR EACH ROW EXECUTE FUNCTION axis.governance_scrub_guard('data');
DROP TRIGGER usage_events_append_only ON usage_events;
CREATE TRIGGER usage_events_append_only BEFORE UPDATE OR DELETE ON usage_events
  FOR EACH ROW EXECUTE FUNCTION axis.governance_scrub_guard('actor,dimensions');

-- eval_hub_docs: same guard as 0013 plus a governance branch (scrub with rev+1, or delete) for any collection.
CREATE OR REPLACE FUNCTION axis.eval_hub_docs_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF current_user = 'axis_governance' THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    IF NEW.tenant_id = OLD.tenant_id AND NEW.coll = OLD.coll AND NEW.key = OLD.key AND NEW.rev = OLD.rev + 1 THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'stale or identity-changing update' USING ERRCODE = 'serialization_failure';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DELETE on eval_hub_docs is forbidden' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll IN ('datasets', 'suites', 'baselines', 'online', 'events') THEN
    RAISE EXCEPTION 'collection % is append-only', OLD.coll USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll = 'runs' AND OLD.data ->> 'status' NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'a finished eval run is immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll = 'runners' AND OLD.data ->> 'revoked_at' IS NOT NULL THEN
    RAISE EXCEPTION 'a revoked runner stays revoked' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll = 'tasks' AND OLD.data ->> 'state' = 'resolved' THEN
    RAISE EXCEPTION 'a resolved review task is immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.coll <> OLD.coll OR NEW.key <> OLD.key OR NEW.rev <> OLD.rev + 1 THEN
    RAISE EXCEPTION 'stale or identity-changing update' USING ERRCODE = 'serialization_failure';
  END IF;
  RETURN NEW;
END $$;

-- runs: a TERMINATED run is absorbing and `input` is immutable (0004). The governance role may scrub `input` (and only `input`) of a run.
CREATE OR REPLACE FUNCTION axis.terminal_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.state = 'terminated' THEN
    IF current_user = 'axis_governance' AND TG_TABLE_NAME = 'runs'
       AND (pg_catalog.to_jsonb(NEW) - 'input') = (pg_catalog.to_jsonb(OLD) - 'input') THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is terminated; no further changes', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION axis.immutable_columns_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE col text;
BEGIN
  FOREACH col IN ARRAY TG_ARGV LOOP
    IF current_user = 'axis_governance' AND TG_TABLE_NAME = 'runs' AND col = 'input' THEN CONTINUE; END IF;
    IF pg_catalog.to_jsonb(NEW) -> col IS DISTINCT FROM pg_catalog.to_jsonb(OLD) -> col THEN
      RAISE EXCEPTION '%.% is immutable', TG_TABLE_NAME, col USING ERRCODE = 'check_violation';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;

-- approvals: a decided approval is final (0004). The governance role may pseudonymise `decided_by` and drop the free-text `comment`.
CREATE OR REPLACE FUNCTION axis.approval_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.status NOT IN ('pending', 'escalated') THEN
    IF current_user = 'axis_governance'
       AND (pg_catalog.to_jsonb(NEW) - 'decided_by' - 'comment') = (pg_catalog.to_jsonb(OLD) - 'decided_by' - 'comment') THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'approval already %', OLD.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
