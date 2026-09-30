-- 0002: tenant-owned control-plane tables. Every table: tenant_id NOT NULL + forced RLS.

CREATE TABLE members (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  user_ref   text NOT NULL,                  -- WorkOS user id
  email      text NOT NULL,
  role       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, user_ref)
);
SELECT axis.enable_tenant_rls('members', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');

CREATE TABLE api_keys (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  name       text NOT NULL,
  prefix     text NOT NULL,
  key_hash   bytea NOT NULL,                 -- hash only; the secret is shown once
  scopes     text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (prefix)
);
SELECT axis.enable_tenant_rls('api_keys', 'tenant_id', 'SELECT, INSERT, UPDATE');

CREATE TABLE model_credentials (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  provider   text NOT NULL,
  label      text NOT NULL,
  secret_ref text NOT NULL,                  -- pointer into the KMS-backed secret store, never the key itself
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, provider, label)
);
SELECT axis.enable_tenant_rls('model_credentials', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');

CREATE TABLE blueprints (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,62}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);
SELECT axis.enable_tenant_rls('blueprints', 'tenant_id', 'SELECT, INSERT');

CREATE TABLE blueprint_versions (
  tenant_id     uuid NOT NULL,
  id            uuid NOT NULL DEFAULT gen_random_uuid(),
  blueprint_id  uuid NOT NULL,
  version       text NOT NULL,
  risk_level    text NOT NULL CHECK (risk_level IN ('minimal', 'limited', 'high')),
  abl           jsonb NOT NULL,
  content_hash  text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
  signature     text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, blueprint_id, version),
  FOREIGN KEY (tenant_id, blueprint_id) REFERENCES blueprints (tenant_id, id)
);
CREATE TRIGGER blueprint_versions_immutable BEFORE UPDATE OR DELETE ON blueprint_versions
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
SELECT axis.enable_tenant_rls('blueprint_versions', 'tenant_id', 'SELECT, INSERT');

CREATE TABLE policy_packs (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,62}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);
SELECT axis.enable_tenant_rls('policy_packs', 'tenant_id', 'SELECT, INSERT');

CREATE TABLE policy_pack_versions (
  tenant_id    uuid NOT NULL,
  id           uuid NOT NULL DEFAULT gen_random_uuid(),
  pack_id      uuid NOT NULL,
  version      text NOT NULL,
  source       jsonb NOT NULL,               -- policy DSL document
  rego         text NOT NULL,                -- compiled output
  content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, pack_id, version),
  FOREIGN KEY (tenant_id, pack_id) REFERENCES policy_packs (tenant_id, id)
);
CREATE TRIGGER policy_pack_versions_immutable BEFORE UPDATE OR DELETE ON policy_pack_versions
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
SELECT axis.enable_tenant_rls('policy_pack_versions', 'tenant_id', 'SELECT, INSERT');

CREATE TABLE runs (
  tenant_id         uuid NOT NULL REFERENCES tenants (id),
  id                uuid NOT NULL DEFAULT gen_random_uuid(),
  blueprint_name    text NOT NULL,
  blueprint_version text NOT NULL,
  state             text NOT NULL DEFAULT 'spawn'
                    CHECK (state IN ('spawn', 'ready', 'running', 'waiting', 'suspended', 'terminated')),
  exit_reason       text,
  trace_id          text NOT NULL CHECK (trace_id ~ '^[0-9a-f]{32}$'),
  input             jsonb NOT NULL DEFAULT '{}',
  idempotency_key   text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  finished_at       timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key)
);
SELECT axis.enable_tenant_rls('runs', 'tenant_id', 'SELECT, INSERT, UPDATE');

CREATE TABLE processes (
  tenant_id   uuid NOT NULL,
  pid         text NOT NULL CHECK (pid ~ '^axp_[0-9A-HJKMNP-TV-Z]{26}$'),
  ppid        text CHECK (ppid IS NULL OR ppid ~ '^axp_[0-9A-HJKMNP-TV-Z]{26}$'),
  run_id      uuid NOT NULL,
  state       text NOT NULL DEFAULT 'spawn'
              CHECK (state IN ('spawn', 'ready', 'running', 'waiting', 'suspended', 'terminated')),
  exit_reason text CHECK (exit_reason IS NULL OR exit_reason IN
              ('completed', 'failed', 'killed', 'budget_exceeded', 'policy_denied', 'timeout', 'parent_terminated')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, pid),
  FOREIGN KEY (tenant_id, run_id) REFERENCES runs (tenant_id, id),
  FOREIGN KEY (tenant_id, ppid) REFERENCES processes (tenant_id, pid),
  CHECK ((state = 'terminated') = (exit_reason IS NOT NULL))
);
SELECT axis.enable_tenant_rls('processes', 'tenant_id', 'SELECT, INSERT, UPDATE');

-- Event-sourced run log: append-only, gapless per run.
CREATE TABLE run_events (
  tenant_id      uuid NOT NULL,
  run_id         uuid NOT NULL,
  sequence       bigint NOT NULL CHECK (sequence >= 1),
  type           text NOT NULL,
  pid            text NOT NULL,
  data           jsonb NOT NULL DEFAULT '{}',
  audit_event_id uuid,
  at             timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, run_id, sequence),
  FOREIGN KEY (tenant_id, run_id) REFERENCES runs (tenant_id, id)
);
CREATE TRIGGER run_events_append_only BEFORE UPDATE OR DELETE ON run_events
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
SELECT axis.enable_tenant_rls('run_events', 'tenant_id', 'SELECT, INSERT');

CREATE TABLE approvals (
  tenant_id    uuid NOT NULL,
  id           uuid NOT NULL DEFAULT gen_random_uuid(),
  run_id       uuid NOT NULL,
  pid          text NOT NULL,
  action       text NOT NULL,
  roles        text[] NOT NULL,
  status       text NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'escalated')),
  requested_at timestamptz NOT NULL DEFAULT now(),
  sla_deadline timestamptz NOT NULL,
  decided_by   text,
  decided_at   timestamptz,
  comment      text,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES runs (tenant_id, id)
);
SELECT axis.enable_tenant_rls('approvals', 'tenant_id', 'SELECT, INSERT, UPDATE');

CREATE TABLE kill_switches (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  scope      text NOT NULL CHECK (scope IN ('tenant', 'agent', 'tool')),
  target     text NOT NULL DEFAULT '',
  engaged    boolean NOT NULL,
  reason     text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, scope, target),
  CHECK ((scope = 'tenant') = (target = ''))
);
SELECT axis.enable_tenant_rls('kill_switches', 'tenant_id', 'SELECT, INSERT, UPDATE');

CREATE TABLE budgets (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  id        uuid NOT NULL DEFAULT gen_random_uuid(),
  scope     text NOT NULL CHECK (scope IN ('tenant', 'agent', 'run')),
  target    text NOT NULL DEFAULT '',
  metric    text NOT NULL CHECK (metric IN ('tokens', 'cost_usd', 'tool_calls', 'runtime_seconds')),
  period    text NOT NULL CHECK (period IN ('run', 'hour', 'day', 'month')),
  soft      numeric CHECK (soft IS NULL OR soft >= 0),
  hard      numeric CHECK (hard IS NULL OR hard >= 0),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, scope, target, metric, period),
  CHECK (soft IS NULL OR hard IS NULL OR soft <= hard)
);
SELECT axis.enable_tenant_rls('budgets', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');
