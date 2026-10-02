"use client";
import { useState } from "react";
import { Badge, Button, Dialog, EmptyState, Input, Select, Table, Tabs, useToast } from "@axis/ui";
import { api, type ApiKey, type Budget, type Member, type ModelKey, type Role } from "@/lib/api";
import { ROLES } from "@/lib/roles";
import { useAction, useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";
import { useCan, useSession } from "@/components/session";

const roleOptions = ROLES.map((r) => ({ value: r, label: r }));

function Members() {
  const res = useResource(() => api.listMembers());
  const canEdit = useCan("admin.members");
  const me = useSession().member;
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const toast = useToast();
  const invite = useAction(() => api.inviteMember(email, role));
  const change = useAction((id: string, r: Role) => api.updateMemberRole(id, r));
  const remove = useAction((id: string) => api.removeMember(id));
  return (
    <div className="flex flex-col gap-4">
      <ResourceView resource={res}>
        {(p) => (
          <Table<Member>
            caption="Members"
            rows={p.items}
            rowKey={(m) => m.id}
            columns={[
              { key: "email", header: "Email", render: (m) => m.email },
              {
                key: "status",
                header: "Status",
                render: (m) => (
                  <Badge tone={m.status === "active" ? "good" : "neutral"}>{m.status}</Badge>
                ),
              },
              {
                key: "role",
                header: "Role",
                render: (m) =>
                  canEdit && m.id !== me.id ? (
                    <Select
                      label={`Role for ${m.email}`}
                      value={m.role}
                      options={roleOptions}
                      onChange={async (e) => {
                        if (await change.run(m.id, e.target.value as Role)) {
                          toast.push("Role updated", "success");
                          res.reload();
                        }
                      }}
                    />
                  ) : (
                    m.role
                  ),
              },
              {
                key: "rm",
                header: "",
                render: (m) =>
                  canEdit && m.id !== me.id ? (
                    <Button
                      variant="danger"
                      aria-label={`Remove ${m.email}`}
                      onClick={async () => {
                        await remove.run(m.id);
                        res.reload();
                      }}
                    >
                      Remove
                    </Button>
                  ) : null,
              },
            ]}
          />
        )}
      </ResourceView>
      {change.error ? <ErrorNote error={change.error} /> : null}
      {remove.error ? <ErrorNote error={remove.error} /> : null}
      {canEdit ? (
        <form
          aria-label="Invite member"
          className="flex max-w-xl flex-wrap items-end gap-3"
          onSubmit={async (e) => {
            e.preventDefault();
            if (await invite.run()) {
              setEmail("");
              toast.push("Member invited", "success");
              res.reload();
            }
          }}
        >
          <Input
            label="Email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <Select
            label="Role"
            value={role}
            options={roleOptions}
            onChange={(e) => setRole(e.target.value as Role)}
          />
          <Button type="submit" loading={invite.pending}>
            Invite
          </Button>
          {invite.error ? <ErrorNote error={invite.error} /> : null}
        </form>
      ) : null}
    </div>
  );
}

function ApiKeys() {
  const res = useResource(() => api.listApiKeys());
  const [name, setName] = useState("");
  const [env, setEnv] = useState("dev");
  const [revealed, setRevealed] = useState<{ name: string; secret: string } | undefined>();
  const [copied, setCopied] = useState(false);
  const create = useAction(() =>
    api.createApiKey({
      name,
      scopes: ["runs:read", "runs:write"],
      environment: env,
      expires_in_days: 90,
    }),
  );
  const rotate = useAction((id: string) => api.rotateApiKey(id));
  const revoke = useAction((id: string) => api.revokeApiKey(id));
  const show = (k: ApiKey | undefined) => {
    if (k?.secret) {
      setCopied(false);
      setRevealed({ name: k.name, secret: k.secret });
    }
    res.reload();
  };
  return (
    <div className="flex flex-col gap-4">
      <ResourceView resource={res}>
        {(p) => (
          <Table<ApiKey>
            caption="API keys"
            rows={p.items}
            rowKey={(k) => k.id}
            empty={
              <EmptyState
                title="No API keys"
                description="Create a key for scripts, CI or the SDKs."
              />
            }
            columns={[
              { key: "name", header: "Name", render: (k) => k.name },
              { key: "prefix", header: "Key", render: (k) => <code>{k.prefix}_...</code> },
              { key: "env", header: "Environment", render: (k) => k.environment },
              { key: "exp", header: "Expires", render: (k) => formatTime(k.expires_at) },
              {
                key: "st",
                header: "Status",
                render: (k) =>
                  k.revoked_at ? (
                    <Badge tone="bad">revoked</Badge>
                  ) : (
                    <Badge tone="good">active</Badge>
                  ),
              },
              {
                key: "act",
                header: "",
                render: (k) =>
                  k.revoked_at ? null : (
                    <div className="flex gap-2">
                      <Button
                        variant="secondary"
                        aria-label={`Rotate ${k.name}`}
                        onClick={async () => show(await rotate.run(k.id))}
                      >
                        Rotate
                      </Button>
                      <Button
                        variant="danger"
                        aria-label={`Revoke ${k.name}`}
                        onClick={async () => {
                          await revoke.run(k.id);
                          res.reload();
                        }}
                      >
                        Revoke
                      </Button>
                    </div>
                  ),
              },
            ]}
          />
        )}
      </ResourceView>
      {rotate.error ? <ErrorNote error={rotate.error} /> : null}
      {revoke.error ? <ErrorNote error={revoke.error} /> : null}
      <form
        aria-label="Create API key"
        className="flex max-w-xl flex-wrap items-end gap-3"
        onSubmit={async (e) => {
          e.preventDefault();
          const k = await create.run();
          if (k) {
            setName("");
            show(k);
          }
        }}
      >
        <Input
          label="Key name"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={80}
        />
        <Select
          label="Environment"
          value={env}
          onChange={(e) => setEnv(e.target.value)}
          options={[
            { value: "dev", label: "dev" },
            { value: "staging", label: "staging" },
            { value: "prod", label: "prod" },
          ]}
        />
        <Button type="submit" loading={create.pending}>
          Create key
        </Button>
      </form>
      {create.error ? <ErrorNote error={create.error} /> : null}
      <Dialog
        open={revealed !== undefined}
        onOpenChange={(o) => !o && setRevealed(undefined)}
        title="Copy your API key now"
        description="This is the only time the full key is shown. It cannot be retrieved later; rotate the key if you lose it."
        footer={<Button onClick={() => setRevealed(undefined)}>I have stored it</Button>}
      >
        <p className="mb-1 text-sm">Key: {revealed?.name}</p>
        <code
          className="block break-all rounded-md bg-[var(--axis-surface-2)] p-2 text-sm"
          data-testid="api-key-secret"
        >
          {revealed?.secret}
        </code>
        <Button
          variant="secondary"
          className="mt-2"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(revealed!.secret);
              setCopied(true);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? "Copied" : "Copy to clipboard"}
        </Button>
      </Dialog>
    </div>
  );
}

function ModelKeys() {
  const res = useResource(() => api.listModelKeys());
  const [provider, setProvider] = useState("anthropic");
  const [label, setLabel] = useState("default");
  const [value, setValue] = useState("");
  const toast = useToast();
  const save = useAction(() => api.putModelKey(provider, label, value));
  const del = useAction((p: string, l: string) => api.deleteModelKey(p, l));
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-[var(--axis-muted)]">
        Bring your own provider keys. Values are write-only: once saved they cannot be read back,
        only replaced or deleted.
      </p>
      <ResourceView resource={res}>
        {(p) => (
          <Table<ModelKey>
            caption="Model keys"
            rows={p.items}
            rowKey={(k) => `${k.provider}/${k.label}`}
            empty={
              <EmptyState
                title="No provider keys"
                description="Without a BYO key, runs use the platform default if your plan includes one."
              />
            }
            columns={[
              { key: "p", header: "Provider", render: (k) => k.provider },
              { key: "l", header: "Label", render: (k) => k.label },
              { key: "u", header: "Updated", render: (k) => formatTime(k.updated_at) },
              {
                key: "d",
                header: "",
                render: (k) => (
                  <Button
                    variant="danger"
                    aria-label={`Delete key ${k.provider}/${k.label}`}
                    onClick={async () => {
                      await del.run(k.provider, k.label);
                      res.reload();
                    }}
                  >
                    Delete
                  </Button>
                ),
              },
            ]}
          />
        )}
      </ResourceView>
      {del.error ? <ErrorNote error={del.error} /> : null}
      <form
        aria-label="Save provider key"
        className="flex max-w-2xl flex-wrap items-end gap-3"
        onSubmit={async (e) => {
          e.preventDefault();
          if (await save.run()) {
            setValue("");
            toast.push("Key saved", "success");
            res.reload();
          }
        }}
      >
        <Input
          label="Provider"
          required
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
        />
        <Input label="Label" required value={label} onChange={(e) => setLabel(e.target.value)} />
        <Input
          label="Key value"
          type="password"
          autoComplete="off"
          required
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <Button type="submit" loading={save.pending}>
          Save key
        </Button>
      </form>
      {save.error ? <ErrorNote error={save.error} /> : null}
    </div>
  );
}

function Budgets() {
  const res = useResource(() => api.listBudgets());
  const can = useCan("admin.budgets");
  const [scope, setScope] = useState<Budget["scope"]>("tenant");
  const [metric, setMetric] = useState<Budget["metric"]>("cost_usd");
  const [period, setPeriod] = useState<Budget["period"]>("month");
  const [soft, setSoft] = useState("");
  const [hard, setHard] = useState("");
  const toast = useToast();
  const save = useAction(async (existing: Budget[]) => {
    const s = soft === "" ? undefined : Number(soft);
    const h = hard === "" ? undefined : Number(hard);
    if ((s !== undefined && !(s >= 0)) || (h !== undefined && !(h >= 0)))
      throw new Error("Limits must be non-negative numbers");
    if (s !== undefined && h !== undefined && s > h)
      throw new Error("The soft limit cannot exceed the hard limit");
    if (s === undefined && h === undefined) throw new Error("Set a soft or hard limit");
    return api.putBudgets([
      ...existing.map((b) => ({
        scope: b.scope,
        metric: b.metric,
        period: b.period,
        ...(b.target ? { target: b.target } : {}),
        ...(b.soft !== undefined ? { soft: b.soft } : {}),
        ...(b.hard !== undefined ? { hard: b.hard } : {}),
      })),
      {
        scope,
        metric,
        period,
        ...(s !== undefined ? { soft: s } : {}),
        ...(h !== undefined ? { hard: h } : {}),
      },
    ]);
  });
  const del = useAction((id: string) => api.deleteBudget(id));
  return (
    <div className="flex flex-col gap-4">
      <ResourceView resource={res}>
        {(p) => (
          <>
            <Table<Budget>
              caption="Budgets"
              rows={p.items}
              rowKey={(b) => b.id}
              empty={
                <EmptyState
                  title="No budgets"
                  description="Budgets cap tokens, cost, runtime and tool calls. The tighter of tenant, agent and run limits wins."
                />
              }
              columns={[
                { key: "scope", header: "Scope", render: (b) => b.scope },
                { key: "metric", header: "Metric", render: (b) => b.metric },
                { key: "period", header: "Period", render: (b) => b.period },
                { key: "soft", header: "Soft", render: (b) => b.soft ?? "-" },
                { key: "hard", header: "Hard", render: (b) => b.hard ?? "-" },
                {
                  key: "d",
                  header: "",
                  render: (b) =>
                    can ? (
                      <Button
                        variant="danger"
                        aria-label={`Delete ${b.scope} ${b.metric} budget`}
                        onClick={async () => {
                          await del.run(b.id);
                          res.reload();
                        }}
                      >
                        Delete
                      </Button>
                    ) : null,
                },
              ]}
            />
            {can ? (
              <form
                aria-label="Add budget"
                className="flex flex-wrap items-end gap-3"
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (await save.run(p.items)) {
                    setSoft("");
                    setHard("");
                    toast.push("Budget saved", "success");
                    res.reload();
                  }
                }}
              >
                <Select
                  label="Scope"
                  value={scope}
                  onChange={(e) => setScope(e.target.value as Budget["scope"])}
                  options={["tenant", "agent", "run"].map((v) => ({ value: v, label: v }))}
                />
                <Select
                  label="Metric"
                  value={metric}
                  onChange={(e) => setMetric(e.target.value as Budget["metric"])}
                  options={["tokens", "cost_usd", "runtime_seconds", "tool_calls"].map((v) => ({
                    value: v,
                    label: v,
                  }))}
                />
                <Select
                  label="Period"
                  value={period}
                  onChange={(e) => setPeriod(e.target.value as Budget["period"])}
                  options={["run", "day", "month"].map((v) => ({ value: v, label: v }))}
                />
                <Input
                  label="Soft limit"
                  inputMode="decimal"
                  value={soft}
                  onChange={(e) => setSoft(e.target.value)}
                />
                <Input
                  label="Hard limit"
                  inputMode="decimal"
                  value={hard}
                  onChange={(e) => setHard(e.target.value)}
                />
                <Button type="submit" loading={save.pending}>
                  Add budget
                </Button>
              </form>
            ) : (
              <p className="text-sm text-[var(--axis-muted)]">
                Your role can view budgets but not change them.
              </p>
            )}
          </>
        )}
      </ResourceView>
      {save.error ? <ErrorNote error={save.error} /> : null}
      {del.error ? <ErrorNote error={del.error} /> : null}
    </div>
  );
}

function Sso() {
  const sso = useResource(() => api.getSso());
  const dirs = useResource(() => api.listDirectories());
  const tenant = useResource(() => api.tenant());
  const owner = useCan("admin.sso");
  const [org, setOrg] = useState<string | undefined>();
  const toast = useToast();
  const save = useAction(() =>
    api.putSso({ ...(sso.data ?? {}), organization_id: org ?? sso.data?.organization_id ?? "" }),
  );
  return (
    <div className="flex flex-col gap-6">
      <section aria-label="Region">
        <h3 className="font-medium">Region</h3>
        <ResourceView resource={tenant}>
          {(t) => (
            <p className="text-sm">
              Data is pinned to <strong>{t.region}</strong>. The region is fixed at signup and
              cannot be changed here.
            </p>
          )}
        </ResourceView>
      </section>
      <section aria-label="Single sign-on" className="flex max-w-xl flex-col gap-3">
        <h3 className="font-medium">Single sign-on</h3>
        <ResourceView
          resource={sso}
          unavailable={{
            title: "SSO is not configured",
            description: "No identity-provider connection exists for this tenant.",
          }}
        >
          {(s) => (
            <>
              <p className="text-sm">
                Connection type: {s.connection_type ?? "not set"}. Just-in-time provisioning:{" "}
                {s.jit_enabled ? `on (default role ${s.jit_default_role ?? "viewer"})` : "off"}.
              </p>
              {owner ? (
                <form
                  aria-label="SSO organization"
                  className="flex items-end gap-3"
                  onSubmit={async (e) => {
                    e.preventDefault();
                    if (await save.run()) {
                      toast.push("SSO settings saved", "success");
                      sso.reload();
                    }
                  }}
                >
                  <Input
                    label="IdP organization ID"
                    value={org ?? s.organization_id ?? ""}
                    onChange={(e) => setOrg(e.target.value)}
                  />
                  <Button type="submit" loading={save.pending}>
                    Save
                  </Button>
                </form>
              ) : (
                <p className="text-sm text-[var(--axis-muted)]">
                  Only the tenant owner can change SSO settings.
                </p>
              )}
              {save.error ? <ErrorNote error={save.error} /> : null}
            </>
          )}
        </ResourceView>
      </section>
      <section aria-label="SCIM directories">
        <h3 className="mb-2 font-medium">SCIM directories</h3>
        <ResourceView
          resource={dirs}
          unavailable={{
            title: "Directory sync is not available",
            description: "SCIM directories are managed by the tenant owner.",
          }}
        >
          {(d) => (
            <Table
              caption="SCIM directories"
              rows={d.items}
              rowKey={(x) => x.id}
              empty={
                <EmptyState
                  title="No directories"
                  description="Connect an IdP directory to provision members automatically."
                />
              }
              columns={[
                { key: "n", header: "Name", render: (x) => x.name },
                { key: "s", header: "Status", render: (x) => x.status },
                { key: "r", header: "Default role", render: (x) => x.default_role },
                { key: "t", header: "Token", render: (x) => <code>{x.token_prefix}_...</code> },
              ]}
            />
          )}
        </ResourceView>
      </section>
    </div>
  );
}

export default function AdminPage() {
  const keys = useCan("admin.keys");
  const members = useCan("admin.members");
  const items = [
    ...(members ? [{ value: "members", label: "Members", content: <Members /> }] : []),
    ...(keys
      ? [
          { value: "keys", label: "API keys", content: <ApiKeys /> },
          { value: "modelkeys", label: "Model keys", content: <ModelKeys /> },
        ]
      : []),
    { value: "budgets", label: "Budgets", content: <Budgets /> },
    ...(members ? [{ value: "sso", label: "SSO, SCIM and region", content: <Sso /> }] : []),
  ];
  return (
    <>
      <title>Admin - AXIS Console</title>
      <PageHeader
        title="Admin"
        description="Tenant administration. Controls you cannot use are hidden; the server enforces every permission."
      />
      <Tabs label="Admin sections" items={items} />
    </>
  );
}
