// Independent Phase 6 review: regression tests for defects found by the adversarial reviewer.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError, type PackValidator } from "../src/index.js";
import { KINDS, cachedValidator, eventsOf, makeWorld, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : `other:${String(e)}`;
  }
};

const pack = (name: string, nRules: number) => ({
  apiVersion: "policy.axis.dev/v1",
  kind: "PolicyPack",
  metadata: { name, version: "1.0.0" },
  spec: {
    defaultDecision: "DENY",
    rules: Array.from({ length: nRules }, (_, i) => ({
      id: `r${i}`,
      enforcementPoints: ["tool_call"],
      when: {
        all: [
          { field: "args.x", op: "eq", value: i },
          { field: "tool.name", op: "in", value: ["a", "b"] },
        ],
      },
      decision: "ALLOW",
    })),
  },
});

describe.each(KINDS)("review: policy publish resource limits (%s store)", (kind) => {
  let w: World;
  let calls = 0;
  const counting: PackValidator = (docs) => {
    calls++;
    return cachedValidator(docs);
  };
  beforeAll(async () => {
    w = await makeWorld(kind, { validator: counting });
  });
  afterAll(() => w.close());

  it("rejects an oversized pack before the synchronous opa check/build can stall the process", async () => {
    // 1400 rules fit in the 256 KiB body limit and take `opa` minutes (300 rules: ~4.5 s): it must never reach the validator.
    const t = await w.tenant();
    const before = calls;
    expect(await code(w.cp.admin.publishPolicy(t.owner, pack("huge", 1400)))).toBe("invalid");
    expect(await code(w.cp.admin.publishPolicy(t.owner, pack("deep", 101)))).toBe("invalid");
    const longList = pack("longlist", 1);
    longList.spec.rules[0]!.when.all[1]!.value = Array.from({ length: 20_000 }, (_, i) => `v${i}`); // one rule, ~40 s in opa
    expect(await code(w.cp.admin.publishPolicy(t.owner, longList))).toBe("invalid");
    expect(calls).toBe(before);
  });

  it("a pack within the limits still publishes and activates; a set above the total limit cannot be activated", async () => {
    const t = await w.tenant();
    const a = await w.cp.admin.publishPolicy(t.owner, pack("set-a", 90));
    const b = await w.cp.admin.publishPolicy(t.owner, pack("set-b", 90));
    const c = await w.cp.admin.publishPolicy(t.owner, pack("set-c", 90));
    await w.cp.admin.activatePolicy(t.owner, a.versionId);
    await w.cp.admin.activatePolicy(t.owner, b.versionId);
    expect(await code(w.cp.admin.activatePolicy(t.owner, c.versionId))).toBe("invalid");
  });
});

describe.each(KINDS)(
  "review: BYO model keys honour 'builders touch only keys they own' (%s store)",
  (kind) => {
    let w: World;
    beforeAll(async () => {
      w = await makeWorld(kind);
    });
    afterAll(() => w.close());

    it("a builder can neither overwrite nor delete a key written by someone else, but manages its own", async () => {
      const t = await w.tenant();
      const b1 = await w.member(t.tenantId, "builder");
      const b2 = await w.member(t.tenantId, "builder");
      const adm = await w.member(t.tenantId, "admin");
      await w.cp.admin.putModelKey(adm.principal, "anthropic", "prod", "admin-secret");
      // another builder cannot replace the admin's production key with its own (traffic redirection) nor destroy it
      expect(await code(w.cp.admin.putModelKey(b1.principal, "anthropic", "prod", "evil"))).toBe(
        "forbidden",
      );
      expect(await code(w.cp.admin.deleteModelKey(b1.principal, "anthropic", "prod"))).toBe(
        "forbidden",
      );
      expect(await w.cp.modelKeys.revealForRuntime(t.tenantId, "anthropic", "prod")).toBe(
        "admin-secret",
      );
      // own key: create, rotate, delete are fine; a peer builder is refused
      await w.cp.admin.putModelKey(b1.principal, "openai", "dev", "one");
      await w.cp.admin.putModelKey(b1.principal, "openai", "dev", "two");
      expect(await code(w.cp.admin.putModelKey(b2.principal, "openai", "dev", "x"))).toBe(
        "forbidden",
      );
      expect(await code(w.cp.admin.deleteModelKey(b2.principal, "openai", "dev"))).toBe(
        "forbidden",
      );
      // an admin may manage anyone's key
      await w.cp.admin.putModelKey(adm.principal, "openai", "dev", "admin-took-over");
      expect(await code(w.cp.admin.deleteModelKey(b1.principal, "openai", "dev"))).toBe(
        "forbidden",
      );
      await w.cp.admin.deleteModelKey(adm.principal, "openai", "dev");
    });
  },
);

describe.each(KINDS)("review: SSO e-mail linking binds one IdP identity (%s store)", (kind) => {
  let w: World;
  const ORG = "org_bind";
  beforeAll(async () => {
    w = await makeWorld(kind);
  });
  afterAll(() => w.close());

  it("a second IdP identity with the same verified e-mail cannot take over a member already bound to another one", async () => {
    const t = await w.tenant();
    await w.cp.admin.setSsoConnection(t.owner, { idpOrgId: ORG, connectionType: "oidc" });
    const invited = await w.cp.admin.inviteMember(t.owner, {
      email: "carol@bind.test",
      role: "admin",
    });
    const login = async (id: string) => {
      const st = await w.cp.sso.begin(ORG);
      const state = new URL(st.redirectUrl).searchParams.get("state")!;
      const codeV = w.idp.complete(state, {
        id,
        email: "Carol@Bind.test",
        emailVerified: true,
        organizationId: ORG,
        connectionType: "oidc",
      });
      return w.cp.sso.callback({ code: codeV, state }, st.cookie);
    };
    const first = await login("idp-carol-1");
    expect(first.memberId).toBe(invited.id);
    expect((await login("idp-carol-1")).memberId).toBe(invited.id); // same identity: still fine
    expect(await code(login("idp-mallory"))).toBe("unauthenticated");
    const ev = await eventsOf(w, t.tenantId);
    expect(
      ev.some(
        (e) =>
          e.action === "auth.sso_login" &&
          e.decision === "DENY" &&
          /identity_mismatch/.test(e.reason ?? ""),
      ),
    ).toBe(true);
  });
});

describe("review: concurrent policy activations never leave the kernel on a stale bundle", () => {
  it("the last bundle written reflects every committed activation, whatever the order of the writes", async () => {
    const puts: { id: string; packs: string[] }[] = [];
    let gate!: () => void;
    const held = new Promise<void>((r) => (gate = r));
    let first = true;
    const w = await makeWorld("memory", {
      bundleSink: {
        put: async (id, b) => {
          if (first && puts.length > 0) {
            first = false; // the FIRST activation's write is held back while the second one completes
            await held;
          }
          puts.push({ id, packs: b.packs });
        },
      },
    });
    try {
      const t = await w.tenant(); // signup publishes the baseline (puts[0])
      const a = await w.cp.admin.publishPolicy(t.owner, pack("race-a", 3));
      const b = await w.cp.admin.publishPolicy(t.owner, pack("race-b", 3));
      const p1 = w.cp.admin.activatePolicy(t.owner, a.versionId); // commits {A}, builds {A}, write held
      await new Promise((r) => setTimeout(r, 50));
      const p2 = w.cp.admin.activatePolicy(t.owner, b.versionId); // commits {A,B}
      await new Promise((r) => setTimeout(r, 300));
      gate();
      await Promise.all([p1, p2]);
      const mine = puts.filter((p) => p.id === t.tenantId);
      expect(mine[mine.length - 1]?.packs.sort()).toEqual(["baseline-deny", "race-a", "race-b"]);
    } finally {
      gate();
      await w.close();
    }
  });
});

describe("review: pre-tenant lookup policies cannot be used to enumerate (real RLS, axis_app)", () => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld("pg");
  });
  afterAll(() => w.close());

  const asApp = async <T>(
    settings: Record<string, string>,
    sql: string,
    params: unknown[] = [],
  ): Promise<T[]> => {
    const c = await w.pool!.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      for (const [k, v] of Object.entries(settings))
        await c.query("SELECT set_config($1,$2,true)", [k, v]);
      const r = await c.query(sql, params);
      await c.query("ROLLBACK");
      return r.rows as T[];
    } finally {
      c.release();
    }
  };

  it("no setting, a wrong hash, an empty hash or SQL-looking values release no row of api_keys, directories or identity_connections", async () => {
    const a = await w.tenant();
    const key = await w.cp.admin.createApiKey(a.owner, { name: "k", scopes: ["*"] });
    const dir = await w.cp.admin.createDirectory(a.owner, "d", "viewer");
    await w.cp.admin.setSsoConnection(a.owner, { idpOrgId: "org_probe", connectionType: "oidc" });
    const none = { "axis.lookup_prefix": "", "axis.lookup_hash": "" };
    expect(await asApp({}, "SELECT * FROM api_keys")).toHaveLength(0);
    expect(await asApp({}, "SELECT * FROM directories")).toHaveLength(0);
    expect(await asApp({}, "SELECT * FROM identity_connections")).toHaveLength(0);
    expect(await asApp(none, "SELECT * FROM api_keys")).toHaveLength(0);
    // the right prefix with a wrong hash, and with a hash of another row
    expect(
      await asApp(
        { "axis.lookup_prefix": key.key.prefix, "axis.lookup_hash": "00".repeat(32) },
        "SELECT * FROM api_keys",
      ),
    ).toHaveLength(0);
    expect(
      await asApp(
        { "axis.lookup_prefix": key.key.prefix, "axis.lookup_hash": "" },
        "SELECT * FROM api_keys",
      ),
    ).toHaveLength(0);
    expect(
      await asApp(
        { "axis.lookup_prefix": "%", "axis.lookup_hash": "00" },
        "SELECT * FROM directories",
      ),
    ).toHaveLength(0);
    expect(
      await asApp({ "axis.lookup_idp_org": "org_%" }, "SELECT * FROM identity_connections"),
    ).toHaveLength(0);
    expect(dir.token).toBeTruthy();
  });
});

describe("review: budget limits are bounded", () => {
  it("rejects limits the runtime could not represent (1e308 overflows once cost is scaled to micro-USD)", async () => {
    const w = await makeWorld("memory");
    try {
      const t = await w.tenant();
      const put = (hard: number) =>
        w.cp.admin.putBudget(t.owner, {
          scope: "tenant",
          metric: "cost_usd",
          period: "month",
          hard,
        });
      expect(await code(put(1e308))).toBe("invalid");
      expect(await code(put(1e12 + 1))).toBe("invalid");
      expect(await code(put(1e12))).toBe("ok");
    } finally {
      await w.close();
    }
  });
});

describe.each(KINDS)(
  "review: an admin cannot reach the owner through an IdP it controls (%s store)",
  (kind) => {
    let w: World;
    beforeAll(async () => {
      w = await makeWorld(kind);
    });
    afterAll(() => w.close());

    it("sso.manage and the IdP admin portal are the owner's alone; the escalation path is closed at its first step", async () => {
      const t = await w.tenant();
      const adm = await w.member(t.tenantId, "admin");
      expect(
        await code(
          w.cp.admin.setSsoConnection(adm.principal, {
            idpOrgId: "org_admin_idp",
            connectionType: "oidc",
          }),
        ),
      ).toBe("forbidden");
      expect(
        await code(
          w.cp.admin.adminPortalLink(adm.principal, "sso", "https://console.example.test/"),
        ),
      ).toBe("forbidden");
      // the owner links the organization; an admin still cannot re-point it
      await w.cp.admin.setSsoConnection(t.owner, {
        idpOrgId: "org_owner_idp",
        connectionType: "oidc",
      });
      expect(
        await code(
          w.cp.admin.setSsoConnection(adm.principal, {
            idpOrgId: "org_owner_idp",
            connectionType: "saml",
            jitEnabled: true,
          }),
        ),
      ).toBe("forbidden");
    });
  },
);
