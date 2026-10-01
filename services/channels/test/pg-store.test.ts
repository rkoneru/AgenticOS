import { randomUUID } from "node:crypto";
import { PgAuditLog } from "@axis/audit";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, inject, it } from "vitest";
import {
  ChannelGateway,
  IdentityService,
  MemoryIdempotencyStore,
  MemoryRateLimiter,
  PgConversationStore,
  SlackAdapter,
  StaticRoutingTable,
} from "../src/index.js";
import { FakeHttp, NOW, Clock, routes, slackReq } from "./helpers.js";
import { storeContract } from "./store-contract.js";

const ROLE = "axis_app";
let pool: pg.Pool;
let admin: pg.Client;

beforeAll(async () => {
  pool = new pg.Pool({ connectionString: inject("dbUrl"), max: 10 });
  admin = new pg.Client({ connectionString: inject("dbUrl") });
  await admin.connect();
});
afterAll(async () => {
  await pool.end();
  await admin.end();
});

async function newTenant(id: string = randomUUID()): Promise<string> {
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')",
    [id, `t-${id.slice(0, 8)}`],
  );
  return id;
}

storeContract("postgres (forced RLS, role axis_app)", async () => ({
  store: new PgConversationStore({ pool, role: ROLE }),
  tenant: () => newTenant(),
}));

const TABLES = [
  "end_users",
  "channel_identities",
  "link_challenges",
  "conversations",
  "conversation_threads",
  "conversation_messages",
];

describe("migration 0007 tenancy", () => {
  it("every channels table has RLS enabled AND forced, and a tenant_isolation policy", async () => {
    const { rows } = await admin.query(
      "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = ANY($1)",
      [TABLES],
    );
    expect(rows).toHaveLength(TABLES.length);
    for (const r of rows)
      expect(r, r.relname).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true });
    const pol = await admin.query(
      "SELECT tablename FROM pg_policies WHERE policyname = 'tenant_isolation' AND tablename = ANY($1)",
      [TABLES],
    );
    expect(pol.rows).toHaveLength(TABLES.length);
  });

  it("the app role sees nothing without a tenant, and only its own rows with one", async () => {
    const store = new PgConversationStore({ pool, role: ROLE });
    const t1 = await newTenant();
    const t2 = await newTenant();
    const a = (await store.resolveIdentity(t1, "slack", "UA")).identity;
    await store.resolveIdentity(t2, "slack", "UB");
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(`SET LOCAL ROLE ${ROLE}`);
      for (const t of TABLES) expect((await c.query(`SELECT 1 FROM ${t}`)).rowCount, t).toBe(0);
      await c.query("SELECT axis.set_tenant($1::uuid)", [t1]);
      const ids = await c.query("SELECT external_id FROM channel_identities");
      expect(ids.rows).toEqual([{ external_id: "UA" }]);
      // a row for another tenant is refused by WITH CHECK, not silently accepted
      await expect(c.query("INSERT INTO end_users (tenant_id) VALUES ($1)", [t2])).rejects.toThrow(
        /row-level security/,
      );
      await c.query("ROLLBACK");
    } finally {
      c.release();
    }
    expect(a.tenant_id).toBe(t1);
  });

  it("composite foreign keys refuse cross-tenant references even for the owner", async () => {
    const store = new PgConversationStore({ pool, role: ROLE });
    const t1 = await newTenant();
    const t2 = await newTenant();
    const eu1 = (await store.resolveIdentity(t1, "slack", "UA")).identity.end_user_id;
    await expect(
      admin.query(
        "INSERT INTO conversations (tenant_id, end_user_id, agent_name, agent_version, last_channel) VALUES ($1, $2, 'a', '1', 'slack')",
        [t2, eu1],
      ),
    ).rejects.toThrow(/foreign key/);
    await expect(
      admin.query(
        "INSERT INTO channel_identities (tenant_id, end_user_id, channel, external_id, verified_by) VALUES ($1, $2, 'sms', '+1', 'provider')",
        [t2, eu1],
      ),
    ).rejects.toThrow(/foreign key/);
    const conv = await store.createConversation(t1, eu1, { name: "a", version: "1" }, "slack");
    await expect(
      admin.query(
        "INSERT INTO conversation_messages (tenant_id, conversation_id, direction, channel, idempotency_key, content_mode, content_hash, size_bytes) VALUES ($1, $2, 'in', 'slack', 'k', 'hash_only', $3, 1)",
        [t2, conv.id, "a".repeat(64)],
      ),
    ).rejects.toThrow(/foreign key/);
  });

  it("the message log is insert-only for the app role and its CHECKs hold", async () => {
    const store = new PgConversationStore({ pool, role: ROLE });
    const t = await newTenant();
    const eu = (await store.resolveIdentity(t, "slack", "UA")).identity.end_user_id;
    const conv = await store.createConversation(t, eu, { name: "a", version: "1" }, "slack");
    await store.appendMessage(t, {
      tenant_id: t,
      conversation_id: conv.id,
      direction: "in",
      channel: "slack",
      idempotency_key: "k",
      content_mode: "hash_only",
      content: null,
      content_hash: "a".repeat(64),
      size_bytes: 1,
      attachments: [],
      audit_event_id: null,
      audit_hash: null,
    });
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(`SET LOCAL ROLE ${ROLE}`);
      await c.query("SELECT axis.set_tenant($1::uuid)", [t]);
      await expect(c.query("UPDATE conversation_messages SET size_bytes = 9")).rejects.toThrow(
        /permission denied/,
      );
      await c.query("ROLLBACK");
      await c.query("BEGIN");
      await c.query(`SET LOCAL ROLE ${ROLE}`);
      await c.query("SELECT axis.set_tenant($1::uuid)", [t]);
      await expect(c.query("DELETE FROM conversation_messages")).rejects.toThrow(
        /permission denied/,
      );
      await c.query("ROLLBACK");
    } finally {
      c.release();
    }
    // content present while content_mode is hash_only violates the CHECK
    await expect(
      store.appendMessage(t, {
        tenant_id: t,
        conversation_id: conv.id,
        direction: "in",
        channel: "slack",
        idempotency_key: "k2",
        content_mode: "hash_only",
        content: "leak",
        content_hash: "a".repeat(64),
        size_bytes: 1,
        attachments: [],
        audit_event_id: null,
        audit_hash: null,
      }),
    ).rejects.toThrow(/check/);
  });

  it("withTenant requires a UUID tenant (no query path without tenant_id)", async () => {
    const store = new PgConversationStore({ pool, role: ROLE });
    await expect(store.findIdentity("not-a-uuid", "slack", "x")).rejects.toThrow(/UUID/);
  });
});

describe("gateway on real Postgres: store + audit chain", () => {
  it("an inbound Slack message lands in the log and in a verifiable hash chain; a replay is deduped", async () => {
    const SLACK_TENANT = "11111111-1111-4111-8111-111111111111";
    await newTenant(SLACK_TENANT);
    const store = new PgConversationStore({ pool, role: ROLE });
    const audit = new PgAuditLog({ pool, role: ROLE });
    const clock = new Clock();
    const limiter = new MemoryRateLimiter(clock.now);
    const gateway = new ChannelGateway({
      adapters: [new SlackAdapter()],
      routes: new StaticRoutingTable(routes()),
      store,
      identity: new IdentityService({ store, now: clock.now, limiter }),
      audit,
      idempotency: new MemoryIdempotencyStore(clock.now),
      limiter,
      http: new FakeHttp(),
      now: clock.now,
    });
    const req = slackReq({ eventId: "EvPG", text: "hello pg" });
    const first = await gateway.handleInbound("slack", req);
    expect(first.outcomes[0]!.kind).toBe("accepted");
    expect((await gateway.handleInbound("slack", req)).outcomes[0]!.kind).toBe("duplicate");
    await gateway.handleInbound("slack", slackReq({ secret: "wrong" }));
    const conv = (first.outcomes[0] as { conversation_id: string }).conversation_id;
    const log = await store.messages(SLACK_TENANT, conv);
    expect(log).toHaveLength(1);
    expect(log[0]!.audit_hash).toMatch(/^[0-9a-f]{64}$/);
    const verdict = await audit.verify(SLACK_TENANT);
    expect(verdict).toMatchObject({ ok: true, length: 3 });
    const events = await audit.read(SLACK_TENANT);
    expect(events.map((e) => e.action)).toEqual([
      "channel.inbound.message",
      "channel.inbound.replayed",
      "channel.inbound.rejected",
    ]);
    expect(events[0]!.hash).toBe(log[0]!.audit_hash);
    expect(NOW).toBeGreaterThan(0);
  });
});
