import { randomUUID } from "node:crypto";
import type pg from "pg";
import { hex } from "./helpers.js";

export const JANE = {
  email: "jane.doe@example.com",
  userRef: "user_jane_01",
  phone: "+15550109999",
  slack: "slack:U0JANE",
  subjectKey: "subj-jane",
};
export const BOB = {
  email: "bob.smith@example.com",
  userRef: "user_bob_02",
  slack: "slack:U0BOB",
  subjectKey: "subj-bob",
};

export interface Seeded {
  tenantId: string;
  janeEndUser: string;
  bobEndUser: string;
  janeMember: string;
  ownerMember: string;
  janeRun: string;
  bobRun: string;
}

/** Populate EVERY subject-data store of one tenant with Jane's and Bob's data (owner/superuser connection). */
export async function seedTenant(admin: pg.Client, tenantId: string): Promise<Seeded> {
  const q = (sql: string, p: unknown[] = []) => admin.query(sql, p);
  const t = tenantId;
  // control-plane members + a session and an API key for Jane
  const owner = (
    await q(
      "INSERT INTO members (tenant_id, user_ref, email, role) VALUES ($1, 'user_owner_00', 'owner@corp.example', 'owner') RETURNING id",
      [t],
    )
  ).rows[0].id as string;
  const jane = (
    await q(
      "INSERT INTO members (tenant_id, user_ref, email, role, display_name, external_id) VALUES ($1, $2, $3, 'builder', 'Jane Doe', 'ext-jane') RETURNING id",
      [t, JANE.userRef, JANE.email],
    )
  ).rows[0].id as string;
  await q(
    "INSERT INTO members (tenant_id, user_ref, email, role, display_name) VALUES ($1, $2, $3, 'viewer', 'Bob Smith')",
    [t, BOB.userRef, BOB.email],
  );
  await q(
    "INSERT INTO sessions (tenant_id, member_id, refresh_hash, auth_method, expires_at) VALUES ($1, $2, decode($3, 'hex'), 'dev', now() + interval '1 day')",
    [t, jane, "11".repeat(32)],
  );
  await q(
    "INSERT INTO api_keys (tenant_id, name, prefix, key_hash, owner_member_id) VALUES ($1, 'jane key', $2, decode($3, 'hex'), $4)",
    [t, `p${hex(8)}`, "22".repeat(32), jane],
  );

  // memory
  const kb = (
    await q("INSERT INTO knowledge_bases (tenant_id, name) VALUES ($1, 'kb-main') RETURNING id", [
      t,
    ])
  ).rows[0].id as string;
  const doc = (
    await q(
      "INSERT INTO memory_documents (tenant_id, kb_id, content_hash, acl, acl_key, subject, created_by) VALUES ($1,$2,$3,'{}','{}',$4,$5) RETURNING id",
      [t, kb, hex(64), JANE.subjectKey, JANE.userRef],
    )
  ).rows[0].id as string;
  await q(
    "INSERT INTO memory_chunks (tenant_id, kb_id, scope, content, subject, document_id, ordinal, created_by) VALUES ($1,$2,'kb',$3,$4,$5,0,$6)",
    [t, kb, `Jane Doe's SSN note ${JANE.email}`, JANE.subjectKey, doc, JANE.userRef],
  );
  await q(
    "INSERT INTO memory_chunks (tenant_id, scope, owner_ref, content, subject, created_by) VALUES ($1,'agent','a1','jane authored note about Bob',$2,$3)",
    [t, BOB.subjectKey, JANE.userRef],
  );
  await q(
    "INSERT INTO memory_chunks (tenant_id, scope, owner_ref, content, subject, created_by) VALUES ($1,'agent','a1','bob fact',$2,$3)",
    [t, BOB.subjectKey, BOB.userRef],
  );

  // channels
  const mkUser = async (slack: string, em: string) => {
    const u = (await q("INSERT INTO end_users (tenant_id) VALUES ($1) RETURNING id", [t])).rows[0]
      .id as string;
    const [ch, ext] = slack.split(":") as [string, string];
    await q(
      "INSERT INTO channel_identities (tenant_id, end_user_id, channel, external_id, verified_by) VALUES ($1,$2,$3,$4,'provider')",
      [t, u, ch, ext],
    );
    await q(
      "INSERT INTO channel_identities (tenant_id, end_user_id, channel, external_id, verified_by) VALUES ($1,$2,'email',$3,'link')",
      [t, u, em],
    );
    const c = (
      await q(
        "INSERT INTO conversations (tenant_id, end_user_id, agent_name, agent_version, last_channel) VALUES ($1,$2,'support','1.0.0','slack') RETURNING id",
        [t, u],
      )
    ).rows[0].id as string;
    await q(
      "INSERT INTO conversation_threads (tenant_id, channel, thread_key, conversation_id) VALUES ($1,'slack',$2,$3)",
      [t, `th-${hex(8)}`, c],
    );
    for (const [channel, content] of [
      ["slack", `hello from ${em}`],
      ["voice", `voice transcript of ${em}`],
    ] as const)
      await q(
        "INSERT INTO conversation_messages (tenant_id, conversation_id, direction, channel, idempotency_key, content_mode, content, content_hash, size_bytes) VALUES ($1,$2,'in',$3,$4,'full',$5,$6,10)",
        [t, c, channel, `k-${hex(8)}`, content, hex(64)],
      );
    return u;
  };
  const janeEU = await mkUser(JANE.slack, JANE.email);
  const bobEU = await mkUser(BOB.slack, BOB.email);

  // billing: pseudonymise-only
  const usage = async (actor: string | null, dims: Record<string, string>, idem: string, qty = 5) =>
    q(
      "INSERT INTO usage_events (tenant_id, idempotency_key, payload_hash, entry_type, meter, quantity, event_time, period_id, source, dimensions, actor) VALUES ($1,$2,$3,'usage','tokens_in',$4,now(),to_char(now(),'YYYY-MM'),'seed',$5,$6)",
      [t, idem, hex(64), qty, JSON.stringify(dims), actor],
    );
  await usage(JANE.userRef, { run: "r1", user: JANE.userRef }, `u-${hex(8)}`, 7);
  await usage(null, { run: "r2", requester: JANE.email }, `u-${hex(8)}`, 11);
  await usage(BOB.userRef, { run: "r3" }, `u-${hex(8)}`, 13);

  // eval hub
  const cases = (ref: string, name: string) => [
    {
      id: "c1",
      input: `question from ${name}`,
      expected: `answer ${name}`,
      tags: ["a"],
      metadata: { subject_ref: ref },
    },
    { id: "c2", input: "generic question", expected: "generic", tags: [], metadata: {} },
  ];
  await q(
    "INSERT INTO eval_hub_docs (tenant_id, coll, key, rev, data) VALUES ($1,'datasets','jane-set@1',1,$2)",
    [
      t,
      JSON.stringify({
        name: "jane-set",
        version: 1,
        ref: "jane-set@1",
        cases: cases(JANE.subjectKey, "jane"),
        created_at: new Date().toISOString(),
      }),
    ],
  );
  await q(
    "INSERT INTO eval_hub_docs (tenant_id, coll, key, rev, data) VALUES ($1,'datasets','bob-set@1',1,$2)",
    [
      t,
      JSON.stringify({
        name: "bob-set",
        version: 1,
        ref: "bob-set@1",
        cases: cases(BOB.subjectKey, "bob"),
        created_at: new Date().toISOString(),
      }),
    ],
  );
  const run = (id: string, ds: string) => ({
    id,
    dataset_ref: ds,
    status: "passed",
    created_at: new Date().toISOString(),
    case_results: [
      {
        case_id: "c1",
        status: "ok",
        output: `output of ${ds}`,
        error: null,
        trace: { note: `trace ${ds}` },
        grades: [],
      },
      { case_id: "c2", status: "ok", output: "generic out", error: null, trace: null, grades: [] },
    ],
  });
  await q(
    "INSERT INTO eval_hub_docs (tenant_id, coll, key, rev, data) VALUES ($1,'runs','run-jane',1,$2)",
    [t, JSON.stringify(run("run-jane", "jane-set@1"))],
  );
  await q(
    "INSERT INTO eval_hub_docs (tenant_id, coll, key, rev, data) VALUES ($1,'runs','run-bob',1,$2)",
    [t, JSON.stringify(run("run-bob", "bob-set@1"))],
  );

  // run logs
  const mkRun = async (principal: string, terminated: boolean) => {
    const id = randomUUID();
    await q(
      "INSERT INTO runs (tenant_id, id, blueprint_name, blueprint_version, trace_id, input) VALUES ($1,$2,'support','1.0.0',$3,$4)",
      [t, id, hex(32), JSON.stringify({ principal, message: `please help ${principal}` })],
    );
    await q(
      "INSERT INTO run_events (tenant_id, run_id, sequence, type, pid, data) VALUES ($1,$2,1,'message','axp_01ARZ3NDEKTSV4RRFFQ69G5FAV',$3)",
      [t, id, JSON.stringify({ text: `hello ${principal}` })],
    );
    await q(
      "INSERT INTO run_events (tenant_id, run_id, sequence, type, pid, data) VALUES ($1,$2,2,'tool','axp_01ARZ3NDEKTSV4RRFFQ69G5FAV',$3)",
      [t, id, JSON.stringify({ tool: "lookup", query: "x" })],
    );
    if (terminated) {
      await q("UPDATE processes SET state = state WHERE false");
      await q(
        "UPDATE runs SET state='terminated', exit_reason='completed', finished_at=now() WHERE tenant_id=$1 AND id=$2",
        [t, id],
      );
    }
    return id;
  };
  const janeRun = await mkRun(`enduser:${janeEU}`, true);
  const bobRun = await mkRun(`enduser:${bobEU}`, true);

  // approvals table
  await q(
    "INSERT INTO approvals (tenant_id, run_id, pid, action, roles, status, sla_deadline, decided_by, decided_at, comment) VALUES ($1,$2,'axp_01ARZ3NDEKTSV4RRFFQ69G5FAV','send_email','{admin}','approved',now()+interval '1 day',$3,now(),$4)",
    [t, bobRun, JANE.userRef, `approved because ${JANE.email} asked`],
  );
  return {
    tenantId: t,
    janeEndUser: janeEU,
    bobEndUser: bobEU,
    janeMember: jane,
    ownerMember: owner,
    janeRun,
    bobRun,
  };
}

/** Generic text dump of every row of every table of one tenant (owner connection), for "no raw value anywhere" scans. */
export async function dumpTenant(
  admin: pg.Client,
  tenantId: string,
  skip: string[] = [],
): Promise<string> {
  const { rows } = await admin.query(
    "SELECT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='tenant_id' GROUP BY 1 ORDER BY 1",
  );
  const parts: string[] = [];
  for (const r of rows as { table_name: string }[]) {
    if (skip.includes(r.table_name)) continue;
    const d = await admin.query(
      `SELECT t::text AS row FROM ${r.table_name} t WHERE tenant_id = $1`,
      [tenantId],
    );
    for (const x of d.rows as { row: string }[]) parts.push(`${r.table_name}: ${x.row}`);
  }
  return parts.join("\n");
}
