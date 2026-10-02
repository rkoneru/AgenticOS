/* global console, process */
// Mutation check for the billing safety logic: apply one targeted edit at a time, run the tests, and require a FAILURE.
// A surviving mutant means a safety property is untested. Usage (from services/billing): node scripts-mutation.mjs [substring ...]
// Files may live outside this package (the migration); paths are relative to services/billing.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const MIG = "../../packages/db/migrations/0008_billing.sql";
const M = [
  // --- ledger: quantity bounds, idempotency, tenant scope, periods, seals
  ["src/types.ts", "if (input.quantity < 0n)", "if (false)"],
  [
    "src/types.ts",
    "if (input.quantity > MAX_QUANTITY || input.quantity < -MAX_QUANTITY)",
    "if (false)",
  ],
  ["src/types.ts", "now.getTime() + MAX_FUTURE_SKEW_MS", "now.getTime() + 1e15"],
  ["src/types.ts", "if (input.quantity === 0n) throw", "if (false) throw"],
  ["src/memory-ledger.ts", "if (existing.payloadHash === hash)", "if (true)"],
  ["src/memory-ledger.ts", "const s = this.st(v.tenantId);", 'const s = this.st("x");'],
  ["src/memory-ledger.ts", "if (s.seals.some((x) => x.periodId === periodId))", "if (false)"],
  ["src/memory-ledger.ts", "assertClosable(periodId, now);", ""],
  [
    "src/periods.ts",
    "while (sealed.has(p)) p = nextPeriod(p);",
    "while (false) p = nextPeriod(p);",
  ],
  ["src/pg-ledger.ts", "if (existing.payload_hash === hash)", "if (true)"],
  ["src/pg-ledger.ts", "if (prior.rows.some((x) => x.period_id === periodId))", "if (false)"],
  ["src/pg-ledger.ts", "assertClosable(periodId, now);", ""],
  ["src/seal.ts", "if (rowsDigest(rows) !== seal.rowsDigest)", "if (false)"],
  ["src/seal.ts", "if (rows.length !== seal.eventCount)", "if (false)"],
  ["src/seal.ts", "if (sealHashOf(seal) !== seal.sealHash)", "if (false)"],
  ["src/seal.ts", "if (!signer.verify(seal.sealHash, seal.signature))", "if (false)"],
  ["src/seal.ts", "return a.length === b.length && timingSafeEqual(a, b);", "return true;"],
  ["src/seal.ts", "prevSealHash: args.prevSealHash,", "prevSealHash: GENESIS_SEAL,"],
  [MIG, "SELECT, INSERT');\n  END LOOP;", "SELECT, INSERT, UPDATE, DELETE');\n  END LOOP;"],
  [
    MIG,
    "CREATE TRIGGER usage_period_guard BEFORE INSERT ON usage_events FOR EACH ROW EXECUTE FUNCTION axis.usage_period_guard();",
    "",
  ],
  [MIG, "PERFORM axis.enable_tenant_rls(t, 'tenant_id', 'SELECT, INSERT');", "PERFORM 1;"],
  // --- emitters: denied is never billed, cache hits are free, tenant binding
  [
    "src/emitters.ts",
    'const BILLABLE = new Set(["ALLOW", "ALLOW_WITH_REDACTION"]);',
    'const BILLABLE = new Set(["ALLOW", "ALLOW_WITH_REDACTION", "DENY", "REQUIRE_APPROVAL"]);',
  ],
  ["src/emitters.ts", 'if (d["ok"] !== true) {', "if (false) {"],
  [
    "src/emitters.ts",
    "const fresh = input > cached ? input - cached : 0n;",
    "const fresh = input;",
  ],
  ["src/emitters.ts", 'if (d["tenant_id"] !== opts.tenantId)', "if (false)"],
  ["src/emitters.ts", "e.seq <= lastSeq", "false"],
  [
    "src/emitters.ts",
    'if (!started) throw new BillingError("INVALID", "the run log must begin with run_started");',
    "",
  ],
  ["src/emitters.ts", 'if (d["phase"] !== "ended") break;', ""],
  // --- rating and money
  ["src/money.ts", "const q = (2n * a + d) / (2n * d);", "const q = a / d;"],
  ["src/money.ts", "shares[i] = (shares[i] as bigint) + 1n;", "shares[i] = shares[i] as bigint;"],
  [
    "src/money.ts",
    "const r = divRound(cum, MICRO_PER_MINOR);",
    "const r = divRound(m, MICRO_PER_MINOR) + prev;",
  ],
  [
    "src/rating.ts",
    "const use = c.remainingMicro < remaining ? c.remainingMicro : remaining;",
    "const use = c.remainingMicro;",
  ],
  [
    "src/rating.ts",
    "row.quantity > 0n ? (row.quantity > allowance ? row.quantity - allowance : 0n) : row.quantity;",
    "row.quantity;",
  ],
  // --- provider safety: live key, live responses, webhook signature, idempotency
  ["src/stripe.ts", "if (!TEST_KEY_RE.test(apiKey)) {", "if (false) {"],
  [
    "src/stripe.ts",
    "const TEST_KEY_RE = /^(sk|rk)_test_",
    "const TEST_KEY_RE = /^(sk|rk)_(test|live)_",
  ],
  ["src/stripe.ts", 'if (body["livemode"] === true)', "if (false)"],
  ["src/stripe.ts", 'headers["idempotency-key"] = idempotencyKey as string;', ""],
  [
    "src/stripe.ts",
    'if (method === "POST" && (!idempotencyKey || idempotencyKey.length > 255))',
    "if (false)",
  ],
  ["src/webhook.ts", "if (Math.abs(args.nowMs / 1000 - t) > tol)", "if (false)"],
  ["src/webhook.ts", "timingSafeEqual(got, expected)) ok = true;", "true) ok = true;"],
  ["src/webhook.ts", "if (!args.secret)", "if (false)"],
  ["src/webhook.ts", "if (o.livemode === true)", "if (false)"],
  [
    "src/webhook.ts",
    'if (!(await (this.o.dedupe ?? (this.o.dedupe = new MemoryEventDedupe())).claim(o.id)))\n      return "duplicate";',
    "",
  ],
  [
    "src/webhook.ts",
    'const expected = Buffer.from(stripeSignature(args.secret, t, args.payload), "hex");',
    'const expected = Buffer.from(stripeSignature(args.secret, t, ""), "hex");',
  ],
  // --- dev server: tenant from the token, scopes
  [
    "src/dev-server.ts",
    'if (q.has("tenant_id") && q.get("tenant_id") !== t) throw new Forbidden();',
    "",
  ],
  [
    "src/dev-server.ts",
    'if (b["tenant_id"] !== undefined && b["tenant_id"] !== t) throw new Forbidden();',
    "",
  ],
  ["src/dev-server.ts", 'if (!auth.scopes.includes("ingest")) throw new Forbidden();', ""],
  ["src/dev-server.ts", 'if (!auth.scopes.includes("admin")) throw new Forbidden();', ""],
  ["src/dev-server.ts", 'if (!auth.scopes.includes("read")) throw new Forbidden();', ""],
  [
    "src/dev-server.ts",
    'tenantId: t,\n      idempotencyKey: str(b["idempotency_key"]',
    'tenantId: T1,\n      idempotencyKey: str(b["idempotency_key"]',
  ],
  // --- adjustments, analytics, reconciliation
  ["src/adjustments.ts", "r.reason.trim().length < 3", "false"],
  ["src/sink.ts", 'if (r.status === "inserted")', "if (true)"],
  ["src/reconcile.ts", "if (expected === actual) continue;", "if (false) continue;"],
  ["src/reconcile.ts", "if (theirs.totalMinor !== myTotal)", "if (false)"],
];

const only = process.argv.slice(2);
const sel = M.filter(
  ([f, from]) => only.length === 0 || only.some((s) => f.includes(s) || from.includes(s)),
);
let survived = 0;
for (const [file, from, to] of sel) {
  const orig = readFileSync(file, "utf8");
  if (!orig.includes(from)) {
    console.log(`SKIP (pattern gone): ${file}: ${from.slice(0, 50)}`);
    survived++;
    continue;
  }
  writeFileSync(file, orig.replace(from, to));
  const r = spawnSync(
    "bash",
    ["../../infra/scripts/with-pg.sh", "pnpm", "exec", "vitest", "run", "--bail", "1"],
    { encoding: "utf8" },
  );
  writeFileSync(file, orig);
  const killed = r.status !== 0;
  if (!killed) survived++;
  console.log(
    `${killed ? "killed  " : "SURVIVED"} ${file}: ${from.slice(0, 60).replace(/\n/g, " ")}`,
  );
}
console.log(`${sel.length - survived}/${sel.length} mutants killed`);
process.exit(survived ? 1 : 0);
