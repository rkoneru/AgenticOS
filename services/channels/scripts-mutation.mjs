/* global console, process */
// Mutation check for the safety logic: apply one targeted edit at a time, run the tests, and require a FAILURE.
// A surviving mutant means a safety property is untested. Usage (from services/channels): node scripts-mutation.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const M = [
  ["src/crypto.ts", "timingSafeEqual(sha256(bytes(a)), sha256(bytes(b)))", "true"],
  [
    "src/crypto.ts",
    "return safeEqual(hmacSha256Hex(secret, data), provided.toLowerCase());",
    "return true;",
  ],
  [
    "src/adapters/slack.ts",
    'if (!safeEqual(slackSignature(key, ts, req.body), sig)) return "bad";',
    "",
  ],
  [
    "src/adapters/slack.ts",
    'withinWindow(Number(ts) * 1000, nowMs, this.windowMs) ? "ok" : "stale"',
    '"ok"',
  ],
  [
    "src/adapters/sms.ts",
    "if (!safeEqual(twilioSignature(token, url, params), sig))",
    "if (false)",
  ],
  [
    "src/adapters/whatsapp.ts",
    "if (!verifyHmacSha256Hex(appSecret, req.body, header.slice(7)))",
    "if (false)",
  ],
  ["src/adapters/whatsapp.ts", "if (keys.size !== 1)", "if (false)"],
  [
    "src/adapters/email.ts",
    "if (!withinWindow(Number(ts) * 1000, ctx.nowMs, this.windowMs))",
    "if (false)",
  ],
  ["src/adapters/teams.ts", 'claimUrl !== body["serviceUrl"]', "false"],
  ["src/jwt.ts", 'if (header["alg"] !== "RS256") return fail("unsupported alg");', ""],
  ["src/jwt.ts", 'if (!ok) return fail("signature mismatch");', ""],
  ["src/jwt.ts", "!auds.includes(o.audience)", "false"],
  ["src/jwt.ts", 'if (exp + skew < nowSec) return fail("expired");', ""],
  ["src/adapters/web.ts", "!safeEqual(mac(key, payload), sig)", "false"],
  ["src/adapters/web.ts", 'if (!originAllowed(s.route, req.headers["origin"]))', "if (false)"],
  [
    "src/gateway.ts",
    "if (!(await this.d.idempotency.claim(idemKey, this.d.idempotencyTtlMs ?? 2 * DAY_MS))) {\n      await this.auditReplay",
    "if (false) {\n      await this.auditReplay",
  ],
  [
    "src/gateway.ts",
    "if (m.tenant_id !== verified.route.tenant_id || m.channel !== channel) {",
    "if (false) {",
  ],
  ["src/gateway.ts", "byThread.end_user_id === endUserId &&", ""],
  ["src/gateway.ts", 'if (!ident && route.settings["allow_unsolicited"] !== true)', "if (false)"],
  ["src/gateway.ts", "ident.end_user_id !== conversation.end_user_id", "false"],
  [
    "src/gateway.ts",
    'throw new ChannelError("AUDIT_FAILED", "audit append failed");',
    "return {} as never;",
  ],
  ["src/identity.ts", "if (!this.limiter.take(", "if (false && !this.limiter.take("],
  ["src/memory-store.ts", 'if (c.consumed) return { ok: false, reason: "consumed" };', ""],
  [
    "src/memory-store.ts",
    'if (c.expires_at_ms <= nowMs) return { ok: false, reason: "expired" };',
    "",
  ],
  ["src/routing.ts", "r.tenant_id === tenant &&", ""],
  ["src/transport.ts", 'if (u.protocol !== "https:")', "if (false)"],
  ["src/transport.ts", "if (!hostAllowed(u.hostname, this.allowedHosts))", "if (false)"],
  ["src/redact.ts", 'phi && mode === "full" ? "redacted_preview" : mode', "mode"],
  ["src/email-compose.ts", "if (/[\\u0000-\\u001f\\u007f]/.test(s))", "if (false)"],
  ["src/limits.ts", "typeAllowed(a.content_type, limits.allowedAttachmentTypes) &&", ""],
];

let survived = 0;
for (const [file, from, to] of M) {
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
console.log(`${M.length - survived}/${M.length} mutants killed`);
process.exit(survived ? 1 : 0);
