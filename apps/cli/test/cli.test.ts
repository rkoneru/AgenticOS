import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { json, problem } from "../../../packages/sdk-ts/test/mock-server.js";
import { COMMANDS, EXIT } from "../src/index.js";
import { findOperation, formatEvent } from "../src/commands.js";
import { markdownReference } from "../src/cli.js";
import { completionScript } from "../src/completion.js";
import { distance } from "../src/cli.js";
import { axis, KEY } from "./harness.js";

const RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f";
const PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const tmp = () => mkdtempSync(join(tmpdir(), "axis-cli-f-"));
const run = (state = "running") => ({
  id: RUN,
  blueprint: { name: "agent-one", version: "1.0.0" },
  state,
  created_at: "2026-01-01T00:00:00Z",
  trace_id: "a".repeat(32),
});
const ev = (n: number) => ({
  sequence: n,
  type: "tool_call",
  pid: PID,
  at: `2026-01-01T00:00:0${n}.000Z`,
  data: { tool: "x" },
});

const VALID_ABL = readFileSync(
  new URL("../../../packages/abl/examples/valid/minimal.yaml", import.meta.url),
  "utf8",
);

describe("help, usage and exit codes", () => {
  it("no args prints help and exits 2; --help exits 0; --version", async () => {
    const a = await axis([]);
    expect(a.code).toBe(EXIT.USAGE);
    expect(a.out).toContain("Exit codes:");
    const b = await axis(["--help"]);
    expect(b.code).toBe(0);
    expect(b.out).toContain("Usage: axis <command>");
    expect((await axis(["--version"])).out).toMatch(/^axis 0\.1\.0/);
    const c = await axis(["run", "--help"]);
    expect(c.code).toBe(0);
    expect(c.out).toContain("start");
    expect((await axis(["run"])).code).toBe(EXIT.USAGE);
    const d = await axis(["run", "get", "--help"]);
    expect(d.out).toContain("Usage: axis run get <run-id>");
    expect((await axis(["help", "run", "get"])).out).toContain("Usage: axis run get");
  });
  it("unknown command and option suggest fixes and exit 2", async () => {
    const a = await axis(["blueprint"]);
    expect(a.code).toBe(2);
    expect(a.err).toContain('did you mean "axis blueprints"');
    expect((await axis(["run", "frobnicate"])).code).toBe(2);
    const b = await axis(["run", "list", "--stat", "x"]);
    expect(b.code).toBe(2);
    expect(b.err).toContain("did you mean --state");
    expect((await axis(["run", "list", "--limit", "abc"])).err).toContain("needs a number");
    expect((await axis(["run", "list", "--state", "bogus"])).err).toContain("must be one of");
    expect((await axis(["run", "list", "--limit"])).err).toContain("needs a value");
    expect((await axis(["run", "list", "--all=1"])).err).toContain("does not take a value");
    expect((await axis(["run", "get"])).err).toContain("usage: axis run get");
    expect((await axis(["run", "get", "a", "b"])).err).toContain("unexpected argument");
    expect(distance("kitten", "sitting")).toBe(3);
  });
  it("no credentials exits 3 with a hint", async () => {
    const r = await axis(["run", "list"], { env: { AXIS_API_KEY: "" } });
    expect(r.code).toBe(EXIT.AUTH);
    expect(r.err).toContain("axis login");
  });
  it("rejected key exits 3; policy denied exits 4; approval required exits 5; other API error exits 1", async () => {
    const bad = await axis(["run", "get", RUN], { mock: { apiKey: "other" } });
    expect(bad.code).toBe(3);
    expect(bad.err).toContain("request id".slice(0, 0) + "hint");
    const deny = await axis(["run", "start", "a-b@1"], {
      mock: {
        overrides: { startRun: () => problem(403, "policy_denied", { trace_id: "b".repeat(32) }) },
      },
    });
    expect(deny.code).toBe(4);
    expect(deny.err).toContain(`axis audit events --trace-id ${"b".repeat(32)}`);
    const ap = await axis(["run", "start", "a-b@1"], {
      mock: {
        overrides: { startRun: () => problem(403, "approval_required", { approval_id: "ap-1" }) },
      },
    });
    expect(ap.code).toBe(5);
    expect(ap.err).toContain("axis approvals approve ap-1");
    const nf = await axis(["run", "get", RUN], {
      mock: {
        overrides: { getRun: () => problem(404, "not_found", {}, { "x-request-id": "rq1" }) },
      },
    });
    expect(nf.code).toBe(1);
    expect(nf.err).toContain("request id: rq1");
    const rl = await axis(["run", "get", RUN], {
      mock: {
        overrides: { getRun: () => problem(429, "rate_limited", {}, { "retry-after": "2" }) },
      },
      env: {},
    });
    expect(rl.code).toBe(1);
    const v = await axis(["blueprints", "publish", "-", "--no-validate"], {
      stdin: VALID_ABL,
      mock: {
        overrides: {
          publishBlueprintVersion: () =>
            problem(422, "validation_failed", { errors: [{ path: "/abl/x", message: "bad" }] }),
        },
      },
    });
    expect(v.code).toBe(1);
    expect(v.err).toContain("/abl/x: bad");
  });
  it("network failure exits 1 with a hint", async () => {
    const out: string[] = [];
    const { run: runCli } = await import("../src/index.js");
    const code = await runCli(["run", "get", RUN], {
      stdout: () => undefined,
      stderr: (s) => void out.push(s),
      env: { AXIS_API_KEY: KEY, AXIS_BASE_URL: "https://x.test/v1" },
      fetch: () => Promise.reject(new Error("down")),
      sleep: () => Promise.resolve(),
    });
    expect(code).toBe(1);
    expect(out.join("")).toContain("could not reach");
  });
  it("an invalid base URL is a usage error", async () => {
    const r = await axis(["run", "list"], { env: { AXIS_BASE_URL: "http://example.com/v1" } });
    expect(r.code).toBe(2);
  });
});

describe("output formats (golden)", () => {
  it("run get as table, json, yaml", async () => {
    const mock = { overrides: { getRun: () => json(run()) } };
    const t = await axis(["run", "get", RUN], { mock });
    expect(t.out).toBe(
      [
        "id           3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f",
        "blueprint    agent-one@1.0.0",
        "state        running",
        "init pid     -",
        `trace id     ${"a".repeat(32)}`,
        "created      2026-01-01T00:00:00Z",
        "finished     -",
        "exit reason  -",
        "",
      ].join("\n"),
    );
    const j = await axis(["run", "get", RUN, "--json"], { mock });
    expect(JSON.parse(j.out).state).toBe("running");
    const y = await axis(["run", "get", RUN, "-o", "yaml"], { mock });
    expect(y.out).toContain("state: running");
  });
  it("run list table golden and --all pagination", async () => {
    const pages: Record<string, unknown> = {
      "": { items: [run()], next_cursor: "n" },
      n: { items: [{ ...run("terminated"), exit_reason: "done" }], next_cursor: null },
    };
    const mock = {
      overrides: {
        listRuns: (c: { url: URL }) => json(pages[c.url.searchParams.get("cursor") ?? ""]),
      },
    };
    const t = await axis(["run", "list", "--all"], { mock });
    expect(t.out).toBe(
      [
        "ID                                    BLUEPRINT        STATE       CREATED               EXIT",
        `${RUN}  agent-one@1.0.0  running     2026-01-01T00:00:00Z  -`,
        `${RUN}  agent-one@1.0.0  terminated  2026-01-01T00:00:00Z  done`,
        "",
      ].join("\n"),
    );
    expect(t.server.calls).toHaveLength(2);
    const one = await axis(
      ["run", "list", "--limit", "5", "--state", "running", "--blueprint", "agent-one"],
      { mock },
    );
    expect(one.server.calls[0]?.url.searchParams.get("limit")).toBe("5");
    expect(one.server.violations).toEqual([]);
  });
  it("color only on a TTY and without --no-color / NO_COLOR", async () => {
    const mock = { overrides: { listRuns: () => json({ items: [run()] }) } };
    expect((await axis(["run", "list"], { mock, tty: true })).out).toContain("\x1b[1m");
    expect((await axis(["run", "list", "--no-color"], { mock, tty: true })).out).not.toContain(
      "\x1b[",
    );
    expect(
      (await axis(["run", "list"], { mock, tty: true, env: { NO_COLOR: "1" } })).out,
    ).not.toContain("\x1b[");
    expect((await axis(["run", "list"], { mock })).out).not.toContain("\x1b[");
  });
});

describe("commands", () => {
  it("run start with input, wait, tail, and approval-pending timeout", async () => {
    const s = await axis(["run", "start", "agent-one@1.0.0", "--input", '{"q":1}'], {
      mock: { overrides: { startRun: () => json(run("ready"), 202) } },
    });
    expect(s.code).toBe(0);
    expect(s.server.calls[0]?.body).toEqual({
      blueprint: { name: "agent-one", version: "1.0.0" },
      input: { q: 1 },
    });
    expect(s.server.calls[0]?.headers.get("idempotency-key")).toBeTruthy();
    const w = await axis(["run", "start", "agent-one@1.0.0", "--wait"], {
      mock: {
        overrides: {
          startRun: () => json(run("ready"), 202),
          getRun: () => json(run("terminated")),
        },
      },
    });
    expect(w.out).toContain("terminated");
    const sse = (e: unknown) =>
      new Response(`id: 1\ndata: ${JSON.stringify(e)}\n\n`, {
        headers: { "content-type": "text/event-stream" },
      });
    const t = await axis(["run", "start", "agent-one@1.0.0", "--tail"], {
      mock: {
        overrides: {
          startRun: () => json(run("ready"), 202),
          listRunEvents: () => sse(ev(1)),
          getRun: () => json(run("terminated")),
        },
      },
    });
    expect(t.out).toContain("tool_call");
    expect(t.err).toContain("streaming events");
    const approval = {
      id: "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f",
      status: "pending",
      run_id: RUN,
      requested_at: "x",
      sla_deadline: "y",
    };
    const p = await axis(["run", "start", "agent-one@1.0.0", "--wait", "--wait-timeout", "0"], {
      mock: {
        overrides: {
          startRun: () => json(run("ready"), 202),
          getRun: () => json(run("waiting")),
          listApprovals: () => json({ items: [approval] }),
        },
      },
    });
    expect(p.code).toBe(5);
    expect(p.err).toContain("waiting for 1 approval");
    const q = await axis(["run", "start", "agent-one@1.0.0", "--wait", "--wait-timeout", "0"], {
      mock: {
        overrides: { startRun: () => json(run("ready"), 202), getRun: () => json(run("waiting")) },
      },
    });
    expect(q.code).toBe(5);
    expect((await axis(["run", "start", "bad", "--input", "nope"])).code).toBe(1);
    expect((await axis(["run", "start", "bad"])).code).toBe(2);
    const dir = tmp();
    writeFileSync(join(dir, "in.json"), '{"a":2}');
    const f = await axis(["run", "start", "agent-one@1.0.0", "--input", join(dir, "in.json")]);
    expect(f.server.calls[0]?.body).toMatchObject({ input: { a: 2 } });
  });
  it("run tail (table and ndjson), replay, signal, cancel", async () => {
    const sse = () =>
      new Response(
        `id: 1\ndata: ${JSON.stringify(ev(1))}\n\nid: 2\ndata: ${JSON.stringify(ev(2))}\n\n`,
        { headers: { "content-type": "text/event-stream" } },
      );
    const mock = { overrides: { listRunEvents: sse, getRun: () => json(run("terminated")) } };
    const t = await axis(["run", "tail", RUN, "--after", "0"], { mock });
    expect(t.out.trim().split("\n")).toHaveLength(2);
    expect(t.out).toContain(`tool_call         ${PID}  {"tool":"x"}`);
    const j = await axis(["run", "tail", RUN, "--json"], { mock });
    expect(
      j.out
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l).sequence),
    ).toEqual([1, 2]);
    const rp = await axis(["run", "replay", RUN], {
      mock: {
        overrides: { listRunEvents: () => json({ items: [ev(1), ev(2)], next_cursor: null }) },
      },
    });
    expect(rp.out).toContain("+   1.000s");
    expect(rp.out).toContain("2 event(s) replayed");
    const rj = await axis(["run", "replay", RUN, "--json"], {
      mock: { overrides: { listRunEvents: () => json({ items: [ev(1)], next_cursor: null }) } },
    });
    expect(JSON.parse(rj.out).events).toHaveLength(1);
    const sg = await axis(["run", "signal", RUN, "pause", "--reason", "r"]);
    expect(sg.server.calls[0]?.body).toEqual({ signal: "PAUSE", reason: "r" });
    expect(sg.out).toContain("signal PAUSE delivered");
    expect((await axis(["run", "signal", RUN, "boom"])).code).toBe(2);
    const c = await axis(["run", "cancel", RUN, "--force"]);
    expect(c.server.calls[0]?.body).toEqual({ signal: "KILL" });
    expect((await axis(["run", "cancel", RUN])).out).toContain("TERM delivered");
    expect(formatEvent({ ...ev(1), data: { big: "x".repeat(200) } })).toContain("...");
  });
  it("approvals list/approve/deny", async () => {
    const l = await axis(["approvals", "list", "--status", "pending"]);
    expect(l.out).toContain("STATUS");
    expect(l.server.calls[0]?.url.searchParams.get("status")).toBe("pending");
    const a = await axis(["approvals", "approve", RUN, "--comment", "ok"]);
    expect(a.server.calls[0]?.body).toEqual({ decision: "approve", comment: "ok" });
    const d = await axis(["approvals", "deny", RUN, "--idempotency-key", "my-key-123"]);
    expect(d.server.calls[0]?.body).toEqual({ decision: "reject" });
    expect(d.server.calls[0]?.headers.get("idempotency-key")).toBe("my-key-123");
    expect(a.server.violations).toEqual([]);
  });
  it("blueprints validate (offline), publish, list, get", async () => {
    const dir = tmp();
    writeFileSync(join(dir, "ok.yaml"), VALID_ABL);
    writeFileSync(join(dir, "bad.yaml"), "apiVersion: abl.axis.dev/v1\nkind: Agent\n");
    const ok = await axis(["blueprints", "validate", join(dir, "ok.yaml")], {
      env: { AXIS_API_KEY: "", AXIS_BASE_URL: "" },
    });
    expect(ok.code).toBe(0);
    expect(ok.server.calls).toHaveLength(0);
    expect(ok.out).toContain("ok.yaml: ok");
    const bad = await axis([
      "blueprints",
      "validate",
      join(dir, "ok.yaml"),
      join(dir, "bad.yaml"),
      "--json",
    ]);
    expect(bad.code).toBe(1);
    const parsed = JSON.parse(bad.out);
    expect(parsed[0].ok).toBe(true);
    expect(parsed[1].issues.length).toBeGreaterThan(0);
    expect((await axis(["blueprints", "validate"])).code).toBe(2);
    expect((await axis(["blueprints", "validate", join(dir, "missing.yaml")])).code).toBe(1);
    const pub = await axis(["blueprints", "publish", join(dir, "ok.yaml")]);
    expect(pub.code).toBe(0);
    expect(pub.server.calls[0]?.body).toMatchObject({ abl: { kind: "Agent" } });
    const refuse = await axis(["blueprints", "publish", join(dir, "bad.yaml")]);
    expect(refuse.code).toBe(1);
    expect(refuse.server.calls).toHaveLength(0);
    expect(refuse.err).toContain("nothing was published");
    const l = await axis(["blueprints", "list"]);
    expect(l.out).toContain("RISK");
    const g = await axis(["blueprints", "get", "agent-one@1.0.0"]);
    expect(g.server.calls[0]?.url.pathname).toContain("/blueprints/agent-one/versions/1.0.0");
    expect((await axis(["blueprints", "get", "nope"])).code).toBe(2);
    expect((await axis(["blueprints", "get", "a", "1"])).code).toBe(0);
    writeFileSync(join(dir, "broken.yaml"), "a: [");
    expect((await axis(["blueprints", "publish", join(dir, "broken.yaml")])).err).toContain(
      "not valid YAML",
    );
  });
  it("policies list/test/publish/activate", async () => {
    const dir = tmp();
    writeFileSync(join(dir, "p.yaml"), "policy_version: '1'\n");
    const l = await axis(["policies", "list"]);
    expect(l.out).toContain("VERSION");
    const req = '{"enforcement_point":"tool_call","action":"x","context":{}}';
    const t = await axis(["policies", "test", join(dir, "p.yaml"), "--request", req]);
    expect(t.code).toBe(0);
    expect(t.server.calls[0]?.body).toMatchObject({ request: { action: "x" } });
    const denied = await axis(["policies", "test", join(dir, "p.yaml"), "--request", req], {
      mock: {
        overrides: {
          testPolicy: () => json({ decision: "DENY", policy_version: "1", reason: "no" }),
        },
      },
    });
    expect(denied.code).toBe(4);
    const need = await axis(["policies", "test", join(dir, "p.yaml"), "--request", req], {
      mock: {
        overrides: {
          testPolicy: () => json({ decision: "REQUIRE_APPROVAL", policy_version: "1" }),
        },
      },
    });
    expect(need.code).toBe(5);
    expect((await axis(["policies", "test", join(dir, "p.yaml")])).code).toBe(2);
    expect((await axis(["policies", "test", join(dir, "p.yaml"), "--request", "[1]"])).code).toBe(
      2,
    );
    expect((await axis(["policies", "publish", join(dir, "p.yaml")])).code).toBe(0);
    // activate by name@version: the pack is found in the listing, then POST /policies/{versionId}/activate
    const listed = {
      overrides: {
        listPolicyPacks: () =>
          json({
            items: [
              {
                name: "p",
                version: "1",
                created_at: "2026-01-01T00:00:00Z",
                version_id: RUN,
                active: false,
              },
            ],
            next_cursor: null,
          }),
      },
    };
    const act = await axis(["policies", "activate", "p@1"], { mock: listed });
    expect(act.code).toBe(0);
    expect(act.server.calls.map((c) => c.operationId)).toEqual([
      "listPolicyPacks",
      "activatePolicyPack",
    ]);
    expect(act.server.calls[1]?.url.pathname).toContain(`/policies/${RUN}/activate`);
    const byId = await axis(["policies", "activate", RUN]);
    expect(byId.server.calls.map((c) => c.operationId)).toEqual(["activatePolicyPack"]);
    const none = await axis(["policies", "activate", "nope@9"], { mock: listed });
    expect(none.code).toBe(1);
    expect(none.err).toContain("no published policy pack nope@9");
    expect((await axis(["policies", "activate", "bad"])).code).toBe(2);
  });
  it("audit events, verify, export", async () => {
    const e = await axis([
      "audit",
      "events",
      "--decision",
      "DENY",
      "--trace-id",
      "a".repeat(32),
      "--from-seq",
      "3",
    ]);
    expect(e.server.calls[0]?.url.searchParams.get("decision")).toBe("DENY");
    expect(e.server.violations).toEqual([]);
    expect((await axis(["audit", "verify"])).out).toContain("audit chain OK");
    const broken = {
      overrides: {
        verifyAuditChain: () =>
          json({ ok: false, verified: 4, broken_at_seq: 5, reason: "hash mismatch" }),
      },
    };
    const b = await axis(["audit", "verify", "--from-seq", "1", "--to-seq", "9"], { mock: broken });
    expect(b.code).toBe(1);
    expect(b.out).toContain("BROKEN at seq 5");
    const x = await axis(["audit", "export"]);
    expect(x.out.trim().split("\n")).toHaveLength(1);
    const file = join(tmp(), "a.ndjson");
    const f = await axis(["audit", "export", "--out", file, "--verify"]);
    expect(f.code).toBe(0);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const refused = await axis(["audit", "export", "--verify"], { mock: broken });
    expect(refused.code).toBe(1);
    expect(refused.out).toBe("");
    const emptyFile = join(tmp(), "e.ndjson");
    await axis(["audit", "export", "--out", emptyFile], {
      mock: { overrides: { listAuditEvents: () => json({ items: [] }) } },
    });
    expect(readFileSync(emptyFile, "utf8")).toBe("");
  });
  it("kill-switch on/off/list, usage, evals", async () => {
    const on = await axis(["kill-switch", "on", "agent", "agent-one", "--reason", "drill"]);
    expect(on.server.calls[0]?.body).toEqual({
      scope: "agent",
      engaged: true,
      target: "agent-one",
      reason: "drill",
    });
    const off = await axis(["kill-switch", "off", "tenant"]);
    expect(off.server.calls[0]?.body).toEqual({ scope: "tenant", engaged: false });
    expect((await axis(["kill-switch", "on", "galaxy"])).code).toBe(2);
    expect((await axis(["kill-switch", "on"])).code).toBe(2);
    expect((await axis(["kill-switch", "on", "agent"])).code).toBe(2);
    const l = await axis(["kill-switch", "list"]);
    expect(l.out).toContain("SCOPE");
    expect(
      (
        await axis(["kill-switch", "list"], {
          mock: { overrides: { listKillSwitches: () => json({ items: [] }) } },
        })
      ).out,
    ).toContain("no kill-switches engaged");
    const u = await axis(["usage", "--group-by", "day"]);
    expect(u.server.calls[0]?.url.searchParams.get("from")).toBe("2026-03-01T00:00:00.000Z");
    expect(u.server.calls[0]?.url.searchParams.get("to")).toBe("2026-03-15T10:00:00.000Z");
    expect(u.out).toContain("QUANTITY");
    expect(
      (
        await axis(["usage", "--from", "2026-01-01T00:00:00Z", "--to", "2026-02-01T00:00:00Z"], {
          mock: { overrides: { getUsage: () => json({ items: [] }) } },
        })
      ).out,
    ).toContain("no usage between");
    const ev2 = await axis(["evals", "start", "smoke", "agent-one@1.0.0"]);
    expect(ev2.server.calls[0]?.body).toEqual({
      suite: "smoke",
      blueprint: { name: "agent-one", version: "1.0.0" },
    });
  });
  it("registry and marketplace commands call their operations (OpenAPI 1.2.0); api calls any operation", async () => {
    const calls = async (argv: string[]) =>
      (await axis(argv)).server.calls.map((c) => c.operationId);
    expect(await calls(["registry", "namespaces"])).toEqual(["listRegistryNamespaces"]);
    expect(await calls(["registry", "claim", "acme"])).toEqual(["claimRegistryNamespace"]);
    expect(await calls(["registry", "keys", "acme"])).toEqual(["listRegistryKeys"]);
    expect(await calls(["registry", "add-key", "acme", "--public-key", "k".repeat(43)])).toEqual([
      "addRegistryKey",
    ]);
    expect(await calls(["registry", "versions", "acme/agent-one"])).toEqual([
      "listRegistryVersions",
    ]);
    expect(await calls(["registry", "yank", "acme/agent-one@1.0.0", "--reason", "bad"])).toEqual([
      "yankRegistryVersion",
    ]);
    expect(await calls(["registry", "resolve", "acme/agent-one@^1"])).toEqual([
      "resolveRegistryBlueprint",
    ]);
    expect(await calls(["marketplace", "search", "helper"])).toEqual(["listMarketplaceListings"]);
    expect(await calls(["marketplace", "show", "acme/agent-one"])).toEqual([
      "getMarketplaceListing",
    ]);
    expect(await calls(["marketplace", "preview", "acme/agent-one@^1"])).toEqual([
      "previewMarketplaceInstall",
    ]);
    expect(await calls(["marketplace", "installs"])).toEqual(["listMarketplaceInstalls"]);
    expect(await calls(["marketplace", "uninstall", "acme/agent-one"])).toEqual([
      "uninstallMarketplaceListing",
    ]);
    expect(await calls(["approvals", "get", RUN])).toEqual(["getApproval"]);
    expect(await calls(["run", "explain", RUN])).toEqual(["explainRun"]);
    expect(await calls(["audit", "explain", "7"])).toEqual(["explainAuditEvent"]);
    for (const bad of [
      ["registry", "claim"],
      ["registry", "versions", "no-slash"],
      ["registry", "yank", "acme/a@1.0.0"],
      ["registry", "yank", "acme/a", "--reason", "x"],
      ["registry", "add-key", "acme"],
      ["marketplace", "show", "a/b/c"],
      ["audit", "explain", "x"],
    ])
      expect((await axis(bad)).code, bad.join(" ")).toBe(2);
  });
  it("marketplace install needs explicit consent: no flag prints the preview and installs nothing", async () => {
    const none = await axis(["marketplace", "install", "acme/agent-one@^1"]);
    expect(none.code).toBe(2);
    expect(none.out).toContain("consent digest");
    expect(none.err).toContain("consent required: nothing was installed");
    expect(none.server.calls.map((c) => c.operationId)).toEqual(["previewMarketplaceInstall"]);
    const yes = await axis(["marketplace", "install", "acme/agent-one@^1", "--yes", "--json"]);
    expect(yes.code).toBe(0);
    expect(yes.server.calls.map((c) => c.operationId)).toEqual([
      "previewMarketplaceInstall",
      "installMarketplaceListing",
    ]);
    // the install echoes what the PREVIEW returned (version, hash, digest), nothing the caller typed
    const preview = JSON.parse(yes.out).preview;
    expect(yes.server.calls[1]?.body).toMatchObject({
      namespace: preview.namespace,
      version: preview.version,
      content_hash: preview.content_hash,
      consent_digest: preview.consent_digest,
    });
    const wrong = await axis([
      "marketplace",
      "install",
      "acme/agent-one",
      "--consent-digest",
      "0".repeat(64),
    ]);
    expect(wrong.code).toBe(1);
    expect(wrong.err).toContain("does not match");
    expect(wrong.server.calls.map((c) => c.operationId)).toEqual(["previewMarketplaceInstall"]);
  });
  it("server-controlled text is shown inert: a publisher's listing cannot drive the terminal (ANSI/OSC escapes, bidi overrides)", async () => {
    const evil = "Helpful\x1b]52;c;Y3VybCBldmlsfHNo\x07 \x1b[2K\x1b[1Afree \u202Egnp.exe\u200B\x9b31m";
    const l = {
      namespace: "acme",
      name: "agent-one",
      title: evil,
      summary: evil,
      categories: ["support"],
      latest: { version: "1.0.0", content_hash: "a".repeat(64), risk_level: "minimal", max_severity: "info" },
      versions: ["1.0.0"],
    };
    const show = await axis(["marketplace", "show", "acme/agent-one"], {
      mock: { overrides: { getMarketplaceListing: () => json(l) } },
    });
    const search = await axis(["marketplace", "search"], {
      mock: { overrides: { listMarketplaceListings: () => json({ items: [l] }) } },
    });
    for (const r of [show, search]) {
      expect(r.code).toBe(0);
      // no control character other than the newline that separates rows, no bidi override, no zero-width character
      // eslint-disable-next-line no-control-regex
      expect(r.out.replace(/\n/g, "")).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/);
      expect(r.out).toContain("Helpful");
    }
    // an error detail written by the server is inert as well
    const bad = await axis(["run", "get", RUN], {
      mock: { overrides: { getRun: () => problem(404, "not_found", { detail: "gone\x1b[2J\x1b]0;pwned\x07" }) } },
    });
    // eslint-disable-next-line no-control-regex
    expect(bad.err).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
  });
  it("registry keygen/sign/publish: the private key stays in its 0600 file, never in output", async () => {
    const dir = tmp();
    const keyFile = join(dir, "pub.pem");
    const kg = await axis(["registry", "keygen", "--out", keyFile, "--json"]);
    expect(kg.code).toBe(0);
    const k = JSON.parse(kg.out);
    expect(k.key_id).toMatch(/^k1-[0-9a-f]{32}$/);
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
    const pem = readFileSync(keyFile, "utf8");
    expect(kg.out + kg.err).not.toContain(pem.split("\n")[1] as string);
    expect((await axis(["registry", "keygen", "--out", keyFile])).code).toBe(1); // never overwrites a key
    const abl = join(dir, "agent.yaml");
    writeFileSync(
      abl,
      [
        "apiVersion: abl.axis.dev/v1",
        "kind: Agent",
        "metadata: { name: demo-agent, version: 1.0.0 }",
        "spec:",
        "  riskClassification: { level: minimal, rationale: Answers general product questions; no decisions about people. }",
        "  model: { primary: { provider: anthropic, model: claude-sonnet-5-5 } }",
        "  instructions: { system: You are a helpful assistant. }",
        "  budgets: { costUsd: { hard: 5 }, toolCalls: { hard: 20 } }",
        "  policy: { packs: ['baseline-deny@^1.0.0'] }",
      ].join("\n"),
    );
    const signed = await axis(["registry", "sign", abl, "--namespace", "acme", "--key", keyFile]);
    expect(signed.code, signed.err).toBe(0);
    const bundle = JSON.parse(signed.out);
    expect(bundle.signature.key_id).toBe(k.key_id);
    expect(bundle.provenance.payloadType).toBe("application/vnd.in-toto+json");
    expect(signed.out).not.toContain(pem.split("\n")[1] as string);
    const bundleFile = join(dir, "bundle.json");
    writeFileSync(bundleFile, signed.out);
    const pub = await axis(["registry", "publish", bundleFile]);
    expect(pub.server.calls.map((c) => c.operationId)).toEqual(["publishRegistryBlueprint"]);
    expect(pub.server.calls[0]?.url.pathname).toContain("/registry/namespaces/acme/blueprints");
    expect(pub.server.violations).toEqual([]);
    const direct = await axis([
      "registry",
      "publish",
      abl,
      "--namespace",
      "acme",
      "--key",
      keyFile,
    ]);
    expect(direct.server.calls.map((c) => c.operationId)).toEqual(["publishRegistryBlueprint"]);
    // bad inputs
    expect((await axis(["registry", "sign", abl, "--namespace", "acme"])).code).toBe(2);
    expect((await axis(["registry", "sign", abl, "--namespace", "acme", "--key", abl])).code).toBe(
      1,
    );
    expect((await axis(["registry", "publish", abl])).code).toBe(2);
    writeFileSync(join(dir, "bad.yaml"), "apiVersion: nope\n");
    expect(
      (
        await axis([
          "registry",
          "sign",
          join(dir, "bad.yaml"),
          "--namespace",
          "acme",
          "--key",
          keyFile,
        ])
      ).code,
    ).toBe(1);
    expect((await axis(["registry", "keygen"])).code).toBe(2);
  });
  it("api calls any operation by operationId", async () => {
    const a = await axis(["api", "getRun", RUN]);
    expect(a.server.calls[0]?.operationId).toBe("getRun");
    const b = await axis(["api", "listRuns", "--param", "limit=3"]);
    expect(b.server.calls[0]?.url.searchParams.get("limit")).toBe("3");
    const c = await axis(["api", "startRun", "--body", '{"blueprint":{"name":"a","version":"1"}}']);
    expect(c.server.violations).toEqual([]);
    expect((await axis(["api"])).code).toBe(2);
    expect((await axis(["api", "nope"])).code).toBe(2);
    expect((await axis(["api", "getRun"])).code).toBe(2);
    expect((await axis(["api", "listRuns", "--param", "bad"])).code).toBe(2);
    expect((await axis(["api", "listRuns", "-o", "yaml"])).out).toContain("items");
  });
  it("findOperation maps a verb and domain onto an operation when one exists", () => {
    const ops = {
      listRegistryBlueprints: {
        id: "listRegistryBlueprints",
        tag: "Registry",
        path: "/registry/blueprints",
      },
      getRun: { id: "getRun", tag: "Runs", path: "/runs/{runId}" },
    } as never;
    expect(findOperation(ops, "registry", /^list/i)?.id).toBe("listRegistryBlueprints");
    expect(findOperation(ops, "marketplace", /^list/i)).toBeUndefined();
  });
});

describe("login, whoami, logout and the config file", () => {
  it("login via stdin saves a 0600 file in a 0700 dir and never prints the key", async () => {
    const home = tmp();
    const r = await axis(
      ["login", "--with-key-stdin", "--base-url", "https://api.test.axis.example/v1"],
      { home, stdin: `${KEY}\n`, env: { AXIS_API_KEY: "" } },
    );
    expect(r.code).toBe(0);
    expect(r.out + r.err).not.toContain(KEY);
    const cfg = join(home, "axis", "config.json");
    expect(statSync(cfg).mode & 0o777).toBe(0o600);
    expect(statSync(join(home, "axis")).mode & 0o777).toBe(0o700);
    expect(JSON.parse(readFileSync(cfg, "utf8")).profiles.default.apiKey).toBe(KEY);
    // use it without the env var
    const w = await axis(["whoami", "--json"], {
      home,
      env: { AXIS_API_KEY: "", AXIS_BASE_URL: "https://api.test.axis.example/v1" },
    });
    expect(w.code).toBe(0);
    const data = JSON.parse(w.out);
    expect(data.credential_source).toBe("profile");
    expect(JSON.stringify(data)).not.toContain(KEY);
    expect(data.key_fingerprint).toMatch(/^[0-9a-f]{8}$/);
    const t = await axis(["whoami"], {
      home,
      env: { AXIS_API_KEY: "", AXIS_BASE_URL: "https://api.test.axis.example/v1" },
    });
    expect(t.out).toContain("key fingerprint");
    const lo = await axis(["logout"], { home });
    expect(lo.out).toContain("Removed profile");
    expect((await axis(["logout"], { home })).code).toBe(1);
  });
  it("login prompts for the key, rejects empty input, refuses a bad key, and device flow is a stub", async () => {
    const home = tmp();
    expect(
      (
        await axis(["login", "--no-verify"], {
          home,
          secret: KEY,
          tty: true,
          env: { AXIS_API_KEY: "" },
        })
      ).code,
    ).toBe(0);
    expect((await axis(["login"], { home, env: { AXIS_API_KEY: "" } })).code).toBe(2);
    expect((await axis(["login", "--with-key-stdin"], { home, stdin: "  \n" })).code).toBe(2);
    const bad = await axis(["login", "--with-key-stdin"], {
      home: tmp(),
      stdin: "wrong-key-123",
      mock: { apiKey: "other" },
      env: { AXIS_API_KEY: "" },
    });
    expect(bad.code).toBe(3);
    expect(existsSync(join(bad.home, "axis", "config.json"))).toBe(false);
    const dev = await axis(["login", "--device"]);
    expect(dev.code).toBe(1);
    expect(dev.err).toContain("not available yet");
  });
  it("profiles and env precedence", async () => {
    const home = tmp();
    mkdirSync(join(home, "axis"), { recursive: true });
    const file = join(home, "axis", "config.json");
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        defaultProfile: "a",
        profiles: { a: { apiKey: "key-from-a-profile" }, b: { apiKey: "key-from-b-profile" } },
      }),
      { mode: 0o600 },
    );
    const b = await axis(["run", "get", RUN, "--profile", "b"], {
      home,
      env: { AXIS_API_KEY: "" },
    });
    expect(b.server.calls[0]?.headers.get("x-axis-api-key")).toBe("key-from-b-profile");
    const a = await axis(["run", "get", RUN], { home, env: { AXIS_API_KEY: "" } });
    expect(a.server.calls[0]?.headers.get("x-axis-api-key")).toBe("key-from-a-profile");
    const e = await axis(["run", "get", RUN], { home });
    expect(e.server.calls[0]?.headers.get("x-axis-api-key")).toBe(KEY);
    const p = await axis(["run", "get", RUN], {
      home,
      env: { AXIS_API_KEY: "", AXIS_PROFILE: "b" },
    });
    expect(p.server.calls[0]?.headers.get("x-axis-api-key")).toBe("key-from-b-profile");
  });
  it("refuses a config file readable by others (exit 3) and malformed config", async () => {
    const home = tmp();
    mkdirSync(join(home, "axis"), { recursive: true });
    const file = join(home, "axis", "config.json");
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        defaultProfile: "default",
        profiles: { default: { apiKey: "k-123456" } },
      }),
    );
    chmodSync(file, 0o644);
    const r = await axis(["run", "list"], { home, env: { AXIS_API_KEY: "" } });
    expect(r.code).toBe(3);
    expect(r.err).toContain("chmod 600");
    expect(r.err).not.toContain("k-123456");
    chmodSync(file, 0o600);
    writeFileSync(file, "not json");
    expect((await axis(["run", "list"], { home, env: { AXIS_API_KEY: "" } })).err).toContain(
      "not valid JSON",
    );
    writeFileSync(file, '{"profiles": 3}');
    expect((await axis(["run", "list"], { home, env: { AXIS_API_KEY: "" } })).err).toContain(
      "unexpected shape",
    );
  });
  it("there is no tenant flag and the tenant is never sent", async () => {
    const r = await axis(["run", "list", "--tenant", "t1"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("unknown option --tenant");
    const ok = await axis(["run", "list"]);
    for (const [k] of ok.server.calls[0]?.headers.entries() ?? []) expect(k).not.toMatch(/tenant/);
  });
});

describe("completions and docs", () => {
  it("bash, zsh and fish scripts are generated and bash parses", () => {
    const bash = completionScript("bash", COMMANDS, "axis");
    expect(bash).toContain("complete -F _axis_complete axis");
    expect(bash).toContain('"run") words="start tail get explain list signal cancel replay"');
    const r = spawnSync("bash", ["-n"], { input: bash, encoding: "utf8" });
    expect(r.status).toBe(0);
    expect(completionScript("zsh", COMMANDS, "axis")).toContain("compdef _axis axis");
    const fish = completionScript("fish", COMMANDS, "axis");
    expect(fish).toContain("complete -c axis -n '__fish_use_subcommand' -a login");
    expect(fish).not.toContain(" docs");
  });
  it("completion command prints a script; bad shell is a usage error", async () => {
    expect((await axis(["completion", "bash"])).out).toContain("_axis_complete");
    expect((await axis(["completion", "tcsh"])).code).toBe(2);
  });
  it("docs/spec/cli.md embeds the command reference generated from --help", () => {
    const doc = readFileSync(new URL("../../../docs/spec/cli.md", import.meta.url), "utf8");
    const m = /<!-- reference:begin -->\n([\s\S]*?)\n<!-- reference:end -->/.exec(doc);
    expect(m?.[1]).toBe(markdownReference(COMMANDS));
  });
  it("the docs command prints the same reference", async () => {
    expect((await axis(["docs"])).out.trim()).toBe(markdownReference(COMMANDS));
  });
  it("every command leaf has a summary and the exit codes are documented in the help", async () => {
    for (const c of COMMANDS) expect(c.summary.length).toBeGreaterThan(5);
    const h = await axis(["--help"]);
    for (const n of ["0  success", "2  usage", "3  authentication", "4  denied", "5  approval"])
      expect(h.out).toContain(n);
  });
});
