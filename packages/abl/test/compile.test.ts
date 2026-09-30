import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse, stringify } from "yaml";
import {
  canonicalJson,
  compileAbl,
  compileAblYaml,
  contentHash,
  manifestSchema,
  validateManifest,
  type RuntimeManifest,
} from "../src/index.js";
import { baseDoc, exampleDir, exampleNames, loadValid, readExample, type Doc } from "./helpers.js";

const goldenPath = (n: string) => new URL(`${n}.manifest.json`, exampleDir("golden"));
const compileOk = (doc: unknown): RuntimeManifest => {
  const r = compileAbl(doc);
  if (!r.ok) throw new Error(JSON.stringify(r));
  return r.manifest;
};

describe("golden manifests", () => {
  const names = exampleNames("valid", ".yaml");
  it("every valid example has a golden file and vice versa", () => {
    expect(exampleNames("golden", ".manifest.json")).toEqual(names);
  });
  for (const name of names) {
    it(`${name} compiles to the checked-in manifest`, () => {
      const golden = JSON.parse(readFileSync(goldenPath(name), "utf8"));
      const r = compileAblYaml(readExample("valid", `${name}.yaml`));
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.manifest).toEqual(golden);
    });
    it(`${name} manifest satisfies the manifest schema`, () => {
      const m = compileOk(loadValid(name));
      const v = validateManifest(m);
      expect(v.ok, JSON.stringify(v)).toBe(true);
    });
  }
});

describe("defaults", () => {
  it("a minimal document gets every documented default", () => {
    const m = compileOk(baseDoc());
    expect(m.routing.stages).toEqual(["llm"]);
    expect(m.memory).toEqual({ run: true, session: false, long_term: false, knowledge_bases: [] });
    expect(m.process).toEqual({
      restart_policy: "never",
      max_restarts: 0,
      max_children: 0,
      timeout_seconds: null,
      supervisor: "one-for-one",
    });
    expect(m.budgets.tokens).toEqual({ soft: null, hard: 1000 });
    expect(m.budgets.cost_usd).toEqual({ soft: null, hard: null });
    expect(m.data).toEqual({ phi: false, residency: null });
    expect([m.policy_packs, m.channels, m.evals, m.tools, m.models.fallbacks]).toEqual([
      [],
      [],
      [],
      [],
      [],
    ]);
    expect(m.risk).toEqual({
      level: "minimal",
      human_oversight_required: false,
      approver_roles: [],
      transparency_notice: null,
    });
  });

  it("tools default to side_effects write and a 60s timeout; explicit values win", () => {
    const d = baseDoc();
    d.spec.tools = [
      { name: "implicit", kind: "code" },
      { name: "explicit", kind: "browser", sideEffects: "none", timeoutSeconds: 5 },
    ];
    const tools = compileOk(d).tools;
    expect(tools[0]).toEqual({
      name: "implicit",
      kind: "code",
      ref: null,
      mcp_server: null,
      side_effects: "write",
      timeout_seconds: 60,
    });
    expect(tools[1]).toMatchObject({ side_effects: "none", timeout_seconds: 5 });
  });

  it("memory.run can be switched off, and explicit values are kept", () => {
    const d = baseDoc();
    d.spec.memory = { run: false, longTerm: true, session: true };
    expect(compileOk(d).memory).toMatchObject({ run: false, long_term: true, session: true });
  });

  it("model params are renamed to snake_case and only present keys appear", () => {
    const d = baseDoc();
    d.spec.model.primary.params = { temperature: 0.2, maxOutputTokens: 512, topP: 0.9 };
    expect(compileOk(d).models.primary.params).toEqual({
      temperature: 0.2,
      max_output_tokens: 512,
      top_p: 0.9,
    });
  });

  it("process and runtime knobs are carried through", () => {
    const d = baseDoc();
    d.spec.process = {
      restartPolicy: "always",
      maxRestarts: 2,
      maxChildren: 4,
      timeoutSeconds: 30,
      supervisor: "rest-for-one",
    };
    d.spec.budgets.runtimeSeconds = { soft: 10, hard: 20 };
    const m = compileOk(d);
    expect(m.process).toEqual({
      restart_policy: "always",
      max_restarts: 2,
      max_children: 4,
      timeout_seconds: 30,
      supervisor: "rest-for-one",
    });
    expect(m.budgets.runtime_seconds).toEqual({ soft: 10, hard: 20 });
  });

  it("the mpm routing stage is allowed", () => {
    const d = baseDoc();
    d.spec.routing = { stages: ["mpm", "llm"] };
    expect(compileOk(d).routing.stages).toEqual(["mpm", "llm"]);
  });
});

describe("compile results", () => {
  it("schema errors give ok:false with issues and no findings", () => {
    const r = compileAbl({ apiVersion: "nope" });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.issues.length).toBeGreaterThan(0);
      expect(r.findings).toEqual([]);
    }
  });

  it("lint errors give ok:false with findings, warnings included, and no issues", () => {
    const d = baseDoc();
    d.spec.data = { phi: true };
    delete d.spec.budgets;
    const r = compileAbl(d);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.issues).toEqual([]);
      expect(r.findings.map((f) => `${f.severity}:${f.code}`)).toEqual([
        "error:ABL005",
        "warning:ABL103",
      ]);
    }
  });

  it("warnings alone still compile and are returned with the manifest", () => {
    const d = baseDoc();
    delete d.spec.budgets;
    const r = compileAbl(d);
    expect(r.ok).toBe(true);
    expect(r.findings.map((f) => f.code)).toEqual(["ABL103"]);
  });

  it("compileAblYaml reports YAML syntax errors as a yaml issue", () => {
    const r = compileAblYaml("a: [unclosed");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.issues[0]?.keyword).toBe("yaml");
  });

  it("compileAblYaml accepts JSON text too", () => {
    expect(compileAblYaml(JSON.stringify(baseDoc())).ok).toBe(true);
  });
});

/** Recursively reorder object keys (reverse alphabetical) without changing meaning. */
function shuffleKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(shuffleKeys);
  if (v !== null && typeof v === "object") {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? 1 : -1))
        .map(([k, x]) => [k, shuffleKeys(x)]),
    );
  }
  return v;
}

function deepFreeze<T>(v: T): T {
  if (v !== null && typeof v === "object") {
    Object.values(v).forEach(deepFreeze);
    Object.freeze(v);
  }
  return v;
}

describe("determinism and purity", () => {
  for (const name of exampleNames("valid", ".yaml")) {
    it(`${name}: compiling twice gives identical output`, () => {
      const doc = loadValid(name);
      expect(JSON.stringify(compileAbl(doc))).toBe(JSON.stringify(compileAbl(doc)));
    });
    it(`${name}: key order of the input does not change the manifest (byte-identical)`, () => {
      const doc = loadValid(name);
      const a = JSON.stringify(compileOk(doc));
      expect(a).toBe(JSON.stringify(compileOk(shuffleKeys(doc))));
      expect(a).toBe(JSON.stringify(compileOk(parse(stringify(doc)))));
    });
    it(`${name}: input is not mutated (deep-frozen input still compiles)`, () => {
      const doc = loadValid(name);
      const before = JSON.stringify(doc);
      compileOk(deepFreeze(structuredClone(doc)));
      compileAbl(doc);
      expect(JSON.stringify(doc)).toBe(before);
    });
  }

  it("manifest shares no references with the input", () => {
    const d = baseDoc();
    d.spec.memory = { knowledgeBases: ["kb-one"] };
    d.spec.routing = { stages: ["rag", "llm"] };
    const m = compileOk(d);
    m.routing.stages.push("cache");
    m.memory.knowledge_bases.push("x");
    expect(d.spec.routing.stages).toEqual(["rag", "llm"]);
    expect(d.spec.memory.knowledgeBases).toEqual(["kb-one"]);
  });

  it("the content hash changes when the document changes, and only then", () => {
    const d = baseDoc();
    const h = compileOk(d).blueprint.content_hash;
    expect(compileOk(structuredClone(d)).blueprint.content_hash).toBe(h);
    const e: Doc = structuredClone(d);
    e.spec.instructions.system = "Be helpful!";
    expect(compileOk(e).blueprint.content_hash).not.toBe(h);
    const f: Doc = structuredClone(d);
    f.spec.budgets.tokens.hard = 1001;
    expect(compileOk(f).blueprint.content_hash).not.toBe(h);
  });

  it("content_hash is the sha256 of the canonical, sorted-key, float-preserving source JSON", () => {
    const expected = createHash("sha256")
      .update(
        '{"apiVersion":"abl.axis.dev/v1","kind":"Agent","metadata":{"name":"hello-agent","version":"1.0.0"},' +
          '"spec":{"instructions":{"system":"You are a helpful assistant."},' +
          '"model":{"primary":{"model":"claude-sonnet-5-5","provider":"anthropic"}},' +
          '"riskClassification":{"level":"minimal","rationale":"Answers general product questions; no decisions about people."}}}',
      )
      .digest("hex");
    expect(compileOk(loadValid("minimal")).blueprint.content_hash).toBe(expected);
  });

  it("float parameters hash deterministically and distinguish close values", () => {
    const a = baseDoc();
    a.spec.model.primary.params = { temperature: 0.1 };
    const b = baseDoc();
    b.spec.model.primary.params = { temperature: 0.10000000000000002 };
    expect(compileOk(a).blueprint.content_hash).toBe(
      compileOk(structuredClone(a)).blueprint.content_hash,
    );
    expect(compileOk(a).blueprint.content_hash).not.toBe(compileOk(b).blueprint.content_hash);
  });
});

describe("canonicalJson", () => {
  it("sorts keys, drops whitespace, keeps floats", () => {
    expect(canonicalJson({ b: [1, 2.5, { z: null, a: true }], a: "x" })).toBe(
      '{"a":"x","b":[1,2.5,{"a":true,"z":null}]}',
    );
  });
  it("rejects non-finite numbers and non-JSON types", () => {
    expect(() => canonicalJson(NaN)).toThrow(TypeError);
    expect(() => canonicalJson(Infinity)).toThrow(TypeError);
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
    expect(() => canonicalJson(() => 1)).toThrow(TypeError);
  });
  it("contentHash is sha256 hex of the canonical text", () => {
    expect(contentHash({ a: 1 })).toBe(createHash("sha256").update('{"a":1}').digest("hex"));
  });
});

describe("manifest schema", () => {
  it("is a draft 2020-12 schema with its own id, separate from the ABL schema", () => {
    expect(manifestSchema).toMatchObject({
      $id: "https://axis.dev/schemas/runtime-manifest/v1.json",
    });
  });

  const good = () => compileOk(loadValid("claims-triage")) as unknown as Doc;
  const mutations: Array<[string, (m: Doc) => void]> = [
    ["missing top-level key", (m) => delete m.evals],
    ["extra top-level key", (m) => (m.extra = 1)],
    ["wrong manifest_version", (m) => (m.manifest_version = 2)],
    ["bad content hash", (m) => (m.blueprint.content_hash = "abc")],
    ["bad risk level", (m) => (m.risk.level = "unacceptable")],
    ["null where string required", (m) => (m.system_prompt = null)],
    ["tool missing a default-applied field", (m) => delete m.tools[0].side_effects],
    ["tool bad kind", (m) => (m.tools[0].kind = "teleport")],
    ["budget hard negative", (m) => (m.budgets.tokens.hard = -1)],
    ["budget with extra key", (m) => (m.budgets.tokens.max = 1)],
    ["unknown model param", (m) => (m.models.primary.params.camelCase = 1)],
    ["fractional max_restarts", (m) => (m.process.max_restarts = 1.5)],
    ["eval threshold above 1", (m) => (m.evals[0].threshold = 1.5)],
    ["duplicate routing stages", (m) => (m.routing.stages = ["llm", "llm"])],
    ["unknown channel", (m) => (m.channels = ["fax"])],
  ];
  for (const [label, mutate] of mutations) {
    it(`rejects: ${label}`, () => {
      const m = good();
      mutate(m);
      const v = validateManifest(m);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.issues.length).toBeGreaterThan(0);
    });
  }
  it("rejects a non-object", () => {
    expect(validateManifest("nope").ok).toBe(false);
  });
});
