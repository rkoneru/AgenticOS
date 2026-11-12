import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { compileAbl, type RuntimeManifest } from "@axis/abl";
import {
  ablToGraph,
  graphToAbl,
  type AblDocLike,
  type AgentNodeData,
  type BudgetNodeData,
  type ChannelNodeData,
  type MemoryNodeData,
  type ModelNodeData,
  type PolicyNodeData,
  type RoutingStageNodeData,
  type StudioEdge,
  type StudioNode,
  type ToolNodeData,
} from "@/lib/studio-graph";
import { starterGraph } from "@/lib/studio-starter";

const examplesDir = fileURLToPath(new URL("../../../packages/abl/examples/valid", import.meta.url));

function manifestOf(doc: unknown): RuntimeManifest {
  const r = compileAbl(doc);
  if (!r.ok) throw new Error(`fixture did not compile: ${JSON.stringify(r.issues)}`);
  return r.manifest;
}

/**
 * `blueprint.content_hash` is defined (docs/spec/abl-v1.md) as the sha256 of the canonical JSON of
 * the *source document itself*, so it is sensitive to the presence/absence of a field even when the
 * field's value is the compiler's own default (e.g. the source explicitly writing `longTerm: false`
 * vs. omitting it - both compile to the same `long_term: false` manifest field, but hash differently).
 * The serializer does not promise to reproduce every such omission choice 1:1 (the spec's own
 * round-trip guarantee is about the compiled manifest, not source-byte identity), so round-trip
 * equivalence is checked on every manifest field except that hash, whose shape is still asserted.
 */
function expectEquivalentManifest(actual: RuntimeManifest, expected: RuntimeManifest): void {
  expect(actual.blueprint.content_hash).toMatch(/^[0-9a-f]{64}$/);
  expect(expected.blueprint.content_hash).toMatch(/^[0-9a-f]{64}$/);
  const strip = (m: RuntimeManifest) => ({
    ...m,
    blueprint: { ...m.blueprint, content_hash: undefined },
  });
  expect(strip(actual)).toEqual(strip(expected));
}

describe("ablToGraph <-> graphToAbl round-trips every valid example", () => {
  const files = readdirSync(examplesDir).filter((f) => f.endsWith(".yaml"));
  expect(files.length).toBeGreaterThan(0);

  for (const file of files) {
    it(`round-trips ${file} to an equivalent compiled manifest`, () => {
      const text = readFileSync(join(examplesDir, file), "utf8");
      const original = parse(text) as AblDocLike;

      const { nodes, edges } = ablToGraph(original);
      const rebuilt = graphToAbl(nodes, edges);

      // The exact YAML/key order need not match (the spec only guarantees the compiled manifest is
      // canonical) but the compiled RuntimeManifest must be identical.
      expectEquivalentManifest(manifestOf(rebuilt), manifestOf(original));
    });
  }
});

describe("ablToGraph <-> graphToAbl structural invariants", () => {
  it("produces exactly one non-deletable agent node and one model node", () => {
    const { nodes } = starterGraph();
    const agentNodes = nodes.filter((n) => n.type === "agent");
    const modelNodes = nodes.filter((n) => n.type === "model");
    expect(agentNodes).toHaveLength(1);
    expect(agentNodes[0]?.deletable).toBe(false);
    expect(modelNodes).toHaveLength(1);
  });

  it("every non-agent, non-chain node has exactly one edge into the agent node", () => {
    const text = readFileSync(join(examplesDir, "claims-triage.yaml"), "utf8");
    const { nodes, edges } = ablToGraph(parse(text) as AblDocLike);
    const stageIds = new Set(nodes.filter((n) => n.type === "routingStage").map((n) => n.id));
    for (const n of nodes) {
      if (n.type === "agent" || stageIds.has(n.id)) continue;
      const toAgent = edges.filter((e) => e.source === n.id && e.target === "agent");
      expect(toAgent, `${n.id} should edge into agent`).toHaveLength(1);
    }
  });

  it("chains routing stages in declared order and edges the tail into the agent", () => {
    const text = readFileSync(join(examplesDir, "claims-triage.yaml"), "utf8");
    const doc = parse(text) as AblDocLike;
    expect(doc.spec.routing?.stages).toEqual(["cache", "rules", "rag", "llm"]);
    const { nodes, edges } = ablToGraph(doc);
    const stageNodes = nodes.filter(
      (n): n is StudioNode<RoutingStageNodeData> => n.type === "routingStage",
    );
    expect(stageNodes.map((n) => n.data.stage)).toEqual(["cache", "rules", "rag", "llm"]);
    expect(edges).toContainEqual(
      expect.objectContaining({ source: "routing:cache", target: "routing:rules" }),
    );
    expect(edges).toContainEqual(
      expect.objectContaining({ source: "routing:rules", target: "routing:rag" }),
    );
    expect(edges).toContainEqual(
      expect.objectContaining({ source: "routing:rag", target: "routing:llm" }),
    );
    expect(edges).toContainEqual(
      expect.objectContaining({ source: "routing:llm", target: "agent" }),
    );
  });

  it("reordering the routing chain's edges changes the serialized stage order", () => {
    const text = readFileSync(join(examplesDir, "claims-triage.yaml"), "utf8");
    const { nodes, edges } = ablToGraph(parse(text) as AblDocLike);
    // Reconnect the chain as rules -> cache -> rag -> llm (swap the first two stages).
    const reordered: StudioEdge[] = edges
      .filter((e) => !e.id.startsWith("routing:"))
      .concat([
        { id: "routing:rules->routing:cache", source: "routing:rules", target: "routing:cache" },
        { id: "routing:cache->routing:rag", source: "routing:cache", target: "routing:rag" },
        { id: "routing:rag->routing:llm", source: "routing:rag", target: "routing:llm" },
        { id: "routing:llm->agent", source: "routing:llm", target: "agent" },
      ]);
    const rebuilt = graphToAbl(nodes, reordered);
    expect(rebuilt.spec.routing?.stages).toEqual(["rules", "cache", "rag", "llm"]);
  });

  it("omits optional spec sections entirely when their node is absent", () => {
    const { nodes, edges } = starterGraph();
    const doc = graphToAbl(nodes, edges);
    expect(doc.spec.tools).toBeUndefined();
    expect(doc.spec.routing).toBeUndefined();
    expect(doc.spec.memory).toBeUndefined();
    expect(doc.spec.budgets).toBeUndefined();
    expect(doc.spec.policy).toBeUndefined();
    expect(doc.spec.channels).toBeUndefined();
  });

  it("builds a from-scratch graph (agent + tool + routing stage) that compiles cleanly", () => {
    const { nodes, edges } = starterGraph();
    const toolNode: StudioNode<ToolNodeData> = {
      id: "tool:0",
      type: "tool",
      position: { x: 0, y: 0 },
      data: { name: "web-search", kind: "function", sideEffects: "read" },
    };
    const stageNode: StudioNode<RoutingStageNodeData> = {
      id: "routing:llm",
      type: "routingStage",
      position: { x: 0, y: 0 },
      data: { stage: "llm" },
    };
    const allNodes = [...nodes, toolNode, stageNode];
    const allEdges: StudioEdge[] = [
      ...edges,
      { id: "tool:0->agent", source: "tool:0", target: "agent" },
      { id: "routing:llm->agent", source: "routing:llm", target: "agent" },
    ];
    const doc = graphToAbl(allNodes, allEdges);
    expect(doc.spec.tools).toEqual([{ name: "web-search", kind: "function", sideEffects: "read" }]);
    expect(doc.spec.routing?.stages).toEqual(["llm"]);
    const r = compileAbl(doc);
    expect(r.ok).toBe(true);
  });

  it("surfaces the high-risk human-oversight requirement when serializing", () => {
    const { nodes, edges } = starterGraph();
    const agent = nodes.find((n): n is StudioNode<AgentNodeData> => n.type === "agent");
    if (!agent) throw new Error("no agent node");
    agent.data = {
      ...agent.data,
      riskLevel: "high",
      transparencyNotice: "You are talking to an AI.",
      humanOversightRequired: true,
      approverRoles: ["ops"],
    };
    const doc = graphToAbl(nodes, edges);
    expect(doc.spec.riskClassification.humanOversight).toEqual({
      required: true,
      approverRoles: ["ops"],
    });
    // compileAbl should accept it (high risk without evals is only a lint *finding*, not a schema
    // failure captured in this assertion - we only assert the schema-level oversight requirement here).
    const r = compileAbl(doc);
    expect(r.ok || (!r.ok && r.issues.every((i) => !i.path.includes("humanOversight")))).toBe(true);
  });
});

describe("graph node payload shapes used by the inspector", () => {
  it("round-trips a full memory/budget/policy/channel node set", () => {
    const text = readFileSync(join(examplesDir, "claims-triage.yaml"), "utf8");
    const { nodes, edges } = ablToGraph(parse(text) as AblDocLike);
    const memory = nodes.find((n): n is StudioNode<MemoryNodeData> => n.type === "memory");
    const budgets = nodes.filter((n): n is StudioNode<BudgetNodeData> => n.type === "budget");
    const policy = nodes.find((n): n is StudioNode<PolicyNodeData> => n.type === "policy");
    const channels = nodes.filter((n): n is StudioNode<ChannelNodeData> => n.type === "channel");
    const model = nodes.find((n): n is StudioNode<ModelNodeData> => n.type === "model");
    expect(memory?.data.knowledgeBases).toEqual(["claims-handbook"]);
    expect(budgets.map((b) => b.data.metric).sort()).toEqual(["costUsd", "tokens", "toolCalls"]);
    expect(policy?.data.packs).toEqual(["baseline-deny@^1.0.0", "phi-redaction@^1.1.0"]);
    expect(channels.map((c) => c.data.kind).sort()).toEqual(["slack", "web"]);
    expect(model?.data.fallbacks).toHaveLength(1);
    const doc = graphToAbl(nodes, edges);
    expectEquivalentManifest(
      manifestOf(doc),
      manifestOf(parse(readFileSync(join(examplesDir, "claims-triage.yaml"), "utf8"))),
    );
  });
});
