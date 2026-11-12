/**
 * Graph <-> ABL serializer for the Agent Studio canvas. Pure, framework-free (no React/React Flow
 * import) so it can be unit-tested directly and reused by any future renderer.
 *
 * Node id scheme (see `docs/adr/0119-agent-studio-graph.md` for the full design rationale):
 *  - "agent"            exactly one, required, not deletable
 *  - "model"             exactly one, required, not deletable (spec.model is required)
 *  - "memory"            at most one (spec.memory is a singleton object)
 *  - "policy"            at most one (spec.policy is a singleton object)
 *  - "tool:<n>"          zero or more, n is a stable per-graph counter (not derived from the array index,
 *                        so tool nodes survive reordering/deletion without renumbering)
 *  - "routing:<stage>"   zero or more, one per enum value; order comes from the chain edges
 *  - "budget:<metric>"   zero or more, one per enum value (spec.budgets keys are fixed, not an array)
 *  - "channel:<kind>"    zero or more, one per enum value (spec.channels is a uniqueItems array)
 *
 * Edges express "data flow into the agent": every non-chain node has a single edge to "agent".
 * Routing stage nodes additionally chain to each other in pipeline order, stage[i] -> stage[i+1],
 * with the last stage also edging into "agent" - that chain IS `routing.stages` order; reconnecting
 * those edges (or using the inspector's up/down reorder buttons) changes the compiled order.
 *
 * Losslessness: `spec.process`, `spec.evals`, `spec.data` (PHI/residency) and `metadata.labels` have
 * no dedicated node/control in
 * this iteration (out of scope per the Studio brief) but are preserved byte-for-byte on the agent
 * node's `passthrough` field so round-tripping a document that already has them never silently drops
 * data; there is just no canvas UI to create or edit them (see NEEDS #527).
 */
import { stringify as yamlStringify } from "yaml";

export const ROUTING_STAGES = ["cache", "rules", "mpm", "rag", "llm"] as const;
export type RoutingStage = (typeof ROUTING_STAGES)[number];

export const BUDGET_METRICS = ["tokens", "costUsd", "runtimeSeconds", "toolCalls"] as const;
export type BudgetMetric = (typeof BUDGET_METRICS)[number];

export const CHANNEL_KINDS = [
  "web",
  "slack",
  "teams",
  "email",
  "sms",
  "whatsapp",
  "voice",
] as const;
export type ChannelKind = (typeof CHANNEL_KINDS)[number];

export const TOOL_KINDS = ["function", "mcp", "code", "browser", "channel", "agent"] as const;
export type ToolKind = (typeof TOOL_KINDS)[number];

export const SIDE_EFFECTS = ["none", "read", "write", "external"] as const;
export type SideEffect = (typeof SIDE_EFFECTS)[number];

export const RISK_LEVELS = ["minimal", "limited", "high"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const MODEL_PROVIDERS = [
  "anthropic",
  "openai",
  "google",
  "azure-openai",
  "bedrock",
  "openai-compatible",
] as const;
export type ModelProvider = (typeof MODEL_PROVIDERS)[number];

export interface StudioModelRef {
  provider: ModelProvider | string;
  model: string;
  endpoint?: string;
  params?: { temperature?: number; maxOutputTokens?: number; topP?: number };
}

export interface AgentPassthrough {
  labels?: Record<string, string>;
  process?: Record<string, unknown>;
  evals?: Record<string, unknown>;
  data?: { phi?: boolean; residency?: string };
}

export interface AgentNodeData {
  name: string;
  version: string;
  description?: string;
  owner?: string;
  riskLevel: RiskLevel;
  rationale: string;
  intendedPurpose?: string;
  transparencyNotice?: string;
  humanOversightRequired: boolean;
  approverRoles: string[];
  instructionsSystem: string;
  passthrough?: AgentPassthrough;
}

export interface ModelNodeData {
  primary: StudioModelRef;
  fallbacks: StudioModelRef[];
}

export interface ToolNodeData {
  name: string;
  kind: ToolKind;
  ref?: string;
  mcpServer?: string;
  description?: string;
  sideEffects?: SideEffect;
  timeoutSeconds?: number;
}

export interface RoutingStageNodeData {
  stage: RoutingStage;
}

export interface MemoryNodeData {
  run: boolean;
  session: boolean;
  longTerm: boolean;
  knowledgeBases: string[];
}

export interface BudgetNodeData {
  metric: BudgetMetric;
  soft?: number;
  hard?: number;
}

export interface PolicyNodeData {
  packs: string[];
}

export interface ChannelNodeData {
  kind: ChannelKind;
}

export type StudioNodeType =
  | "agent"
  | "model"
  | "tool"
  | "routingStage"
  | "memory"
  | "budget"
  | "policy"
  | "channel";

export type StudioNodeData =
  | AgentNodeData
  | ModelNodeData
  | ToolNodeData
  | RoutingStageNodeData
  | MemoryNodeData
  | BudgetNodeData
  | PolicyNodeData
  | ChannelNodeData;

/** Structurally compatible with `@xyflow/react`'s `Node<T>` (id/position/data/type), framework-free. */
export interface StudioNode<T extends StudioNodeData = StudioNodeData> {
  id: string;
  type: StudioNodeType;
  position: { x: number; y: number };
  data: T;
  deletable?: boolean;
}

/** Structurally compatible with `@xyflow/react`'s `Edge`. */
export interface StudioEdge {
  id: string;
  source: string;
  target: string;
}

export interface StudioGraph {
  nodes: StudioNode[];
  edges: StudioEdge[];
}

// Minimal structural view of an ABL v1 document - matches `@axis/abl`'s `AblDocument` but declared
// locally so this module has zero runtime dependency on `@axis/abl` (only ever used for typing).
export interface AblDocLike {
  apiVersion: "abl.axis.dev/v1";
  kind: "Agent";
  metadata: {
    name: string;
    version: string;
    description?: string;
    owner?: string;
    labels?: Record<string, string>;
  };
  spec: {
    riskClassification: {
      level: RiskLevel;
      rationale: string;
      intendedPurpose?: string;
      transparencyNotice?: string;
      humanOversight?: { required: boolean; approverRoles?: string[] };
    };
    model: { primary: StudioModelRef; fallbacks?: StudioModelRef[] };
    routing?: { stages?: RoutingStage[] };
    instructions: { system: string };
    tools?: ToolNodeData[];
    memory?: {
      run?: boolean;
      session?: boolean;
      longTerm?: boolean;
      knowledgeBases?: string[];
    };
    budgets?: Partial<Record<BudgetMetric, { soft?: number; hard?: number }>>;
    process?: Record<string, unknown>;
    policy?: { packs?: string[] };
    channels?: ChannelKind[];
    data?: { phi?: boolean; residency?: string };
    evals?: Record<string, unknown>;
  };
}

const AGENT_ID = "agent";
const MODEL_ID = "model";
const MEMORY_ID = "memory";
const POLICY_ID = "policy";
const toolId = (n: number): string => `tool:${n}`;
const routingId = (stage: RoutingStage): string => `routing:${stage}`;
const budgetId = (metric: BudgetMetric): string => `budget:${metric}`;
const channelId = (kind: ChannelKind): string => `channel:${kind}`;

function layout(col: number, row: number): { x: number; y: number } {
  return { x: col * 260, y: row * 140 };
}

/** Build an initial Studio graph from an ABL document. Pure; does not mutate `doc`. */
export function ablToGraph(doc: AblDocLike): StudioGraph {
  const nodes: StudioNode[] = [];
  const edges: StudioEdge[] = [];
  const spec = doc.spec;

  const passthrough: AgentPassthrough = {};
  if (doc.metadata.labels) passthrough.labels = { ...doc.metadata.labels };
  if (spec.process) passthrough.process = structuredCloneLike(spec.process);
  if (spec.evals) passthrough.evals = structuredCloneLike(spec.evals);
  if (spec.data) passthrough.data = { ...spec.data };

  nodes.push({
    id: AGENT_ID,
    type: "agent",
    position: layout(2, 2),
    deletable: false,
    data: {
      name: doc.metadata.name,
      version: doc.metadata.version,
      ...(doc.metadata.description ? { description: doc.metadata.description } : {}),
      ...(doc.metadata.owner ? { owner: doc.metadata.owner } : {}),
      riskLevel: spec.riskClassification.level,
      rationale: spec.riskClassification.rationale,
      ...(spec.riskClassification.intendedPurpose
        ? { intendedPurpose: spec.riskClassification.intendedPurpose }
        : {}),
      ...(spec.riskClassification.transparencyNotice
        ? { transparencyNotice: spec.riskClassification.transparencyNotice }
        : {}),
      humanOversightRequired: spec.riskClassification.humanOversight?.required ?? false,
      approverRoles: spec.riskClassification.humanOversight?.approverRoles ?? [],
      instructionsSystem: spec.instructions.system,
      ...(Object.keys(passthrough).length ? { passthrough } : {}),
    } satisfies AgentNodeData,
  });

  nodes.push({
    id: MODEL_ID,
    type: "model",
    position: layout(0, 0),
    deletable: false,
    data: {
      primary: cloneModelRef(spec.model.primary),
      fallbacks: (spec.model.fallbacks ?? []).map(cloneModelRef),
    } satisfies ModelNodeData,
  });
  edges.push(edge(MODEL_ID, AGENT_ID));

  (spec.tools ?? []).forEach((tool, i) => {
    const id = toolId(i);
    nodes.push({
      id,
      type: "tool",
      position: layout(4, i),
      data: { ...tool } satisfies ToolNodeData,
    });
    edges.push(edge(id, AGENT_ID));
  });

  const stages = spec.routing?.stages ?? [];
  stages.forEach((stage, i) => {
    const id = routingId(stage);
    nodes.push({
      id,
      type: "routingStage",
      position: layout(i, 4),
      data: { stage } satisfies RoutingStageNodeData,
    });
    if (i === 0) return;
    edges.push(edge(routingId(stages[i - 1] as RoutingStage), id));
  });
  if (stages.length > 0) {
    edges.push(edge(routingId(stages[stages.length - 1] as RoutingStage), AGENT_ID));
  }

  if (spec.memory) {
    nodes.push({
      id: MEMORY_ID,
      type: "memory",
      position: layout(0, 3),
      data: {
        run: spec.memory.run ?? false,
        session: spec.memory.session ?? false,
        longTerm: spec.memory.longTerm ?? false,
        knowledgeBases: spec.memory.knowledgeBases ?? [],
      } satisfies MemoryNodeData,
    });
    edges.push(edge(MEMORY_ID, AGENT_ID));
  }

  let bi = 0;
  for (const metric of BUDGET_METRICS) {
    const b = spec.budgets?.[metric];
    if (!b) continue;
    const id = budgetId(metric);
    nodes.push({
      id,
      type: "budget",
      position: layout(0, 5 + bi),
      data: {
        metric,
        ...(b.soft !== undefined ? { soft: b.soft } : {}),
        ...(b.hard !== undefined ? { hard: b.hard } : {}),
      } satisfies BudgetNodeData,
    });
    edges.push(edge(id, AGENT_ID));
    bi++;
  }

  if (spec.policy) {
    nodes.push({
      id: POLICY_ID,
      type: "policy",
      position: layout(4, 3),
      data: { packs: spec.policy.packs ?? [] } satisfies PolicyNodeData,
    });
    edges.push(edge(POLICY_ID, AGENT_ID));
  }

  (spec.channels ?? []).forEach((kind, i) => {
    const id = channelId(kind);
    nodes.push({
      id,
      type: "channel",
      position: layout(4, 5 + i),
      data: { kind } satisfies ChannelNodeData,
    });
    edges.push(edge(id, AGENT_ID));
  });

  return { nodes, edges };
}

/** Rebuild an ABL document from the Studio graph. Pure; does not mutate `nodes`/`edges`. */
export function graphToAbl(nodes: StudioNode[], edges: StudioEdge[]): AblDocLike {
  const agent = nodes.find((n): n is StudioNode<AgentNodeData> => n.type === "agent");
  const model = nodes.find((n): n is StudioNode<ModelNodeData> => n.type === "model");
  if (!agent) throw new Error("graphToAbl: graph has no agent node");
  if (!model) throw new Error("graphToAbl: graph has no model node");
  const a = agent.data;
  const m = model.data;

  const tools = nodes
    .filter((n): n is StudioNode<ToolNodeData> => n.type === "tool")
    .map((n) => ({ ...n.data }));

  const stageOrder = orderRoutingStages(nodes, edges);

  const memoryNode = nodes.find((n): n is StudioNode<MemoryNodeData> => n.type === "memory");
  const policyNode = nodes.find((n): n is StudioNode<PolicyNodeData> => n.type === "policy");
  const budgetNodes = nodes.filter((n): n is StudioNode<BudgetNodeData> => n.type === "budget");
  const channelNodes = nodes.filter((n): n is StudioNode<ChannelNodeData> => n.type === "channel");

  const budgets: AblDocLike["spec"]["budgets"] = {};
  for (const n of budgetNodes) {
    budgets[n.data.metric] = {
      ...(n.data.soft !== undefined ? { soft: n.data.soft } : {}),
      ...(n.data.hard !== undefined ? { hard: n.data.hard } : {}),
    };
  }

  const doc: AblDocLike = {
    apiVersion: "abl.axis.dev/v1",
    kind: "Agent",
    metadata: {
      name: a.name,
      version: a.version,
      ...(a.description ? { description: a.description } : {}),
      ...(a.owner ? { owner: a.owner } : {}),
      ...(a.passthrough?.labels ? { labels: a.passthrough.labels } : {}),
    },
    spec: {
      riskClassification: {
        level: a.riskLevel,
        rationale: a.rationale,
        ...(a.intendedPurpose ? { intendedPurpose: a.intendedPurpose } : {}),
        ...(a.transparencyNotice ? { transparencyNotice: a.transparencyNotice } : {}),
        ...(a.humanOversightRequired || a.approverRoles.length > 0
          ? {
              humanOversight: {
                required: a.humanOversightRequired,
                ...(a.approverRoles.length ? { approverRoles: [...a.approverRoles] } : {}),
              },
            }
          : {}),
      },
      model: {
        primary: cloneModelRef(m.primary),
        ...(m.fallbacks.length ? { fallbacks: m.fallbacks.map(cloneModelRef) } : {}),
      },
      ...(stageOrder.length ? { routing: { stages: stageOrder } } : {}),
      instructions: { system: a.instructionsSystem },
      ...(tools.length ? { tools } : {}),
      ...(memoryNode
        ? {
            memory: {
              run: memoryNode.data.run,
              session: memoryNode.data.session,
              longTerm: memoryNode.data.longTerm,
              ...(memoryNode.data.knowledgeBases.length
                ? { knowledgeBases: [...memoryNode.data.knowledgeBases] }
                : {}),
            },
          }
        : {}),
      ...(Object.keys(budgets).length ? { budgets } : {}),
      ...(a.passthrough?.process ? { process: a.passthrough.process } : {}),
      ...(a.passthrough?.data ? { data: a.passthrough.data } : {}),
      ...(policyNode
        ? { policy: { packs: [...policyNode.data.packs] } }
        : {}),
      ...(channelNodes.length ? { channels: channelNodes.map((n) => n.data.kind) } : {}),
      ...(a.passthrough?.evals ? { evals: a.passthrough.evals } : {}),
    },
  };
  return doc;
}

/** Topological order of routing-stage nodes from their chain edges (falls back to canvas order for an
 * unconnected/partial chain, so a mid-edit graph never throws). */
export function orderRoutingStages(nodes: StudioNode[], edges: StudioEdge[]): RoutingStage[] {
  const stageNodes = nodes.filter(
    (n): n is StudioNode<RoutingStageNodeData> => n.type === "routingStage",
  );
  if (stageNodes.length === 0) return [];
  const ids = new Set(stageNodes.map((n) => n.id));
  const next = new Map<string, string>();
  const hasIncoming = new Set<string>();
  for (const e of edges) {
    if (ids.has(e.source) && ids.has(e.target)) {
      next.set(e.source, e.target);
      hasIncoming.add(e.target);
    }
  }
  const starts = stageNodes.filter((n) => !hasIncoming.has(n.id));
  const headId = (starts[0] ?? stageNodes[0])?.id;
  const order: RoutingStage[] = [];
  const seen = new Set<string>();
  let cur: string | undefined = headId;
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    const node = stageNodes.find((n) => n.id === cur);
    if (node) order.push(node.data.stage);
    cur = next.get(cur);
  }
  // Any stage node the chain didn't reach (a disconnected node mid-edit) is appended in canvas order.
  for (const n of stageNodes) {
    if (!seen.has(n.id)) order.push(n.data.stage);
  }
  return order;
}

function cloneModelRef(ref: StudioModelRef): StudioModelRef {
  return {
    provider: ref.provider,
    model: ref.model,
    ...(ref.endpoint ? { endpoint: ref.endpoint } : {}),
    ...(ref.params ? { params: { ...ref.params } } : {}),
  };
}

function edge(source: string, target: string): StudioEdge {
  return { id: `${source}->${target}`, source, target };
}

/** `graphToAbl` followed by a deterministic YAML render, for the live preview panel and for handing
 * the result to `BlueprintEditor`. */
export function graphToAblYaml(nodes: StudioNode[], edges: StudioEdge[]): string {
  return yamlStringify(graphToAbl(nodes, edges));
}

// Avoids a hard dependency on the DOM/Node `structuredClone` global existing in every test runner.
function structuredCloneLike<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}
