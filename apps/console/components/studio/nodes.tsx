"use client";
import { Handle, Position, type NodeProps, type NodeTypes } from "@xyflow/react";
import type {
  AgentNodeData,
  BudgetNodeData,
  ChannelNodeData,
  MemoryNodeData,
  ModelNodeData,
  PolicyNodeData,
  RoutingStageNodeData,
  ToolNodeData,
} from "@/lib/studio-graph";

/**
 * Small, information-dense node cards. Each type gets a distinct left-border accent (not a garish
 * fill) so the canvas reads as one consistent dev-tool surface in both themes via the existing
 * `--axis-*` tokens, never a hardcoded color.
 */
const CARD =
  "w-56 rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] px-3 py-2 text-xs text-[var(--axis-fg)] shadow-sm outline-none focus-visible:outline-2 focus-visible:outline-[var(--axis-focus)]";
const TITLE = "flex items-center gap-1.5 text-[13px] font-semibold";
const ROW = "mt-1 truncate text-[var(--axis-muted)]";

function accent(color: string): string {
  return `border-l-[3px]`.concat(" ", color);
}

function Dot({ className }: { className: string }) {
  return <span aria-hidden="true" className={`inline-block h-2 w-2 rounded-full ${className}`} />;
}

function TargetHandle() {
  return <Handle type="target" position={Position.Left} />;
}
function SourceHandle() {
  return <Handle type="source" position={Position.Right} />;
}

function AgentNode({ data, selected }: NodeProps & { data: AgentNodeData }) {
  return (
    <div
      className={`${CARD} border-l-[3px] border-l-[var(--axis-accent)] ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <TargetHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-accent)]" /> Agent
      </div>
      <div className="mt-1 font-mono text-[13px]">
        {data.name}@{data.version}
      </div>
      <div className={ROW}>risk: {data.riskLevel}</div>
      <div className={ROW}>{data.instructionsSystem}</div>
    </div>
  );
}

function ModelNode({ data, selected }: NodeProps & { data: ModelNodeData }) {
  return (
    <div
      className={`${CARD} ${accent("border-l-[var(--axis-info-text)]")} ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <SourceHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-info-text)]" /> Model
      </div>
      <div className="mt-1 font-mono">
        {data.primary.provider}/{data.primary.model}
      </div>
      {data.fallbacks.length ? (
        <div className={ROW}>
          +{data.fallbacks.length} fallback{data.fallbacks.length === 1 ? "" : "s"}
        </div>
      ) : null}
    </div>
  );
}

function ToolNode({ data, selected }: NodeProps & { data: ToolNodeData }) {
  return (
    <div
      className={`${CARD} ${accent("border-l-[var(--axis-good-text)]")} ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <SourceHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-good-text)]" /> Tool
      </div>
      <div className="mt-1 font-mono">{data.name}</div>
      <div className={ROW}>
        {data.kind} - {data.sideEffects ?? "write"}
      </div>
    </div>
  );
}

const STAGE_LABEL: Record<RoutingStageNodeData["stage"], string> = {
  cache: "Cache",
  rules: "Rules",
  mpm: "MPM",
  rag: "RAG",
  llm: "LLM",
};

function RoutingStageNode({ data, selected }: NodeProps & { data: RoutingStageNodeData }) {
  return (
    <div
      className={`${CARD} w-36 ${accent("border-l-[var(--axis-warn-text)]")} ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <TargetHandle />
      <SourceHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-warn-text)]" /> Stage
      </div>
      <div className="mt-1 font-mono">{STAGE_LABEL[data.stage]}</div>
    </div>
  );
}

function MemoryNode({ data, selected }: NodeProps & { data: MemoryNodeData }) {
  const on: string[] = [];
  if (data.run) on.push("run");
  if (data.session) on.push("session");
  if (data.longTerm) on.push("long-term");
  return (
    <div
      className={`${CARD} ${accent("border-l-[var(--axis-danger-text)]")} ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <SourceHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-danger-text)]" /> Memory
      </div>
      <div className="mt-1 font-mono">{on.join(", ") || "none"}</div>
      {data.knowledgeBases.length ? (
        <div className={ROW}>KB: {data.knowledgeBases.join(", ")}</div>
      ) : null}
    </div>
  );
}

function BudgetNode({ data, selected }: NodeProps & { data: BudgetNodeData }) {
  return (
    <div
      className={`${CARD} ${accent("border-l-[var(--axis-muted)]")} ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <SourceHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-muted)]" /> Budget
      </div>
      <div className="mt-1 font-mono">{data.metric}</div>
      <div className={ROW}>
        soft {data.soft ?? "-"} / hard {data.hard ?? "-"}
      </div>
    </div>
  );
}

function PolicyNode({ data, selected }: NodeProps & { data: PolicyNodeData }) {
  return (
    <div
      className={`${CARD} ${accent("border-l-[var(--axis-accent)]")} ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <SourceHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-accent)]" /> Policy
      </div>
      <div className={ROW}>{data.packs.length ? data.packs.join(", ") : "no packs"}</div>
    </div>
  );
}

function ChannelNode({ data, selected }: NodeProps & { data: ChannelNodeData }) {
  return (
    <div
      className={`${CARD} w-36 ${accent("border-l-[var(--axis-info-text)]")} ${selected ? "ring-2 ring-[var(--axis-focus)]" : ""}`}
    >
      <SourceHandle />
      <div className={TITLE}>
        <Dot className="bg-[var(--axis-info-text)]" /> Channel
      </div>
      <div className="mt-1 font-mono">{data.kind}</div>
    </div>
  );
}

export const studioNodeTypes: NodeTypes = {
  agent: AgentNode,
  model: ModelNode,
  tool: ToolNode,
  routingStage: RoutingStageNode,
  memory: MemoryNode,
  budget: BudgetNode,
  policy: PolicyNode,
  channel: ChannelNode,
};
