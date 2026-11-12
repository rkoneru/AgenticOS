"use client";
import { Button, Input, Select, Textarea } from "@axis/ui";
import {
  CHANNEL_KINDS,
  MODEL_PROVIDERS,
  RISK_LEVELS,
  ROUTING_STAGES,
  SIDE_EFFECTS,
  TOOL_KINDS,
  type AgentNodeData,
  type BudgetNodeData,
  type ChannelNodeData,
  type MemoryNodeData,
  type ModelNodeData,
  type PolicyNodeData,
  type RoutingStageNodeData,
  type StudioNode,
  type StudioNodeData,
  type ToolNodeData,
} from "@/lib/studio-graph";
import { ListEditor } from "./list-editor";

const opts = (vs: readonly string[]) => vs.map((v) => ({ value: v, label: v }));

function AgentForm({
  data,
  onChange,
}: {
  data: AgentNodeData;
  onChange: (next: AgentNodeData) => void;
}) {
  const needsTransparency = data.riskLevel === "limited" || data.riskLevel === "high";
  const needsOversight = data.riskLevel === "high";
  const oversightInvalid = needsOversight && data.approverRoles.length === 0;
  return (
    <div className="flex flex-col gap-3">
      <Input
        label="Name"
        value={data.name}
        onChange={(e) => onChange({ ...data, name: e.target.value })}
        hint="DNS-label style: lowercase letters, digits, hyphens."
      />
      <Input
        label="Version"
        value={data.version}
        onChange={(e) => onChange({ ...data, version: e.target.value })}
        hint="SemVer, e.g. 1.0.0"
      />
      <Select
        label="Risk level"
        options={opts(RISK_LEVELS)}
        value={data.riskLevel}
        onChange={(e) => {
          const riskLevel = e.target.value as AgentNodeData["riskLevel"];
          onChange({
            ...data,
            riskLevel,
            humanOversightRequired: riskLevel === "high" ? true : data.humanOversightRequired,
          });
        }}
      />
      <Textarea
        label="Rationale"
        value={data.rationale}
        onChange={(e) => onChange({ ...data, rationale: e.target.value })}
        hint="At least 10 characters. Why this risk level (EU AI Act)."
        rows={3}
      />
      <Textarea
        label="Transparency notice"
        value={data.transparencyNotice ?? ""}
        onChange={(e) => onChange({ ...data, transparencyNotice: e.target.value })}
        error={
          needsTransparency && !data.transparencyNotice
            ? "Required when risk level is limited or high."
            : undefined
        }
        hint="Shown to end users when they interact with the agent."
        rows={2}
      />
      <div className="flex flex-col gap-1">
        <label className="flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            checked={data.humanOversightRequired}
            disabled={needsOversight}
            onChange={(e) => onChange({ ...data, humanOversightRequired: e.target.checked })}
          />
          Human oversight required
        </label>
        {needsOversight ? (
          <p className="text-xs text-[var(--axis-muted)]">
            Required because risk level is high; it cannot be turned off here.
          </p>
        ) : null}
      </div>
      <ListEditor
        label="Approver roles"
        hint={
          needsOversight
            ? "Required: at least one role, because risk level is high."
            : "Roles allowed to approve this agent's gated actions."
        }
        items={data.approverRoles}
        onChange={(approverRoles) => onChange({ ...data, approverRoles })}
        addLabel="Add approver role"
        placeholder="e.g. ops"
      />
      {oversightInvalid ? (
        <p role="alert" className="text-xs text-[var(--axis-danger-text)]">
          High risk requires at least one approver role.
        </p>
      ) : null}
      <Textarea
        label="System instructions"
        value={data.instructionsSystem}
        onChange={(e) => onChange({ ...data, instructionsSystem: e.target.value })}
        rows={6}
      />
    </div>
  );
}

function ModelForm({
  data,
  onChange,
}: {
  data: ModelNodeData;
  onChange: (next: ModelNodeData) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      <Select
        label="Provider"
        options={opts(MODEL_PROVIDERS)}
        value={data.primary.provider}
        onChange={(e) =>
          onChange({ ...data, primary: { ...data.primary, provider: e.target.value } })
        }
      />
      <Input
        label="Model"
        value={data.primary.model}
        onChange={(e) => onChange({ ...data, primary: { ...data.primary, model: e.target.value } })}
      />
      <Input
        label="Endpoint (optional)"
        value={data.primary.endpoint ?? ""}
        onChange={(e) =>
          onChange({
            ...data,
            primary: { ...data.primary, endpoint: e.target.value || undefined },
          })
        }
      />
      <p className="text-xs text-[var(--axis-muted)]">
        {data.fallbacks.length} fallback model{data.fallbacks.length === 1 ? "" : "s"} - edit
        fallbacks in the YAML preview below for now.
      </p>
    </div>
  );
}

function ToolForm({ data, onChange }: { data: ToolNodeData; onChange: (next: ToolNodeData) => void }) {
  return (
    <div className="flex flex-col gap-3">
      <Input label="Name" value={data.name} onChange={(e) => onChange({ ...data, name: e.target.value })} />
      <Select
        label="Kind"
        options={opts(TOOL_KINDS)}
        value={data.kind}
        onChange={(e) => onChange({ ...data, kind: e.target.value as ToolNodeData["kind"] })}
      />
      <Select
        label="Side effects"
        options={opts(SIDE_EFFECTS)}
        value={data.sideEffects ?? "write"}
        onChange={(e) =>
          onChange({ ...data, sideEffects: e.target.value as ToolNodeData["sideEffects"] })
        }
        hint="Policy packs key off this. Defaults to write (conservative) when unset."
      />
      {data.kind === "mcp" ? (
        <Input
          label="MCP server URL"
          value={data.mcpServer ?? ""}
          error={!data.mcpServer ? "Required for kind = mcp." : undefined}
          onChange={(e) => onChange({ ...data, mcpServer: e.target.value })}
        />
      ) : null}
      <Input
        label="Ref (optional)"
        value={data.ref ?? ""}
        hint="Registry reference, e.g. web-search@^1.2.0"
        onChange={(e) => onChange({ ...data, ref: e.target.value || undefined })}
      />
      <Input
        label="Timeout seconds (optional)"
        type="number"
        value={data.timeoutSeconds ?? ""}
        onChange={(e) =>
          onChange({
            ...data,
            timeoutSeconds: e.target.value ? Number(e.target.value) : undefined,
          })
        }
      />
    </div>
  );
}

function RoutingStageForm({ data }: { data: RoutingStageNodeData }) {
  return (
    <div className="flex flex-col gap-2 text-sm">
      <p>
        Stage: <span className="font-mono">{data.stage}</span>
      </p>
      <p className="text-xs text-[var(--axis-muted)]">
        Routing stage kinds are fixed by NEXUS ({ROUTING_STAGES.join(", ")}). Reorder the pipeline
        in the "Routing order" panel below the canvas, or by dragging this chain's edges.
      </p>
    </div>
  );
}

function MemoryForm({
  data,
  onChange,
}: {
  data: MemoryNodeData;
  onChange: (next: MemoryNodeData) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      {(["run", "session", "longTerm"] as const).map((k) => (
        <label key={k} className="flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            checked={data[k]}
            onChange={(e) => onChange({ ...data, [k]: e.target.checked })}
          />
          {k === "longTerm" ? "Long-term" : k}
        </label>
      ))}
      <ListEditor
        label="Knowledge bases"
        items={data.knowledgeBases}
        onChange={(knowledgeBases) => onChange({ ...data, knowledgeBases })}
        addLabel="Add knowledge base"
      />
    </div>
  );
}

function BudgetForm({
  data,
  onChange,
}: {
  data: BudgetNodeData;
  onChange: (next: BudgetNodeData) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm">
        Metric: <span className="font-mono">{data.metric}</span>
      </p>
      <Input
        label="Soft limit"
        type="number"
        value={data.soft ?? ""}
        onChange={(e) =>
          onChange({ ...data, soft: e.target.value ? Number(e.target.value) : undefined })
        }
        hint="Warn/notify threshold."
      />
      <Input
        label="Hard limit"
        type="number"
        value={data.hard ?? ""}
        error={
          data.soft !== undefined && data.hard !== undefined && data.soft > data.hard
            ? "Soft must not exceed hard."
            : undefined
        }
        onChange={(e) =>
          onChange({ ...data, hard: e.target.value ? Number(e.target.value) : undefined })
        }
        hint="TKI terminates the run with budget_exceeded past this."
      />
    </div>
  );
}

function PolicyForm({
  data,
  onChange,
}: {
  data: PolicyNodeData;
  onChange: (next: PolicyNodeData) => void;
}) {
  return (
    <ListEditor
      label="Policy packs"
      items={data.packs}
      onChange={(packs) => onChange({ ...data, packs })}
      addLabel="Add policy pack"
      placeholder="e.g. baseline-deny@^1.0.0"
    />
  );
}

function ChannelForm({ data }: { data: ChannelNodeData }) {
  return (
    <p className="text-sm">
      Channel: <span className="font-mono">{data.kind}</span>. Channel kinds are fixed (
      {CHANNEL_KINDS.join(", ")}); remove this node and add another to pick a different one.
    </p>
  );
}

export function Inspector({
  node,
  onChange,
  onDelete,
  onClose,
}: {
  node: StudioNode;
  onChange: (id: string, data: StudioNodeData) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}) {
  const set = (data: StudioNodeData) => onChange(node.id, data);
  const removable = node.deletable !== false;
  return (
    <aside
      aria-label={`${node.type} inspector`}
      className="flex w-80 shrink-0 flex-col gap-3 overflow-y-auto border-l border-[var(--axis-border)] bg-[var(--axis-surface)] p-4"
    >
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold capitalize">{node.type} node</h2>
        <Button type="button" variant="ghost" onClick={onClose} aria-label="Close inspector">
          Close
        </Button>
      </div>
      {node.type === "agent" ? (
        <AgentForm data={node.data as AgentNodeData} onChange={set} />
      ) : node.type === "model" ? (
        <ModelForm data={node.data as ModelNodeData} onChange={set} />
      ) : node.type === "tool" ? (
        <ToolForm data={node.data as ToolNodeData} onChange={set} />
      ) : node.type === "routingStage" ? (
        <RoutingStageForm data={node.data as RoutingStageNodeData} />
      ) : node.type === "memory" ? (
        <MemoryForm data={node.data as MemoryNodeData} onChange={set} />
      ) : node.type === "budget" ? (
        <BudgetForm data={node.data as BudgetNodeData} onChange={set} />
      ) : node.type === "policy" ? (
        <PolicyForm data={node.data as PolicyNodeData} onChange={set} />
      ) : node.type === "channel" ? (
        <ChannelForm data={node.data as ChannelNodeData} />
      ) : null}
      {removable ? (
        <Button type="button" variant="danger" onClick={() => onDelete(node.id)}>
          Remove node
        </Button>
      ) : (
        <p className="text-xs text-[var(--axis-muted)]">
          This node is required and cannot be removed.
        </p>
      )}
    </aside>
  );
}
