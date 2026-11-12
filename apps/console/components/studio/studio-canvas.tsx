"use client";
import "@xyflow/react/dist/style.css";
import { useCallback, useMemo, useRef, useState } from "react";
import {
  Background,
  Controls,
  ReactFlow,
  ReactFlowProvider,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node,
  type OnSelectionChangeParams,
} from "@xyflow/react";
import { parse } from "yaml";
import { Button, CodeEditor, useToast } from "@axis/ui";
import { BlueprintEditor } from "@/components/blueprint-editor";
import { AblStatusBar } from "@/components/abl-status";
import { useAblCheck } from "@/lib/use-abl-check";
import {
  BUDGET_METRICS,
  CHANNEL_KINDS,
  ROUTING_STAGES,
  ablToGraph,
  graphToAblYaml,
  orderRoutingStages,
  type AblDocLike,
  type BudgetMetric,
  type ChannelKind,
  type RoutingStage,
  type StudioEdge,
  type StudioNode,
  type StudioNodeData,
} from "@/lib/studio-graph";
import { starterGraph } from "@/lib/studio-starter";
import { studioNodeTypes } from "./nodes";
import { Inspector } from "./inspector";
import { StudioToolbar } from "./toolbar";
import { RoutingOrderEditor } from "./routing-order";

function toRfNodes(nodes: StudioNode[]): Node[] {
  return nodes as unknown as Node[];
}
function toRfEdges(edges: StudioEdge[]): Edge[] {
  return edges as unknown as Edge[];
}
function toStudioNodes(nodes: Node[]): StudioNode[] {
  return nodes as unknown as StudioNode[];
}
function toStudioEdges(edges: Edge[]): StudioEdge[] {
  return edges as unknown as StudioEdge[];
}

let toolCounter = 0;
function nextToolId(existing: StudioNode[]): string {
  const used = new Set(existing.map((n) => n.id));
  let id: string;
  do {
    id = `tool:${toolCounter++}`;
  } while (used.has(id));
  return id;
}

function StudioCanvasInner() {
  const initial = useMemo(() => starterGraph(), []);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>(toRfNodes(initial.nodes));
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(toRfEdges(initial.edges));
  const [selectedId, setSelectedId] = useState<string | undefined>();
  const [previewOpen, setPreviewOpen] = useState(true);
  const [reviewText, setReviewText] = useState<string | undefined>();
  const toast = useToast();
  const liveRef = useRef<HTMLDivElement>(null);

  const studioNodes = toStudioNodes(nodes);
  const studioEdges = toStudioEdges(edges);
  const yamlText = useMemo(() => graphToAblYaml(studioNodes, studioEdges), [nodes, edges]);
  const { check, checking, checkError } = useAblCheck(yamlText);

  const announce = useCallback((msg: string) => {
    if (liveRef.current) liveRef.current.textContent = msg;
  }, []);

  const onConnect = useCallback(
    (c: Connection) => setEdges((eds) => addEdge(c, eds)),
    [setEdges],
  );

  const onSelectionChange = useCallback(({ nodes: sel }: OnSelectionChangeParams) => {
    setSelectedId(sel[0]?.id);
  }, []);

  const addNode = useCallback(
    (node: StudioNode, edgeToAgent = true) => {
      setNodes((cur) => [...cur, node] as unknown as Node[]);
      if (edgeToAgent) {
        setEdges(
          (cur) =>
            [...cur, { id: `${node.id}->agent`, source: node.id, target: "agent" }] as unknown as Edge[],
        );
      }
      setSelectedId(node.id);
    },
    [setNodes, setEdges],
  );

  const onAddTool = useCallback(() => {
    const id = nextToolId(studioNodes);
    addNode({
      id,
      type: "tool",
      position: { x: 780, y: 40 + studioNodes.filter((n) => n.type === "tool").length * 120 },
      data: { name: `new-tool-${id.split(":")[1]}`, kind: "function", sideEffects: "read" },
    });
  }, [addNode, studioNodes]);

  const onAddRoutingStage = useCallback(() => {
    const present = new Set(
      studioNodes.filter((n) => n.type === "routingStage").map((n) => (n.data as { stage: string }).stage),
    );
    const stage = ROUTING_STAGES.find((s) => !present.has(s));
    if (!stage) return;
    const id = `routing:${stage}`;
    const stageNodes = studioNodes.filter((n) => n.type === "routingStage");
    const prev = stageNodes[stageNodes.length - 1];
    setNodes((cur) => [
      ...cur,
      { id, type: "routingStage", position: { x: 40 + stageNodes.length * 170, y: 420 }, data: { stage } },
    ] as unknown as Node[]);
    setEdges((cur) => {
      const next = [...cur].filter((e) => e.id !== `${prev?.id}->agent`);
      if (prev) next.push({ id: `${prev.id}->${id}`, source: prev.id, target: id } as Edge);
      next.push({ id: `${id}->agent`, source: id, target: "agent" } as Edge);
      return next;
    });
    setSelectedId(id);
  }, [studioNodes, setNodes, setEdges]);

  const onAddMemory = useCallback(() => {
    if (studioNodes.some((n) => n.type === "memory")) return;
    addNode({
      id: "memory",
      type: "memory",
      position: { x: 40, y: 420 },
      data: { run: true, session: false, longTerm: false, knowledgeBases: [] },
    });
  }, [addNode, studioNodes]);

  const onAddBudget = useCallback(() => {
    const present = new Set(studioNodes.filter((n) => n.type === "budget").map((n) => (n.data as { metric: BudgetMetric }).metric));
    const metric = BUDGET_METRICS.find((m) => !present.has(m));
    if (!metric) return;
    addNode({
      id: `budget:${metric}`,
      type: "budget",
      position: { x: 40, y: 560 + present.size * 90 },
      data: { metric },
    });
  }, [addNode, studioNodes]);

  const onAddPolicy = useCallback(() => {
    if (studioNodes.some((n) => n.type === "policy")) return;
    addNode({
      id: "policy",
      type: "policy",
      position: { x: 780, y: 420 },
      data: { packs: [] },
    });
  }, [addNode, studioNodes]);

  const onAddChannel = useCallback(() => {
    const present = new Set(studioNodes.filter((n) => n.type === "channel").map((n) => (n.data as { kind: ChannelKind }).kind));
    const kind = CHANNEL_KINDS.find((k) => !present.has(k));
    if (!kind) return;
    addNode({
      id: `channel:${kind}`,
      type: "channel",
      position: { x: 780, y: 560 + present.size * 90 },
      data: { kind },
    });
  }, [addNode, studioNodes]);

  const onNodeDataChange = useCallback(
    (id: string, data: StudioNodeData) => {
      setNodes((cur) =>
        (cur as unknown as StudioNode[]).map((n) => (n.id === id ? { ...n, data } : n)) as unknown as Node[],
      );
    },
    [setNodes],
  );

  const onNodeDelete = useCallback(
    (id: string) => {
      setNodes((cur) => cur.filter((n) => n.id !== id));
      setEdges((cur) => cur.filter((e) => e.source !== id && e.target !== id));
      setSelectedId(undefined);
      announce("Node removed");
    },
    [setNodes, setEdges, announce],
  );

  const onReorderStages = useCallback(
    (order: RoutingStage[]) => {
      setEdges((cur) => {
        const ids = new Set(order.map((s) => `routing:${s}`));
        const kept = (cur as unknown as StudioEdge[]).filter(
          (e) => !(ids.has(e.source) && (ids.has(e.target) || e.target === "agent")),
        );
        const rebuilt: StudioEdge[] = [];
        for (let i = 1; i < order.length; i++) {
          rebuilt.push({
            id: `routing:${order[i - 1]}->routing:${order[i]}`,
            source: `routing:${order[i - 1]}`,
            target: `routing:${order[i]}`,
          });
        }
        const last = order[order.length - 1];
        if (last) rebuilt.push({ id: `routing:${last}->agent`, source: `routing:${last}`, target: "agent" });
        return [...kept, ...rebuilt] as unknown as Edge[];
      });
      announce("Routing order updated");
    },
    [setEdges, announce],
  );

  const onNew = useCallback(() => {
    const g = starterGraph();
    setNodes(toRfNodes(g.nodes));
    setEdges(toRfEdges(g.edges));
    setSelectedId(undefined);
    setReviewText(undefined);
    announce("Canvas reset to the starter blueprint");
  }, [setNodes, setEdges, announce]);

  const onLoadYaml = useCallback(
    (text: string): { ok: boolean; error?: string } => {
      try {
        const doc = parse(text) as AblDocLike;
        if (!doc?.spec?.riskClassification || !doc?.spec?.model || !doc?.metadata?.name) {
          return { ok: false, error: "Not a recognizable ABL document (missing metadata/spec)." };
        }
        const g = ablToGraph(doc);
        setNodes(toRfNodes(g.nodes));
        setEdges(toRfEdges(g.edges));
        setSelectedId(undefined);
        setReviewText(undefined);
        announce("Loaded ABL into the canvas");
        return { ok: true };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : "Invalid YAML" };
      }
    },
    [setNodes, setEdges, announce],
  );

  const selectedNode = selectedId ? studioNodes.find((n) => n.id === selectedId) : undefined;
  const stageNodes = studioNodes.filter((n) => n.type === "routingStage");
  const stageOrder = orderRoutingStages(studioNodes, studioEdges);

  const canAddRoutingStage = stageNodes.length < ROUTING_STAGES.length;
  const canAddMemory = !studioNodes.some((n) => n.type === "memory");
  const canAddBudget = studioNodes.filter((n) => n.type === "budget").length < BUDGET_METRICS.length;
  const canAddPolicy = !studioNodes.some((n) => n.type === "policy");
  const canAddChannel = studioNodes.filter((n) => n.type === "channel").length < CHANNEL_KINDS.length;

  return (
    <div className="flex flex-col gap-3">
      <div ref={liveRef} aria-live="polite" className="sr-only" />
      <StudioToolbar
        onAddTool={onAddTool}
        onAddRoutingStage={onAddRoutingStage}
        onAddMemory={onAddMemory}
        onAddBudget={onAddBudget}
        onAddPolicy={onAddPolicy}
        onAddChannel={onAddChannel}
        onNew={onNew}
        onLoadYaml={onLoadYaml}
        canAddRoutingStage={canAddRoutingStage}
        canAddMemory={canAddMemory}
        canAddBudget={canAddBudget}
        canAddPolicy={canAddPolicy}
        canAddChannel={canAddChannel}
      />
      <div className="flex h-[70vh] min-h-[480px] overflow-hidden rounded-md border border-[var(--axis-border)]">
        <div className="axis-studio-flow relative flex-1">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onSelectionChange={onSelectionChange}
            nodeTypes={studioNodeTypes}
            deleteKeyCode={["Backspace", "Delete"]}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background />
            <Controls />
          </ReactFlow>
        </div>
        {selectedNode ? (
          <Inspector
            node={selectedNode}
            onChange={onNodeDataChange}
            onDelete={onNodeDelete}
            onClose={() => setSelectedId(undefined)}
          />
        ) : null}
      </div>
      <RoutingOrderEditor stageNodes={stageNodes} order={stageOrder} onReorder={onReorderStages} />
      <section className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold">Generated ABL (preview)</h2>
          <Button type="button" variant="ghost" onClick={() => setPreviewOpen((o) => !o)}>
            {previewOpen ? "Collapse" : "Expand"}
          </Button>
        </div>
        {previewOpen ? (
          <div className="flex flex-col gap-2">
            <AblStatusBar checking={checking} check={check} checkError={checkError} />
            <CodeEditor
              label="Generated YAML"
              value={yamlText}
              onChange={() => undefined}
              readOnly
              markers={check?.diagnostics ?? []}
              rows={16}
            />
          </div>
        ) : null}
      </section>
      <div>
        <Button
          type="button"
          onClick={() => {
            setReviewText(yamlText);
            toast.push("Opened in the blueprint editor below", "info");
          }}
        >
          Continue to review &amp; publish
        </Button>
      </div>
      {reviewText !== undefined ? (
        <section className="flex flex-col gap-2 border-t border-[var(--axis-border)] pt-4">
          <h2 className="text-sm font-semibold">Review &amp; publish</h2>
          <p className="text-sm text-[var(--axis-muted)]">
            This is the same blueprint editor and publish flow as{" "}
            <code>/blueprints/new</code>, seeded from the canvas above.
          </p>
          <BlueprintEditor key={reviewText} initial={reviewText} />
        </section>
      ) : null}
    </div>
  );
}

export function StudioCanvas() {
  return (
    <ReactFlowProvider>
      <StudioCanvasInner />
    </ReactFlowProvider>
  );
}
