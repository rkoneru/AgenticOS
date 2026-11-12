"use client";
import { Button } from "@axis/ui";
import type { RoutingStage, StudioNode } from "@/lib/studio-graph";

const STAGE_LABEL: Record<RoutingStage, string> = {
  cache: "Cache",
  rules: "Rules",
  mpm: "MPM",
  rag: "RAG",
  llm: "LLM",
};

/**
 * Keyboard-accessible alternative to reordering the routing chain by dragging edges: Up/Down
 * buttons rewrite the chain's edges to match. This is the fallback the Studio brief calls for,
 * since dragging a React Flow edge has no built-in keyboard equivalent.
 */
export function RoutingOrderEditor({
  stageNodes,
  order,
  onReorder,
}: {
  stageNodes: StudioNode[];
  order: RoutingStage[];
  onReorder: (order: RoutingStage[]) => void;
}) {
  if (stageNodes.length === 0) return null;
  const idFor = (stage: RoutingStage) => `routing:${stage}`;
  return (
    <section
      aria-label="Routing order"
      className="flex flex-col gap-2 border-t border-[var(--axis-border)] bg-[var(--axis-surface)] p-3"
    >
      <h2 className="text-sm font-semibold">Routing order</h2>
      <p className="text-xs text-[var(--axis-muted)]">
        NEXUS runs these stages in order; the first to resolve a request short-circuits the rest.
        Reorder by dragging the chain's edges on the canvas, or with these buttons.
      </p>
      <ol className="flex flex-wrap items-center gap-2">
        {order.map((stage, i) => (
          <li key={idFor(stage)} className="flex items-center gap-1">
            <span className="rounded-full border border-[var(--axis-border)] bg-[var(--axis-surface-2)] px-2 py-1 font-mono text-xs">
              {i + 1}. {STAGE_LABEL[stage]}
            </span>
            <Button
              type="button"
              variant="ghost"
              aria-label={`Move ${STAGE_LABEL[stage]} earlier`}
              disabled={i === 0}
              onClick={() => {
                const next = [...order];
                [next[i - 1], next[i]] = [next[i] as RoutingStage, next[i - 1] as RoutingStage];
                onReorder(next);
              }}
            >
              Up
            </Button>
            <Button
              type="button"
              variant="ghost"
              aria-label={`Move ${STAGE_LABEL[stage]} later`}
              disabled={i === order.length - 1}
              onClick={() => {
                const next = [...order];
                [next[i], next[i + 1]] = [next[i + 1] as RoutingStage, next[i] as RoutingStage];
                onReorder(next);
              }}
            >
              Down
            </Button>
          </li>
        ))}
      </ol>
    </section>
  );
}
