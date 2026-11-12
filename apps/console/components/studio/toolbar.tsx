"use client";
import { useRef, useState } from "react";
import { Button, Dialog, Textarea, useToast } from "@axis/ui";

export function StudioToolbar({
  onAddTool,
  onAddRoutingStage,
  onAddMemory,
  onAddBudget,
  onAddPolicy,
  onAddChannel,
  onNew,
  onLoadYaml,
  canAddRoutingStage,
  canAddMemory,
  canAddBudget,
  canAddPolicy,
  canAddChannel,
}: {
  onAddTool: () => void;
  onAddRoutingStage: () => void;
  onAddMemory: () => void;
  onAddBudget: () => void;
  onAddPolicy: () => void;
  onAddChannel: () => void;
  onNew: () => void;
  onLoadYaml: (text: string) => { ok: boolean; error?: string };
  canAddRoutingStage: boolean;
  canAddMemory: boolean;
  canAddBudget: boolean;
  canAddPolicy: boolean;
  canAddChannel: boolean;
}) {
  const [loadOpen, setLoadOpen] = useState(false);
  const [loadText, setLoadText] = useState("");
  const [loadError, setLoadError] = useState<string | undefined>();
  const toast = useToast();
  const liveRef = useRef<HTMLDivElement>(null);

  function announce(msg: string) {
    if (liveRef.current) liveRef.current.textContent = msg;
  }

  return (
    <div
      role="toolbar"
      aria-label="Studio actions"
      className="flex flex-wrap items-center gap-2 border-b border-[var(--axis-border)] bg-[var(--axis-surface)] p-2"
    >
      <Button
        type="button"
        variant="secondary"
        onClick={() => {
          onAddTool();
          announce("Tool node added");
        }}
      >
        Add tool
      </Button>
      <Button
        type="button"
        variant="secondary"
        disabled={!canAddRoutingStage}
        title={canAddRoutingStage ? undefined : "All routing stages are already on the canvas."}
        onClick={() => {
          onAddRoutingStage();
          announce("Routing stage node added");
        }}
      >
        Add routing stage
      </Button>
      <Button
        type="button"
        variant="secondary"
        disabled={!canAddMemory}
        title={canAddMemory ? undefined : "A memory node is already on the canvas."}
        onClick={() => {
          onAddMemory();
          announce("Memory node added");
        }}
      >
        Add memory
      </Button>
      <Button
        type="button"
        variant="secondary"
        disabled={!canAddBudget}
        title={canAddBudget ? undefined : "All budget metrics are already on the canvas."}
        onClick={() => {
          onAddBudget();
          announce("Budget node added");
        }}
      >
        Add budget
      </Button>
      <Button
        type="button"
        variant="secondary"
        disabled={!canAddPolicy}
        title={canAddPolicy ? undefined : "A policy node is already on the canvas."}
        onClick={() => {
          onAddPolicy();
          announce("Policy node added");
        }}
      >
        Add policy pack
      </Button>
      <Button
        type="button"
        variant="secondary"
        disabled={!canAddChannel}
        title={canAddChannel ? undefined : "All channel kinds are already on the canvas."}
        onClick={() => {
          onAddChannel();
          announce("Channel node added");
        }}
      >
        Add channel
      </Button>
      <span className="mx-1 h-6 w-px bg-[var(--axis-border)]" aria-hidden="true" />
      <Button type="button" variant="ghost" onClick={onNew}>
        New
      </Button>
      <Button type="button" variant="ghost" onClick={() => setLoadOpen(true)}>
        Load from YAML
      </Button>
      <div ref={liveRef} aria-live="polite" className="sr-only" />
      <Dialog
        open={loadOpen}
        onOpenChange={setLoadOpen}
        title="Load from YAML"
        description="Paste an ABL document to replace the current canvas with it."
        footer={
          <>
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setLoadOpen(false);
                setLoadError(undefined);
                setLoadText("");
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              onClick={() => {
                const r = onLoadYaml(loadText);
                if (r.ok) {
                  setLoadOpen(false);
                  setLoadError(undefined);
                  setLoadText("");
                  toast.push("Loaded ABL into the canvas", "success");
                } else {
                  setLoadError(r.error ?? "Could not parse that as ABL.");
                }
              }}
            >
              Load
            </Button>
          </>
        }
      >
        <Textarea
          label="ABL (YAML)"
          value={loadText}
          onChange={(e) => setLoadText(e.target.value)}
          error={loadError}
          rows={14}
        />
      </Dialog>
    </div>
  );
}
