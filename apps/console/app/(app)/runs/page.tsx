"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button, EmptyState, Select, Table, Textarea, useToast } from "@axis/ui";
import { api, type ProcessState, type Run } from "@/lib/api";
import { errorText, useAction, usePaged, useResource } from "@/lib/hooks";
import { formatTime, shortId } from "@/lib/format";
import { ErrorNote, LoadMore, PageHeader, StateBadge } from "@/components/common";
import { Can } from "@/components/session";

const STATES: ProcessState[] = ["spawn", "ready", "running", "waiting", "suspended", "terminated"];

function StartRun({ onStarted }: { onStarted: (r: Run) => void }) {
  const bps = useResource(() => api.listBlueprints({ limit: 200 }));
  const [choice, setChoice] = useState("");
  const [input, setInput] = useState("{}");
  const [inputError, setInputError] = useState<string | undefined>();
  const toast = useToast();
  const start = useAction(async () => {
    const [name, version] = choice.split("@");
    if (!name || !version) throw new Error("Choose a blueprint version");
    let parsed: Record<string, unknown>;
    try {
      const v: unknown = JSON.parse(input || "{}");
      if (typeof v !== "object" || v === null || Array.isArray(v))
        throw new Error("Input must be a JSON object");
      parsed = v as Record<string, unknown>;
    } catch (e) {
      setInputError(e instanceof Error ? e.message : "Invalid JSON");
      throw new Error("Fix the input JSON first");
    }
    setInputError(undefined);
    return api.startRun({ name, version }, parsed);
  });
  const options = [
    { value: "", label: "Select a blueprint version" },
    ...(bps.data?.items ?? []).map((b) => ({
      value: `${b.name}@${b.version}`,
      label: `${b.name} @ ${b.version}`,
    })),
  ];
  return (
    <form
      aria-label="Start a run"
      className="mb-6 flex max-w-xl flex-col gap-3 rounded-md border border-[var(--axis-border)] p-4"
      onSubmit={async (e) => {
        e.preventDefault();
        const r = await start.run();
        if (r) {
          toast.push("Run started", "success");
          onStarted(r);
        }
      }}
    >
      <h2 className="text-base font-semibold">Start a run</h2>
      <Select
        label="Blueprint"
        options={options}
        value={choice}
        onChange={(e) => setChoice(e.target.value)}
        required
      />
      <Textarea
        label="Input (JSON object)"
        rows={4}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        error={inputError}
        className="font-mono"
      />
      {start.error ? <ErrorNote error={start.error} /> : null}
      <div>
        <Button type="submit" loading={start.pending}>
          Start run
        </Button>
      </div>
    </form>
  );
}

export default function RunsPage() {
  const router = useRouter();
  const [state, setState] = useState<ProcessState | "">("");
  const list = usePaged(
    (cursor) =>
      api.listRuns({ limit: 50, ...(state ? { state } : {}), ...(cursor ? { cursor } : {}) }),
    [state],
  );
  return (
    <>
      <title>Runs - AXIS Console</title>
      <PageHeader title="Runs" description="Agent runs and their process lifecycle." />
      <Can cap="runs.start">
        <StartRun onStarted={(r) => router.push(`/runs/${r.id}`)} />
      </Can>
      <div className="mb-3 max-w-xs">
        <Select
          label="Filter by state"
          value={state}
          onChange={(e) => setState(e.target.value as ProcessState | "")}
          options={[
            { value: "", label: "All states" },
            ...STATES.map((s) => ({ value: s, label: s })),
          ]}
        />
      </div>
      {list.error ? <ErrorNote error={list.error} onRetry={list.reload} /> : null}
      {list.loading ? <p role="status">Loading...</p> : null}
      {!list.loading && !list.error ? (
        <Table<Run>
          caption="Runs"
          rows={list.items}
          rowKey={(r) => r.id}
          empty={
            <EmptyState
              title="No runs"
              description={
                state ? `No runs in state ${state}.` : "Start a run from a published blueprint."
              }
            />
          }
          columns={[
            {
              key: "id",
              header: "Run",
              render: (r) => <Link href={`/runs/${r.id}`}>{shortId(r.id)}</Link>,
            },
            {
              key: "bp",
              header: "Blueprint",
              render: (r) => `${r.blueprint.name} @ ${r.blueprint.version}`,
            },
            { key: "state", header: "State", render: (r) => <StateBadge state={r.state} /> },
            { key: "created", header: "Started", render: (r) => formatTime(r.created_at) },
            { key: "finished", header: "Finished", render: (r) => formatTime(r.finished_at) },
          ]}
        />
      ) : null}
      <LoadMore cursor={list.cursor} loading={list.loadingMore} onMore={list.more} />
      <span className="sr-only">{list.error ? errorText(list.error) : ""}</span>
    </>
  );
}
