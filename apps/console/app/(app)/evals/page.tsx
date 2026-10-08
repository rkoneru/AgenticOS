"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button, EmptyState, Input, Select, Table } from "@axis/ui";
import { api, type EvalRun } from "@/lib/api";
import { useAction, useResource } from "@/lib/hooks";
import { can } from "@/lib/roles";
import { parseBlueprintRef } from "@/lib/eval-ref";
import { formatTime } from "@/lib/format";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";
import { EvalsNav, RunStatus, score, usePolling } from "@/components/evals";
import { useSession } from "@/components/session";

export default function EvalsPage() {
  const session = useSession();
  const router = useRouter();
  const [status, setStatus] = useState("");
  const runs = useResource(
    () => api.listEvalRuns({ limit: 100, ...(status ? { status } : {}) }),
    [status],
  );
  const suites = useResource(() => api.listEvalSuites());
  const [suite, setSuite] = useState("");
  const [bp, setBp] = useState("");
  const parsed = parseBlueprintRef(bp);
  const start = useAction(async () => {
    const r = await api.startEvalRun(suite || (suites.data?.items[0]?.ref ?? ""), parsed!);
    router.push(`/evals/runs/${r.id}`);
    return r;
  });
  const live = (runs.data?.items ?? []).some(
    (r) => r.status === "queued" || r.status === "running",
  );
  usePolling(runs.reload, live);
  return (
    <>
      <title>Evals - AXIS Console</title>
      <PageHeader
        title="Evals"
        description="Eval runs against blueprint versions. Releases are blocked when evals regress."
      />
      <EvalsNav />
      {can(session.member.role, "evals.write") ? (
        <form
          className="mb-6 flex max-w-3xl flex-wrap items-end gap-3"
          aria-label="Start an eval run"
          onSubmit={(e) => {
            e.preventDefault();
            void start.run();
          }}
        >
          <Select
            label="Suite"
            value={suite}
            onChange={(e) => setSuite(e.target.value)}
            options={[
              { value: "", label: "(first suite)" },
              ...(suites.data?.items ?? []).map((s) => ({ value: s.ref, label: s.ref })),
            ]}
          />
          <Input
            label="Blueprint (namespace/name@version)"
            value={bp}
            onChange={(e) => setBp(e.target.value)}
            placeholder="acme/answer-agent@1.0.0"
            error={bp !== "" && !parsed ? "Use [namespace/]name@version" : undefined}
          />
          <Button
            type="submit"
            loading={start.pending}
            disabled={!parsed || (suites.data?.items.length ?? 0) === 0}
          >
            Start eval run
          </Button>
        </form>
      ) : null}
      {start.error ? <ErrorNote error={start.error} /> : null}
      <div className="mb-3 max-w-xs">
        <Select
          label="Status"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          options={["", "queued", "running", "passed", "failed", "errored"].map((v) => ({
            value: v,
            label: v === "" ? "All" : v,
          }))}
        />
      </div>
      <ResourceView resource={runs}>
        {(p) => (
          <Table<EvalRun>
            caption="Eval runs"
            rows={p.items}
            rowKey={(r) => r.id}
            empty={
              <EmptyState
                title="No eval runs"
                description="Start a suite against a blueprint version."
              />
            }
            columns={[
              {
                key: "id",
                header: "Run",
                render: (r) => <Link href={`/evals/runs/${r.id}`}>{r.id.slice(0, 8)}</Link>,
              },
              { key: "suite", header: "Suite", render: (r) => r.suite },
              {
                key: "bp",
                header: "Blueprint",
                render: (r) =>
                  r.blueprint
                    ? `${r.blueprint.namespace ? `${r.blueprint.namespace}/` : ""}${r.blueprint.name}@${r.blueprint.version}`
                    : "-",
              },
              { key: "status", header: "Status", render: (r) => <RunStatus run={r} /> },
              { key: "score", header: "Score", render: (r) => score(r.score) },
              { key: "thr", header: "Threshold", render: (r) => r.threshold ?? "-" },
              { key: "when", header: "Created", render: (r) => formatTime(r.created_at) },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
