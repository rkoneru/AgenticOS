"use client";
import Link from "next/link";
import { use } from "react";
import { Badge, Table } from "@axis/ui";
import { api, type EvalCaseResult, type EvalGrade } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { EvalsNav, RunStatus, score, usePolling } from "@/components/evals";
import { ScoreBars } from "@/components/eval-charts";

const gradeTone = (g: EvalGrade) =>
  g.status === "scored"
    ? g.score >= 0.5
      ? "good"
      : "bad"
    : g.status === "pending"
      ? "warn"
      : "bad";

function CaseRow({ c }: { c: EvalCaseResult }) {
  const decisions = c.trace?.gate_decisions ?? [];
  return (
    <details
      className="rounded-md border border-[var(--axis-border)] p-3"
      data-testid={`case-${c.case_id}`}
    >
      <summary className="cursor-pointer text-sm">
        <strong>{c.case_id}</strong> <Badge>{c.status}</Badge> score {score(c.score)}
      </summary>
      <div className="mt-2 flex flex-col gap-3 text-sm">
        <div>
          <h4 className="font-medium">Agent output</h4>
          {/* untrusted text: rendered as a text node, never as markup */}
          <pre
            className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-[var(--axis-surface-2)] p-2"
            data-testid="case-output"
          >
            {c.output ?? "(no output)"}
          </pre>
        </div>
        <Table<EvalGrade>
          caption={`Grades of case ${c.case_id}`}
          rows={c.grades}
          rowKey={(g) => g.grader_id}
          columns={[
            { key: "g", header: "Grader", render: (g) => g.grader_id },
            { key: "k", header: "Kind", render: (g) => g.kind },
            {
              key: "s",
              header: "Status",
              render: (g) => <Badge tone={gradeTone(g)}>{g.status}</Badge>,
            },
            { key: "sc", header: "Score", render: (g) => score(g.score) },
            { key: "d", header: "Detail", render: (g) => g.detail ?? "" },
          ]}
        />
        {decisions.length > 0 ? (
          <Table
            caption={`Kernel decisions of case ${c.case_id}`}
            rows={decisions.map((d, i) => ({ ...d, i }))}
            rowKey={(d) => String(d.i)}
            columns={[
              { key: "a", header: "Action", render: (d) => d.action },
              { key: "p", header: "Point", render: (d) => d.enforcement_point },
              { key: "d", header: "Decision", render: (d) => d.decision },
              { key: "r", header: "Reason", render: (d) => d.reason },
            ]}
          />
        ) : null}
        {c.trace?.trace_id ? (
          <p>
            Trace{" "}
            <Link href={`/audit?trace_id=${encodeURIComponent(c.trace.trace_id)}`}>
              {c.trace.trace_id.slice(0, 12)}
            </Link>{" "}
            in the audit log
          </p>
        ) : null}
      </div>
    </details>
  );
}

export default function EvalRunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const res = useResource(() => api.getEvalRun(id), [id]);
  const cmp = useResource(() => api.getEvalComparison(id), [id, res.data?.status]);
  const live = res.data?.status === "queued" || res.data?.status === "running";
  usePolling(res.reload, live);
  return (
    <>
      <title>{`Eval run ${id.slice(0, 8)} - AXIS Console`}</title>
      <PageHeader
        title={`Eval run ${id.slice(0, 8)}`}
        description="Scores are recomputed by the Eval Hub from the per-case grades."
      />
      <EvalsNav />
      <ResourceView resource={res}>
        {(r) => {
          const perGrader = Object.entries(r.scores?.per_grader ?? {}).sort();
          const base = cmp.data;
          return (
            <div className="flex flex-col gap-4">
              <dl className="grid max-w-3xl grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-[12rem_1fr]">
                <dt className="text-[var(--axis-muted)]">Status</dt>
                <dd data-testid="run-status">
                  <RunStatus run={r} />
                </dd>
                <dt className="text-[var(--axis-muted)]">Suite</dt>
                <dd>{r.suite}</dd>
                <dt className="text-[var(--axis-muted)]">Blueprint</dt>
                <dd>
                  {r.blueprint
                    ? `${r.blueprint.namespace ? `${r.blueprint.namespace}/` : ""}${r.blueprint.name}@${r.blueprint.version}`
                    : "-"}{" "}
                  <code>{r.blueprint?.content_hash.slice(0, 12)}</code>
                </dd>
                <dt className="text-[var(--axis-muted)]">Overall</dt>
                <dd data-testid="run-score">
                  {score(r.score)} (needs {r.threshold ?? "-"})
                </dd>
                <dt className="text-[var(--axis-muted)]">Runner</dt>
                <dd>{r.runner_id ?? "-"}</dd>
                <dt className="text-[var(--axis-muted)]">Finished</dt>
                <dd>{formatTime(r.finished_at)}</dd>
                {r.failure_reason ? (
                  <>
                    <dt className="text-[var(--axis-muted)]">Failure</dt>
                    <dd>{r.failure_reason}</dd>
                  </>
                ) : null}
                {(r.scores?.failures ?? []).length > 0 ? (
                  <>
                    <dt className="text-[var(--axis-muted)]">Suite rules failed</dt>
                    <dd>{r.scores?.failures.join("; ")}</dd>
                  </>
                ) : null}
              </dl>
              {base ? (
                <p className="text-sm" data-testid="baseline-compare">
                  Against the baseline run{" "}
                  <Link href={`/evals/runs/${base.baseline_run_id}`}>
                    {base.baseline_run_id.slice(0, 8)}
                  </Link>
                  : delta <strong>{base.delta === null ? "-" : base.delta.toFixed(3)}</strong>{" "}
                  (tolerance {base.tolerance}){" "}
                  {base.blocking ? (
                    <Badge tone="bad">regression: blocks release</Badge>
                  ) : (
                    <Badge tone="good">within tolerance</Badge>
                  )}
                </p>
              ) : null}
              <ScoreBars
                title="Score per grader"
                rows={perGrader.map(([label, value]) => ({ label, value }))}
              />
              <section aria-labelledby="cases-h">
                <h2 id="cases-h" className="mb-2 text-base font-semibold">
                  Cases
                </h2>
                <div className="flex flex-col gap-2">
                  {r.case_results.length === 0 ? (
                    <p className="text-sm text-[var(--axis-muted)]">
                      No case has been reported yet.
                    </p>
                  ) : (
                    r.case_results.map((c) => <CaseRow key={c.case_id} c={c} />)
                  )}
                </div>
              </section>
            </div>
          );
        }}
      </ResourceView>
    </>
  );
}
