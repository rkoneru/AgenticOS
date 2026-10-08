"use client";
import Link from "next/link";
import { useState } from "react";
import { Button, Input, Table } from "@axis/ui";
import { api, type EvalBaseline, type EvalComparison, type EvalRunDetail } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { EvalsNav, score } from "@/components/evals";
import { ScoreBars, ScoreHistory } from "@/components/eval-charts";

/** The history of a blueprint's score on one suite (every finished run, oldest first) and any run compared with its baseline. */
export default function BaselinesPage() {
  const [bp, setBp] = useState("");
  const [suite, setSuite] = useState("");
  const [q, setQ] = useState<{ bp: string; suite: string } | undefined>();
  const base = useResource(
    () =>
      q ? api.listEvalBaselines(q.bp, q.suite) : Promise.resolve({ items: [] as EvalBaseline[] }),
    [q?.bp, q?.suite],
  );
  const runs = useResource(
    () =>
      q
        ? api.listEvalRuns({ blueprint: q.bp, suite: q.suite, limit: 100 })
        : Promise.resolve({ items: [] }),
    [q?.bp, q?.suite],
  );
  const [pick, setPick] = useState<string | undefined>();
  const cmp = useResource(async (): Promise<
    { run: EvalRunDetail; base: EvalRunDetail; c: EvalComparison } | undefined
  > => {
    if (!pick) return undefined;
    const c = await api.getEvalComparison(pick);
    if (!c) return undefined;
    const [run, b] = await Promise.all([api.getEvalRun(pick), api.getEvalRun(c.baseline_run_id)]);
    return { run, base: b, c };
  }, [pick]);
  const finished = (runs.data?.items ?? [])
    .filter((r) => r.scores && typeof r.score === "number")
    .sort((a, b) => ((a.finished_at ?? "") < (b.finished_at ?? "") ? -1 : 1));
  return (
    <>
      <title>Eval baselines - AXIS Console</title>
      <PageHeader
        title="Baselines"
        description="The run a release is judged against: promoted when a version is released, never moved by a regression."
      />
      <EvalsNav />
      <form
        className="mb-6 flex max-w-3xl flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setQ({ bp: bp.trim(), suite: suite.trim() });
          setPick(undefined);
        }}
      >
        <Input
          label="Blueprint name"
          value={bp}
          onChange={(e) => setBp(e.target.value)}
          placeholder="answer-agent"
        />
        <Input
          label="Suite"
          value={suite}
          onChange={(e) => setSuite(e.target.value)}
          placeholder="answers@1.0.0"
        />
        <Button type="submit" disabled={bp.trim() === "" || suite.trim() === ""}>
          Show history
        </Button>
      </form>
      {q ? (
        <div className="flex flex-col gap-4">
          <ResourceView resource={base}>
            {(b) => (
              <Table<EvalBaseline>
                caption="Baseline history"
                rows={b.items}
                rowKey={(x) => String(x.seq)}
                empty={
                  <p className="text-sm text-[var(--axis-muted)]">
                    No baseline yet: it is promoted when a passing version is released.
                  </p>
                }
                columns={[
                  { key: "seq", header: "#", render: (x) => x.seq },
                  {
                    key: "run",
                    header: "Run",
                    render: (x) => (
                      <Link href={`/evals/runs/${x.run_id}`}>{x.run_id.slice(0, 8)}</Link>
                    ),
                  },
                  { key: "s", header: "Score", render: (x) => score(x.overall) },
                  { key: "by", header: "Set by", render: (x) => x.set_by },
                  { key: "at", header: "At", render: (x) => formatTime(x.at) },
                ]}
              />
            )}
          </ResourceView>
          <ScoreHistory
            title="Score of every finished run"
            points={finished.map((r) => ({
              label: `${r.blueprint?.version ?? ""} ${r.id.slice(0, 6)}`,
              value: r.score as number,
            }))}
          />
          <Table
            caption="Runs"
            rows={finished}
            rowKey={(r) => r.id}
            columns={[
              { key: "v", header: "Version", render: (r) => r.blueprint?.version },
              { key: "s", header: "Score", render: (r) => score(r.score) },
              { key: "st", header: "Status", render: (r) => r.status },
              {
                key: "c",
                header: "",
                render: (r) => (
                  <Button
                    variant="secondary"
                    onClick={() => setPick(r.id)}
                    aria-label={`Compare run ${r.id.slice(0, 6)} with the baseline`}
                  >
                    Compare
                  </Button>
                ),
              },
            ]}
          />
          {pick ? (
            cmp.data ? (
              <>
                <p className="text-sm" data-testid="compare-summary">
                  Delta{" "}
                  <strong>{cmp.data.c.delta === null ? "-" : cmp.data.c.delta.toFixed(3)}</strong>{" "}
                  against the baseline (tolerance {cmp.data.c.tolerance}):{" "}
                  {cmp.data.c.blocking ? "blocks the release" : "within tolerance"}
                </p>
                <ScoreBars
                  title="Per grader: this run against the baseline"
                  rows={Object.keys(cmp.data.run.scores?.per_grader ?? {})
                    .sort()
                    .map((g) => ({
                      label: g,
                      value: cmp.data!.run.scores!.per_grader[g] as number,
                      other: cmp.data!.base.scores?.per_grader[g],
                    }))}
                />
              </>
            ) : cmp.loading ? (
              <p role="status">Comparing...</p>
            ) : (
              <p className="text-sm">
                This run has no baseline to compare with (it may be the baseline).
              </p>
            )
          ) : null}
        </div>
      ) : null}
    </>
  );
}
