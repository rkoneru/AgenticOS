"use client";
import { Badge, EmptyState } from "@axis/ui";
import { api } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { EvalsNav, score, usePolling } from "@/components/evals";
import { ScoreHistory } from "@/components/eval-charts";

export default function OnlinePage() {
  const sum = useResource(() => api.getEvalOnlineSummary());
  const cfg = useResource(() => api.listEvalSampling());
  usePolling(sum.reload, true, 5000);
  return (
    <>
      <title>Online evals - AXIS Console</title>
      <PageHeader
        title="Online evals"
        description="A deterministic sample of production runs, graded after the fact. History and alerts only: it never gates, allows or blocks a release."
      />
      <EvalsNav />
      <ResourceView resource={sum}>
        {(s) =>
          s.items.length === 0 ? (
            <EmptyState
              title="No sampling configured"
              description="An admin sets one with `axis evals sampling put`."
            />
          ) : (
            <div className="flex flex-col gap-6">
              {s.items.map((i) => {
                const c = cfg.data?.items.find((x) => x.id === i.sampling_id);
                const recent = [...i.recent].reverse();
                return (
                  <section
                    key={i.sampling_id}
                    aria-label={`Sampling ${i.sampling_id}`}
                    data-testid={`sampling-${i.sampling_id}`}
                  >
                    <h2 className="mb-1 text-base font-semibold">
                      {i.sampling_id}{" "}
                      <span className="text-sm font-normal text-[var(--axis-muted)]">
                        {i.blueprint_name} / {i.suite_ref}
                      </span>
                    </h2>
                    <p className="mb-2 flex flex-wrap items-center gap-2 text-sm">
                      <span>
                        {i.count} sample(s), mean <strong>{score(i.mean)}</strong>
                      </span>
                      {c ? (
                        <span>
                          rate {c.rate}, at most {c.max_per_hour}/hour, redaction {c.redaction}
                        </span>
                      ) : null}
                      {i.alerting ? (
                        <Badge tone="bad">alerting (mean below {i.alert_threshold})</Badge>
                      ) : null}
                      {!i.enabled ? <Badge>disabled</Badge> : null}
                    </p>
                    <ScoreHistory
                      title={`Recent samples of ${i.sampling_id}`}
                      points={recent.map((r) => ({
                        label: `${formatTime(r.at)} v${r.blueprint_version}`,
                        value: r.score,
                      }))}
                    />
                  </section>
                );
              })}
            </div>
          )
        }
      </ResourceView>
    </>
  );
}
