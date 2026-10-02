"use client";
import { Badge, EmptyState, Table } from "@axis/ui";
import { api, type EvalRun } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";

export default function EvalsPage() {
  const res = useResource(() => api.listEvalRuns());
  return (
    <>
      <title>Evals - AXIS Console</title>
      <PageHeader title="Evals" description="Eval Hub suites run against blueprint versions." />
      <ResourceView
        resource={res}
        unavailable={{
          title: "Evals are not available yet",
          description:
            "Eval Hub ships in Phase 8. Once it is enabled for your deployment, suites and scored runs appear here.",
        }}
      >
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
              { key: "suite", header: "Suite", render: (r) => r.suite },
              {
                key: "status",
                header: "Status",
                render: (r) => (
                  <Badge
                    tone={
                      r.status === "passed"
                        ? "good"
                        : r.status === "failed" || r.status === "errored"
                          ? "bad"
                          : "info"
                    }
                  >
                    {r.status}
                  </Badge>
                ),
              },
              { key: "score", header: "Score", render: (r) => r.score ?? "-" },
              { key: "thr", header: "Threshold", render: (r) => r.threshold ?? "-" },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
