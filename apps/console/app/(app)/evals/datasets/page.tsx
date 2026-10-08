"use client";
import Link from "next/link";
import { Badge, EmptyState, Table } from "@axis/ui";
import { api, type EvalDatasetVersion } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { EvalsNav } from "@/components/evals";

export default function DatasetsPage() {
  const res = useResource(() => api.listEvalDatasets());
  return (
    <>
      <title>Eval datasets - AXIS Console</title>
      <PageHeader
        title="Datasets"
        description="Immutable numbered versions. A suite pins one version and its content hash."
      />
      <EvalsNav />
      <ResourceView resource={res}>
        {(p) => (
          <Table<EvalDatasetVersion>
            caption="Dataset versions"
            rows={p.items}
            rowKey={(d) => d.ref}
            empty={
              <EmptyState
                title="No datasets"
                description="Create one with `axis evals datasets create`."
              />
            }
            columns={[
              {
                key: "ref",
                header: "Dataset",
                render: (d) => (
                  <Link href={`/evals/datasets/${encodeURIComponent(d.ref)}`}>{d.ref}</Link>
                ),
              },
              { key: "n", header: "Cases", render: (d) => d.case_count },
              {
                key: "phi",
                header: "PHI",
                render: (d) => (d.phi ? <Badge tone="warn">redacted before storage</Badge> : "no"),
              },
              {
                key: "h",
                header: "Content hash",
                render: (d) => <code>{d.content_hash.slice(0, 12)}</code>,
              },
              { key: "t", header: "Created", render: (d) => formatTime(d.created_at) },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
