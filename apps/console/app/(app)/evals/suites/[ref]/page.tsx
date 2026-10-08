"use client";
import { use } from "react";
import { Table } from "@axis/ui";
import { api } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";
import { EvalsNav } from "@/components/evals";

export default function SuitePage({ params }: { params: Promise<{ ref: string }> }) {
  const { ref } = use(params);
  const r = decodeURIComponent(ref);
  const res = useResource(() => api.getEvalSuite(r), [r]);
  return (
    <>
      <title>{`${r} - AXIS Console`}</title>
      <PageHeader title={r} />
      <EvalsNav />
      <ResourceView resource={res}>
        {(s) => (
          <div className="flex flex-col gap-3">
            <dl className="grid max-w-3xl grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-[12rem_1fr]">
              <dt className="text-[var(--axis-muted)]">Dataset</dt>
              <dd>{s.dataset_ref}</dd>
              <dt className="text-[var(--axis-muted)]">Pass threshold</dt>
              <dd>{s.pass_threshold}</dd>
              <dt className="text-[var(--axis-muted)]">Regression tolerance</dt>
              <dd>{s.tolerance}</dd>
              <dt className="text-[var(--axis-muted)]">Suite hash</dt>
              <dd>
                <code>{s.suite_hash}</code>
              </dd>
            </dl>
            <Table
              caption="Graders"
              rows={s.graders}
              rowKey={(g) => g.id}
              columns={[
                { key: "id", header: "Grader", render: (g) => g.id },
                { key: "k", header: "Kind", render: (g) => g.kind },
                { key: "w", header: "Weight", render: (g) => g.weight },
              ]}
            />
          </div>
        )}
      </ResourceView>
    </>
  );
}
