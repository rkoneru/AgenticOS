"use client";
import Link from "next/link";
import { EmptyState, Table } from "@axis/ui";
import { api, type EvalSuite } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";
import { EvalsNav } from "@/components/evals";

export default function SuitesPage() {
  const res = useResource(() => api.listEvalSuites());
  return (
    <>
      <title>Eval suites - AXIS Console</title>
      <PageHeader
        title="Suites"
        description="Immutable definitions: a dataset version, graders, a pass threshold and a regression tolerance."
      />
      <EvalsNav />
      <ResourceView resource={res}>
        {(p) => (
          <Table<EvalSuite>
            caption="Suites"
            rows={p.items}
            rowKey={(s) => s.ref}
            empty={
              <EmptyState
                title="No suites"
                description="Create one with `axis evals suites create`."
              />
            }
            columns={[
              {
                key: "ref",
                header: "Suite",
                render: (s) => (
                  <Link href={`/evals/suites/${encodeURIComponent(s.ref)}`}>{s.ref}</Link>
                ),
              },
              { key: "ds", header: "Dataset", render: (s) => s.dataset_ref },
              {
                key: "g",
                header: "Graders",
                render: (s) => s.graders.map((g) => `${g.id} (${g.kind})`).join(", "),
              },
              { key: "p", header: "Pass at", render: (s) => s.pass_threshold },
              { key: "t", header: "Tolerance", render: (s) => s.tolerance },
              {
                key: "r",
                header: "Required",
                render: (s) => (s.required_for_release ? "yes" : "no"),
              },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
