"use client";
import { use } from "react";
import { Table } from "@axis/ui";
import { api } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";
import { EvalsNav } from "@/components/evals";

const text = (v: unknown): string => (typeof v === "string" ? v : JSON.stringify(v));

export default function DatasetPage({ params }: { params: Promise<{ ref: string }> }) {
  const { ref } = use(params);
  const [name, version] = decodeURIComponent(ref).split("@");
  const res = useResource(() => api.getEvalDataset(name as string, Number(version)), [ref]);
  return (
    <>
      <title>{`${decodeURIComponent(ref)} - AXIS Console`}</title>
      <PageHeader
        title={decodeURIComponent(ref)}
        description="Case inputs and expected answers are shown as plain text."
      />
      <EvalsNav />
      <ResourceView resource={res}>
        {(d) => (
          <>
            <p className="mb-3 text-sm">
              {d.case_count} case(s), content hash <code>{d.content_hash}</code>
              {d.phi ? " (PHI: redacted before it was stored)" : ""}
            </p>
            <Table
              caption="Cases"
              rows={d.cases ?? []}
              rowKey={(c) => c.id}
              columns={[
                { key: "id", header: "Case", render: (c) => c.id },
                {
                  key: "in",
                  header: "Input",
                  render: (c) => (
                    <pre className="whitespace-pre-wrap break-words">{text(c.input)}</pre>
                  ),
                },
                {
                  key: "exp",
                  header: "Expected",
                  render: (c) =>
                    c.expected == null ? (
                      "-"
                    ) : (
                      <pre className="whitespace-pre-wrap break-words">{text(c.expected)}</pre>
                    ),
                },
              ]}
            />
          </>
        )}
      </ResourceView>
    </>
  );
}
