"use client";
import { use } from "react";
import { Table } from "@axis/ui";
import { api } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";
import { ComplianceNav, EvidenceNote, StatusBadge, sectionTone } from "@/components/compliance";

export default function DocumentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const res = useResource(() => api.getComplianceDocument(decodeURIComponent(id)), [id]);
  return (
    <>
      <title>{`${decodeURIComponent(id)} - AXIS Console`}</title>
      <PageHeader
        title={decodeURIComponent(id)}
        description="Verified again on every read: the hash of the body, the Markdown and the seal."
      />
      <ComplianceNav />
      <EvidenceNote />
      <ResourceView resource={res}>
        {(d) => {
          const sections = Object.entries(d.document.body.sections);
          return (
            <>
              <p className="mb-3 text-sm" data-testid="verification">
                Verification:{" "}
                {d.verification.ok ? (
                  <StatusBadge tone="good">verified</StatusBadge>
                ) : (
                  <StatusBadge tone="bad">{`failed: ${d.verification.failed.join(", ")}`}</StatusBadge>
                )}{" "}
                content hash <code>{d.document.content_hash}</code>, sealed with{" "}
                {d.document.seal.alg} key <code>{d.document.seal.key_id}</code>
              </p>
              {d.document.body.disclaimer ? (
                <p className="mb-4 max-w-3xl text-sm">{d.document.body.disclaimer}</p>
              ) : null}
              <h2 className="mb-2 text-base font-semibold">Sections</h2>
              <Table
                caption="Sections"
                rows={sections}
                rowKey={([k]) => k}
                columns={[
                  { key: "s", header: "Section", render: ([, s]) => s.title },
                  { key: "a", header: "Annex IV", render: ([, s]) => s.annex_iv.join(", ") },
                  {
                    key: "st",
                    header: "Status",
                    render: ([, s]) => (
                      <StatusBadge tone={sectionTone(s.status)}>{s.status}</StatusBadge>
                    ),
                  },
                  { key: "g", header: "Gaps", render: ([, s]) => s.gaps.length },
                ]}
              />
              <h2 className="mb-2 mt-6 text-base font-semibold">Annex IV coverage</h2>
              <Table
                caption="Annex IV coverage"
                rows={d.document.body.annex_iv_coverage}
                rowKey={(c) => c.point}
                columns={[
                  { key: "p", header: "Point", render: (c) => c.point },
                  { key: "t", header: "Title", render: (c) => c.title },
                  {
                    key: "st",
                    header: "Status",
                    render: (c) => (
                      <StatusBadge tone={sectionTone(c.status)}>{c.status}</StatusBadge>
                    ),
                  },
                ]}
              />
              <h2 className="mb-2 mt-6 text-base font-semibold">
                Gaps ({d.document.body.gaps.length})
              </h2>
              <Table
                caption="Gaps"
                rows={d.document.body.gaps}
                rowKey={(g) => `${g.section}/${g.item}/${g.reason}`}
                empty={<p>No gaps were found by the generator.</p>}
                columns={[
                  { key: "s", header: "Section", render: (g) => g.section },
                  { key: "i", header: "Item", render: (g) => g.item },
                  { key: "r", header: "Reason", render: (g) => g.reason },
                ]}
              />
              <h2 className="mb-2 mt-6 text-base font-semibold">Markdown</h2>
              <pre
                className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md border border-[var(--axis-border)] p-3 text-xs"
                tabIndex={0}
                aria-label="Document Markdown"
                data-testid="document-markdown"
              >
                {d.document.markdown}
              </pre>
            </>
          );
        }}
      </ResourceView>
    </>
  );
}
