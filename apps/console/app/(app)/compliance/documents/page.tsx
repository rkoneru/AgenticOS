"use client";
import Link from "next/link";
import { EmptyState, Table } from "@axis/ui";
import { api, type ComplianceDocumentSummary } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { ComplianceNav, EvidenceNote } from "@/components/compliance";

export default function DocumentsPage() {
  const res = useResource(() => api.listComplianceDocuments());
  return (
    <>
      <title>Technical documentation - AXIS Console</title>
      <PageHeader
        title="Technical documentation"
        description="Annex IV structured documents assembled from the platform's own records, sealed with a hash and a signature. What could not be evidenced is listed as a gap."
      />
      <ComplianceNav />
      <EvidenceNote />
      <ResourceView
        resource={res}
        unavailable={{
          title: "Compliance is not available",
          description: "This deployment does not serve the compliance records.",
        }}
      >
        {(p) => (
          <Table<ComplianceDocumentSummary>
            caption="Generated documents"
            rows={p.items}
            rowKey={(d) => d.document_id}
            empty={
              <EmptyState
                title="No documents yet"
                description="Generate one with `axis compliance documents generate <name@version>`."
              />
            }
            columns={[
              {
                key: "id",
                header: "Document",
                render: (d) => (
                  <Link href={`/compliance/documents/${encodeURIComponent(d.document_id)}`}>
                    {d.document_id}
                  </Link>
                ),
              },
              {
                key: "bp",
                header: "Blueprint",
                render: (d) => `${d.blueprint.name}@${d.blueprint.version}`,
              },
              { key: "v", header: "Version", render: (d) => d.doc_version },
              { key: "gaps", header: "Gaps", render: (d) => d.gap_count },
              { key: "gen", header: "Generated", render: (d) => formatTime(d.generated_at) },
              { key: "by", header: "By", render: (d) => d.generated_by },
              {
                key: "h",
                header: "Content hash",
                render: (d) => <code>{d.content_hash.slice(0, 12)}</code>,
              },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
