"use client";
import { EmptyState, Table } from "@axis/ui";
import { api, type ComplianceAssessment } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";
import {
  ComplianceNav,
  EvidenceNote,
  StatusBadge,
  riskTone,
  stateTone,
} from "@/components/compliance";

export default function AssessmentsPage() {
  const res = useResource(() => api.listComplianceAssessments());
  return (
    <>
      <title>Impact assessments - AXIS Console</title>
      <PageHeader
        title="AI impact assessments"
        description="The latest version of each assessment. A reviewed version never changes, and the reviewer is never its author."
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
          <Table<ComplianceAssessment>
            caption="Impact assessments"
            rows={p.items}
            rowKey={(a) => a.assessment_id}
            empty={
              <EmptyState
                title="No impact assessments yet"
                description="Start one with `axis compliance assessments create --file assessment.yaml`."
              />
            }
            columns={[
              {
                key: "title",
                header: "Assessment",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (a) => a.title,
              },
              { key: "sys", header: "System", render: (a) => <code>{a.system_id}</code> },
              { key: "v", header: "Version", render: (a) => a.version },
              {
                key: "state",
                header: "State",
                render: (a) => <StatusBadge tone={stateTone(a.state)}>{a.state}</StatusBadge>,
              },
              {
                key: "risk",
                header: "Risk",
                render: (a) => (
                  <StatusBadge tone={riskTone(a.risk_rating)}>{a.risk_rating}</StatusBadge>
                ),
              },
              { key: "risks", header: "Risks listed", render: (a) => a.risks.length },
              {
                key: "author",
                header: "Author",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (a) => a.author,
              },
              {
                key: "rev",
                header: "Reviewed by",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (a) => a.reviewed_by ?? "-",
              },
              { key: "due", header: "Review due", render: (a) => a.review_due },
              {
                key: "od",
                header: "Overdue",
                render: (a) =>
                  a.overdue ? (
                    <StatusBadge tone="bad">{a.overdue_reason ?? "overdue"}</StatusBadge>
                  ) : (
                    "no"
                  ),
              },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
