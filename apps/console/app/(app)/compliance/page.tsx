"use client";
import { EmptyState, Table } from "@axis/ui";
import { api, type ComplianceSystem } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { ComplianceNav, EvidenceNote, StatusBadge, riskTone } from "@/components/compliance";

export default function InventoryPage() {
  const res = useResource(() => api.listComplianceSystems());
  return (
    <>
      <title>AI system inventory - AXIS Console</title>
      <PageHeader
        title="AI system inventory"
        description="Every AI system with its owner, purpose, risk level and linked blueprint versions. Each change is a new version."
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
          <Table<ComplianceSystem>
            caption="AI systems"
            rows={p.items}
            rowKey={(s) => s.system_id}
            empty={
              <EmptyState
                title="No AI systems yet"
                description="Register one with `axis compliance systems create --file system.yaml`."
              />
            }
            columns={[
              { key: "id", header: "System", render: (s) => <code>{s.system_id}</code> },
              {
                key: "name",
                header: "Name",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (s) => s.name,
              },
              {
                key: "purpose",
                header: "Purpose",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (s) => s.purpose,
              },
              {
                key: "owner",
                header: "Owner",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (s) => s.owner,
              },
              {
                key: "risk",
                header: "Risk",
                render: (s) => (
                  <StatusBadge tone={riskTone(s.risk_level)}>{s.risk_level}</StatusBadge>
                ),
              },
              { key: "stage", header: "Stage", render: (s) => s.lifecycle_stage },
              {
                key: "bp",
                header: "Blueprints",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (s) =>
                  s.blueprints.length === 0
                    ? "-"
                    : s.blueprints.map((b) => `${b.name}@${b.version}`).join(", "),
              },
              { key: "v", header: "Version", render: (s) => s.version },
              { key: "u", header: "Updated", render: (s) => formatTime(s.updated_at) },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
