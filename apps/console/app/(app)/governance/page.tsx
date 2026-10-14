"use client";
import Link from "next/link";
import { EmptyState, Table } from "@axis/ui";
import { api, type GovernanceRequest } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import {
  GovernanceNav,
  GovernanceNote,
  StatusBadge,
  isOverdue,
  requestTone,
} from "@/components/governance";

export default function RequestsPage() {
  const res = useResource(() => api.listGovernanceRequests());
  return (
    <>
      <title>Data-subject requests - AXIS Console</title>
      <PageHeader
        title="Data-subject requests"
        description="Export, erasure and restriction requests with their 30-day clock. Nothing is exported or erased before the requester is verified."
      />
      <GovernanceNav />
      <GovernanceNote />
      <ResourceView
        resource={res}
        unavailable={{
          title: "Data governance is not available",
          description: "This deployment does not serve the data-governance service.",
        }}
      >
        {(p) => (
          <Table<GovernanceRequest>
            caption="Data-subject requests"
            rows={p.items}
            rowKey={(r) => r.id}
            empty={
              <EmptyState
                title="No requests yet"
                description="Open one with `axis governance requests create --kind erase --file ids.yaml`."
              />
            }
            columns={[
              {
                key: "id",
                header: "Request",
                render: (r) => (
                  <Link href={`/governance/requests/${encodeURIComponent(r.id)}`}>
                    <code>{r.id.slice(0, 8)}</code>
                  </Link>
                ),
              },
              { key: "kind", header: "Kind", render: (r) => r.kind },
              {
                key: "status",
                header: "Status",
                render: (r) => <StatusBadge tone={requestTone(r.status)}>{r.status}</StatusBadge>,
              },
              {
                key: "subject",
                header: "Subject",
                className: "[overflow-wrap:anywhere] min-w-32",
                render: (r) => <code>{r.subject_ref}</code>,
              },
              { key: "recv", header: "Received", render: (r) => formatTime(r.received_at) },
              {
                key: "due",
                header: "Due",
                render: (r) => (
                  <>
                    {formatTime(r.due_at)}
                    {r.extended ? " (extended)" : ""}
                    {isOverdue(r) ? (
                      <>
                        {" "}
                        <StatusBadge tone="bad">overdue</StatusBadge>
                      </>
                    ) : null}
                  </>
                ),
              },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
