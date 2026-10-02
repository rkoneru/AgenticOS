"use client";
import Link from "next/link";
import { useState } from "react";
import { EmptyState, Select, Table } from "@axis/ui";
import { api, type Approval, type ApprovalStatus } from "@/lib/api";
import { useNow, usePaged } from "@/lib/hooks";
import { countdown } from "@/lib/sla";
import { formatTime, shortId } from "@/lib/format";
import { ApprovalBadge, ErrorNote, LoadMore, PageHeader } from "@/components/common";

export default function ApprovalsPage() {
  const [status, setStatus] = useState<ApprovalStatus | "">("pending");
  const list = usePaged(
    (cursor) =>
      api.listApprovals({
        limit: 50,
        ...(status ? { status } : {}),
        ...(cursor ? { cursor } : {}),
      }),
    [status],
  );
  const now = useNow(1000);
  return (
    <>
      <title>Approvals - AXIS Console</title>
      <PageHeader title="Approvals" description="Actions waiting for a human decision." />
      <div className="mb-3 max-w-xs">
        <Select
          label="Status"
          value={status}
          onChange={(e) => setStatus(e.target.value as ApprovalStatus | "")}
          options={[
            { value: "", label: "All" },
            ...(["pending", "approved", "rejected", "expired", "escalated"] as const).map((s) => ({
              value: s,
              label: s,
            })),
          ]}
        />
      </div>
      {list.error ? <ErrorNote error={list.error} onRetry={list.reload} /> : null}
      {list.loading ? <p role="status">Loading...</p> : null}
      {!list.loading && !list.error ? (
        <Table<Approval>
          caption="Approvals"
          rows={list.items}
          rowKey={(a) => a.id}
          empty={
            <EmptyState
              title="Nothing to approve"
              description="When an agent action needs a human decision it appears here."
            />
          }
          columns={[
            {
              key: "id",
              header: "Approval",
              render: (a) => <Link href={`/approvals/${a.id}`}>{shortId(a.id)}</Link>,
            },
            { key: "action", header: "Action", render: (a) => a.action ?? "-" },
            { key: "status", header: "Status", render: (a) => <ApprovalBadge status={a.status} /> },
            { key: "req", header: "Requested", render: (a) => formatTime(a.requested_at) },
            {
              key: "sla",
              header: "SLA",
              render: (a) => (a.status === "pending" ? countdown(a.sla_deadline, now).label : "-"),
            },
          ]}
        />
      ) : null}
      <LoadMore cursor={list.cursor} loading={list.loadingMore} onMore={list.more} />
    </>
  );
}
