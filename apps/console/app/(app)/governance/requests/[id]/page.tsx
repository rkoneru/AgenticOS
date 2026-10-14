"use client";
import { use } from "react";
import { api } from "@/lib/api";
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

export default function RequestPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const rid = decodeURIComponent(id);
  const res = useResource(() => api.getGovernanceRequest(rid), [rid]);
  return (
    <>
      <title>{`Request ${rid.slice(0, 8)} - AXIS Console`}</title>
      <PageHeader title={`Request ${rid.slice(0, 8)}`} description="One data-subject request." />
      <GovernanceNav />
      <GovernanceNote />
      <ResourceView resource={res}>
        {(r) => (
          <>
            <dl className="mb-4 grid max-w-3xl grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="font-medium">Request</dt>
              <dd>
                <code className="[overflow-wrap:anywhere]">{r.id}</code>
              </dd>
              <dt className="font-medium">Kind</dt>
              <dd>{r.kind}</dd>
              <dt className="font-medium">Status</dt>
              <dd data-testid="request-status">
                <StatusBadge tone={requestTone(r.status)}>{r.status}</StatusBadge>
                {isOverdue(r) ? (
                  <>
                    {" "}
                    <StatusBadge tone="bad">overdue</StatusBadge>
                  </>
                ) : null}
              </dd>
              <dt className="font-medium">Subject</dt>
              <dd>
                <code className="[overflow-wrap:anywhere]">{r.subject_ref}</code> (opaque; the
                identifiers are sealed and are not shown)
              </dd>
              <dt className="font-medium">Received</dt>
              <dd>{formatTime(r.received_at)}</dd>
              <dt className="font-medium">Due</dt>
              <dd>
                {formatTime(r.due_at)}
                {r.extended ? " (extended)" : ""}
              </dd>
              <dt className="font-medium">Verified</dt>
              <dd className="[overflow-wrap:anywhere]">
                {r.verified_at
                  ? `${formatTime(r.verified_at)} by ${r.verified_method ?? "-"}`
                  : "not verified"}
              </dd>
              <dt className="font-medium">Destination region</dt>
              <dd>{r.destination_region ?? "-"}</dd>
            </dl>
            <h2 className="mb-2 text-base font-semibold">Result</h2>
            <pre
              data-testid="request-result"
              className="max-w-3xl overflow-auto rounded-md bg-[var(--axis-surface-2)] p-3 text-xs"
              tabIndex={0}
            >
              {JSON.stringify(r.result, null, 2)}
            </pre>
          </>
        )}
      </ResourceView>
    </>
  );
}
