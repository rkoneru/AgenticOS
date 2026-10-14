"use client";
import { useState } from "react";
import { EmptyState, Table } from "@axis/ui";
import { api, type GovernanceHold } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { GovernanceNav, GovernanceNote, StatusBadge } from "@/components/governance";

export default function HoldsPage() {
  const [all, setAll] = useState(false);
  const res = useResource(() => api.listGovernanceHolds({ all }), [all]);
  return (
    <>
      <title>Legal holds - AXIS Console</title>
      <PageHeader
        title="Legal holds"
        description="While a hold is active, retention purges and erasure skip the data it covers."
      />
      <GovernanceNav />
      <GovernanceNote />
      <label className="mb-3 flex items-center gap-2 text-sm">
        <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
        Include released holds
      </label>
      <ResourceView
        resource={res}
        unavailable={{
          title: "Data governance is not available",
          description: "This deployment does not serve the data-governance service.",
        }}
      >
        {(p) => (
          <Table<GovernanceHold>
            caption="Legal holds"
            rows={p.items}
            rowKey={(h) => h.id}
            empty={
              <EmptyState
                title="No holds"
                description="Place one with `axis governance holds place --scope tenant --reason ...`."
              />
            }
            columns={[
              { key: "id", header: "Hold", render: (h) => <code>{h.id.slice(0, 8)}</code> },
              { key: "kind", header: "Kind", render: (h) => h.kind },
              { key: "scope", header: "Scope", render: (h) => h.scope },
              {
                key: "case",
                header: "Case",
                className: "[overflow-wrap:anywhere] min-w-24",
                render: (h) => h.case_ref ?? "-",
              },
              {
                key: "reason",
                header: "Reason",
                className: "[overflow-wrap:anywhere] min-w-40",
                render: (h) => h.reason,
              },
              { key: "by", header: "Placed by", render: (h) => h.placed_by },
              { key: "at", header: "Placed", render: (h) => formatTime(h.placed_at) },
              {
                key: "state",
                header: "State",
                render: (h) =>
                  h.released_at ? (
                    <StatusBadge tone="neutral">{`released ${formatTime(h.released_at)}`}</StatusBadge>
                  ) : (
                    <StatusBadge tone="warn">active</StatusBadge>
                  ),
              },
            ]}
          />
        )}
      </ResourceView>
    </>
  );
}
