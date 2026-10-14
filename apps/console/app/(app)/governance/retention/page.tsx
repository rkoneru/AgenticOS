"use client";
import { EmptyState, Table } from "@axis/ui";
import { api, type GovernanceRetentionClass, type GovernanceRetentionReport } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { GovernanceNav, GovernanceNote, StatusBadge, runStatusTone } from "@/components/governance";

const UNAVAILABLE = {
  title: "Data governance is not available",
  description: "This deployment does not serve the data-governance service.",
};

export default function RetentionPage() {
  const periods = useResource(() => api.getGovernanceRetention());
  const runs = useResource(() => api.listGovernanceRetentionRuns());
  const residency = useResource(() => api.getGovernanceResidency());
  return (
    <>
      <title>Retention and residency - AXIS Console</title>
      <PageHeader
        title="Retention and residency"
        description="How long each class of data is kept, what the purge runs did, and where the tenant's data may be written."
      />
      <GovernanceNav />
      <GovernanceNote />
      <h2 className="mb-2 text-base font-semibold">Residency</h2>
      <ResourceView resource={residency} unavailable={UNAVAILABLE}>
        {(r) => (
          <p className="mb-6 text-sm" data-testid="residency">
            Home region <code>{r.home_region}</code>; data may be written to:{" "}
            {r.allowed_regions.map((x) => (
              <code key={x} className="mr-1">
                {x}
              </code>
            ))}
          </p>
        )}
      </ResourceView>
      <h2 className="mb-2 text-base font-semibold">Retention periods</h2>
      <ResourceView resource={periods} unavailable={UNAVAILABLE}>
        {(p) => (
          <Table<GovernanceRetentionClass>
            caption="Retention periods"
            rows={p.items}
            rowKey={(c) => c.data_class}
            empty={<EmptyState title="No retention classes" description="Nothing is configured." />}
            columns={[
              { key: "c", header: "Data class", render: (c) => c.data_class },
              { key: "rq", header: "Requested (days)", render: (c) => c.requested_days },
              { key: "ef", header: "Effective (days)", render: (c) => c.effective_days },
              {
                key: "cl",
                header: "Clamped",
                render: (c) =>
                  c.clamped ? (
                    <StatusBadge tone="warn">
                      {c.clamped === "min" ? "raised to minimum" : "lowered to maximum"}
                    </StatusBadge>
                  ) : (
                    "no"
                  ),
              },
              { key: "src", header: "Source", render: (c) => c.source },
            ]}
          />
        )}
      </ResourceView>
      <h2 className="mb-2 mt-6 text-base font-semibold">Purge runs</h2>
      <ResourceView resource={runs} unavailable={UNAVAILABLE}>
        {(p) =>
          p.items.length === 0 ? (
            <EmptyState
              title="No runs yet"
              description="Preview one with `axis governance retention run`; it is a dry run unless you pass --execute."
            />
          ) : (
            <>
              {p.items.map((r: GovernanceRetentionReport) => (
                <div key={r.run_id} className="mb-6">
                  <p className="mb-1 text-sm">
                    <code>{r.run_id.slice(0, 8)}</code> started {formatTime(r.started_at)}{" "}
                    <StatusBadge tone={r.dry_run ? "info" : "good"}>
                      {r.dry_run ? "dry run" : "purge"}
                    </StatusBadge>
                  </p>
                  <Table
                    caption={`Run ${r.run_id.slice(0, 8)}`}
                    rows={r.classes}
                    rowKey={(c) => c.data_class}
                    columns={[
                      { key: "c", header: "Data class", render: (c) => c.data_class },
                      {
                        key: "s",
                        header: "Status",
                        render: (c) => (
                          <StatusBadge tone={runStatusTone(c.status)}>{c.status}</StatusBadge>
                        ),
                      },
                      { key: "d", header: "Days", render: (c) => c.effective_days },
                      { key: "m", header: "Matched", render: (c) => c.matched },
                      { key: "p", header: "Purged", render: (c) => c.purged },
                      { key: "h", header: "Held", render: (c) => c.protected_by_hold },
                      {
                        key: "e",
                        header: "Error",
                        className: "[overflow-wrap:anywhere] min-w-32",
                        render: (c) => c.error ?? "-",
                      },
                    ]}
                  />
                </div>
              ))}
            </>
          )
        }
      </ResourceView>
    </>
  );
}
