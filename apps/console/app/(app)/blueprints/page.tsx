"use client";
import Link from "next/link";
import { Badge, EmptyState, Table } from "@axis/ui";
import { api, type BlueprintVersion } from "@/lib/api";
import { usePaged } from "@/lib/hooks";
import { formatTime, shortId } from "@/lib/format";
import { ErrorNote, LoadMore, PageHeader } from "@/components/common";
import { Can } from "@/components/session";

export default function BlueprintsPage() {
  const list = usePaged((cursor) =>
    api.listBlueprints({ limit: 50, ...(cursor ? { cursor } : {}) }),
  );
  return (
    <>
      <title>Blueprints - AXIS Console</title>
      <PageHeader
        title="Blueprints"
        description="Versioned ABL agent definitions. Published versions are immutable."
        actions={
          <Can cap="blueprints.write">
            <Link
              href="/blueprints/new"
              className="rounded-md bg-[var(--axis-accent)] px-3 py-1.5 text-sm font-medium text-[var(--axis-accent-fg)] no-underline"
            >
              New blueprint
            </Link>
          </Can>
        }
      />
      {list.error ? <ErrorNote error={list.error} onRetry={list.reload} /> : null}
      {list.loading ? <p role="status">Loading...</p> : null}
      {!list.loading && !list.error ? (
        <Table<BlueprintVersion>
          caption="Blueprint versions"
          rows={list.items}
          rowKey={(b) => `${b.name}@${b.version}`}
          empty={
            <EmptyState
              title="No blueprints yet"
              description="Create your first agent blueprint to get started."
            />
          }
          columns={[
            {
              key: "name",
              header: "Name",
              render: (b) => (
                <Link
                  href={`/blueprints/${encodeURIComponent(b.name)}/${encodeURIComponent(b.version)}`}
                >
                  {b.name}
                </Link>
              ),
            },
            { key: "version", header: "Version", render: (b) => b.version },
            {
              key: "risk",
              header: "Risk",
              render: (b) => (
                <Badge
                  tone={
                    b.risk_level === "high" ? "bad" : b.risk_level === "limited" ? "warn" : "good"
                  }
                >
                  {b.risk_level}
                </Badge>
              ),
            },
            {
              key: "hash",
              header: "Content hash",
              render: (b) => <code>{b.content_hash ? shortId(b.content_hash, 12) : "-"}</code>,
            },
            { key: "created", header: "Published", render: (b) => formatTime(b.created_at) },
          ]}
        />
      ) : null}
      <LoadMore cursor={list.cursor} loading={list.loadingMore} onMore={list.more} />
    </>
  );
}
