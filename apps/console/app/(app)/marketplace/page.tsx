"use client";
import Link from "next/link";
import { useState } from "react";
import { Badge, EmptyState, Input } from "@axis/ui";
import { api } from "@/lib/api";
import { features } from "@/lib/features";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";

const NA = {
  title: "Marketplace is not available",
  description:
    "The marketplace and registry are not enabled for this deployment. Blueprints you publish stay private to your tenant.",
};

export default function MarketplacePage() {
  const [q, setQ] = useState("");
  const res = useResource(
    () =>
      features.marketplace
        ? api.listListings({ q })
        : Promise.reject(Object.assign(new Error("disabled"), { notAvailable: true })),
    [q],
  );
  if (!features.marketplace) {
    return (
      <>
        <PageHeader title="Marketplace" />
        <EmptyState {...NA} />
      </>
    );
  }
  return (
    <>
      <title>Marketplace - AXIS Console</title>
      <PageHeader
        title="Marketplace"
        description="Browse agents and tools. Installing shows exactly which permissions you are granting."
      />
      <div className="mb-4 max-w-sm">
        <Input label="Search" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <ResourceView resource={res} unavailable={NA}>
        {(p) =>
          p.items.length === 0 ? (
            <EmptyState title="No listings found" />
          ) : (
            <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" aria-label="Listings">
              {p.items.map((l) => (
                <li
                  key={l.id}
                  className="rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] p-4"
                >
                  <h2 className="font-semibold">
                    <Link href={`/marketplace/${encodeURIComponent(l.id)}`}>{l.name}</Link>
                  </h2>
                  <p className="text-xs text-[var(--axis-muted)]">
                    {l.publisher} - v{l.version}
                  </p>
                  <p className="mt-2 text-sm">{l.summary}</p>
                  {l.installed ? (
                    <div className="mt-2">
                      <Badge tone="good">installed</Badge>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )
        }
      </ResourceView>
    </>
  );
}
