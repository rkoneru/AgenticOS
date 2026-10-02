"use client";
import { use } from "react";
import { stringify } from "yaml";
import { Badge } from "@axis/ui";
import { api } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { PageHeader, ResourceView } from "@/components/common";
import { BlueprintEditor } from "@/components/blueprint-editor";

export default function BlueprintVersionPage({
  params,
}: {
  params: Promise<{ name: string; version: string }>;
}) {
  const { name, version } = use(params);
  const n = decodeURIComponent(name);
  const v = decodeURIComponent(version);
  const res = useResource(() => api.getBlueprintVersion(n, v), [n, v]);
  return (
    <>
      <title>{`${n}@${v} - AXIS Console`}</title>
      <PageHeader
        title={`${n} @ ${v}`}
        description="Published versions are immutable. Edit below and publish a new version."
      />
      <ResourceView resource={res}>
        {(b) => (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Badge
                tone={
                  b.risk_level === "high" ? "bad" : b.risk_level === "limited" ? "warn" : "good"
                }
              >
                risk: {b.risk_level}
              </Badge>
              <span>Published {formatTime(b.created_at)}</span>
              {b.content_hash ? <code>{b.content_hash}</code> : null}
            </div>
            <BlueprintEditor initial={stringify(b.abl)} />
          </div>
        )}
      </ResourceView>
    </>
  );
}
