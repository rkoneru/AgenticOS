"use client";
import { useState } from "react";
import { Badge, Button, EmptyState, Input } from "@axis/ui";
import { api, type ResolvedBlueprint } from "@/lib/api";
import { useAction, useResource } from "@/lib/hooks";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";

/**
 * The registry from the console is READ-ONLY on purpose: publishing needs the publisher's Ed25519 private key and the platform
 * compiler (`axis registry sign` / `publish`), and a private key must never enter a browser. Resolving shows what the SERVER verified.
 */
export default function RegistryPage() {
  const ns = useResource(() => api.listRegistryNamespaces());
  const [ref, setRef] = useState("");
  const [out, setOut] = useState<ResolvedBlueprint | undefined>();
  const resolve = useAction(async () => {
    setOut(undefined);
    const r = await api.resolveRegistry(ref.trim());
    setOut(r);
    return r;
  });
  return (
    <>
      <title>Registry - AXIS Console</title>
      <PageHeader
        title="Registry"
        description="Signed blueprints. Every resolve re-verifies the content hash, the publisher's signature and the provenance attestation."
      />
      <h2 className="mb-2 text-base font-semibold">Your namespaces</h2>
      <ResourceView resource={ns}>
        {(r) =>
          r.items.length === 0 ? (
            <EmptyState
              title="No namespaces yet"
              description="An admin claims one with `axis registry claim <namespace>`."
            />
          ) : (
            <ul aria-label="Namespaces" className="mb-6 list-disc pl-5 text-sm">
              {r.items.map((n) => (
                <li key={n.namespace}>
                  {n.namespace}{" "}
                  {n.public ? <Badge tone="good">public</Badge> : <Badge>private</Badge>}
                </li>
              ))}
            </ul>
          )
        }
      </ResourceView>
      <h2 className="mb-2 mt-4 text-base font-semibold">Resolve and verify</h2>
      <form
        className="flex max-w-xl flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void resolve.run();
        }}
      >
        <Input
          label="Reference (namespace/name@range)"
          value={ref}
          onChange={(e) => setRef(e.target.value)}
          placeholder="acme/claims-agent@^1"
        />
        <Button type="submit" loading={resolve.pending} disabled={ref.trim() === ""}>
          Resolve
        </Button>
      </form>
      {resolve.error ? <ErrorNote error={resolve.error} /> : null}
      {out ? (
        <dl
          className="mt-4 grid max-w-3xl grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[12rem_1fr]"
          data-testid="resolved"
        >
          <dt className="text-[var(--axis-muted)]">Resolved</dt>
          <dd>
            {out.namespace}/{out.name}@{out.version} <Badge tone="good">verified</Badge>
          </dd>
          <dt className="text-[var(--axis-muted)]">Content hash</dt>
          <dd>
            <code>{out.content_hash}</code>
          </dd>
          <dt className="text-[var(--axis-muted)]">Signed by key</dt>
          <dd>{out.verification.key_id}</dd>
          <dt className="text-[var(--axis-muted)]">Builder</dt>
          <dd>{out.verification.builder ?? "-"}</dd>
          <dt className="text-[var(--axis-muted)]">State</dt>
          <dd>{out.state ?? "-"}</dd>
        </dl>
      ) : null}
    </>
  );
}
