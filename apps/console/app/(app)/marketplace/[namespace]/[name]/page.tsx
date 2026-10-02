"use client";
import { use, useState } from "react";
import { Badge, Button, Dialog, useToast } from "@axis/ui";
import { api, type InstallPreview, type Listing } from "@/lib/api";
import { useAction, useResource } from "@/lib/hooks";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";
import { useCan } from "@/components/session";

function Install({ l, installed, onDone }: { l: Listing; installed: boolean; onDone: () => void }) {
  const can = useCan("marketplace.install");
  const [preview, setPreview] = useState<InstallPreview | null>(null);
  const [agree, setAgree] = useState(false);
  const toast = useToast();
  const load = useAction(async () => {
    setAgree(false);
    const p = await api.previewInstall(l.namespace, l.name, l.latest ? l.latest.version : "*");
    setPreview(p);
    return p;
  });
  const install = useAction(() => {
    if (!preview) throw new Error("no preview");
    return api.installListing(preview);
  });
  if (!can)
    return (
      <p className="text-sm text-[var(--axis-muted)]">
        Your role cannot install listings. Ask an admin.
      </p>
    );
  if (installed) return <Badge tone="good">installed</Badge>;
  return (
    <>
      <Button loading={load.pending} onClick={() => void load.run()}>
        Install...
      </Button>
      {load.error ? <ErrorNote error={load.error} /> : null}
      <Dialog
        open={preview !== null}
        onOpenChange={(o) => {
          if (!o) {
            setPreview(null);
            install.reset();
          }
        }}
        title={`Install ${l.title}?`}
        description="Review the permissions this listing requests. Nothing is granted until you confirm."
        footer={
          <>
            <Button variant="secondary" onClick={() => setPreview(null)}>
              Cancel
            </Button>
            <Button
              disabled={!agree}
              loading={install.pending}
              onClick={async () => {
                if (await install.run()) {
                  toast.push(`${l.title} installed`, "success");
                  setPreview(null);
                  onDone();
                }
              }}
            >
              Grant and install
            </Button>
          </>
        }
      >
        {preview ? (
          <div className="flex flex-col gap-3 text-sm" data-testid="permission-diff">
            <p>
              <strong>
                {preview.namespace}/{preview.name}@{preview.version}
              </strong>{" "}
              <code className="text-xs">{preview.content_hash.slice(0, 12)}</code>
            </p>
            <div>
              <h3 className="font-medium">Permissions requested beyond your baseline</h3>
              {preview.diff.added.length === 0 ? (
                <p className="text-[var(--axis-muted)]">None.</p>
              ) : (
                <ul className="ml-5 list-disc">
                  {preview.diff.added.map((p) => (
                    <li key={p.key}>
                      <strong>{p.key}</strong> ({p.change}, level {p.level})
                    </li>
                  ))}
                </ul>
              )}
            </div>
            {preview.findings.length ? (
              <div>
                <h3 className="font-medium">Security review findings</h3>
                <ul className="ml-5 list-disc">
                  {preview.findings.map((f) => (
                    <li key={f.id}>
                      {f.id} ({f.severity}): {f.message}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            <p>
              Risk level:{" "}
              <Badge
                tone={
                  preview.risk_level === "high"
                    ? "bad"
                    : preview.risk_level === "limited"
                      ? "warn"
                      : "good"
                }
              >
                {preview.risk_level}
              </Badge>
            </p>
            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                checked={agree}
                onChange={(e) => setAgree(e.target.checked)}
                className="mt-1"
              />
              <span>I have reviewed these permissions and consent to grant them to {l.title}.</span>
            </label>
            {install.error ? <ErrorNote error={install.error} /> : null}
          </div>
        ) : null}
      </Dialog>
    </>
  );
}

export default function ListingPage({
  params,
}: {
  params: Promise<{ namespace: string; name: string }>;
}) {
  const { namespace, name } = use(params);
  const res = useResource(
    () => api.getListing(decodeURIComponent(namespace), decodeURIComponent(name)),
    [namespace, name],
  );
  const installs = useResource(() => api.listInstalls(), [namespace, name]);
  return (
    <>
      <title>Listing - AXIS Console</title>
      <ResourceView
        resource={res}
        unavailable={{
          title: "Listing not available",
          description: "This listing does not exist or the marketplace is not enabled.",
        }}
      >
        {(l) => (
          <>
            <PageHeader
              title={l.title}
              description={`${l.namespace}/${l.name}${l.latest ? ` - v${l.latest.version}` : ""}`}
            />
            <p className="mb-4 max-w-prose text-sm">{l.summary}</p>
            <Install
              l={l}
              installed={(installs.data?.items ?? []).some(
                (i) =>
                  i.namespace === l.namespace && i.name === l.name && i.state !== "uninstalled",
              )}
              onDone={() => {
                res.reload();
                installs.reload();
              }}
            />
          </>
        )}
      </ResourceView>
    </>
  );
}
