"use client";
import { use, useState } from "react";
import { Badge, Button, Dialog, useToast } from "@axis/ui";
import { api, type ListingDetail } from "@/lib/api";
import { diffPermissions } from "@/lib/permissions";
import { useAction, useResource } from "@/lib/hooks";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";
import { useCan } from "@/components/session";

function Install({ l, onDone }: { l: ListingDetail; onDone: () => void }) {
  const can = useCan("marketplace.install");
  const [open, setOpen] = useState(false);
  const [agree, setAgree] = useState(false);
  const toast = useToast();
  const diff = diffPermissions(l.permissions, l.installed_permissions);
  const install = useAction(() => api.installListing(l.id, l.permissions));
  if (!can)
    return (
      <p className="text-sm text-[var(--axis-muted)]">
        Your role cannot install listings. Ask an admin.
      </p>
    );
  if (l.installed && !diff.needsConsent)
    return <Badge tone="good">installed, no new permissions</Badge>;
  return (
    <>
      <Button
        onClick={() => {
          setAgree(false);
          install.reset();
          setOpen(true);
        }}
      >
        {l.installed ? "Review update" : "Install..."}
      </Button>
      <Dialog
        open={open}
        onOpenChange={setOpen}
        title={`${l.installed ? "Update" : "Install"} ${l.name}?`}
        description="Review the permissions this listing requests. Nothing is granted until you confirm."
        footer={
          <>
            <Button variant="secondary" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!agree}
              loading={install.pending}
              onClick={async () => {
                if (await install.run()) {
                  toast.push(`${l.name} installed`, "success");
                  setOpen(false);
                  onDone();
                }
              }}
            >
              Grant and install
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3 text-sm" data-testid="permission-diff">
          <div>
            <h3 className="font-medium">
              {l.installed ? "New permissions" : "Permissions requested"}
            </h3>
            {diff.added.length === 0 ? (
              <p className="text-[var(--axis-muted)]">None.</p>
            ) : (
              <ul className="ml-5 list-disc">
                {diff.added.map((p) => (
                  <li key={`${p.kind}:${p.value}`}>
                    <strong>{p.kind}:</strong> {p.value}
                  </li>
                ))}
              </ul>
            )}
          </div>
          {diff.removed.length ? (
            <div>
              <h3 className="font-medium">No longer requested</h3>
              <ul className="ml-5 list-disc">
                {diff.removed.map((p) => (
                  <li key={`${p.kind}:${p.value}`}>
                    {p.kind}: {p.value}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {diff.unchanged.length ? (
            <div>
              <h3 className="font-medium">Already granted</h3>
              <ul className="ml-5 list-disc">
                {diff.unchanged.map((p) => (
                  <li key={`${p.kind}:${p.value}`}>
                    {p.kind}: {p.value}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <p>
            Maximum risk level:{" "}
            <Badge
              tone={
                l.permissions.max_risk_level === "high"
                  ? "bad"
                  : l.permissions.max_risk_level === "limited"
                    ? "warn"
                    : "good"
              }
            >
              {l.permissions.max_risk_level}
            </Badge>
            {diff.riskRaised && l.installed ? " (raised)" : ""}
          </p>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={agree}
              onChange={(e) => setAgree(e.target.checked)}
              className="mt-1"
            />
            <span>I have reviewed these permissions and consent to grant them to {l.name}.</span>
          </label>
          {install.error ? <ErrorNote error={install.error} /> : null}
        </div>
      </Dialog>
    </>
  );
}

export default function ListingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const res = useResource(() => api.getListing(decodeURIComponent(id)), [id]);
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
            <PageHeader title={l.name} description={`${l.publisher} - v${l.version}`} />
            <p className="mb-4 max-w-prose text-sm">{l.summary}</p>
            <Install l={l} onDone={res.reload} />
          </>
        )}
      </ResourceView>
    </>
  );
}
