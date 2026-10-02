"use client";
import { useState } from "react";
import { Badge, Button, Dialog, EmptyState, Input, useToast } from "@axis/ui";
import { api } from "@/lib/api";
import { useAction, useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";
import { useCan } from "@/components/session";

export default function KillSwitchPage() {
  const res = useResource(() => api.listKillSwitches());
  const can = useCan("killswitch.set");
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState<boolean | undefined>();
  const set = useAction((engaged: boolean) =>
    api.setKillSwitch({ scope: "tenant", engaged, ...(reason ? { reason } : {}) }),
  );
  return (
    <>
      <title>Kill switch - AXIS Console</title>
      <PageHeader
        title="Kill switch"
        description="Stop every action of this tenant at the Risk Kernel. Engaging takes effect on the next gated action; releasing restores normal policy decisions."
      />
      <ResourceView resource={res}>
        {(r) => {
          const tenant = r.items.find((k) => k.scope === "tenant");
          const engaged = tenant?.engaged === true;
          return (
            <div className="flex max-w-xl flex-col gap-4">
              <p className="text-sm">
                Tenant kill switch:{" "}
                <span data-testid="ks-state">
                  <Badge tone={engaged ? "bad" : "good"}>{engaged ? "ENGAGED" : "released"}</Badge>
                </span>
                {tenant ? ` (updated ${formatTime(tenant.updated_at)})` : ""}
              </p>
              {r.items.length === 0 ? <EmptyState title="No kill switches have been set" /> : null}
              {can ? (
                <>
                  <Input
                    label="Reason (recorded in the audit log)"
                    value={reason}
                    maxLength={500}
                    onChange={(e) => setReason(e.target.value)}
                  />
                  <div>
                    <Button
                      variant={engaged ? "primary" : "danger"}
                      onClick={() => setConfirm(!engaged)}
                    >
                      {engaged
                        ? "Release the tenant kill switch..."
                        : "Engage the tenant kill switch..."}
                    </Button>
                  </div>
                  {set.error ? <ErrorNote error={set.error} /> : null}
                  <Dialog
                    open={confirm !== undefined}
                    onOpenChange={(o) => !o && setConfirm(undefined)}
                    title={confirm ? "Engage the kill switch?" : "Release the kill switch?"}
                    description={
                      confirm
                        ? "Every gated action of every agent in this tenant is denied until you release it."
                        : "Agents resume under the tenant's normal policy."
                    }
                    footer={
                      <>
                        <Button variant="secondary" onClick={() => setConfirm(undefined)}>
                          Cancel
                        </Button>
                        <Button
                          variant={confirm ? "danger" : "primary"}
                          loading={set.pending}
                          onClick={async () => {
                            const want = confirm as boolean;
                            if (await set.run(want)) {
                              toast.push(
                                want ? "Kill switch engaged" : "Kill switch released",
                                "success",
                              );
                              setConfirm(undefined);
                              res.reload();
                            }
                          }}
                        >
                          {confirm ? "Engage" : "Release"}
                        </Button>
                      </>
                    }
                  />
                </>
              ) : (
                <p className="text-sm text-[var(--axis-muted)]">
                  Your role cannot change kill switches.
                </p>
              )}
            </div>
          );
        }}
      </ResourceView>
    </>
  );
}
