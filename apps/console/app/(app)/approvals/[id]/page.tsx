"use client";
import Link from "next/link";
import { use, useState } from "react";
import { Button, Dialog, Textarea, useToast } from "@axis/ui";
import { api, type Approval } from "@/lib/api";
import { useAction, useNow, useResource } from "@/lib/hooks";
import { countdown } from "@/lib/sla";
import { formatTime } from "@/lib/format";
import {
  ApprovalBadge,
  ErrorNote,
  Explanation,
  PageHeader,
  ResourceView,
} from "@/components/common";
import { useCan, useSession } from "@/components/session";

function Decision({ a, onDone }: { a: Approval; onDone: () => void }) {
  const me = useSession().member;
  const allowed = useCan("approvals.decide");
  const [pending, setPending] = useState<"approve" | "reject" | undefined>();
  const [comment, setComment] = useState("");
  const toast = useToast();
  const decide = useAction(async (d: "approve" | "reject") =>
    api.decideApproval(a.id, d, comment || undefined),
  );
  const self = a.requested_by !== undefined && a.requested_by !== null && a.requested_by === me.id;
  if (a.status !== "pending")
    return (
      <p className="text-sm">
        Decided: <ApprovalBadge status={a.status} /> {a.decided_by ? `by ${a.decided_by}` : ""}{" "}
        {a.comment ? `- ${a.comment}` : ""}
      </p>
    );
  if (!allowed)
    return <p className="text-sm text-[var(--axis-muted)]">Your role cannot decide approvals.</p>;
  return (
    <div className="flex flex-col gap-3">
      {self ? (
        <p role="note" className="rounded-md border border-[var(--axis-warn)] p-3 text-sm">
          You cannot approve or deny a request made on your own behalf. Another approver must
          decide. The server enforces this.
        </p>
      ) : null}
      <Textarea
        label="Comment (optional, recorded in the audit log)"
        maxLength={1000}
        rows={3}
        value={comment}
        onChange={(e) => setComment(e.target.value)}
      />
      <div className="flex gap-2">
        <Button disabled={self} onClick={() => setPending("approve")}>
          Approve...
        </Button>
        <Button variant="danger" disabled={self} onClick={() => setPending("reject")}>
          Deny...
        </Button>
      </div>
      {decide.error ? <ErrorNote error={decide.error} /> : null}
      <Dialog
        open={pending !== undefined}
        onOpenChange={(o) => !o && setPending(undefined)}
        title={pending === "approve" ? "Approve this action?" : "Deny this action?"}
        description={`${a.action ?? "Action"} requested by run ${a.run_id.slice(0, 8)}. This decision is recorded in the audit log and cannot be undone.`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setPending(undefined)}>
              Cancel
            </Button>
            <Button
              variant={pending === "reject" ? "danger" : "primary"}
              loading={decide.pending}
              onClick={async () => {
                const r = await decide.run(pending!);
                setPending(undefined);
                if (r) {
                  toast.push(pending === "approve" ? "Approved" : "Denied", "success");
                  onDone();
                }
              }}
            >
              Confirm {pending === "approve" ? "approval" : "denial"}
            </Button>
          </>
        }
      />
    </div>
  );
}

export default function ApprovalPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const res = useResource(() => api.getApproval(id), [id]);
  const now = useNow(1000);
  return (
    <>
      <title>{`Approval ${id.slice(0, 8)} - AXIS Console`}</title>
      <PageHeader title={`Approval ${id.slice(0, 8)}`} />
      <ResourceView resource={res}>
        {(a) => {
          const c = countdown(a.sla_deadline, now);
          return (
            <div className="flex flex-col gap-5">
              <dl className="grid max-w-3xl grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[12rem_1fr]">
                <dt className="text-[var(--axis-muted)]">Status</dt>
                <dd>
                  <ApprovalBadge status={a.status} />
                </dd>
                <dt className="text-[var(--axis-muted)]">Action</dt>
                <dd>{a.action ?? "-"}</dd>
                <dt className="text-[var(--axis-muted)]">Run</dt>
                <dd>
                  <Link href={`/runs/${a.run_id}`}>{a.run_id}</Link>
                </dd>
                <dt className="text-[var(--axis-muted)]">Arguments hash</dt>
                <dd>
                  <code data-testid="args-hash">{a.args_hash ?? "not provided"}</code>
                </dd>
                <dt className="text-[var(--axis-muted)]">Policy reason</dt>
                <dd data-testid="policy-reason">{a.policy_reason ?? "not provided"}</dd>
                {a.matched_rule_ids?.length ? (
                  <>
                    <dt className="text-[var(--axis-muted)]">Matched rules</dt>
                    <dd>{a.matched_rule_ids.join(", ")}</dd>
                  </>
                ) : null}
                <dt className="text-[var(--axis-muted)]">Eligible roles</dt>
                <dd>{a.roles?.join(", ") ?? "-"}</dd>
                <dt className="text-[var(--axis-muted)]">Requested</dt>
                <dd>{formatTime(a.requested_at)}</dd>
                <dt className="text-[var(--axis-muted)]">SLA deadline</dt>
                <dd>
                  {formatTime(a.sla_deadline)}{" "}
                  {a.status === "pending" ? (
                    <span
                      data-testid="sla"
                      className={
                        c.state === "ok" ? "" : "font-semibold text-[var(--axis-warn-text)]"
                      }
                    >
                      ({c.label})
                    </span>
                  ) : null}
                </dd>
              </dl>
              <Decision a={a} onDone={res.reload} />
              <Explanation kind="approval" id={a.id} />
            </div>
          );
        }}
      </ResourceView>
    </>
  );
}
