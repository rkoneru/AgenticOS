"use client";
import { useState } from "react";
import { Badge, Button, EmptyState, Input, Select, Textarea } from "@axis/ui";
import { api, type EvalReviewTask } from "@/lib/api";
import { useAction, useResource } from "@/lib/hooks";
import { can } from "@/lib/roles";
import { formatTime } from "@/lib/format";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";
import { EvalsNav, usePolling } from "@/components/evals";
import { useSession } from "@/components/session";

function Task({
  t,
  canReview,
  onChange,
}: {
  t: EvalReviewTask;
  canReview: boolean;
  onChange: () => void;
}) {
  const [score, setScore] = useState("");
  const [comment, setComment] = useState("");
  const claim = useAction(async () => {
    await api.claimEvalReviewTask(t.id);
    onChange();
  });
  const grade = useAction(async () => {
    await api.gradeEvalReviewTask(t.id, Number(score), comment);
    setScore("");
    setComment("");
    onChange();
  });
  const skip = useAction(async () => {
    await api.skipEvalReviewTask(t.id, comment.trim() || "not my area");
    onChange();
  });
  const claimed = t.state === "claimed";
  const valid = score !== "" && Number(score) >= 0 && Number(score) <= 1 && comment.trim() !== "";
  return (
    <li
      className="rounded-md border border-[var(--axis-border)] p-3 text-sm"
      data-testid={`task-${t.case_id}`}
    >
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <strong>
          {t.suite_ref} / {t.case_id}
        </strong>
        <Badge tone={t.state === "needs_adjudication" ? "warn" : "info"}>
          {t.state.replace("_", " ")}
        </Badge>
        {t.run_id.startsWith("online:") ? <Badge>production sample</Badge> : null}
        {t.double_grade ? <Badge>double graded</Badge> : null}
        <span className="text-[var(--axis-muted)]">due {formatTime(t.sla_deadline)}</span>
        {t.sla_breached ? <Badge tone="bad">SLA breached</Badge> : null}
      </div>
      <p>
        <em>Rubric:</em> {t.rubric}
      </p>
      <p className="mt-2 font-medium">Answer to grade</p>
      {/* untrusted, already redacted by the runner and by the hub: shown as text only */}
      <pre
        className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-[var(--axis-surface-2)] p-2"
        data-testid="task-output"
      >
        {t.case_output ?? "(no output)"}
      </pre>
      {canReview ? (
        <div className="mt-3 flex flex-col gap-2">
          {!claimed ? (
            <div>
              <Button onClick={() => void claim.run()} loading={claim.pending}>
                Claim to grade
              </Button>
            </div>
          ) : (
            <div className="flex max-w-xl flex-col gap-2">
              <Input
                label={`Score (0 to 1) for ${t.case_id}`}
                inputMode="decimal"
                value={score}
                onChange={(e) => setScore(e.target.value)}
              />
              <Textarea
                label={`Comment for ${t.case_id}`}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                rows={2}
              />
              <div className="flex gap-2">
                <Button onClick={() => void grade.run()} loading={grade.pending} disabled={!valid}>
                  Submit grade
                </Button>
                <Button variant="secondary" onClick={() => void skip.run()} loading={skip.pending}>
                  Skip
                </Button>
              </div>
            </div>
          )}
          {[claim.error, grade.error, skip.error].map((e, i) =>
            e ? <ErrorNote key={i} error={e} /> : null,
          )}
        </div>
      ) : null}
    </li>
  );
}

export default function ReviewQueuePage() {
  const session = useSession();
  const [state, setState] = useState("");
  const res = useResource(() => api.listEvalReviewTasks(state ? { state } : {}), [state]);
  usePolling(res.reload, true, 4000);
  const canReview = can(session.member.role, "evals.review");
  return (
    <>
      <title>Review queue - AXIS Console</title>
      <PageHeader
        title="Review queue"
        description="Human grades. You never see (or get) tasks for a blueprint you published or a run you started."
      />
      <EvalsNav />
      <div className="mb-3 max-w-xs">
        <Select
          label="State"
          value={state}
          onChange={(e) => setState(e.target.value)}
          options={["", "open", "claimed", "needs_adjudication", "resolved"].map((v) => ({
            value: v,
            label: v === "" ? "All" : v.replace("_", " "),
          }))}
        />
      </div>
      <ResourceView resource={res}>
        {(p) =>
          p.items.length === 0 ? (
            <EmptyState
              title="Nothing to review"
              description="Tasks for work you started or published are not shown to you."
            />
          ) : (
            <ul aria-label="Review tasks" className="flex flex-col gap-3">
              {p.items.map((t) => (
                <Task key={t.id} t={t} canReview={canReview} onChange={res.reload} />
              ))}
            </ul>
          )
        }
      </ResourceView>
    </>
  );
}
