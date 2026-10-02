"use client";
import { useState, type ReactNode } from "react";
import { Badge, Button, EmptyState, type Tone } from "@axis/ui";
import type {
  ApprovalStatus,
  Decision,
  Explanation as ExplanationData,
  ProcessState,
} from "@/lib/api";
import { ApiError, api } from "@/lib/api";
import { errorText, useResource, type Resource } from "@/lib/hooks";
import type { Gauge } from "@/lib/replay";
import { formatNumber } from "@/lib/format";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold">{title}</h1>
        {description ? <p className="text-sm text-[var(--axis-muted)]">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}

export function ErrorNote({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center gap-3 rounded-md border border-[var(--axis-danger)] p-3 text-sm"
    >
      <span>{errorText(error)}</span>
      {error instanceof ApiError && error.traceId ? (
        <code className="text-xs">trace {error.traceId}</code>
      ) : null}
      {onRetry ? (
        <Button variant="secondary" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

/** Loading / error / not-available wrapper around a Resource. */
export function ResourceView<T>({
  resource,
  children,
  unavailable,
}: {
  resource: Resource<T>;
  children: (data: T) => ReactNode;
  /** Shown when the endpoint is not served (404/405/501), e.g. a phase that has not shipped. */
  unavailable?: { title: string; description: string };
}) {
  if (resource.loading && resource.data === undefined)
    return (
      <p role="status" aria-live="polite">
        Loading...
      </p>
    );
  if (resource.error) {
    if (unavailable && resource.error instanceof ApiError && resource.error.notAvailable) {
      return <EmptyState title={unavailable.title} description={unavailable.description} />;
    }
    return <ErrorNote error={resource.error} onRetry={resource.reload} />;
  }
  if (resource.data === undefined) return null;
  return <>{children(resource.data)}</>;
}

const stateTone: Record<ProcessState, Tone> = {
  spawn: "info",
  ready: "info",
  running: "info",
  waiting: "warn",
  suspended: "warn",
  terminated: "neutral",
};
export const StateBadge = ({ state }: { state: ProcessState | "unknown" }) => (
  <Badge tone={state === "unknown" ? "neutral" : stateTone[state]}>{state}</Badge>
);

const decTone: Record<Decision, Tone> = {
  ALLOW: "good",
  DENY: "bad",
  REQUIRE_APPROVAL: "warn",
  ALLOW_WITH_REDACTION: "info",
};
export const DecisionBadge = ({ decision }: { decision: Decision }) => (
  <Badge tone={decTone[decision]}>{decision}</Badge>
);

const apprTone: Record<ApprovalStatus, Tone> = {
  pending: "warn",
  approved: "good",
  rejected: "bad",
  expired: "neutral",
  escalated: "info",
};
export const ApprovalBadge = ({ status }: { status: ApprovalStatus }) => (
  <Badge tone={apprTone[status]}>{status}</Badge>
);

export function GaugeBar({
  g,
  format = formatNumber,
}: {
  g: Gauge;
  format?: (n: number) => string;
}) {
  const pct = g.ratio === undefined ? 0 : Math.round(g.ratio * 100);
  const color =
    g.level === "hard"
      ? "var(--axis-danger)"
      : g.level === "soft"
        ? "var(--axis-warn)"
        : "var(--axis-accent)";
  const limit = g.hard ?? g.soft;
  return (
    <div className="flex flex-col gap-1" data-testid={`gauge-${g.label}`}>
      <div className="flex justify-between text-sm">
        <span>{g.label}</span>
        <span>
          {format(g.used)}
          {limit !== undefined ? ` / ${format(limit)}` : " (no limit)"}
        </span>
      </div>
      {limit !== undefined ? (
        <svg
          role="meter"
          aria-label={`${g.label} used`}
          aria-valuemin={0}
          aria-valuemax={limit}
          aria-valuenow={Math.min(g.used, limit)}
          aria-valuetext={`${pct}% of limit${g.level === "soft" ? ", soft limit reached" : g.level === "hard" ? ", hard limit reached" : ""}`}
          width="100%"
          height="10"
          className="rounded-full bg-[var(--axis-surface-3)]"
        >
          <rect x="0" y="0" width={`${pct}%`} height="10" rx="5" fill={color} />
        </svg>
      ) : null}
      {g.level === "soft" || g.level === "hard" ? (
        <span className="text-xs text-[var(--axis-warn-text)]">
          {g.level === "hard" ? "Hard limit reached" : "Soft limit reached"}
        </span>
      ) : null}
    </div>
  );
}

/** Plain-text list that never interprets markup. */
function Lines({ items, ordered }: { items: string[]; ordered?: boolean }) {
  const Tag = ordered ? "ol" : "ul";
  return (
    <Tag className={`${ordered ? "list-decimal" : "list-disc"} ml-5 text-sm`}>
      {items.map((t, i) => (
        <li key={i}>{t}</li>
      ))}
    </Tag>
  );
}

/**
 * AGIL explanation panel. Fetches the explanation the service produced from the audit log and renders
 * exactly its fields as text; nothing here composes or infers explanation content.
 */
export function Explanation({
  kind,
  id,
  traceId,
}: {
  kind: "run" | "approval" | "audit";
  id: string;
  /** For `audit`: lets an audit event ID (not a seq) be resolved. */
  traceId?: string | undefined;
}) {
  const res = useResource<ExplanationData>(
    () =>
      kind === "run"
        ? api.explainRun(id)
        : kind === "approval"
          ? api.explainApproval(id)
          : api.explainAuditEvent(id, traceId),
    [kind, id, traceId],
  );
  const [open, setOpen] = useState(true);
  return (
    <section
      aria-label="AGIL explanation"
      className="rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] p-4"
      data-testid="agil-panel"
    >
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-base font-semibold">Explanation (AGIL)</h2>
        <Button variant="ghost" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          {open ? "Hide" : "Show"}
        </Button>
      </div>
      {open ? (
        <div className="mt-2 flex flex-col gap-3">
          <ResourceView
            resource={res}
            unavailable={{
              title: "No explanation available",
              description:
                "AGIL has not produced an explanation for this item. It is read-only and never affects decisions.",
            }}
          >
            {(x) => (
              <>
                <p className="text-sm">{x.summary}</p>
                {x.steps.length ? (
                  <div>
                    <h3 className="text-sm font-medium">What happened</h3>
                    <Lines items={x.steps} ordered />
                  </div>
                ) : null}
                {x.decision_refs.length ? (
                  <div>
                    <h3 className="text-sm font-medium">Decisions referenced</h3>
                    <ul className="ml-5 list-disc text-sm">
                      {x.decision_refs.map((r) => (
                        <li key={r.audit_event_id}>
                          <a href={`/audit?event=${encodeURIComponent(r.audit_event_id)}`}>
                            {r.seq !== undefined ? `audit event #${r.seq}` : r.audit_event_id}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {x.remediation.length ? (
                  <div>
                    <h3 className="text-sm font-medium">What you can do</h3>
                    <Lines items={x.remediation} />
                  </div>
                ) : null}
              </>
            )}
          </ResourceView>
        </div>
      ) : null}
    </section>
  );
}

export function LoadMore({
  cursor,
  loading,
  onMore,
}: {
  cursor: string | null | undefined;
  loading: boolean;
  onMore: () => void;
}) {
  if (!cursor) return null;
  return (
    <div className="mt-3">
      <Button variant="secondary" loading={loading} onClick={onMore}>
        Load more
      </Button>
    </div>
  );
}
