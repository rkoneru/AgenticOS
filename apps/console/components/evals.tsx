"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect } from "react";
import { Badge, EmptyState, Table, type Tone } from "@axis/ui";
import { api, type EvalRun } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";

const TABS = [
  { href: "/evals", label: "Runs" },
  { href: "/evals/datasets", label: "Datasets" },
  { href: "/evals/suites", label: "Suites" },
  { href: "/evals/baselines", label: "Baselines" },
  { href: "/evals/review", label: "Review queue" },
  { href: "/evals/online", label: "Online" },
];

export function EvalsNav() {
  const path = usePathname();
  return (
    <nav aria-label="Evals sections" className="mb-4 flex flex-wrap gap-1 text-sm">
      {TABS.map((t) => {
        const active =
          t.href === "/evals"
            ? path === "/evals" || path.startsWith("/evals/runs")
            : path.startsWith(t.href);
        return (
          <Link
            key={t.href}
            href={t.href}
            aria-current={active ? "page" : undefined}
            className={`rounded-md px-3 py-1.5 text-[var(--axis-fg)] no-underline ${active ? "bg-[var(--axis-surface-3)] font-semibold" : "hover:bg-[var(--axis-surface-2)]"}`}
          >
            {t.label}
          </Link>
        );
      })}
    </nav>
  );
}

export const runTone = (s: EvalRun["status"]): Tone =>
  s === "passed" ? "good" : s === "failed" || s === "errored" ? "bad" : "info";

export function RunStatus({ run }: { run: Pick<EvalRun, "status" | "pending_human"> }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <Badge tone={runTone(run.status)}>{run.status}</Badge>
      {run.status === "running" && (run.pending_human ?? 0) > 0 ? (
        <Badge tone="warn">awaiting {run.pending_human} human grade(s)</Badge>
      ) : null}
    </span>
  );
}

export const score = (n: number | null | undefined): string =>
  typeof n === "number" ? n.toFixed(3) : "-";

/** Re-run `reload` every `ms` while `live` (a run in flight): live status without a stream endpoint. */
export function usePolling(reload: () => void, live: boolean, ms = 1500): void {
  useEffect(() => {
    if (!live) return;
    const t = setInterval(reload, ms);
    return () => clearInterval(t);
  }, [reload, live, ms]);
}

/**
 * The release gate for ONE blueprint version, with the version's eval history and its signed attestations. Read-only: the console asks
 * the gate, it never decides one. All text from the server is rendered as text.
 */
export function ReleaseGatePanel({
  namespace,
  name,
  version,
  contentHash,
}: {
  namespace?: string | undefined;
  name: string;
  version: string;
  contentHash: string;
}) {
  const bp = { ...(namespace ? { namespace } : {}), name, version, content_hash: contentHash };
  const gate = useResource(() => api.gateEval(bp), [namespace, name, version, contentHash]);
  const history = useResource(
    () => api.listEvalRuns({ blueprint: name, content_hash: contentHash, limit: 50 }),
    [name, contentHash],
  );
  const att = useResource(
    () =>
      namespace
        ? api.listEvalAttestations(namespace, name, version)
        : Promise.resolve({ items: [] }),
    [namespace, name, version],
  );
  return (
    <section
      aria-labelledby="gate-h"
      className="mt-6 rounded-md border border-[var(--axis-border)] p-4"
      data-testid="gate-panel"
    >
      <h2 id="gate-h" className="mb-2 text-base font-semibold">
        Release gate
      </h2>
      {gate.error ? (
        <p role="alert" className="text-sm">
          The release gate could not be asked ({gate.error.message}). Treat the release as blocked.
        </p>
      ) : gate.data ? (
        <div className="flex flex-col gap-2 text-sm">
          <p>
            <Badge tone={gate.data.allowed ? "good" : "bad"}>
              <span data-testid="gate-verdict">{gate.data.allowed ? "ALLOWED" : "BLOCKED"}</span>
            </Badge>{" "}
            {gate.data.allowed
              ? "Every required suite has a fresh, intact, passing run of this exact content."
              : "This version cannot be released."}
          </p>
          {gate.data.reasons.length > 0 ? (
            <ul aria-label="Gate reasons" className="list-disc pl-5">
              {gate.data.reasons.map((r, i) => (
                <li key={`${r.code}-${i}`}>
                  <code>{r.code}</code>
                  {r.suite_ref ? <> [{r.suite_ref}]</> : null}: {r.message}
                </li>
              ))}
            </ul>
          ) : null}
          {gate.data.runs.length > 0 ? (
            <ul aria-label="Gate evidence" className="text-[var(--axis-muted)]">
              {gate.data.runs.map((r) => (
                <li key={r.suite_ref}>
                  {r.suite_ref}:{" "}
                  {r.run_id ? (
                    <Link href={`/evals/runs/${r.run_id}`}>{r.run_id.slice(0, 8)}</Link>
                  ) : (
                    "no run"
                  )}{" "}
                  score {score(r.overall)} (needs {r.required_threshold})
                  {r.delta !== null ? <> , vs baseline {r.delta.toFixed(3)}</> : null}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : (
        <p role="status">Asking the gate...</p>
      )}
      <h3 className="mb-1 mt-4 text-sm font-semibold">Eval history of this version</h3>
      {history.data ? (
        <Table<EvalRun>
          caption="Eval runs of this version"
          rows={history.data.items}
          rowKey={(r) => r.id}
          empty={
            <p className="text-sm text-[var(--axis-muted)]">
              No eval run is bound to this content yet.
            </p>
          }
          columns={[
            { key: "suite", header: "Suite", render: (r) => r.suite },
            { key: "status", header: "Status", render: (r) => <RunStatus run={r} /> },
            { key: "score", header: "Score", render: (r) => score(r.score) },
            { key: "when", header: "Finished", render: (r) => formatTime(r.finished_at) },
            {
              key: "open",
              header: "",
              render: (r) => <Link href={`/evals/runs/${r.id}`}>Details</Link>,
            },
          ]}
        />
      ) : (
        <p role="status">Loading...</p>
      )}
      {namespace ? (
        <>
          <h3 className="mb-1 mt-4 text-sm font-semibold">Signed attestations</h3>
          {att.data ? (
            <Table
              caption="Eval attestations of this version"
              rows={att.data.items}
              rowKey={(a) => a.run_id}
              empty={
                <p className="text-sm text-[var(--axis-muted)]">
                  No attestation is attached to this version.
                </p>
              }
              columns={[
                { key: "run", header: "Run", render: (a) => a.run_id.slice(0, 8) },
                { key: "suite", header: "Suite", render: (a) => a.suite_ref },
                { key: "score", header: "Score", render: (a) => score(a.overall) },
                {
                  key: "ok",
                  header: "Verified",
                  render: (a) => (
                    <Badge tone={a.verified ? "good" : "bad"}>
                      {a.verified ? "verified" : "NOT verified"}
                    </Badge>
                  ),
                },
              ]}
            />
          ) : att.error ? (
            <p className="text-sm">{att.error.message}</p>
          ) : (
            <p role="status">Loading...</p>
          )}
        </>
      ) : null}
    </section>
  );
}

export { EmptyState };
