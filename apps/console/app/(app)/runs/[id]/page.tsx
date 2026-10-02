"use client";
import { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Badge, Button, Timeline, useToast, type TimelineItem } from "@axis/ui";
import { api, type Budget, type RunEvent } from "@/lib/api";
import { consumeRunEvents } from "@/lib/sse";
import { describeEvent, eventTone, gauge, mergeEvents, replayTo } from "@/lib/replay";
import { useResource } from "@/lib/hooks";
import { formatTime, formatUsd } from "@/lib/format";
import {
  Explanation,
  GaugeBar,
  PageHeader,
  ResourceView,
  StateBadge,
  ErrorNote,
} from "@/components/common";
import { Can } from "@/components/session";

const TERMINAL = "terminated";

function useRunEvents(runId: string, live: boolean) {
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [status, setStatus] = useState<"connecting" | "live" | "ended" | "error">("connecting");
  const [error, setError] = useState<Error | undefined>();
  const last = useRef(0);
  useEffect(() => {
    let stop = false;
    const ac = new AbortController();
    async function backfill() {
      // Backfill first (also the only path once the run has ended), then follow the stream.
      let after = last.current;
      for (;;) {
        const page = await api.listRunEvents(runId, { after_sequence: after, limit: 200 });
        if (stop) return;
        if (page.items.length === 0) break;
        setEvents((cur) => mergeEvents(cur, page.items));
        after = Math.max(after, ...page.items.map((e) => e.sequence));
        last.current = after;
        if (page.items.length < 200) break;
      }
    }
    async function run() {
      try {
        await backfill();
        if (stop) return;
        if (!live) {
          setStatus("ended");
          return;
        }
        const stream = await api.streamRunEvents(runId, last.current, ac.signal);
        setStatus("live");
        await consumeRunEvents(stream, (e) => {
          last.current = Math.max(last.current, e.sequence);
          setEvents((cur) => mergeEvents(cur, [e]));
        });
        if (!stop) setStatus("ended");
      } catch (e) {
        if (stop || ac.signal.aborted) return;
        setError(e instanceof Error ? e : new Error(String(e)));
        setStatus("error");
      }
    }
    void run();
    return () => {
      stop = true;
      ac.abort();
    };
  }, [runId, live]);
  return { events, status, error };
}

export default function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const run = useResource(() => api.getRun(id), [id]);
  const budgets = useResource(() => api.listBudgets(), []);
  const live = run.data ? run.data.state !== TERMINAL : false;
  const { events, status, error } = useRunEvents(id, run.data !== undefined && live);
  const [cursor, setCursor] = useState<number | "live">("live");
  const [playing, setPlaying] = useState(false);
  const toast = useToast();

  const max = events.length ? events[events.length - 1]!.sequence : 0;
  const at = cursor === "live" ? max : Math.min(cursor, max);
  const state = useMemo(() => replayTo(events, at), [events, at]);

  // Auto-play the scrubber.
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setCursor((c) => {
        const cur = c === "live" ? 0 : c;
        const next = events.find((e) => e.sequence > cur)?.sequence;
        if (next === undefined) {
          setPlaying(false);
          return c;
        }
        return next;
      });
    }, 500);
    return () => clearInterval(t);
  }, [playing, events]);

  const reloadRun = run.reload;
  useEffect(() => {
    // Refresh the run record when the log reaches a terminal transition.
    if (state.state === TERMINAL && run.data && run.data.state !== TERMINAL && cursor === "live")
      reloadRun();
  }, [state.state, run.data, cursor, reloadRun]);

  const signal = useCallback(
    async (s: "PAUSE" | "RESUME" | "TERM") => {
      try {
        await api.signalRun(id, s);
        toast.push(`Signal ${s} sent`, "success");
        run.reload();
      } catch (e) {
        toast.push(e instanceof Error ? e.message : "Signal failed", "error");
      }
    },
    [id],
  );

  const runBudgets: Budget[] = (budgets.data?.items ?? []).filter(
    (b) => b.scope === "run" || b.scope === "tenant",
  );
  const lim = (metric: Budget["metric"]) => runBudgets.find((b) => b.metric === metric);
  const gauges = [
    gauge("tokens", state.tokens, lim("tokens")?.soft, lim("tokens")?.hard),
    gauge("cost (USD)", state.costUsd, lim("cost_usd")?.soft, lim("cost_usd")?.hard),
    gauge("tool calls", state.toolCalls, lim("tool_calls")?.soft, lim("tool_calls")?.hard),
  ];

  const items: TimelineItem[] = events
    .filter((e) => e.sequence <= at)
    .map((e) => ({
      id: String(e.sequence),
      title: `#${e.sequence} ${e.type}`,
      at: formatTime(e.at),
      detail: describeEvent(e),
      tone: eventTone(e),
    }));
  const denial = events.find(
    (e) =>
      e.type === "gate_decision" &&
      (e.data?.["decision"] === "DENY" || e.data?.["decision"] === "REQUIRE_APPROVAL"),
  );

  return (
    <>
      <title>{`Run ${id.slice(0, 8)} - AXIS Console`}</title>
      <PageHeader
        title={`Run ${id.slice(0, 8)}`}
        description="Live event timeline with replay over the append-only event log."
        actions={
          <Can cap="runs.signal">
            <Button variant="secondary" onClick={() => signal("PAUSE")}>
              Pause
            </Button>
            <Button variant="secondary" onClick={() => signal("RESUME")}>
              Resume
            </Button>
            <Button variant="danger" onClick={() => signal("TERM")}>
              Terminate
            </Button>
          </Can>
        }
      />
      <ResourceView resource={run}>
        {(r) => (
          <div className="flex flex-col gap-5">
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <StateBadge state={r.state} />
              <span>
                {r.blueprint.name} @ {r.blueprint.version}
              </span>
              <span>Started {formatTime(r.created_at)}</span>
              {r.exit_reason ? <span>Exit: {r.exit_reason}</span> : null}
              {r.trace_id ? (
                <a href={`/audit?trace_id=${encodeURIComponent(r.trace_id)}`}>
                  trace <code>{r.trace_id.slice(0, 8)}</code>
                </a>
              ) : null}
              <Badge tone={status === "live" ? "good" : status === "error" ? "bad" : "neutral"}>
                stream: {status}
              </Badge>
            </div>
            {error ? <ErrorNote error={error} /> : null}

            <section aria-label="Budgets and cost" className="grid gap-4 sm:grid-cols-3">
              {gauges.map((g) => (
                <GaugeBar
                  key={g.label}
                  g={g}
                  {...(g.label.startsWith("cost") ? { format: formatUsd } : {})}
                />
              ))}
            </section>

            <section
              aria-label="Replay"
              className="rounded-md border border-[var(--axis-border)] p-4"
            >
              <h2 className="mb-2 text-base font-semibold">Replay</h2>
              <div className="flex flex-wrap items-center gap-3">
                <label htmlFor="scrub" className="text-sm">
                  Event
                </label>
                <input
                  id="scrub"
                  type="range"
                  min={0}
                  max={max}
                  step={1}
                  value={at}
                  disabled={max === 0}
                  onChange={(e) => {
                    setPlaying(false);
                    const v = Number(e.target.value);
                    setCursor(v >= max ? "live" : v);
                  }}
                  aria-valuetext={`Event ${at} of ${max}`}
                  className="min-w-40 flex-1"
                />
                <output htmlFor="scrub" className="text-sm" data-testid="replay-pos">
                  {at} / {max}
                </output>
                <Button
                  variant="secondary"
                  disabled={max === 0}
                  onClick={() => {
                    if (!playing && cursor === "live") setCursor(0);
                    setPlaying((p) => !p);
                  }}
                >
                  {playing ? "Pause replay" : "Play replay"}
                </Button>
                <Button
                  variant="ghost"
                  disabled={cursor === "live"}
                  onClick={() => {
                    setPlaying(false);
                    setCursor("live");
                  }}
                >
                  Jump to live
                </Button>
              </div>
              <dl
                className="mt-3 grid grid-cols-2 gap-2 text-sm sm:grid-cols-5"
                data-testid="replay-state"
              >
                <div>
                  <dt className="text-[var(--axis-muted)]">State</dt>
                  <dd>
                    <StateBadge state={state.state} />
                  </dd>
                </div>
                <div>
                  <dt className="text-[var(--axis-muted)]">Model calls</dt>
                  <dd>{state.modelCalls}</dd>
                </div>
                <div>
                  <dt className="text-[var(--axis-muted)]">Tool calls</dt>
                  <dd>{state.toolCalls}</dd>
                </div>
                <div>
                  <dt className="text-[var(--axis-muted)]">Denials</dt>
                  <dd>{state.denials}</dd>
                </div>
                <div>
                  <dt className="text-[var(--axis-muted)]">Approvals asked</dt>
                  <dd>{state.approvalsRequested}</dd>
                </div>
              </dl>
            </section>

            <section aria-label="Event timeline">
              <h2 className="mb-2 text-base font-semibold">Timeline</h2>
              {items.length === 0 ? (
                <p className="text-sm text-[var(--axis-muted)]">No events yet.</p>
              ) : (
                <Timeline label="Run events" items={items} activeId={String(at)} />
              )}
            </section>

            <Explanation kind="run" id={id} />
            {denial?.audit_event_id ? (
              <Explanation kind="audit" id={denial.audit_event_id} />
            ) : null}
          </div>
        )}
      </ResourceView>
    </>
  );
}
