"use client";
import { useEffect, useMemo, useState } from "react";
import { Badge, Button, EmptyState, Input, Select, Table } from "@axis/ui";
import { api, type AuditEvent, type AuditVerdict, type Decision } from "@/lib/api";
import { reasonText, sortBySeq, verifyChainLocal, type LocalVerdict } from "@/lib/hashchain";
import { useAction, usePaged } from "@/lib/hooks";
import { formatTime, shortId } from "@/lib/format";
import { DecisionBadge, ErrorNote, Explanation, LoadMore, PageHeader } from "@/components/common";

export default function AuditPage() {
  const [trace, setTrace] = useState("");
  const [decision, setDecision] = useState<Decision | "">("");
  const [text, setText] = useState("");
  const [selected, setSelected] = useState<AuditEvent | undefined>();
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    setTrace(sp.get("trace_id") ?? "");
  }, []);
  const traceValid = trace === "" || /^[0-9a-f]{32}$/.test(trace);
  const list = usePaged(
    (cursor) =>
      api.listAuditEvents({
        limit: 100,
        ...(trace && traceValid ? { trace_id: trace } : {}),
        ...(decision ? { decision } : {}),
        ...(cursor ? { cursor } : {}),
      }),
    [trace, traceValid, decision],
  );
  const shown = useMemo(() => {
    const q = text.trim().toLowerCase();
    return q
      ? list.items.filter((e) =>
          [e.action, e.actor.id, e.reason ?? "", e.enforcement_point, e.blueprint.name].some((s) =>
            s.toLowerCase().includes(q),
          ),
        )
      : list.items;
  }, [list.items, text]);

  const [server, setServer] = useState<AuditVerdict | undefined>();
  const [local, setLocal] = useState<LocalVerdict | undefined>();
  const [skipped, setSkipped] = useState(false);
  const verify = useAction(async () => {
    setServer(undefined);
    setLocal(undefined);
    const sorted = sortBySeq(list.items);
    const from = sorted[0]?.seq;
    const to = sorted[sorted.length - 1]?.seq;
    const filtered = Boolean(trace || decision);
    const anchorEvt =
      !filtered && from && from > 1
        ? (await api.listAuditEvents({ limit: 1, from_seq: from - 1 })).items[0]
        : undefined;
    const s = await api.verifyAudit(from && to ? { from_seq: from, to_seq: to } : {});
    // A filtered view is not contiguous, so it cannot be re-hashed on its own.
    const l = filtered
      ? undefined
      : await verifyChainLocal(
          sorted,
          anchorEvt ? { seq: anchorEvt.seq, hash: anchorEvt.hash } : undefined,
        );
    setSkipped(filtered);
    setServer(s);
    setLocal(l);
  });

  return (
    <>
      <title>Audit - AXIS Console</title>
      <PageHeader
        title="Audit explorer"
        description="Append-only, hash-chained events. Verification is recomputed independently in your browser."
      />
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <Input
          label="Trace ID"
          value={trace}
          onChange={(e) => setTrace(e.target.value.trim())}
          error={traceValid ? undefined : "A trace ID is 32 lowercase hex characters"}
          placeholder="32 hex characters"
        />
        <Select
          label="Decision"
          value={decision}
          onChange={(e) => setDecision(e.target.value as Decision | "")}
          options={[
            { value: "", label: "All" },
            ...(["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"] as const).map(
              (d) => ({ value: d, label: d }),
            ),
          ]}
        />
        <Input
          label="Search loaded events"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="action, actor, reason"
        />
      </div>

      <section
        aria-label="Chain verification"
        className="mb-4 rounded-md border border-[var(--axis-border)] p-3"
      >
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="secondary" loading={verify.pending} onClick={() => void verify.run()}>
            Verify hash chain
          </Button>
          <span className="text-sm text-[var(--axis-muted)]">
            Checks the loaded range on the server and again in this browser.
          </span>
        </div>
        {verify.error ? (
          <div className="mt-2">
            <ErrorNote error={verify.error} />
          </div>
        ) : null}
        <div
          aria-live="polite"
          className="mt-2 flex flex-col gap-1 text-sm"
          data-testid="verify-result"
        >
          {server ? (
            <p>
              Server:{" "}
              {server.ok ? <Badge tone="good">verified</Badge> : <Badge tone="bad">BROKEN</Badge>}{" "}
              {server.verified} events
              {server.broken_at_seq ? `, broken at seq ${server.broken_at_seq}` : ""}
              {server.reason ? ` (${server.reason})` : ""}
            </p>
          ) : null}
          {local ? (
            <p>
              This browser:{" "}
              {local.ok ? (
                <Badge tone="good">consistent</Badge>
              ) : (
                <Badge tone="bad">INCONSISTENT</Badge>
              )}{" "}
              {local.ok
                ? `${local.length} events${local.length ? `, seq ${local.firstSeq}-${local.lastSeq}` : ""}`
                : `seq ${local.brokenAtSeq}: ${reasonText(local.reason)}`}
            </p>
          ) : null}
          {skipped ? (
            <p>
              This browser: not checked (a filtered view is not a contiguous slice of the chain;
              clear the filters to re-hash).
            </p>
          ) : null}
          {server && local && server.ok !== local.ok ? (
            <p role="alert" className="font-semibold text-[var(--axis-danger-text)]">
              The server and this browser disagree. Treat the log as untrusted and escalate.
            </p>
          ) : null}
        </div>
      </section>

      {list.error ? <ErrorNote error={list.error} onRetry={list.reload} /> : null}
      {list.loading ? <p role="status">Loading...</p> : null}
      {!list.loading && !list.error ? (
        <Table<AuditEvent>
          caption="Audit events"
          rows={shown}
          rowKey={(e) => e.id}
          empty={<EmptyState title="No matching events" />}
          columns={[
            { key: "seq", header: "Seq", render: (e) => e.seq },
            { key: "ts", header: "Time", render: (e) => formatTime(e.ts) },
            { key: "actor", header: "Actor", render: (e) => `${e.actor.type}:${e.actor.id}` },
            { key: "action", header: "Action", render: (e) => e.action },
            {
              key: "dec",
              header: "Decision",
              render: (e) => <DecisionBadge decision={e.decision} />,
            },
            {
              key: "trace",
              header: "Trace",
              render: (e) => (
                <button type="button" className="underline" onClick={() => setTrace(e.trace_id)}>
                  {shortId(e.trace_id)}
                </button>
              ),
            },
            {
              key: "open",
              header: "",
              render: (e) => (
                <Button
                  variant="ghost"
                  aria-label={`Details for event ${e.seq}`}
                  onClick={() => setSelected(e)}
                >
                  Details
                </Button>
              ),
            },
          ]}
        />
      ) : null}
      <LoadMore cursor={list.cursor} loading={list.loadingMore} onMore={list.more} />

      {selected ? (
        <section
          aria-label="Event detail"
          className="mt-6 flex flex-col gap-3 rounded-md border border-[var(--axis-border)] p-4"
          data-testid="audit-detail"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Event #{selected.seq}</h2>
            <Button variant="ghost" onClick={() => setSelected(undefined)}>
              Close
            </Button>
          </div>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-[10rem_1fr]">
            {(
              [
                ["Id", selected.id],
                ["Trace", selected.trace_id],
                ["Enforcement point", selected.enforcement_point],
                ["Policy version", selected.policy_version],
                ["Reason", selected.reason ?? "-"],
                ["Inputs hash", selected.inputs_hash],
                ["Outputs hash", selected.outputs_hash],
                ["Previous hash", selected.prev_hash],
                ["Hash", selected.hash],
              ] as const
            ).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-[var(--axis-muted)]">{k}</dt>
                <dd className="break-all">
                  <code>{v}</code>
                </dd>
              </div>
            ))}
          </dl>
          {selected.decision !== "ALLOW" ? <Explanation kind="audit" id={selected.id} /> : null}
        </section>
      ) : null}
    </>
  );
}
