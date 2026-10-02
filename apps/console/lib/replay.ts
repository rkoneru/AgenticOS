import type { RunEvent, ProcessState } from "./api";

export interface ReplayState {
  /** Highest sequence applied (0 = before the first event). */
  sequence: number;
  state: ProcessState | "unknown";
  tokens: number;
  costUsd: number;
  toolCalls: number;
  modelCalls: number;
  denials: number;
  approvalsRequested: number;
  lastDecision?: string;
}

export const emptyReplay: ReplayState = {
  sequence: 0,
  state: "unknown",
  tokens: 0,
  costUsd: 0,
  toolCalls: 0,
  modelCalls: 0,
  denials: 0,
  approvalsRequested: 0,
};

const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0);

const STATES: ReadonlySet<string> = new Set([
  "spawn",
  "ready",
  "running",
  "waiting",
  "suspended",
  "terminated",
]);

/** Fold one event into the state. Pure; unknown event types only advance the sequence. */
export function applyEvent(s: ReplayState, e: RunEvent): ReplayState {
  const next: ReplayState = { ...s, sequence: Math.max(s.sequence, e.sequence) };
  const d = e.data ?? {};
  switch (e.type) {
    case "state_transition": {
      const to = d["to"];
      if (typeof to === "string" && STATES.has(to)) next.state = to as ProcessState;
      break;
    }
    case "model_call":
      next.modelCalls += 1;
      next.tokens += num(d["tokens"]);
      next.costUsd += num(d["cost_usd"]);
      break;
    case "tool_call":
      next.toolCalls += 1;
      break;
    case "gate_decision": {
      const dec = d["decision"];
      if (typeof dec === "string") {
        next.lastDecision = dec;
        if (dec === "DENY") next.denials += 1;
        if (dec === "REQUIRE_APPROVAL") next.approvalsRequested += 1;
      }
      break;
    }
    default:
      break;
  }
  return next;
}

/** Sort by sequence and drop duplicates (a reconnect can replay events). */
export function mergeEvents(existing: RunEvent[], incoming: RunEvent[]): RunEvent[] {
  const bySeq = new Map<number, RunEvent>();
  for (const e of existing) bySeq.set(e.sequence, e);
  for (const e of incoming) bySeq.set(e.sequence, e);
  return [...bySeq.values()].sort((a, b) => a.sequence - b.sequence);
}

/** State after applying every event with `sequence <= upTo`. */
export function replayTo(events: readonly RunEvent[], upTo: number): ReplayState {
  let s = emptyReplay;
  for (const e of events) {
    if (e.sequence > upTo) break;
    s = applyEvent(s, e);
  }
  return s;
}

export function describeEvent(e: RunEvent): string {
  const d = e.data ?? {};
  const str = (k: string): string => (typeof d[k] === "string" ? (d[k] as string) : "");
  switch (e.type) {
    case "state_transition":
      return `${str("from") || "?"} -> ${str("to") || "?"}`;
    case "model_call":
      return `model ${str("model") || "?"}, ${num(d["tokens"])} tokens`;
    case "tool_call":
      return `tool ${str("tool") || "?"}`;
    case "gate_decision":
      return `${str("decision") || "?"}${str("reason") ? `: ${str("reason")}` : ""}`;
    default:
      return e.type;
  }
}

export function eventTone(e: RunEvent): "neutral" | "good" | "bad" | "warn" {
  if (e.type !== "gate_decision") return "neutral";
  const dec = e.data?.["decision"];
  if (dec === "DENY") return "bad";
  if (dec === "REQUIRE_APPROVAL") return "warn";
  if (dec === "ALLOW" || dec === "ALLOW_WITH_REDACTION") return "good";
  return "neutral";
}

export interface Gauge {
  label: string;
  used: number;
  soft?: number | undefined;
  hard?: number | undefined;
  /** 0..1 of the hard limit (or soft when only soft is set); undefined when no limit. */
  ratio?: number | undefined;
  level: "ok" | "soft" | "hard" | "none";
}

export function gauge(label: string, used: number, soft?: number, hard?: number): Gauge {
  const limit = hard ?? soft;
  const ratio = limit && limit > 0 ? Math.min(used / limit, 1) : undefined;
  let level: Gauge["level"] = "none";
  if (hard !== undefined && used >= hard) level = "hard";
  else if (soft !== undefined && used >= soft) level = "soft";
  else if (limit !== undefined) level = "ok";
  return { label, used, soft, hard, ratio, level };
}
