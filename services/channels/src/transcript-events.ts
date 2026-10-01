import { ChannelError, type AgentRef } from "./types.js";

/**
 * A transcript event relayed by the runtime for a channel the gateway does not terminate itself (voice). It carries facts and
 * hashes only: the redacted preview lives in the runtime's run log (docs/adr/0017), never in the audit chain. Every string is
 * checked against a narrow charset, because the gateway builds the audit `reason` from them.
 */
export interface TranscriptEvent {
  kind: "call" | "turn";
  channel: "voice";
  call_id: string;
  trace_id: string;
  agent: AgentRef;
  run_id?: string;
  /** call: connected | consent | ended */
  phase?: string;
  reason?: string;
  duration_ms?: number;
  detail?: Record<string, string | number | boolean>;
  /** turn */
  turn?: number;
  role?: "user" | "agent" | "system" | "dtmf";
  text_sha256?: string;
  size?: number;
  redacted?: boolean;
  truncated?: boolean;
  audio_sha256?: string;
  audio_bytes?: number;
}

const TOKEN = /^[A-Za-z0-9:_.\-]{1,64}$/;
const ID = /^[A-Za-z0-9_\-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const TRACE = /^[0-9a-f]{32}$/;
export const CALL_PHASES = ["connected", "consent", "ended"] as const;
export const TURN_ROLES = ["user", "agent", "system", "dtmf"] as const;

const bad = (what: string): never => {
  throw new ChannelError("INVALID", `transcript event: ${what}`);
};
const tok = (v: unknown, what: string): string =>
  typeof v === "string" && TOKEN.test(v) ? v : bad(what);
const int = (v: unknown, what: string, max = 2 ** 31): number =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max ? v : bad(what);

export function parseTranscriptEvent(b: Record<string, unknown>): TranscriptEvent {
  if (b["channel"] !== "voice") bad("channel must be voice");
  const kind = b["kind"];
  if (kind !== "call" && kind !== "turn") bad("kind must be call or turn");
  if (typeof b["call_id"] !== "string" || !ID.test(b["call_id"])) bad("call_id");
  if (typeof b["trace_id"] !== "string" || !TRACE.test(b["trace_id"])) bad("trace_id");
  const agent = b["agent"] as Record<string, unknown> | undefined;
  if (typeof agent !== "object" || agent === null) bad("agent");
  const out: TranscriptEvent = {
    kind: kind as "call" | "turn",
    channel: "voice",
    call_id: b["call_id"] as string,
    trace_id: b["trace_id"] as string,
    agent: {
      name: tok(agent?.["name"], "agent.name"),
      version: tok(agent?.["version"], "agent.version"),
    },
  };
  if (b["run_id"] !== undefined) out.run_id = tok(b["run_id"], "run_id");
  if (kind === "call") {
    const phase = b["phase"];
    if (!CALL_PHASES.includes(phase as (typeof CALL_PHASES)[number])) bad("phase");
    out.phase = phase as string;
    if (b["reason"] !== undefined && b["reason"] !== null) out.reason = tok(b["reason"], "reason");
    if (b["duration_ms"] !== undefined && b["duration_ms"] !== null)
      out.duration_ms = int(b["duration_ms"], "duration_ms");
    const d = b["detail"];
    if (d !== undefined && d !== null) {
      if (typeof d !== "object" || Array.isArray(d)) bad("detail");
      const detail: Record<string, string | number | boolean> = {};
      for (const [k, v] of Object.entries(d as Record<string, unknown>)) {
        if (v === null) continue;
        if (!/^[a-z][a-z0-9_]{0,31}$/.test(k)) bad("detail key");
        detail[k] =
          typeof v === "boolean"
            ? v
            : typeof v === "number"
              ? int(v, "detail value")
              : tok(v, "detail value");
        if (Object.keys(detail).length > 16) bad("detail size");
      }
      out.detail = detail;
    }
    return out;
  }
  const role = b["role"];
  if (!TURN_ROLES.includes(role as (typeof TURN_ROLES)[number])) bad("role");
  out.role = role as NonNullable<TranscriptEvent["role"]>;
  out.turn = int(b["turn"], "turn", 100_000);
  if (typeof b["text_sha256"] !== "string" || !HEX64.test(b["text_sha256"])) bad("text_sha256");
  out.text_sha256 = b["text_sha256"] as string;
  out.size = int(b["size"], "size", 1_000_000);
  out.redacted = b["redacted"] === true;
  out.truncated = b["truncated"] === true;
  if (b["audio_sha256"] !== undefined && b["audio_sha256"] !== null) {
    if (typeof b["audio_sha256"] !== "string" || !HEX64.test(b["audio_sha256"]))
      bad("audio_sha256");
    out.audio_sha256 = b["audio_sha256"] as string;
  }
  out.audio_bytes =
    b["audio_bytes"] === undefined ? 0 : int(b["audio_bytes"], "audio_bytes", 2 ** 40);
  return out;
}
