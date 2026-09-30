import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface Transition {
  from: string;
  to: string;
  on: string;
}
export interface ProcessModel {
  version: number;
  pid: { regex: string };
  states: string[];
  initial: string;
  terminal: string[];
  transitions: Transition[];
  signals: Record<string, { graceful: boolean }>;
}

export const processModel: ProcessModel = JSON.parse(
  readFileSync(fileURLToPath(new URL("../process-model.json", import.meta.url)), "utf8"),
);

const PID_RE = new RegExp(processModel.pid.regex);
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function isPid(value: unknown): value is string {
  return typeof value === "string" && PID_RE.test(value);
}

/** Generate a PID: `axp_` + ULID (48-bit ms timestamp + 80 random bits, Crockford base32). */
export function newPid(nowMs: number = Date.now(), rand: Buffer = randomBytes(10)): string {
  let ts = "";
  let t = nowMs;
  for (let i = 0; i < 10; i++) {
    ts = CROCKFORD[t % 32] + ts;
    t = Math.floor(t / 32);
  }
  let bits = 0n;
  for (const b of rand) bits = (bits << 8n) | BigInt(b);
  let r = "";
  for (let i = 0; i < 16; i++) {
    r = CROCKFORD[Number(bits & 31n)] + r;
    bits >>= 5n;
  }
  return `axp_${ts}${r}`;
}

/** Returns the next state, or undefined when the transition is illegal. */
export function nextState(state: string, event: string): string | undefined {
  return processModel.transitions.find((t) => t.from === state && t.on === event)?.to;
}

export function isTerminal(state: string): boolean {
  return processModel.terminal.includes(state);
}
