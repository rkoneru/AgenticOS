import { ROLE_RANK } from "@axis/control-plane";
import { forbidden } from "./errors.js";
import type { HubPrincipal, PlatformActor, RunnerActor, TenantActor } from "./types.js";

/**
 * Minimum control-plane role rank per action. The `reviewer` role (a hub-level role for human graders) may read and review, nothing else.
 *   read   : viewer and up, reviewers
 *   write  : builder and up (datasets, suites, starting runs)
 *   admin  : admin and up (runners, baselines, sampling, review sweeps)
 *   review : operator/builder and up, reviewers (human grading)
 */
export const ACTION_MIN_RANK = {
  "evals.read": ROLE_RANK.viewer,
  "evals.write": ROLE_RANK.builder,
  "evals.admin": ROLE_RANK.admin,
  "evals.review": ROLE_RANK.operator,
} as const;
export type HubAction = keyof typeof ACTION_MIN_RANK;

const REVIEWER_ACTIONS: readonly HubAction[] = ["evals.read", "evals.review"];

/** Throws `forbidden` unless a tenant principal's role reaches the action's minimum. Unknown roles/actions are denied. */
export function requireTenant(p: HubPrincipal, action: HubAction): TenantActor {
  if (p?.kind !== "tenant") throw forbidden("tenant credential required");
  if (p.role === "reviewer") {
    if (!REVIEWER_ACTIONS.includes(action)) throw forbidden(`role reviewer may not ${action}`);
    return p;
  }
  const need = ACTION_MIN_RANK[action];
  const have = (ROLE_RANK as Record<string, number | undefined>)[p.role];
  if (need === undefined || have === undefined || have < need)
    throw forbidden(`role ${String(p.role)} may not ${action}`);
  return p;
}

export function requireRunner(p: HubPrincipal): RunnerActor {
  if (p?.kind !== "runner" || !p.runnerId) throw forbidden("runner credential required");
  return p;
}

/** Tenant members may read; so may that tenant's runners (they poll their queue and sampling configs). */
export function requireReader(p: HubPrincipal): TenantActor | RunnerActor {
  if (p?.kind === "runner") return requireRunner(p);
  return requireTenant(p, "evals.read");
}

export function requirePlatform(p: HubPrincipal): PlatformActor {
  if (p?.kind !== "platform" || (p.service !== "registry" && p.service !== "marketplace"))
    throw forbidden("platform credential required");
  return p;
}

/** The subject recorded as the actor of an audit event. */
export function actorOf(p: HubPrincipal): { type: "human" | "system"; id: string } {
  if (p.kind === "tenant") return { type: "human", id: p.subject };
  if (p.kind === "runner") return { type: "system", id: `runner:${p.runnerId}` };
  return { type: "system", id: `${p.service}:${p.subject}` };
}
