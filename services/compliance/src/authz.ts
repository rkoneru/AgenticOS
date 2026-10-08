import { forbidden } from "./errors.js";

/**
 * Roles are the control-plane roles. The gateway has already decided `api.compliance.*` with the authz pack; this is the service's
 * own check (defence in depth, and the only check for the dev HTTP surface).
 *   read   : everyone except billing
 *   write  : owner, admin, builder (inventory, assessment drafts, submitting, generating documents)
 *   review : owner, admin, auditor (approve / reject a submitted assessment; independence from the author is enforced separately)
 */
export const ACTION_ROLES = {
  "compliance.read": ["owner", "admin", "builder", "operator", "auditor", "viewer"],
  "compliance.write": ["owner", "admin", "builder"],
  "compliance.review": ["owner", "admin", "auditor"],
} as const;
export type ComplianceAction = keyof typeof ACTION_ROLES;

export interface ComplianceActor {
  tenantId: string;
  /** The authenticated member (or key owner). Never taken from a request body. */
  subject: string;
  role: string;
}

/** Throws `forbidden` unless the role may perform the action. Unknown roles and actions are denied. */
export function requireRole(p: ComplianceActor, action: ComplianceAction): ComplianceActor {
  const roles = (ACTION_ROLES as Record<string, readonly string[] | undefined>)[action];
  if (
    !p ||
    typeof p.tenantId !== "string" ||
    p.tenantId === "" ||
    typeof p.subject !== "string" ||
    p.subject === "" ||
    !roles ||
    !roles.includes(p.role)
  )
    throw forbidden(`role ${String(p?.role)} may not ${action}`);
  return p;
}
