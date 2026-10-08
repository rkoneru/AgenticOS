import type { Role } from "./api";

/** UI-only role model for hiding controls. The server remains the authority and re-checks every call. */
export type Capability =
  | "blueprints.write"
  | "runs.start"
  | "runs.signal"
  | "approvals.decide"
  | "policies.write"
  | "policies.activate"
  | "audit.read"
  | "usage.read"
  | "admin.members"
  | "admin.keys"
  | "admin.modelkeys"
  | "admin.budgets"
  | "admin.sso"
  | "marketplace.install"
  | "killswitch.set"
  | "evals.write"
  | "evals.review";

const RANK: Record<Role, number> = {
  owner: 100,
  admin: 80,
  builder: 50,
  operator: 50,
  auditor: 40,
  billing: 40,
  viewer: 10,
};

const RULES: Record<Capability, (r: Role) => boolean> = {
  "blueprints.write": (r) => RANK[r] >= 50 && r !== "operator",
  "runs.start": (r) => RANK[r] >= 50,
  "runs.signal": (r) => RANK[r] >= 50,
  "approvals.decide": (r) => RANK[r] >= 50 || r === "auditor",
  "policies.write": (r) => RANK[r] >= 80,
  "policies.activate": (r) => RANK[r] >= 80,
  "audit.read": (r) => RANK[r] >= 40,
  "usage.read": (r) => RANK[r] >= 40,
  "admin.members": (r) => RANK[r] >= 80,
  "admin.keys": (r) => RANK[r] >= 50,
  "admin.modelkeys": (r) => RANK[r] >= 50,
  "admin.budgets": (r) => RANK[r] >= 80,
  "admin.sso": (r) => r === "owner",
  "marketplace.install": (r) => RANK[r] >= 80,
  "killswitch.set": (r) => RANK[r] >= 80,
  "evals.write": (r) => RANK[r] >= 50 && r !== "operator",
  "evals.review": (r) => RANK[r] >= 50,
};

export const can = (role: Role | undefined, cap: Capability): boolean =>
  role ? RULES[cap](role) : false;

export const ROLES: Role[] = [
  "owner",
  "admin",
  "builder",
  "operator",
  "auditor",
  "billing",
  "viewer",
];

export interface NavItem {
  href: string;
  label: string;
  show: (r: Role) => boolean;
}

export const NAV: NavItem[] = [
  { href: "/blueprints", label: "Blueprints", show: () => true },
  { href: "/runs", label: "Runs", show: () => true },
  { href: "/approvals", label: "Approvals", show: () => true },
  { href: "/policies", label: "Policies", show: () => true },
  { href: "/evals", label: "Evals", show: () => true },
  { href: "/audit", label: "Audit", show: (r) => can(r, "audit.read") },
  { href: "/usage", label: "Usage", show: (r) => can(r, "usage.read") },
  { href: "/registry", label: "Registry", show: () => true },
  { href: "/compliance", label: "Compliance", show: (r) => r !== "billing" },
  { href: "/marketplace", label: "Marketplace", show: () => true },
  { href: "/kill-switch", label: "Kill switch", show: (r) => RANK[r] >= 50 },
  { href: "/admin", label: "Admin", show: (r) => RANK[r] >= 50 },
];
