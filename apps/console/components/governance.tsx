"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Badge, type Tone } from "@axis/ui";

const TABS = [
  { href: "/governance", label: "Data-subject requests" },
  { href: "/governance/holds", label: "Legal holds" },
  { href: "/governance/retention", label: "Retention and residency" },
];

export function GovernanceNav() {
  const path = usePathname();
  return (
    <nav aria-label="Governance sections" className="mb-4 flex flex-wrap gap-1 text-sm">
      {TABS.map((t) => {
        const active =
          t.href === "/governance"
            ? path === "/governance" || path.startsWith("/governance/requests")
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

/** The wording rule of docs/compliance: engineering for data-protection duties, never a statement that anything is compliant. */
export function GovernanceNote() {
  return (
    <p className="mb-4 max-w-3xl text-sm text-[var(--axis-muted)]" data-testid="governance-note">
      These pages are read-only. They show the state of data-subject requests, legal holds and
      retention; identifiers are never displayed. Requests, holds and purges are made by the
      tenant&apos;s privacy officer with the CLI or an SDK. This is evidence-ready engineering, not
      a statement that any law or standard is met.
    </p>
  );
}

export const requestTone = (s: string): Tone =>
  s === "completed"
    ? "good"
    : s === "rejected" || s === "cancelled"
      ? "neutral"
      : s === "processing" || s === "verified"
        ? "info"
        : "warn";

export const runStatusTone = (s: string): Tone =>
  s === "purged"
    ? "good"
    : s === "error" || s === "settings_unavailable"
      ? "bad"
      : s === "skipped_hold"
        ? "warn"
        : "neutral";

/** Open requests past their due date. Computed in the browser from the server's `due_at`. */
export const isOverdue = (r: { status: string; due_at: string }, now = Date.now()): boolean =>
  !["completed", "rejected", "cancelled"].includes(r.status) && Date.parse(r.due_at) < now;

export function StatusBadge({ tone, children }: { tone: Tone; children: string }) {
  return <Badge tone={tone}>{children}</Badge>;
}
