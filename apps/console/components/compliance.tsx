"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Badge, type Tone } from "@axis/ui";

const TABS = [
  { href: "/compliance", label: "AI system inventory" },
  { href: "/compliance/assessments", label: "Impact assessments" },
  { href: "/compliance/documents", label: "Technical documentation" },
];

export function ComplianceNav() {
  const path = usePathname();
  return (
    <nav aria-label="Compliance sections" className="mb-4 flex flex-wrap gap-1 text-sm">
      {TABS.map((t) => {
        const active = t.href === "/compliance" ? path === "/compliance" : path.startsWith(t.href);
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

/** The wording rule of docs/compliance: these are records and evidence, never a statement that anything is certified or compliant. */
export function EvidenceNote() {
  return (
    <p className="mb-4 max-w-3xl text-sm text-[var(--axis-muted)]" data-testid="evidence-note">
      These pages are read-only records and evidence, designed for and evidence-ready toward ISO/IEC
      42001 and the EU AI Act. They are not a certification and not a statement that any system
      meets a standard. Create and change records with the CLI or an SDK.
    </p>
  );
}

export const riskTone = (r: string): Tone =>
  r === "high" || r === "critical" ? "bad" : r === "limited" || r === "medium" ? "warn" : "good";

export const stateTone = (s: string): Tone =>
  s === "approved" ? "good" : s === "rejected" ? "bad" : s === "in_review" ? "info" : "neutral";

export const sectionTone = (s: string): Tone =>
  s === "complete" || s === "evidenced" ? "good" : s === "partial" ? "warn" : "bad";

export function StatusBadge({ tone, children }: { tone: Tone; children: string }) {
  return <Badge tone={tone}>{children}</Badge>;
}
