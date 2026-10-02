import type { ReactNode } from "react";
import { cn } from "./cn";

export type Tone = "neutral" | "good" | "warn" | "bad" | "info";

const tones: Record<Tone, string> = {
  neutral: "bg-[var(--axis-surface-2)] text-[var(--axis-fg)]",
  good: "bg-[var(--axis-good-bg)] text-[var(--axis-good-text)]",
  warn: "bg-[var(--axis-warn-bg)] text-[var(--axis-warn-text)]",
  bad: "bg-[var(--axis-danger-bg)] text-[var(--axis-danger-text)]",
  info: "bg-[var(--axis-info-bg)] text-[var(--axis-info-text)]",
};

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-[var(--axis-border)] px-2 py-0.5 text-xs font-medium",
        tones[tone],
      )}
    >
      {children}
    </span>
  );
}
