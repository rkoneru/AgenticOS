import type { ReactNode } from "react";
import { cn } from "./cn";

export interface TimelineItem {
  id: string;
  title: string;
  at?: string;
  detail?: ReactNode;
  tone?: "neutral" | "good" | "bad" | "warn";
}

export function Timeline({
  items,
  label,
  activeId,
}: {
  items: TimelineItem[];
  label: string;
  activeId?: string | undefined;
}) {
  return (
    <ol
      aria-label={label}
      className="flex flex-col gap-2 border-l border-[var(--axis-border)] pl-4"
    >
      {items.map((i) => (
        <li
          key={i.id}
          aria-current={i.id === activeId ? "step" : undefined}
          className={cn("relative text-sm", i.id === activeId && "font-semibold")}
        >
          <span
            aria-hidden="true"
            className={cn(
              "absolute -left-[1.4rem] top-1.5 h-2 w-2 rounded-full",
              i.tone === "bad"
                ? "bg-[var(--axis-danger)]"
                : i.tone === "good"
                  ? "bg-[var(--axis-good)]"
                  : i.tone === "warn"
                    ? "bg-[var(--axis-warn)]"
                    : "bg-[var(--axis-muted)]",
            )}
          />
          <div className="flex flex-wrap items-baseline gap-2">
            <span>{i.title}</span>
            {i.at ? <time className="text-xs text-[var(--axis-muted)]">{i.at}</time> : null}
          </div>
          {i.detail ? <div className="text-[var(--axis-muted)]">{i.detail}</div> : null}
        </li>
      ))}
    </ol>
  );
}
