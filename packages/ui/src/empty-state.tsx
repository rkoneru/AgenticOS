import type { ReactNode } from "react";

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-md border border-dashed border-[var(--axis-border)] p-8 text-center">
      <h2 className="text-base font-semibold">{title}</h2>
      {description ? (
        <p className="max-w-prose text-sm text-[var(--axis-muted)]">{description}</p>
      ) : null}
      {action}
    </div>
  );
}
