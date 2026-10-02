import { cn } from "./cn";
import { diffLines } from "./diff";

const sign = { same: " ", add: "+", del: "-" } as const;

/** Line diff. Text is rendered as React text nodes; markers are also conveyed in words for screen readers. */
export function DiffView({
  before,
  after,
  label,
}: {
  before: string;
  after: string;
  label: string;
}) {
  const ops = diffLines(before, after);
  const changed = ops.some((o) => o.kind !== "same");
  return (
    <figure
      aria-label={label}
      className="overflow-x-auto rounded-md border border-[var(--axis-border)] font-mono text-xs"
    >
      {!changed ? <p className="p-3 text-[var(--axis-muted)]">No differences.</p> : null}
      <pre className="m-0 p-0">
        {ops.map((o, i) => (
          <div
            key={i}
            data-kind={o.kind}
            className={cn(
              "px-3 whitespace-pre",
              o.kind === "add" && "bg-[var(--axis-good-bg)] text-[var(--axis-good-text)]",
              o.kind === "del" && "bg-[var(--axis-danger-bg)] text-[var(--axis-danger-text)]",
            )}
          >
            <span aria-hidden="true">{sign[o.kind]} </span>
            {o.kind !== "same" ? (
              <span className="sr-only">{o.kind === "add" ? "added: " : "removed: "}</span>
            ) : null}
            {o.text}
          </div>
        ))}
      </pre>
    </figure>
  );
}
