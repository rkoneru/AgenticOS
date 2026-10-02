import { useId, type ReactNode } from "react";
import { cn } from "./cn";

export interface EditorMarker {
  line: number; // 1-based
  column: number; // 1-based
  message: string;
  severity: "error" | "warning";
}

export interface CodeEditorProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  markers?: EditorMarker[];
  readOnly?: boolean;
  rows?: number;
}

/**
 * Lightweight code editor: a labelled monospace textarea with a line-number gutter
 * (lines with a diagnostic are flagged). Diagnostics are listed beneath as plain text.
 */
export function CodeEditor({
  label,
  value,
  onChange,
  markers = [],
  readOnly,
  rows = 24,
}: CodeEditorProps) {
  const id = useId();
  const lines = value.split("\n").length;
  const flagged = new Map<number, EditorMarker["severity"]>();
  for (const m of markers) {
    if (flagged.get(m.line) !== "error") flagged.set(m.line, m.severity);
  }
  const gutter: ReactNode[] = [];
  for (let n = 1; n <= lines; n++) {
    const sev = flagged.get(n);
    gutter.push(
      <div
        key={n}
        data-line={n}
        data-severity={sev}
        className={cn(
          sev === "error" && "text-[var(--axis-danger-text)] font-bold",
          sev === "warning" && "text-[var(--axis-warn-text)] font-bold",
        )}
      >
        {n}
      </div>,
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <div className="flex overflow-hidden rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] font-mono text-sm leading-6">
        <div
          aria-hidden="true"
          className="select-none bg-[var(--axis-surface-2)] px-2 text-right text-[var(--axis-muted)]"
        >
          {gutter}
        </div>
        <textarea
          id={id}
          value={value}
          readOnly={readOnly}
          spellCheck={false}
          rows={rows}
          wrap="off"
          onChange={(e) => onChange(e.target.value)}
          aria-describedby={markers.length ? `${id}-diag` : undefined}
          className="w-full resize-y overflow-auto whitespace-pre bg-transparent px-2 leading-6 text-[var(--axis-fg)] outline-none focus-visible:outline-2 focus-visible:outline-[var(--axis-focus)]"
        />
      </div>
      {markers.length ? (
        <ul id={`${id}-diag`} aria-label="Diagnostics" className="flex flex-col gap-1 text-sm">
          {markers.map((m, i) => (
            <li key={i} data-severity={m.severity}>
              <span className="font-mono">
                {m.line}:{m.column}
              </span>{" "}
              <span
                className={
                  m.severity === "error"
                    ? "text-[var(--axis-danger-text)]"
                    : "text-[var(--axis-warn-text)]"
                }
              >
                {m.severity}
              </span>
              : {m.message}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
