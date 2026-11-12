"use client";
import { useId, useState } from "react";
import { Button, Input } from "@axis/ui";

/**
 * A keyboard-operable editor for a `string[]` field (approver roles, knowledge bases, policy
 * packs): an "Add" input plus a list of entries each with Up/Down/Remove buttons. This is the
 * fallback the brief asks for in place of drag-to-reorder, which has no keyboard equivalent.
 */
export function ListEditor({
  label,
  hint,
  items,
  onChange,
  addLabel = "Add",
  placeholder,
}: {
  label: string;
  hint?: string;
  items: string[];
  onChange: (next: string[]) => void;
  addLabel?: string;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState("");
  const id = useId();

  function add() {
    const v = draft.trim();
    if (!v) return;
    onChange([...items, v]);
    setDraft("");
  }

  return (
    <div className="flex flex-col gap-1">
      <span className="text-sm font-medium" id={`${id}-label`}>
        {label}
      </span>
      {hint ? <p className="text-xs text-[var(--axis-muted)]">{hint}</p> : null}
      <ul aria-labelledby={`${id}-label`} className="flex flex-col gap-1">
        {items.map((v, i) => (
          <li key={`${v}-${i}`} className="flex items-center gap-1">
            <span className="flex-1 truncate rounded border border-[var(--axis-border)] bg-[var(--axis-surface-2)] px-2 py-1 font-mono text-xs">
              {v}
            </span>
            <Button
              type="button"
              variant="ghost"
              aria-label={`Move ${v} up`}
              disabled={i === 0}
              onClick={() => {
                const next = [...items];
                [next[i - 1], next[i]] = [next[i] as string, next[i - 1] as string];
                onChange(next);
              }}
            >
              Up
            </Button>
            <Button
              type="button"
              variant="ghost"
              aria-label={`Move ${v} down`}
              disabled={i === items.length - 1}
              onClick={() => {
                const next = [...items];
                [next[i], next[i + 1]] = [next[i + 1] as string, next[i] as string];
                onChange(next);
              }}
            >
              Down
            </Button>
            <Button
              type="button"
              variant="ghost"
              aria-label={`Remove ${v}`}
              onClick={() => onChange(items.filter((_, j) => j !== i))}
            >
              Remove
            </Button>
          </li>
        ))}
      </ul>
      <form
        className="flex items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
      >
        <div className="flex-1">
          <Input
            label={addLabel}
            value={draft}
            placeholder={placeholder}
            onChange={(e) => setDraft(e.target.value)}
          />
        </div>
        <Button type="submit" variant="secondary">
          {addLabel}
        </Button>
      </form>
    </div>
  );
}
