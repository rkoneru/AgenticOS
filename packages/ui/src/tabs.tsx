import * as RT from "@radix-ui/react-tabs";
import type { ReactNode } from "react";

export interface TabItem {
  value: string;
  label: string;
  content: ReactNode;
}

export function Tabs({
  items,
  defaultValue,
  label,
}: {
  items: TabItem[];
  defaultValue?: string;
  label: string;
}) {
  const first = items[0]?.value;
  return (
    <RT.Root defaultValue={defaultValue ?? first}>
      <RT.List aria-label={label} className="flex gap-1 border-b border-[var(--axis-border)]">
        {items.map((i) => (
          <RT.Trigger
            key={i.value}
            value={i.value}
            className="px-3 py-2 text-sm data-[state=active]:border-b-2 data-[state=active]:border-[var(--axis-accent)] data-[state=active]:font-semibold focus-visible:outline-2 focus-visible:outline-[var(--axis-focus)]"
          >
            {i.label}
          </RT.Trigger>
        ))}
      </RT.List>
      {items.map((i) => (
        <RT.Content key={i.value} value={i.value} className="pt-4">
          {i.content}
        </RT.Content>
      ))}
    </RT.Root>
  );
}
