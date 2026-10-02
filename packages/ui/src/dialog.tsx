import * as RD from "@radix-ui/react-dialog";
import type { ReactNode } from "react";

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children?: ReactNode;
  footer?: ReactNode;
}

/** Modal dialog with focus trap, Escape to close, and labelled title/description (Radix). */
export function Dialog({ open, onOpenChange, title, description, children, footer }: DialogProps) {
  return (
    <RD.Root open={open} onOpenChange={onOpenChange}>
      <RD.Portal>
        <RD.Overlay className="fixed inset-0 bg-black/50" />
        <RD.Content
          className="fixed left-1/2 top-1/2 w-[min(32rem,calc(100vw-2rem))] max-h-[90vh] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-[var(--axis-border)] bg-[var(--axis-surface)] p-5 text-[var(--axis-fg)] shadow-xl"
          {...(description ? {} : { "aria-describedby": undefined })}
        >
          <RD.Title className="text-lg font-semibold">{title}</RD.Title>
          {description ? (
            <RD.Description className="mt-1 text-sm text-[var(--axis-muted)]">
              {description}
            </RD.Description>
          ) : null}
          <div className="mt-4">{children}</div>
          {footer ? <div className="mt-5 flex justify-end gap-2">{footer}</div> : null}
        </RD.Content>
      </RD.Portal>
    </RD.Root>
  );
}
