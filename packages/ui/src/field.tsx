import {
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { cn } from "./cn";

const control =
  "w-full rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] px-3 py-1.5 text-sm text-[var(--axis-fg)] focus-visible:outline-2 focus-visible:outline-[var(--axis-focus)] disabled:opacity-60 aria-[invalid=true]:border-[var(--axis-danger)]";

interface FieldCommon {
  label: string;
  hint?: string;
  error?: string | undefined;
}

function FieldShell({
  id,
  label,
  hint,
  error,
  children,
}: FieldCommon & { id: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      {children}
      {hint ? (
        <p id={`${id}-hint`} className="text-xs text-[var(--axis-muted)]">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${id}-err`} role="alert" className="text-xs text-[var(--axis-danger-text)]">
          {error}
        </p>
      ) : null}
    </div>
  );
}

const describedBy = (id: string, hint?: string, error?: string) =>
  [hint ? `${id}-hint` : "", error ? `${id}-err` : ""].filter(Boolean).join(" ") || undefined;

export function Input({
  label,
  hint,
  error,
  className,
  ...rest
}: FieldCommon & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  return (
    <FieldShell id={id} label={label} hint={hint} error={error}>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(id, hint, error)}
        className={cn(control, className)}
        {...rest}
      />
    </FieldShell>
  );
}

export function Textarea({
  label,
  hint,
  error,
  className,
  ...rest
}: FieldCommon & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const id = useId();
  return (
    <FieldShell id={id} label={label} hint={hint} error={error}>
      <textarea
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(id, hint, error)}
        className={cn(control, className)}
        {...rest}
      />
    </FieldShell>
  );
}

export interface SelectOption {
  value: string;
  label: string;
}

export function Select({
  label,
  hint,
  error,
  options,
  className,
  ...rest
}: FieldCommon & { options: SelectOption[] } & SelectHTMLAttributes<HTMLSelectElement>) {
  const id = useId();
  return (
    <FieldShell id={id} label={label} hint={hint} error={error}>
      <select
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(id, hint, error)}
        className={cn(control, className)}
        {...rest}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </FieldShell>
  );
}
