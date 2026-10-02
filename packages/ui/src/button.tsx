import type { ButtonHTMLAttributes } from "react";
import { cn } from "./cn";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

const variants: Record<ButtonVariant, string> = {
  primary: "bg-[var(--axis-accent)] text-[var(--axis-accent-fg)] hover:opacity-90",
  secondary:
    "bg-[var(--axis-surface-2)] text-[var(--axis-fg)] border border-[var(--axis-border)] hover:bg-[var(--axis-surface-3)]",
  danger: "bg-[var(--axis-danger)] text-white hover:opacity-90",
  ghost: "bg-transparent text-[var(--axis-fg)] hover:bg-[var(--axis-surface-2)]",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  loading?: boolean;
}

export function Button({
  variant = "primary",
  loading = false,
  disabled,
  className,
  children,
  type = "button",
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        "inline-flex min-h-9 items-center justify-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--axis-focus)] disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        className,
      )}
      {...rest}
    >
      {loading ? <span aria-hidden="true">...</span> : null}
      {children}
    </button>
  );
}
