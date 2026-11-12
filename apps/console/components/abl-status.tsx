"use client";
import { Badge } from "@axis/ui";
import type { AblCheckResult } from "@/lib/api";
import { ErrorNote } from "./common";

/**
 * The status row (Checking.../Valid/N errors, N warnings, risk level, name@version) plus the
 * validation-unavailable error note. Shared by `BlueprintEditor` and the Agent Studio preview
 * panel so the two surfaces render identical diagnostics summaries for the same `AblCheckResult`.
 */
export function AblStatusBar({
  checking,
  check,
  checkError,
}: {
  checking: boolean;
  check: AblCheckResult | undefined;
  checkError: string | undefined;
}) {
  const errors = check?.diagnostics.filter((d) => d.severity === "error").length ?? 0;
  const warnings = check?.diagnostics.filter((d) => d.severity === "warning").length ?? 0;
  return (
    <>
      <div
        className="flex flex-wrap items-center gap-2"
        aria-live="polite"
        data-testid="abl-status"
      >
        {checking ? (
          <Badge>Checking...</Badge>
        ) : check ? (
          check.ok ? (
            <Badge tone="good">Valid</Badge>
          ) : (
            <Badge tone="bad">
              {errors} error{errors === 1 ? "" : "s"}
            </Badge>
          )
        ) : null}
        {warnings > 0 ? (
          <Badge tone="warn">
            {warnings} warning{warnings === 1 ? "" : "s"}
          </Badge>
        ) : null}
        {check?.riskLevel ? <Badge tone="info">risk: {check.riskLevel}</Badge> : null}
        {check?.name ? (
          <span className="text-sm text-[var(--axis-muted)]">
            {check.name}@{check.version}
          </span>
        ) : null}
      </div>
      {checkError ? <ErrorNote error={new Error(checkError)} /> : null}
    </>
  );
}
