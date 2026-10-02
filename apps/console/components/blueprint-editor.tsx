"use client";
import { useEffect, useRef, useState } from "react";
import { Badge, Button, CodeEditor, useToast } from "@axis/ui";
import { ApiError, api, type AblCheckResult } from "@/lib/api";
import { useAction } from "@/lib/hooks";
import { useCan } from "./session";
import { ErrorNote } from "./common";

const DEBOUNCE_MS = 300;

export function BlueprintEditor({
  initial,
  onPublished,
}: {
  initial: string;
  onPublished?: (name: string, version: string) => void;
}) {
  const [text, setText] = useState(initial);
  const [check, setCheck] = useState<AblCheckResult | undefined>();
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | undefined>();
  const canWrite = useCan("blueprints.write");
  const toast = useToast();
  const seq = useRef(0);

  useEffect(() => {
    const mine = ++seq.current;
    const ac = new AbortController();
    setChecking(true);
    const t = setTimeout(() => {
      api.validateAbl(text, ac.signal).then(
        (r) => {
          if (mine !== seq.current) return;
          setCheck(r);
          setCheckError(undefined);
          setChecking(false);
        },
        (e: unknown) => {
          if (mine !== seq.current || ac.signal.aborted) return;
          setCheckError(e instanceof Error ? e.message : "Validation unavailable");
          setChecking(false);
        },
      );
    }, DEBOUNCE_MS);
    return () => {
      clearTimeout(t);
      ac.abort();
    };
  }, [text]);

  const publish = useAction(async () => {
    if (!check?.ok || !check.doc) throw new Error("Fix the errors first");
    return api.publishBlueprint(check.doc);
  });

  async function onPublish() {
    const v = await publish.run();
    if (v) {
      toast.push(`Published ${v.name}@${v.version}`, "success");
      onPublished?.(v.name, v.version);
    }
  }

  const errors = check?.diagnostics.filter((d) => d.severity === "error").length ?? 0;
  const warnings = check?.diagnostics.filter((d) => d.severity === "warning").length ?? 0;
  const serverErrors = publish.error instanceof ApiError ? publish.error.errors : [];

  return (
    <div className="flex flex-col gap-3">
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
      <CodeEditor
        label="ABL (YAML)"
        value={text}
        onChange={setText}
        markers={check?.diagnostics ?? []}
        rows={26}
      />
      {publish.error ? (
        <div role="alert" className="rounded-md border border-[var(--axis-danger)] p-3 text-sm">
          <p>{publish.error.message}</p>
          {serverErrors.length ? (
            <ul className="ml-5 list-disc">
              {serverErrors.map((e, i) => (
                <li key={i}>
                  {e.path}: {e.message}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
      <div className="flex gap-2">
        {canWrite ? (
          <Button onClick={onPublish} disabled={!check?.ok || checking} loading={publish.pending}>
            Publish version
          </Button>
        ) : (
          <p className="text-sm text-[var(--axis-muted)]">Your role cannot publish blueprints.</p>
        )}
      </div>
    </div>
  );
}
