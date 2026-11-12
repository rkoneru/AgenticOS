"use client";
import { useState } from "react";
import { Button, CodeEditor, useToast } from "@axis/ui";
import { ApiError, api } from "@/lib/api";
import { useAction } from "@/lib/hooks";
import { useAblCheck } from "@/lib/use-abl-check";
import { useCan } from "./session";
import { AblStatusBar } from "./abl-status";

export function BlueprintEditor({
  initial,
  onPublished,
}: {
  initial: string;
  onPublished?: (name: string, version: string) => void;
}) {
  const [text, setText] = useState(initial);
  const { check, checking, checkError } = useAblCheck(text);
  const canWrite = useCan("blueprints.write");
  const toast = useToast();

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

  const serverErrors = publish.error instanceof ApiError ? publish.error.errors : [];

  return (
    <div className="flex flex-col gap-3">
      <AblStatusBar checking={checking} check={check} checkError={checkError} />
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
