"use client";
import { useEffect, useRef, useState } from "react";
import { api, type AblCheckResult } from "./api";

const DEBOUNCE_MS = 300;

export interface AblCheckState {
  check: AblCheckResult | undefined;
  checking: boolean;
  checkError: string | undefined;
}

/**
 * Debounced live ABL validation against `api.validateAbl` (the real `@axis/abl` compiler/linter,
 * reached through `/api/abl/validate`). Shared by `BlueprintEditor` and the Agent Studio preview
 * panel so both editing surfaces run the exact same validation pipeline.
 */
export function useAblCheck(text: string): AblCheckState {
  const [check, setCheck] = useState<AblCheckResult | undefined>();
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | undefined>();
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

  return { check, checking, checkError };
}
