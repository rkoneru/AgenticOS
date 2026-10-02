import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { cn } from "./cn";

export interface ToastItem {
  id: number;
  message: string;
  tone: "info" | "error" | "success";
}

interface ToastApi {
  push: (message: string, tone?: ToastItem["tone"]) => void;
}

const Ctx = createContext<ToastApi>({ push: () => undefined });

/** Toasts are announced politely (errors assertively) through live regions. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push = useCallback((message: string, tone: ToastItem["tone"] = "info") => {
    setItems((cur) => [...cur.slice(-4), { id: Date.now() + Math.random(), message, tone }]);
  }, []);
  const dismiss = (id: number) => setItems((cur) => cur.filter((t) => t.id !== id));
  const api = useMemo(() => ({ push }), [push]);
  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex max-w-[calc(100vw-2rem)] flex-col gap-2">
        {items.map((t) => (
          <div
            key={t.id}
            role={t.tone === "error" ? "alert" : "status"}
            className={cn(
              "flex items-start gap-3 rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] px-3 py-2 text-sm shadow-lg",
              t.tone === "error" && "border-[var(--axis-danger)]",
            )}
          >
            <span>{t.message}</span>
            <button
              type="button"
              aria-label="Dismiss notification"
              className="ml-auto text-[var(--axis-muted)]"
              onClick={() => dismiss(t.id)}
            >
              x
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export const useToast = (): ToastApi => useContext(Ctx);
