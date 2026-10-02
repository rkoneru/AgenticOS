"use client";
import { createContext, useContext, type ReactNode } from "react";
import type { Role, Session } from "@/lib/api";
import { can, type Capability } from "@/lib/roles";

const Ctx = createContext<Session | undefined>(undefined);

export function SessionProvider({ session, children }: { session: Session; children: ReactNode }) {
  return <Ctx.Provider value={session}>{children}</Ctx.Provider>;
}

export function useSession(): Session {
  const s = useContext(Ctx);
  if (!s) throw new Error("useSession outside SessionProvider");
  return s;
}

export function useCan(cap: Capability): boolean {
  return can(useSession().member.role as Role, cap);
}

/** Renders children only when the role has the capability. UI hint only: the server still authorises. */
export function Can({
  cap,
  children,
  fallback = null,
}: {
  cap: Capability;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return useCan(cap) ? <>{children}</> : <>{fallback}</>;
}
