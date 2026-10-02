"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { Button, EmptyState, ErrorBoundary, ToastProvider } from "@axis/ui";
import { api } from "@/lib/api";
import { useResource } from "@/lib/hooks";
import { NAV } from "@/lib/roles";
import { features } from "@/lib/features";
import { SessionProvider } from "./session";

function ThemeToggle() {
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system");
  useEffect(() => {
    try {
      const t = localStorage.getItem("axis-theme");
      if (t === "light" || t === "dark") setTheme(t);
    } catch {
      /* storage blocked: keep system */
    }
  }, []);
  useEffect(() => {
    const el = document.documentElement;
    if (theme === "system") el.removeAttribute("data-theme");
    else el.setAttribute("data-theme", theme);
    try {
      if (theme === "system") localStorage.removeItem("axis-theme");
      else localStorage.setItem("axis-theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  const next = theme === "dark" ? "light" : theme === "light" ? "system" : "dark";
  return (
    <Button
      variant="ghost"
      onClick={() => setTheme(next)}
      aria-label={`Theme: ${theme}. Switch to ${next}`}
    >
      Theme: {theme}
    </Button>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const session = useResource(() => api.session());
  const [navOpen, setNavOpen] = useState(false);
  useEffect(() => setNavOpen(false), [pathname]);

  if (session.loading)
    return (
      <p role="status" className="p-6">
        Loading session...
      </p>
    );
  if (session.error || !session.data) {
    return (
      <div className="p-6">
        <EmptyState
          title="Could not load your session"
          description={session.error?.message ?? "Sign in again to continue."}
          action={<a href="/login">Sign in</a>}
        />
      </div>
    );
  }
  const s = session.data;
  const items = NAV.filter((n) => n.show(s.member.role)).filter((n) =>
    n.href === "/marketplace" ? features.marketplace : true,
  );
  return (
    <SessionProvider session={s}>
      <ToastProvider>
        <a href="#main" className="skip-link">
          Skip to content
        </a>
        <div className="flex min-h-screen flex-col md:flex-row">
          <header className="flex items-center justify-between gap-2 border-b border-[var(--axis-border)] p-3 md:hidden">
            <strong>AXIS</strong>
            <Button
              variant="secondary"
              aria-expanded={navOpen}
              aria-controls="primary-nav"
              onClick={() => setNavOpen((o) => !o)}
            >
              Menu
            </Button>
          </header>
          <nav
            id="primary-nav"
            aria-label="Primary"
            className={`${navOpen ? "flex" : "hidden"} flex-col gap-1 border-b border-[var(--axis-border)] bg-[var(--axis-surface)] p-3 md:flex md:w-56 md:shrink-0 md:border-b-0 md:border-r`}
          >
            <strong className="hidden px-2 py-1 md:block">AXIS</strong>
            {items.map((n) => {
              const active = pathname === n.href || pathname.startsWith(`${n.href}/`);
              return (
                <Link
                  key={n.href}
                  href={n.href}
                  aria-current={active ? "page" : undefined}
                  className={`rounded-md px-2 py-1.5 text-[var(--axis-fg)] no-underline ${active ? "bg-[var(--axis-surface-3)] font-semibold" : "hover:bg-[var(--axis-surface-2)]"}`}
                >
                  {n.label}
                </Link>
              );
            })}
            <div className="mt-auto flex flex-col gap-2 pt-4 text-xs text-[var(--axis-muted)]">
              <span>
                {s.member.email} ({s.member.role})
              </span>
              <span>
                {s.tenant.name} / {s.tenant.region}
              </span>
              <ThemeToggle />
              <form
                method="post"
                action="/api/axis/auth/logout"
                onSubmit={(e) => {
                  e.preventDefault();
                  void api.logout().finally(() => window.location.assign("/login"));
                }}
              >
                <Button type="submit" variant="secondary">
                  Sign out
                </Button>
              </form>
            </div>
          </nav>
          <main id="main" tabIndex={-1} className="min-w-0 flex-1 p-4 md:p-6">
            <ErrorBoundary>{children}</ErrorBoundary>
          </main>
        </div>
      </ToastProvider>
    </SessionProvider>
  );
}
