import { ssoDefaultOrg, ssoStartUrl, features } from "@/lib/features";
import { safeReturnTo } from "@/lib/security";

export const metadata = { title: "Sign in" };

const ROLES = ["owner", "admin", "builder", "operator", "auditor", "billing", "viewer"];

export default async function Login({
  searchParams,
}: {
  searchParams: Promise<{ return_to?: string; error?: string }>;
}) {
  const sp = await searchParams;
  const returnTo = safeReturnTo(sp.return_to);
  return (
    <main
      id="main"
      className="mx-auto flex min-h-screen max-w-md flex-col justify-center gap-4 p-6"
    >
      <h1 className="text-2xl font-semibold">Sign in to AXIS</h1>
      {sp.error ? (
        <p role="alert" className="rounded-md border border-[var(--axis-danger)] p-3 text-sm">
          Sign-in failed. Try again or contact your administrator.
        </p>
      ) : null}
      <form method="get" action={ssoStartUrl} className="flex flex-col gap-3">
        <label htmlFor="org" className="text-sm font-medium">
          Organization
        </label>
        <input
          id="org"
          name="org"
          required
          defaultValue={ssoDefaultOrg}
          autoComplete="organization"
          className="rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] px-3 py-2"
        />
        {features.devLogin ? (
          <>
            <label htmlFor="role" className="text-sm font-medium">
              Dev IdP: sign in as role
            </label>
            <select
              id="role"
              name="role"
              defaultValue="admin"
              className="rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] px-3 py-2"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </>
        ) : null}
        <input type="hidden" name="return_to" value={returnTo} />
        <button
          type="submit"
          className="min-h-9 rounded-md bg-[var(--axis-accent)] px-3 py-2 font-medium text-[var(--axis-accent-fg)]"
        >
          Continue with SSO
        </button>
      </form>
    </main>
  );
}
