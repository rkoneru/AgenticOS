import type { Metadata } from "next";
import { headers } from "next/headers";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "AXIS Console", template: "%s - AXIS Console" },
  description: "Operate governed agents: blueprints, runs, approvals, policies, audit.",
  robots: { index: false, follow: false },
};

// CSP nonces require per-request rendering (see proxy.ts).
export const dynamic = "force-dynamic";

export default async function RootLayout({ children }: { children: ReactNode }) {
  await headers();
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
