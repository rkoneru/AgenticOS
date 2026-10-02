import { readFileSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

// The REAL stack (e2e/interfaces_stack.py): `make console-e2e` boots it and exports STACK_JSON. The console is served by `next start`
// (built beforehand) and talks to the gateway and the control plane through its BFF; there is no mock in this suite.
const stack = JSON.parse(readFileSync(process.env["STACK_JSON"] ?? "stack.json", "utf8")) as {
  gateway_origin: string;
  cp: string;
  idp: string;
};
const WEB = 3100;

export default defineConfig({
  testDir: "./e2e-real",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  reporter: [["list"]],
  use: {
    baseURL: `http://localhost:${WEB}`,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: `pnpm exec next start -p ${WEB}`,
    url: `http://localhost:${WEB}/login`,
    env: {
      AXIS_API_URL: stack.gateway_origin,
      AXIS_CONTROL_PLANE_URL: stack.cp,
      AXIS_IDP_ORIGINS: stack.idp,
      AXIS_GATEWAY_BEARER: "1",
      AXIS_INSECURE_HTTP: "1",
      NEXT_TELEMETRY_DISABLED: "1",
    },
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
