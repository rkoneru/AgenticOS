// k6 scenarios for the HTTP gateway. Run by `make loadtest` (via perf/src/cli.ts --k6) or by hand:
//   k6 run -e BASE_URL=http://127.0.0.1:PORT/v1 -e API_KEY=... -e REG_REF=ns/helper-agent@^1 perf/k6/gateway.js
// Open model: constant-arrival-rate executors (the arrival rate does not depend on response times), so latencies are not coordinated-omission
// biased. Thresholds are the proposed NFR targets of docs/nfr.md; k6 exits non-zero when one is crossed.
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE_URL;
const KEY = __ENV.API_KEY;
const REF = __ENV.REG_REF || "";
const RATE = Number(__ENV.RATE || 100);
const DURATION = __ENV.DURATION || "20s";
const H = { headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" } };

const arrival = (exec, rate) => ({
  executor: "constant-arrival-rate",
  exec,
  rate,
  timeUnit: "1s",
  duration: DURATION,
  preAllocatedVUs: 50,
  maxVUs: 500,
});

export const options = {
  scenarios: {
    auth_me: arrival("me", RATE),
    audit_list: arrival("auditList", Math.max(1, Math.floor(RATE / 5))),
    audit_verify: arrival("auditVerify", Math.max(1, Math.floor(RATE / 50))),
    registry_resolve: arrival("registryResolve", Math.max(1, Math.floor(RATE / 5))),
    run_start: arrival("runStart", Math.max(1, Math.floor(RATE / 15))),
  },
  thresholds: {
    "http_req_duration{scenario:auth_me}": ["p(99)<200"],
    "http_req_duration{scenario:audit_list}": ["p(99)<200"],
    "http_req_duration{scenario:registry_resolve}": ["p(99)<200"],
    "http_req_duration{scenario:run_start}": ["p(99)<200"],
    http_req_failed: ["rate<0.01"],
  },
};

export function me() {
  check(http.get(`${BASE}/me`, H), { 200: (r) => r.status === 200 });
}
export function auditList() {
  check(http.get(`${BASE}/audit/events?limit=50`, H), { 200: (r) => r.status === 200 });
}
export function auditVerify() {
  check(http.post(`${BASE}/audit/verify`, "{}", H), { 200: (r) => r.status === 200 });
}
export function registryResolve() {
  check(http.get(`${BASE}/registry/resolve?ref=${encodeURIComponent(REF)}`, H), {
    200: (r) => r.status === 200,
  });
}
export function runStart() {
  const body = JSON.stringify({
    blueprint: { name: "claims-agent", version: "1.0.0" },
    input: { prompt: `hello ${__ITER}` },
  });
  check(http.post(`${BASE}/runs`, body, H), { 202: (r) => r.status === 202 });
}
