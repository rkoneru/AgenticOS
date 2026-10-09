// k6: SSE fan-out. Many subscribers read ONE run's event stream (the run must exist and be waiting, see perf/src/scenarios.ts sseFanOut for the
// driver that also approves it). Usage: k6 run -e BASE_URL=... -e API_KEY=... -e RUN_ID=... -e VUS=100 perf/k6/sse.js
import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: Number(__ENV.VUS || 50),
  duration: __ENV.DURATION || "20s",
  thresholds: { checks: ["rate>0.99"] },
};

export default function () {
  const r = http.get(`${__ENV.BASE_URL}/runs/${__ENV.RUN_ID}/events`, {
    headers: { authorization: `Bearer ${__ENV.API_KEY}`, accept: "text/event-stream" },
    timeout: "30s",
  });
  check(r, {
    "stream 200": (x) => x.status === 200,
    "has events": (x) => x.body && x.body.includes("data:"),
  });
}
