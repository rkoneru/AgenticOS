// k6: gRPC GateService.Evaluate (the Risk Kernel). Usage (from the repo root so the proto path resolves):
//   k6 run -e KERNEL=127.0.0.1:PORT -e TENANT_ID=... -e KERNEL_TOKEN=... perf/k6/gate-grpc.js
import grpc from "k6/net/grpc";
import { check } from "k6";

const client = new grpc.Client();
client.load(["proto"], "axis/runtime/v1/gate.proto");

export const options = {
  scenarios: {
    gate: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.RATE || 200),
      timeUnit: "1s",
      duration: __ENV.DURATION || "20s",
      preAllocatedVUs: 50,
      maxVUs: 400,
    },
  },
  thresholds: { grpc_req_duration: ["p(99)<25"], checks: ["rate>0.999"] },
};

const hex = (n) =>
  Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join("");

export default function () {
  if (__ITER === 0) client.connect(__ENV.KERNEL, { plaintext: true });
  const req = {
    tenant_id: __ENV.TENANT_ID,
    trace: { trace_id: hex(32), span_id: hex(16) },
    actor: { type: "TYPE_AGENT", id: "k6", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    blueprint: { name: "claims-agent", version: "1.0.0" },
    enforcement_point: "ENFORCEMENT_POINT_TOOL_CALL",
    action: "lookup-claim",
    context: {
      tool: { name: "lookup-claim", kind: "function", side_effects: "read" },
      args: { claim_id: "c-1" },
    },
  };
  const res = client.invoke("axis.runtime.v1.GateService/Evaluate", req, {
    metadata: { authorization: `Bearer ${__ENV.KERNEL_TOKEN}` },
  });
  check(res, {
    ok: (r) => r && r.status === grpc.StatusOK,
    allow: (r) => r && r.message && r.message.decision === "DECISION_ALLOW",
  });
}
