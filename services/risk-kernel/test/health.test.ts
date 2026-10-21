import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PROTO_ROOT,
  addHealthService,
  createGateServer,
  listen,
  staticTokenAuthenticator,
} from "../src/index.js";
import { harness, type Harness } from "./helpers.js";

/**
 * The standard gRPC health-checking protocol (grpc.health.v1.Health, NEEDS #507): a real client,
 * over a real socket, against a real running server — the same thing the chart's native `grpc`
 * readiness/liveness probe does, proving Check actually answers SERVING rather than merely that
 * the listener accepts a TCP connection.
 */

type HealthClient = grpc.Client & {
  Check: (
    req: { service: string },
    cb: (e: grpc.ServiceError | null, r: { status: string }) => void,
  ) => void;
  Watch: (req: { service: string }) => grpc.ClientReadableStream<{ status: string }>;
};

function loadHealthClient(port: number): HealthClient {
  const def = protoLoader.loadSync("grpc/health/v1/health.proto", {
    includeDirs: [PROTO_ROOT],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(def) as unknown as {
    grpc: {
      health: { v1: { Health: new (a: string, c: grpc.ChannelCredentials) => HealthClient } };
    };
  };
  return new pkg.grpc.health.v1.Health(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
}

let h: Harness;
let server: grpc.Server;
let client: HealthClient;

beforeAll(async () => {
  h = await harness();
  server = createGateServer({
    kernel: h.kernel,
    audit: h.audit,
    killSwitches: h.kill,
    authenticate: staticTokenAuthenticator({}),
  });
  addHealthService(server);
  const port = await listen(server, "127.0.0.1:0");
  client = loadHealthClient(port);
});

afterAll(() => {
  client.close();
  server.forceShutdown();
});

function check(service: string): Promise<{ status: string }> {
  return new Promise((resolve, reject) => {
    client.Check({ service }, (err, r) => (err ? reject(err) : resolve(r)));
  });
}

describe("grpc.health.v1.Health", () => {
  it("Check on the overall server (empty service name) returns SERVING", async () => {
    const r = await check("");
    expect(r.status).toBe("SERVING");
  });

  it("Check on a named service also returns SERVING (no per-service distinction modeled)", async () => {
    const r = await check("axis.runtime.v1.GateService");
    expect(r.status).toBe("SERVING");
  });

  it("Watch streams the current status once and stays open until cancelled", async () => {
    const call = client.Watch({ service: "" });
    const first = await new Promise<{ status: string }>((resolve, reject) => {
      call.once("data", resolve);
      call.once("error", reject);
    });
    expect(first.status).toBe("SERVING");
    call.cancel();
  });

  it("addHealthService honors a custom isServing predicate (not-serving path)", async () => {
    const s2 = createGateServer({
      kernel: h.kernel,
      audit: h.audit,
      killSwitches: h.kill,
      authenticate: staticTokenAuthenticator({}),
    });
    addHealthService(s2, (service) => service !== "degraded");
    const port = await listen(s2, "127.0.0.1:0");
    const c2 = loadHealthClient(port);
    const r = await new Promise<{ status: string }>((resolve, reject) => {
      c2.Check({ service: "degraded" }, (err, resp) => (err ? reject(err) : resolve(resp)));
    });
    expect(r.status).toBe("NOT_SERVING");
    c2.close();
    s2.forceShutdown();
  });
});
