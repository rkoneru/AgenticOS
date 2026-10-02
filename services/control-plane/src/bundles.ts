import { opaBuildWasm } from "@axis/policy";
import { randomBytes } from "node:crypto";
import { mkdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { CpError } from "./errors.js";
import type { PolicyPackService } from "./policies.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface PublishedBundle {
  /** An `opa build -t wasm` bundle (.tar.gz), the format the Risk Kernel loads. */
  tarGz: Uint8Array;
  policyVersion: string;
  packs: string[];
}

/** Where a tenant's compiled policy goes so a Risk Kernel can load it. Production: an object store + a signed manifest (NEEDS). */
export interface BundleSink {
  put(tenantId: string, bundle: PublishedBundle): Promise<void>;
}

/**
 * DEV mechanism (NOT production): one `<tenant uuid>.tar.gz` per tenant in a directory the kernel's dev process reads
 * (`AXIS_POLICY_BUNDLE_DIR`). Written atomically (temp file + rename) so the kernel never reads a half-written bundle.
 */
export class FileBundleSink implements BundleSink {
  constructor(private readonly dir: string) {}

  async put(tenantId: string, bundle: PublishedBundle): Promise<void> {
    if (!UUID.test(tenantId)) throw new CpError("invalid", "bad tenant id");
    await mkdir(this.dir, { recursive: true });
    const tmp = join(this.dir, `.${tenantId}.${randomBytes(6).toString("hex")}.tmp`);
    await writeFile(tmp, bundle.tarGz, { mode: 0o600 });
    await rename(tmp, join(this.dir, `${tenantId.toLowerCase()}.tar.gz`));
  }
}

/**
 * Publishes what a tenant's ACTIVE policy packs compile to (`PolicyPackService.effective`, which re-validates the whole set)
 * to a `BundleSink`. Called after signup (the baseline-deny floor) and after every activation or deactivation. A failure is
 * `unavailable`: the activation itself is already committed and audited, the kernel keeps the bundle it has (documented
 * staleness window, NEEDS), and a retry of the same activation republishes.
 */
export class PolicyBundlePublisher {
  private readonly build: (rego: string) => Uint8Array;
  constructor(
    private readonly o: {
      policies: PolicyPackService;
      sink: BundleSink;
      build?: (rego: string) => Uint8Array;
    },
  ) {
    this.build = o.build ?? opaBuildWasm;
  }

  async publish(tenantId: string): Promise<{ policyVersion: string; packs: string[] }> {
    try {
      const eff = await this.o.policies.effective(tenantId);
      await this.o.sink.put(tenantId, {
        tarGz: this.build(eff.rego),
        policyVersion: eff.policyVersion,
        packs: eff.packs,
      });
      return { policyVersion: eff.policyVersion, packs: eff.packs };
    } catch (err) {
      if (err instanceof CpError && err.code !== "invalid") throw err;
      throw new CpError("unavailable", "policy bundle could not be published");
    }
  }
}
