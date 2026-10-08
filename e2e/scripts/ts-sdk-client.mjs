// The TypeScript SDK as a command for the interfaces e2e: node ts-sdk-client.mjs <op> '<json args>'  (AXIS_API_KEY / AXIS_TOKEN, AXIS_BASE_URL)
// Prints the result as JSON, or {"error": {...}} with exit code 1. Uses ONLY the public SDK surface.
import { Axis, AxisApiError, AxisError } from "@axis/sdk";

const [op, raw] = process.argv.slice(2);
const a = JSON.parse(raw ?? "{}");
const ax = new Axis({
  ...(process.env.AXIS_TOKEN
    ? { token: process.env.AXIS_TOKEN }
    : { apiKey: process.env.AXIS_API_KEY }),
  baseUrl: process.env.AXIS_BASE_URL,
  allowInsecure: true,
  maxRetries: 0,
});

const ops = {
  me: () => ax.me(),
  policiesPublish: () => ax.policies.publish(a.policy),
  policiesList: () => ax.policies.list(),
  policiesActivate: () => ax.policies.activate(a.version_id),
  blueprintsPublish: () => ax.blueprints.publish(a.abl),
  blueprintsGet: () => ax.blueprints.get(a.name, a.version),
  blueprintsList: () => ax.blueprints.list(),
  registryClaim: () => ax.registry.claim(a.namespace),
  registryKeys: () => ax.registry.keys(a.namespace),
  registryAddKey: () => ax.registry.addKey(a.namespace, a.public_key),
  registryPublish: () => ax.registry.publish(a.namespace, a.bundle),
  registryVersions: () => ax.registry.versions(a.namespace, a.name),
  registryResolve: () => ax.registry.resolve(a.ref),
  marketListings: () => ax.marketplace.listings(a.q ? { q: a.q } : {}),
  marketPreview: () => ax.marketplace.preview(a.namespace, a.name, a.range),
  marketInstall: () =>
    a.consent_digest === undefined
      ? ax.marketplace.installWithConsent(a.namespace, a.name, a.range, { consent: () => true })
      : ax.marketplace.install({
          namespace: a.namespace,
          name: a.name,
          version: a.version,
          contentHash: a.content_hash,
          consentDigest: a.consent_digest,
        }),
  marketInstalls: () => ax.marketplace.installs(),
  marketUninstall: () => ax.marketplace.uninstall(a.namespace, a.name),
  runStart: () =>
    ax.runs.start({ blueprint: { name: a.name, version: a.version }, input: a.input }),
  runGet: () => ax.runs.get(a.id),
  runWait: () => ax.runs.wait(a.id, { timeoutMs: 120000, pollIntervalMs: 300 }),
  runEvents: async () => {
    const out = [];
    for await (const e of ax.runs.allEvents(a.id)) out.push(e);
    return out;
  },
  runStream: async () => {
    const out = [];
    for await (const e of ax.runs.stream(a.id)) out.push(e);
    return out;
  },
  runExplain: () => ax.runs.explain(a.id),
  approvalsList: () => ax.approvals.list(a.status ? { status: a.status } : {}),
  approvalsGet: () => ax.approvals.get(a.id),
  approve: () => ax.approvals.approve(a.id, a.comment),
  reject: () => ax.approvals.reject(a.id, a.comment),
  auditEvents: async () => {
    const out = [];
    for await (const e of ax.audit.iterate(a.trace_id ? { trace_id: a.trace_id } : {})) out.push(e);
    return out;
  },
  auditVerify: () => ax.audit.verify({}),
  auditExplain: () => ax.audit.explainEvent(a.seq),
  usage: () => ax.usage.get({ from: a.from, to: a.to, groupBy: a.group_by }),
  killSwitch: () => ax.killSwitches.set({ scope: "tenant", engaged: a.engaged, reason: a.reason }),
  killSwitchList: () => ax.killSwitches.list(),
  // ---- Phase 8: the Eval Hub ----
  evalsDatasetCreate: () => ax.evals.datasets.create(a.body),
  evalsDatasetGet: () => ax.evals.datasets.get(a.name, a.version ?? "latest"),
  evalsDatasetList: () => ax.evals.datasets.list(a.name ? { name: a.name } : {}),
  evalsSuiteCreate: () => ax.evals.suites.create(a.body),
  evalsSuiteGet: () => ax.evals.suites.get(a.ref),
  evalsSuiteList: () => ax.evals.suites.list(),
  evalsRunStart: () =>
    ax.evals.start({ suite: a.suite, blueprint: a.blueprint, ...(a.mode ? { mode: a.mode } : {}) }),
  evalsRunGet: () => ax.evals.get(a.id),
  evalsRunWait: () =>
    ax.evals.wait(a.id, { timeoutMs: a.timeout_ms ?? 180000, pollIntervalMs: 300 }),
  evalsRunList: () => ax.evals.list(a.params ?? {}),
  evalsCompare: () => ax.evals.comparison(a.id),
  evalsGate: () => ax.evals.gate({ blueprint: a.blueprint, suites: a.suites }),
  evalsBaselineList: () => ax.evals.baselines.list(a.blueprint, a.suite),
  evalsBaselineSet: () => ax.evals.baselines.set(a.run_id),
  evalsReviewTasks: () => ax.evals.review.tasks(a.params ?? {}),
  evalsReviewClaim: () => ax.evals.review.claim(a.id),
  evalsReviewGrade: () => ax.evals.review.grade(a.id, { score: a.score, comment: a.comment }),
  evalsReviewSkip: () => ax.evals.review.skip(a.id, a.reason),
  evalsSamplingPut: () => ax.evals.sampling.put(a.id, a.body),
  evalsSamplingList: () => ax.evals.sampling.list(),
  evalsSamplingSummary: () => ax.evals.sampling.summary(a.params ?? {}),
  evalsRunnersList: () => ax.evals.runners.list(),
  evalsRunnersRegister: () => ax.evals.runners.register(a.id, a.description),
  evalsRunnersRevoke: () => ax.evals.runners.revoke(a.id),
  registryAttestations: () => ax.registry.evalAttestations(a.namespace, a.name, a.version),
  systemCreate: () => ax.compliance.systems.create(a.body),
  systemGet: () => ax.compliance.systems.get(a.id, a.version),
  systemList: () => ax.compliance.systems.list(a.params ?? {}),
  assessmentCreate: () => ax.compliance.assessments.create(a.body),
  assessmentGet: () => ax.compliance.assessments.get(a.id, a.version),
  assessmentList: () => ax.compliance.assessments.list(a.params ?? {}),
  assessmentSubmit: () => ax.compliance.assessments.submit(a.id, a.expected),
  assessmentReview: () => ax.compliance.assessments.review(a.id, a.expected, a.decision, a.comment),
  docGenerate: () => ax.compliance.documents.generate(a.blueprint),
  docGet: () => ax.compliance.documents.get(a.id),
  docList: () => ax.compliance.documents.list(a.params ?? {}),
};

try {
  console.log(JSON.stringify((await ops[op]()) ?? null));
} catch (e) {
  const status = e instanceof AxisApiError ? e.status : undefined;
  console.log(
    JSON.stringify({
      error: {
        status: status ?? null,
        code: e?.code ?? null,
        name: e?.name,
        message: String(e?.message ?? e),
      },
    }),
  );
  process.exit(1);
}
