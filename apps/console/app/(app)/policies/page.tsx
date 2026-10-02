"use client";
import { useMemo, useState } from "react";
import { Badge, Button, CodeEditor, DiffView, Dialog, Table, useToast } from "@axis/ui";
import { ApiError, api, type PolicyPack } from "@/lib/api";
import { parseCases, runCases, SAMPLE_CASES, type CaseResult } from "@/lib/policy-tests";
import { useAction, useResource } from "@/lib/hooks";
import { formatTime } from "@/lib/format";
import { ErrorNote, PageHeader, ResourceView } from "@/components/common";
import { useCan } from "@/components/session";

const SAMPLE_POLICY = JSON.stringify(
  {
    apiVersion: "policy.axis.dev/v1",
    kind: "PolicyPack",
    metadata: { name: "my-pack", version: "1.0.0" },
    spec: { rules: [] },
  },
  null,
  2,
);

function parseJson(
  text: string,
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  try {
    const v: unknown = JSON.parse(text);
    if (typeof v !== "object" || v === null || Array.isArray(v))
      return { ok: false, error: "Must be a JSON object" };
    return { ok: true, value: v as Record<string, unknown> };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Invalid JSON" };
  }
}

export default function PoliciesPage() {
  const packs = useResource(() => api.listPolicyPacks());
  const [policyText, setPolicyText] = useState(SAMPLE_POLICY);
  const [casesText, setCasesText] = useState(SAMPLE_CASES);
  const [results, setResults] = useState<CaseResult[] | undefined>();
  const [activating, setActivating] = useState<PolicyPack | undefined>();
  const canWrite = useCan("policies.write");
  const canActivate = useCan("policies.activate");
  const toast = useToast();

  const policy = useMemo(() => parseJson(policyText), [policyText]);
  const cases = useMemo(() => parseCases(casesText), [casesText]);

  const test = useAction(async () => {
    if (!policy.ok) throw new Error(`Policy: ${policy.error}`);
    if ("error" in cases) throw new Error(cases.error);
    setResults(await runCases(cases.cases, (req) => api.testPolicy(policy.value, req)));
  });
  const publish = useAction(async () => {
    if (!policy.ok) throw new Error(`Policy: ${policy.error}`);
    return api.publishPolicyPack(policy.value);
  });
  const activate = useAction(async (p: PolicyPack) =>
    api.activatePolicy(p.version_id ?? p.version),
  );

  const activeDoc = packs.data?.items.find((p) => p.name === activating?.name && p.active)?.policy;
  const before = activeDoc ? JSON.stringify(activeDoc, null, 2) : "";
  const after = activating?.policy ? JSON.stringify(activating.policy, null, 2) : "";
  const passed = results?.filter((r) => r.pass).length ?? 0;

  return (
    <>
      <title>Policies - AXIS Console</title>
      <PageHeader
        title="Policies"
        description="Policy packs compile to Rego and gate every tool, memory and message action. Anything not explicitly allowed is denied."
      />
      <section aria-label="Policy packs" className="mb-8">
        <h2 className="mb-2 text-lg font-semibold">Packs</h2>
        <ResourceView resource={packs}>
          {(p) => (
            <Table<PolicyPack>
              caption="Policy packs"
              rows={p.items}
              rowKey={(x) => `${x.name}@${x.version}`}
              columns={[
                { key: "name", header: "Pack", render: (x) => x.name },
                { key: "ver", header: "Version", render: (x) => x.version },
                {
                  key: "active",
                  header: "Active",
                  render: (x) =>
                    x.active ? <Badge tone="good">active</Badge> : <Badge>inactive</Badge>,
                },
                { key: "created", header: "Created", render: (x) => formatTime(x.created_at) },
                {
                  key: "act",
                  header: "",
                  render: (x) =>
                    canActivate && !x.active ? (
                      <Button
                        variant="secondary"
                        onClick={() => {
                          activate.reset();
                          setActivating(x);
                        }}
                      >
                        Review and activate
                      </Button>
                    ) : null,
                },
              ]}
            />
          )}
        </ResourceView>
      </section>

      <section aria-label="Editor and tests" className="grid gap-6 lg:grid-cols-2">
        <div className="flex flex-col gap-3">
          <h2 className="text-lg font-semibold">Policy document</h2>
          <CodeEditor
            label="Policy (JSON, policy-v1)"
            value={policyText}
            onChange={setPolicyText}
            rows={20}
            markers={
              policy.ok ? [] : [{ line: 1, column: 1, severity: "error", message: policy.error }]
            }
          />
          {canWrite ? (
            <div>
              <Button
                variant="secondary"
                disabled={!policy.ok}
                loading={publish.pending}
                onClick={async () => {
                  const r = await publish.run();
                  if (r) {
                    toast.push(`Published ${r.name}@${r.version}`, "success");
                    packs.reload();
                  }
                }}
              >
                Publish pack version
              </Button>
            </div>
          ) : null}
          {publish.error ? <PolicyError error={publish.error} /> : null}
        </div>
        <div className="flex flex-col gap-3">
          <h2 className="text-lg font-semibold">Test cases</h2>
          <CodeEditor
            label="Cases (JSON array of {name, request, expect})"
            value={casesText}
            onChange={setCasesText}
            rows={14}
            markers={
              "error" in cases
                ? [{ line: 1, column: 1, severity: "error", message: cases.error }]
                : []
            }
          />
          <div>
            <Button loading={test.pending} onClick={() => void test.run()}>
              Run tests
            </Button>
          </div>
          {test.error ? <PolicyError error={test.error} /> : null}
          {results ? (
            <div aria-live="polite" data-testid="policy-results">
              <p className="mb-2 text-sm font-medium">
                {passed} of {results.length} passed
              </p>
              <Table<CaseResult>
                caption="Policy test results"
                rows={results}
                rowKey={(r) => r.name}
                columns={[
                  { key: "name", header: "Case", render: (r) => r.name },
                  {
                    key: "res",
                    header: "Result",
                    render: (r) => (
                      <Badge tone={r.pass ? "good" : "bad"}>{r.pass ? "pass" : "fail"}</Badge>
                    ),
                  },
                  { key: "exp", header: "Expected", render: (r) => r.expected },
                  { key: "act", header: "Actual", render: (r) => r.actual ?? r.error ?? "-" },
                  { key: "why", header: "Reason", render: (r) => r.reason ?? "-" },
                ]}
              />
            </div>
          ) : null}
        </div>
      </section>

      <Dialog
        open={activating !== undefined}
        onOpenChange={(o) => !o && setActivating(undefined)}
        title={`Activate ${activating?.name ?? ""}@${activating?.version ?? ""}`}
        description="Activation replaces the currently active version of this pack for every agent in the tenant. Review the change."
        footer={
          <>
            <Button variant="secondary" onClick={() => setActivating(undefined)}>
              Cancel
            </Button>
            <Button
              loading={activate.pending}
              onClick={async () => {
                const r = await activate.run(activating!);
                if (r !== undefined) {
                  toast.push("Policy activated", "success");
                  setActivating(undefined);
                  packs.reload();
                }
              }}
            >
              Activate
            </Button>
          </>
        }
      >
        {activating?.policy ? (
          <DiffView label="Policy changes" before={before} after={after} />
        ) : (
          <p className="text-sm text-[var(--axis-muted)]">
            The control plane did not return the document for this version, so no diff can be shown.
          </p>
        )}
        {activate.error ? <PolicyError error={activate.error} /> : null}
      </Dialog>
    </>
  );
}

function PolicyError({ error }: { error: Error }) {
  const items = error instanceof ApiError ? error.errors : [];
  return (
    <div>
      <ErrorNote error={error} />
      {items.length ? (
        <ul className="ml-5 mt-2 list-disc text-sm">
          {items.map((e, i) => (
            <li key={i}>
              {e.path}: {e.message}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
