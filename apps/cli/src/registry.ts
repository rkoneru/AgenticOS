import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { compileAbl, formatFindings, formatIssues } from "@axis/abl";
import { ablContentHash, buildStatement, signBlueprint, signStatement } from "@axis/registry";
import type { InstallPreview, SignedBundle } from "@axis/sdk";
import { parse } from "yaml";
import type { Command, Ctx, FlagSpec } from "./cli.js";
import { CliError, EXIT, UsageError } from "./exit.js";
import { keyValues, table } from "./render.js";

/**
 * `axis registry ...` and `axis marketplace ...` (OpenAPI 1.2.0, ADR 0053).
 *
 * Signing is OFFLINE: the Ed25519 private key is read from a local PEM file and never leaves this process, the SDK never sees it and
 * nothing here logs it. The provenance statement carries the ABL compiler's own lint results (the registry recomputes them), so the
 * compiler runs here, on the publisher's machine, not on the server.
 */

const NS = /^[a-z][a-z0-9-]{1,62}$/;

function emit(ctx: Ctx, data: unknown, human: () => string): void {
  ctx.out(ctx.format === "table" ? human() : JSON.stringify(data, null, 2));
}

/** Like ssh: a signing key other users can read is refused (it signs for the whole namespace). */
function refuseSharedKeyFile(path: string): void {
  if (process.platform === "win32") return;
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0)
    throw new CliError(
      `key file ${path} is accessible by other users (mode ${mode.toString(8)})`,
      EXIT.AUTH,
      [`run: chmod 600 ${path}`],
    );
}

function readPemKey(path: string): KeyObject {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new CliError(`cannot read the key file ${path} (${(e as NodeJS.ErrnoException).code})`);
  }
  try {
    const k = createPrivateKey(text);
    if (k.asymmetricKeyType !== "ed25519") throw new Error("not ed25519");
    refuseSharedKeyFile(path);
    return k;
  } catch (e) {
    if (e instanceof CliError) throw e;
    // never echo key material: say what is wrong with the FILE, not what is in it
    throw new CliError(`${path} is not an Ed25519 private key in PEM (PKCS#8) form`);
  }
}

const SPKI_PREFIX_LEN = 12;
function rawPublic(priv: KeyObject): Buffer {
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  return spki.subarray(SPKI_PREFIX_LEN);
}
const keyIdOf = (raw: Uint8Array): string =>
  `k1-${createHash("sha256").update(raw).digest("hex").slice(0, 32)}`;

/** `ns/name` or `ns/name@range` (range defaults to the whole catalogue: "*"). */
function parseListingRef(ref: string, usage: string): { ns: string; name: string; range: string } {
  const at = ref.indexOf("@");
  const base = at === -1 ? ref : ref.slice(0, at);
  const range = at === -1 ? "*" : ref.slice(at + 1);
  const [ns, name, ...extra] = base.split("/");
  if (!ns || !name || extra.length > 0 || !NS.test(ns) || !NS.test(name) || range === "")
    throw new UsageError(`expected <namespace>/<name>[@range]; usage: axis ${usage}`);
  return { ns, name, range };
}

function need(ctx: Ctx, n: number, usage: string): string[] {
  if (ctx.args.length !== n)
    throw new UsageError(
      ctx.args.length < n
        ? `missing argument; usage: axis ${usage}`
        : `unexpected argument "${ctx.args[n]}"; usage: axis ${usage}`,
    );
  return ctx.args;
}

// ----------------------------------------------------------------------------------------- registry

async function keygen(ctx: Ctx): Promise<number> {
  const out = ctx.str("out");
  if (!out)
    throw new UsageError("--out <file> is required (the private key is written there, mode 0600)");
  const { privateKey } = generateKeyPairSync("ed25519");
  try {
    writeFileSync(out, privateKey.export({ format: "pem", type: "pkcs8" }), {
      mode: 0o600,
      flag: "wx",
    });
  } catch (e) {
    throw new CliError(
      `cannot write ${out} (${(e as NodeJS.ErrnoException).code}); it must not exist yet`,
    );
  }
  const raw = rawPublic(privateKey);
  const data = { key_file: out, public_key: raw.toString("base64url"), key_id: keyIdOf(raw) };
  emit(ctx, data, () =>
    keyValues(
      [
        ["private key", `${out} (keep it secret; it never leaves this machine)`],
        ["public key", data.public_key],
        ["key id", data.key_id],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function namespaces(ctx: Ctx): Promise<number> {
  const r = await ctx.client().registry.namespaces();
  emit(ctx, r, () =>
    r.items.length === 0
      ? "your tenant owns no registry namespaces"
      : table(
          r.items,
          [
            { header: "namespace", get: (n) => n.namespace },
            { header: "public", get: (n) => n.public },
            { header: "created", get: (n) => n.created_at },
          ],
          ctx.style,
        ),
  );
  return EXIT.OK;
}

async function claim(ctx: Ctx): Promise<number> {
  const [ns] = need(ctx, 1, "registry claim <namespace>");
  const r = await ctx.client().registry.claim(ns as string);
  emit(ctx, r, () => `claimed namespace ${r.namespace}`);
  return EXIT.OK;
}

async function keys(ctx: Ctx): Promise<number> {
  const [ns] = need(ctx, 1, "registry keys <namespace>");
  const r = await ctx.client().registry.keys(ns as string);
  emit(ctx, r, () =>
    r.items.length === 0
      ? "no publisher keys"
      : table(
          r.items,
          [
            { header: "key id", get: (k) => k.key_id },
            { header: "valid from", get: (k) => k.valid_from },
            { header: "valid until", get: (k) => k.valid_until },
            { header: "revoked", get: (k) => k.revoked_at },
          ],
          ctx.style,
        ),
  );
  return EXIT.OK;
}

async function addKey(ctx: Ctx): Promise<number> {
  const [ns] = need(ctx, 1, "registry add-key <namespace> (--public-key <b64url> | --key <pem>)");
  const pub = ctx.str("public-key");
  const keyFile = ctx.str("key");
  if ((pub === undefined) === (keyFile === undefined))
    throw new UsageError("give exactly one of --public-key <base64url> or --key <private key PEM>");
  const publicKey = pub ?? rawPublic(readPemKey(keyFile as string)).toString("base64url");
  const r = await ctx.client().registry.addKey(ns as string, publicKey);
  emit(ctx, r, () => `registered key ${r.key_id} for ${ns}`);
  return EXIT.OK;
}

interface Signed {
  namespace: string;
  bundle: SignedBundle;
  name: string;
  version: string;
}

function signFile(ctx: Ctx, file: string, namespace: string, keyPath: string): Signed {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    throw new CliError(`cannot read ${file} (${(e as NodeJS.ErrnoException).code ?? "error"})`);
  }
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (e) {
    throw new CliError(`${file} is not valid YAML/JSON: ${(e as Error).message.split("\n")[0]}`);
  }
  const compiled = compileAbl(doc);
  if (!compiled.ok)
    throw new CliError(`${file} does not validate`, EXIT.ERROR, [
      ...formatIssues(compiled.issues),
      ...formatFindings(compiled.findings),
    ]);
  const key = readPemKey(keyPath);
  const keyId = keyIdOf(rawPublic(key));
  const meta = (doc as { metadata: { name: string; version: string } }).metadata;
  const level = (doc as { spec: { riskClassification: { level: string } } }).spec.riskClassification
    .level;
  const hash = ablContentHash(doc);
  const at = (ctx.deps.now ?? (() => new Date()))();
  const sig = signBlueprint(
    { namespace, name: meta.name, version: meta.version, riskLevel: level, contentHash: hash },
    { keyId, privateKey: key },
    at,
  );
  const provenance = signStatement(
    buildStatement(
      {
        namespace,
        name: meta.name,
        version: meta.version,
        abl: doc,
        builderId: ctx.str("builder") ?? "axis-cli",
        sourceRef: ctx.str("source-ref") ?? `file:${file}`,
        now: at,
      },
      hash,
    ),
    { keyId, privateKey: key },
  );
  return {
    namespace,
    name: meta.name,
    version: meta.version,
    bundle: {
      abl: doc as SignedBundle["abl"],
      signature: { key_id: sig.keyId, signed_at: sig.signedAt, sig: sig.sig },
      provenance,
    },
  };
}

const SIGN_FLAGS: readonly FlagSpec[] = [
  { name: "namespace", type: "string", placeholder: "<ns>", desc: "Registry namespace (yours)" },
  {
    name: "key",
    type: "string",
    placeholder: "<pem>",
    desc: "Ed25519 private key file (PKCS#8 PEM)",
  },
  {
    name: "builder",
    type: "string",
    placeholder: "<id>",
    desc: "Builder id recorded in the provenance",
  },
  {
    name: "source-ref",
    type: "string",
    placeholder: "<ref>",
    desc: "Source reference recorded in the provenance",
  },
];

async function sign(ctx: Ctx): Promise<number> {
  const [file] = need(ctx, 1, "registry sign <abl-file> --namespace <ns> --key <pem>");
  const ns = ctx.str("namespace");
  const key = ctx.str("key");
  if (!ns || !key) throw new UsageError("--namespace and --key are required");
  const s = signFile(ctx, file as string, ns, key);
  const doc = { namespace: s.namespace, ...s.bundle };
  const out = ctx.str("out");
  if (out) {
    writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
    ctx.err(`signed ${ns}/${s.name}@${s.version}; bundle written to ${out}`);
  } else ctx.out(JSON.stringify(doc, null, 2));
  return EXIT.OK;
}

async function publish(ctx: Ctx): Promise<number> {
  const [file] = need(
    ctx,
    1,
    "registry publish <bundle.json | abl-file --key <pem>> --namespace <ns>",
  );
  let bundle: SignedBundle | undefined;
  let ns = ctx.str("namespace");
  const keyPath = ctx.str("key");
  let text = "";
  try {
    text = readFileSync(file as string, "utf8");
  } catch (e) {
    throw new CliError(`cannot read ${file} (${(e as NodeJS.ErrnoException).code ?? "error"})`);
  }
  let parsed: unknown;
  try {
    parsed = parse(text);
  } catch {
    parsed = undefined;
  }
  const asBundle = parsed as {
    namespace?: string;
    signature?: unknown;
    provenance?: unknown;
    abl?: unknown;
  };
  if (asBundle && asBundle.signature && asBundle.provenance && asBundle.abl) {
    bundle = {
      abl: asBundle.abl as SignedBundle["abl"],
      signature: asBundle.signature as SignedBundle["signature"],
      provenance: asBundle.provenance as SignedBundle["provenance"],
    };
    ns = ns ?? asBundle.namespace;
  } else if (keyPath && ns) {
    bundle = signFile(ctx, file as string, ns, keyPath).bundle;
  }
  if (!bundle || !ns)
    throw new UsageError(
      "give a signed bundle (from `axis registry sign`) with --namespace, or an ABL file with --namespace and --key",
    );
  const r = await ctx.client().registry.publish(ns, bundle);
  emit(ctx, r, () =>
    keyValues(
      [
        ["published", `${r.namespace}/${r.name}@${r.version}`],
        ["content hash", r.content_hash],
        ["risk", r.risk_level],
        ["signed by", r.signature.key_id],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function versions(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "registry versions <namespace>/<name>");
  const { ns, name } = parseListingRef(ref as string, "registry versions <namespace>/<name>");
  const r = await ctx.client().registry.versions(ns, name);
  emit(ctx, r, () =>
    r.items.length === 0
      ? "no versions"
      : table(
          r.items,
          [
            { header: "version", get: (v) => v.version },
            { header: "state", get: (v) => v.state },
            { header: "risk", get: (v) => v.risk_level },
            { header: "hash", get: (v) => v.content_hash.slice(0, 12) },
            { header: "published", get: (v) => v.published_at },
          ],
          ctx.style,
        ),
  );
  return EXIT.OK;
}

async function yank(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "registry yank <namespace>/<name>@<version> --reason <text>");
  const reason = ctx.str("reason");
  if (!reason) throw new UsageError("--reason is required");
  const { ns, name, range } = parseListingRef(
    ref as string,
    "registry yank <namespace>/<name>@<version>",
  );
  if (range === "*")
    throw new UsageError("an exact version is required: <namespace>/<name>@<version>");
  const r = await ctx.client().registry.yank(ns, name, range, reason);
  emit(ctx, r, () => `yanked ${ns}/${name}@${range}`);
  return EXIT.OK;
}

async function resolve(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "registry resolve <namespace>/<name>@<range>");
  const r = await ctx.client().registry.resolve(ref as string);
  emit(ctx, r, () =>
    keyValues(
      [
        ["resolved", `${r.namespace}/${r.name}@${r.version}`],
        ["state", r.state],
        ["content hash", r.content_hash],
        ["verified", `signature and provenance (key ${r.verification.key_id})`],
        ["builder", r.verification.builder],
        ["source", r.verification.source_ref],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

// ----------------------------------------------------------------------------------------- marketplace

async function search(ctx: Ctx): Promise<number> {
  const q = ctx.args.join(" ") || undefined;
  const category = ctx.str("category");
  const r = await ctx.client().marketplace.listings({
    ...(q ? { q } : {}),
    ...(category ? { category } : {}),
  });
  emit(ctx, r, () =>
    r.items.length === 0
      ? "no listings"
      : table(
          r.items,
          [
            { header: "listing", get: (l) => `${l.namespace}/${l.name}` },
            { header: "latest", get: (l) => l.latest?.version },
            { header: "risk", get: (l) => l.latest?.risk_level },
            { header: "title", get: (l) => l.title },
          ],
          ctx.style,
        ),
  );
  return EXIT.OK;
}

async function show(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "marketplace show <namespace>/<name>");
  const { ns, name } = parseListingRef(ref as string, "marketplace show <namespace>/<name>");
  const l = await ctx.client().marketplace.listing(ns, name);
  emit(ctx, l, () =>
    keyValues(
      [
        ["listing", `${l.namespace}/${l.name}`],
        ["title", l.title],
        ["summary", l.summary],
        ["categories", l.categories.join(", ")],
        ["latest", l.latest?.version],
        ["versions", l.versions.join(", ")],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

function previewText(p: InstallPreview, ctx: Ctx): string {
  const head = keyValues(
    [
      ["listing", `${p.namespace}/${p.name}@${p.version}`],
      ["content hash", p.content_hash],
      ["risk", `${p.risk_level} (max finding severity: ${p.max_severity ?? "none"})`],
      ["consent digest", p.consent_digest],
    ],
    ctx.style,
  );
  const added =
    p.diff.added.length === 0
      ? "this listing asks for nothing beyond your tenant baseline"
      : `PERMISSIONS THIS INSTALL ADDS:\n${table(
          p.diff.added,
          [
            { header: "permission", get: (a) => a.key },
            { header: "change", get: (a) => a.change },
            { header: "level", get: (a) => a.level },
          ],
          ctx.style,
        )}`;
  const findings =
    p.findings.length === 0
      ? ""
      : `\nFINDINGS:\n${table(
          p.findings,
          [
            { header: "id", get: (f) => f.id },
            { header: "severity", get: (f) => f.severity },
            { header: "message", get: (f) => f.message },
          ],
          ctx.style,
        )}`;
  return `${head}\n\n${added}${findings}`;
}

async function previewCmd(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "marketplace preview <namespace>/<name>[@range]");
  const { ns, name, range } = parseListingRef(
    ref as string,
    "marketplace preview <namespace>/<name>[@range]",
  );
  const p = await ctx.client().marketplace.preview(ns, name, range);
  emit(ctx, p, () => previewText(p, ctx));
  return EXIT.OK;
}

async function install(ctx: Ctx): Promise<number> {
  const usage =
    "marketplace install <namespace>/<name>[@range] (--yes | --consent-digest <digest>)";
  const [ref] = need(ctx, 1, usage);
  const { ns, name, range } = parseListingRef(ref as string, usage);
  const ax = ctx.client();
  const p = await ax.marketplace.preview(ns, name, range);
  const digest = ctx.str("consent-digest");
  if (!ctx.bool("yes") && digest === undefined) {
    // Consent is explicit: show exactly what would be granted and stop. Nothing was installed.
    ctx.out(ctx.format === "table" ? previewText(p, ctx) : JSON.stringify(p, null, 2));
    throw new UsageError("consent required: nothing was installed", [
      `to consent to exactly this: axis marketplace install ${ns}/${name}@${p.version} --consent-digest ${p.consent_digest}`,
      "or pass --yes to consent to the permissions listed above",
    ]);
  }
  if (digest !== undefined && digest !== p.consent_digest)
    throw new CliError(
      "the consent digest does not match the current permission diff (the listing or your baseline changed): preview again",
      EXIT.ERROR,
      [`axis marketplace preview ${ns}/${name}@${range}`],
    );
  const i = await ax.marketplace.install({
    namespace: p.namespace,
    name: p.name,
    version: p.version,
    contentHash: p.content_hash,
    consentDigest: p.consent_digest,
  });
  emit(ctx, { preview: p, install: i }, () =>
    keyValues(
      [
        ["installed", `${i.namespace}/${i.name}@${i.version}`],
        ["state", i.state],
        ["granted", i.granted.map((g) => g.key).join(", ")],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function installs(ctx: Ctx): Promise<number> {
  const r = await ctx.client().marketplace.installs();
  emit(ctx, r, () =>
    r.items.length === 0
      ? "nothing installed"
      : table(
          r.items,
          [
            { header: "listing", get: (i) => `${i.namespace}/${i.name}` },
            { header: "version", get: (i) => i.version },
            { header: "state", get: (i) => i.state },
            { header: "consented", get: (i) => i.consented_at },
          ],
          ctx.style,
        ),
  );
  return EXIT.OK;
}

async function uninstall(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "marketplace uninstall <namespace>/<name>");
  const { ns, name } = parseListingRef(ref as string, "marketplace uninstall <namespace>/<name>");
  const r = await ctx.client().marketplace.uninstall(ns, name);
  emit(ctx, r, () => `uninstalled ${ns}/${name}`);
  return EXIT.OK;
}

export const REGISTRY_COMMANDS: Command[] = [
  { path: ["registry"], summary: "Signed blueprint registry (private namespaces per tenant)" },
  {
    path: ["registry", "keygen"],
    summary: "Create an Ed25519 publisher key pair (offline)",
    flags: [
      {
        name: "out",
        type: "string",
        placeholder: "<file>",
        desc: "Private key file to create (PEM, mode 0600; must not exist)",
      },
    ],
    description:
      "The private key is written to a local file and never sent anywhere. Register the printed public key with `axis registry add-key`.",
    run: keygen,
  },
  {
    path: ["registry", "namespaces"],
    summary: "List the namespaces your tenant owns",
    run: namespaces,
  },
  {
    path: ["registry", "claim"],
    summary: "Claim a namespace for your tenant (admin)",
    usage: "<namespace>",
    run: claim,
  },
  {
    path: ["registry", "keys"],
    summary: "List a namespace's publisher keys",
    usage: "<namespace>",
    run: keys,
  },
  {
    path: ["registry", "add-key"],
    summary: "Register a publisher public key for a namespace (admin)",
    usage: "<namespace> (--public-key <b64url> | --key <pem>)",
    flags: [
      {
        name: "public-key",
        type: "string",
        placeholder: "<b64url>",
        desc: "Raw Ed25519 public key, base64url",
      },
      {
        name: "key",
        type: "string",
        placeholder: "<pem>",
        desc: "Derive the public key from this private key file",
      },
    ],
    run: addKey,
  },
  {
    path: ["registry", "sign"],
    summary: "Sign an ABL file offline: detached signature plus provenance attestation",
    usage: "<abl-file>",
    flags: [
      ...SIGN_FLAGS,
      {
        name: "out",
        type: "string",
        placeholder: "<file>",
        desc: "Write the signed bundle here instead of stdout",
      },
    ],
    description:
      "Validates and lints the file with the platform compiler, then signs with the local key. Output is the bundle `registry publish` accepts.",
    run: sign,
  },
  {
    path: ["registry", "publish"],
    summary: "Publish a signed blueprint version (immutable; verified before it is stored)",
    usage: "<bundle.json | abl-file>",
    flags: SIGN_FLAGS,
    run: publish,
  },
  {
    path: ["registry", "versions"],
    summary: "List the versions of a blueprint with their state",
    usage: "<namespace>/<name>",
    run: versions,
  },
  {
    path: ["registry", "yank"],
    summary: "Yank a version so it stops resolving (admin)",
    usage: "<namespace>/<name>@<version>",
    flags: [{ name: "reason", type: "string", placeholder: "<text>", desc: "Why (recorded)" }],
    run: yank,
  },
  {
    path: ["registry", "resolve"],
    summary: "Resolve namespace/name@range and verify it (hash, signature, provenance)",
    usage: "<namespace>/<name>@<range>",
    description:
      "Exit 1 with the failed check codes when the best version does not verify; it never falls back to an older one.",
    run: resolve,
  },
  {
    path: ["marketplace"],
    summary: "Security-reviewed marketplace listings and consented installs",
  },
  {
    path: ["marketplace", "search"],
    summary: "Search the catalog",
    usage: "[query]",
    flags: [
      { name: "category", type: "string", placeholder: "<name>", desc: "Only this category" },
    ],
    run: search,
  },
  {
    path: ["marketplace", "show"],
    summary: "Show one listing",
    usage: "<namespace>/<name>",
    run: show,
  },
  {
    path: ["marketplace", "preview"],
    summary: "Show what installing would grant: permission diff, findings, consent digest (admin)",
    usage: "<namespace>/<name>[@range]",
    run: previewCmd,
  },
  {
    path: ["marketplace", "install"],
    summary: "Install a listing with explicit consent to the permission diff (admin)",
    usage: "<namespace>/<name>[@range]",
    flags: [
      { name: "yes", type: "boolean", desc: "Consent to the permissions listed by the preview" },
      {
        name: "consent-digest",
        type: "string",
        placeholder: "<digest>",
        desc: "Consent to exactly the diff with this digest",
      },
    ],
    description:
      "Without --yes or --consent-digest the preview is printed and nothing is installed (exit 2).",
    run: install,
  },
  { path: ["marketplace", "installs"], summary: "List your tenant's installs", run: installs },
  {
    path: ["marketplace", "uninstall"],
    summary: "Uninstall a listing (admin)",
    usage: "<namespace>/<name>",
    run: uninstall,
  },
];
