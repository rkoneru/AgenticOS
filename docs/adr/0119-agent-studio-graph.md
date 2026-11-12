# ADR 0119: Agent Studio - `@xyflow/react` and the graph<->ABL serializer

## Status

Accepted

## Context

The console's only way to compose an ABL blueprint was `BlueprintEditor`, a plain-YAML text editor
(`apps/console/components/blueprint-editor.tsx`). This adds a second, visual authoring surface at
`/studio`: a node-based canvas for the same ABL v1 document (`docs/spec/abl-v1.md`,
`packages/abl/schema/abl-v1.schema.json`), without forking the validation or publish path.

## Decision

### Library: `@xyflow/react`

Added `@xyflow/react@^12.12.1` to `apps/console/package.json` (MIT-licensed; the standard
node-graph/data-flow canvas library for React). No alternative was seriously considered: it is the
library a literal reading of "interactive data-flow canvas" names, and the task brief named it
directly. Pinned to the latest stable release at the time (`12.12.1`; `13.0.0` was only available as
`-next` pre-releases), matching this repo's `^x.y.z` pinning convention for other dependencies.

### Graph <-> ABL serializer (`apps/console/lib/studio-graph.ts`)

Pure, framework-free functions `ablToGraph(doc) -> {nodes, edges}` and
`graphToAbl(nodes, edges) -> doc`, with no import of `@xyflow/react` or React - the module's types
(`StudioNode`, `StudioEdge`) are structurally compatible with React Flow's `Node`/`Edge` so the
Studio canvas can use them directly, but the serializer itself is testable with plain objects and
has no DOM/React dependency.

**Node id scheme.** Fixed-id singletons for nodes the schema makes "at most one of"
(`agent`, `model`, `memory`, `policy`); `kind`-keyed ids for nodes the schema already treats as a
unique-keyed or `uniqueItems` set (`routing:<stage>`, `budget:<metric>`, `channel:<kind>` - the
schema's own enums bound how many of each can ever exist, so the id scheme just mirrors that);
counter-keyed ids for the one genuinely-repeatable, freely-named collection (`tool:<n>`). This means
the toolbar's "Add routing stage" / "Add budget" / "Add channel" buttons can simply fill in the next
missing enum value in canonical order without a picker dialog - simpler to build and fully
keyboard-operable with one Enter per click, at the cost of not letting the user choose which enum
value to add next out of canonical order (documented as NEEDS #527).

**Routing stages as a chain, not an array field.** `spec.routing.stages` is the one place ABL's own
order is semantically load-bearing _and_ visually interesting (NEXUS runs stages in listed order;
the first to resolve short-circuits the rest) - exactly what "interactive data flow" means in the
brief. Modeling it as a left-to-right chain of nodes (`stage[i] -> stage[i+1]`, tail `-> agent`)
makes that order a first-class, visible, reconnectable part of the graph, instead of a hidden array
property on one node. `graphToAbl` recovers the order with a topological walk of the chain edges
(`orderRoutingStages`), falling back to canvas array order for any stage node the chain doesn't
reach (an edge mid-edit), so a transiently-disconnected graph never throws.

**Node ordering for everything else.** `tools`, `channels` and the budgets/memory/policy singleton
fields have no equivalent "data flow" to render, so their serialized array order is simply the
order their nodes appear in the `nodes` array - which `ablToGraph` builds in document order, and
which the canvas's own add/remove operations preserve (append on add, filter on remove). This is
not visually represented on the canvas (there's no "list order" edge for tools), which is a real,
intentional simplification: reordering tools or channels has no effect on compiled semantics (the
schema does not treat their order as significant the way it does for `routing.stages`), so nothing
is lost by not surfacing it.

**Losslessness vs. scope.** The node palette in the brief is `agent, model, tool, routingStage,
memory, budget, policy, channel` - deliberately not every ABL section. `spec.process`, `spec.evals`,
`spec.data` (PHI/residency) and `metadata.labels` have no dedicated node or inspector control yet.
Dropping them on every round-trip would make loading an existing blueprint with any of those fields
lossy in a way a user would not expect from "load this YAML into the canvas". Instead `ablToGraph`
captures them verbatim into a `passthrough` field on the (always-present) agent node, and
`graphToAbl` re-emits them unchanged; there is simply no UI to create or edit them yet - doing so
requires the plain `BlueprintEditor`. This is the design the round-trip test in
`apps/console/test/studio-graph.test.ts` depends on: every fixture in `packages/abl/examples/valid/`
(including `claims-triage.yaml`, which exercises `process` and `evals`) round-trips to a RuntimeManifest
that is identical except for `blueprint.content_hash`, which is excluded from the comparison on
purpose (see below).

**Why the round-trip test excludes `content_hash`.** `docs/spec/abl-v1.md` defines
`blueprint.content_hash` as the sha256 of the canonical JSON of the _source document itself_, not of
its compiled semantics - so a rebuilt document that is semantically identical but omits/adds a
field at its compiler-default value (e.g. `memory.longTerm: false` written explicitly vs. omitted,
both compiling to the same `long_term: false`) hashes differently even though nothing about the
agent's behavior changed. The task's own allowance ("don't require byte-identical YAML... require
the compiled RuntimeManifest to match") is read here as applying to the manifest's _semantic_
fields; the test asserts both hashes are well-formed sha256 hex strings and compares every other
manifest field, rather than asserting a guarantee the spec itself does not make for this kind of
round-trip.

### High-risk constraint surfaced in the UI, not just the validator

`riskClassification.level: high` requires `humanOversight.required: true` with at least one
`approverRoles` entry (schema `allOf`/`if`/`then`). The agent inspector form
(`components/studio/inspector.tsx`) ties `humanOversightRequired` to the risk-level select (forcing
it `true` and disabling the checkbox once `high` is selected) and shows an inline required-marker on
the approver-roles list editor, rather than only catching the problem in the live-validation preview
after the fact.

### Keyboard accessibility

React Flow's node drag is inherently mouse-centric, and dragging an edge to reconnect the routing
chain has no built-in keyboard equivalent. Per-node a11y otherwise comes for free from the library:
nodes are focusable (`tabIndex=0`, `role="group"`) and Enter/Space triggers the same selection path
as a click, which this canvas reads via `onSelectionChange` to drive the inspector panel - so Tab +
Enter + the inspector form covers every node-editing action without any extra plumbing. The one gap
(reordering the routing chain) gets a dedicated keyboard-operable "Routing order" panel
(`components/studio/routing-order.tsx`) with Up/Down buttons that rewrite the chain's edges; the
same Up/Down pattern (`components/studio/list-editor.tsx`) covers reordering approver roles,
knowledge bases and policy packs, none of which have a drag affordance at all in this design.

## Consequences

- Loading any `packages/abl/examples/valid/*.yaml` fixture into the canvas and publishing without
  edits reproduces an equivalent blueprint; editing in the canvas and switching to the plain YAML
  editor shows the exact same generated document, because both go through `graphToAblYaml` ->
  `api.validateAbl` -> `api.publishBlueprint`, the identical pipeline `BlueprintEditor` always used.
- A blueprint using `process`, `evals`, `data` (PHI/residency) or `metadata.labels` can be loaded and
  re-published unchanged from the canvas, but those fields cannot be _created or edited_ there yet -
  a real, documented gap (NEEDS #527), not a silent one.
- `routing.stages`, `budgets`, `channels` reaching their enum's full cardinality disable the
  corresponding "Add" toolbar button (with an explanatory `title`) rather than failing silently or
  producing a duplicate/invalid node.
