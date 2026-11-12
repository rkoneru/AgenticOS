import { parse } from "yaml";
import { STARTER_ABL } from "./abl-starter";
import { ablToGraph, type AblDocLike, type StudioGraph } from "./studio-graph";

/** The Studio canvas's "New" starter graph: the same `hello-agent` blueprint `/blueprints/new`
 * seeds its text editor with, converted through `ablToGraph` so both entry points start from one
 * source of truth. */
export function starterGraph(): StudioGraph {
  return ablToGraph(parse(STARTER_ABL) as AblDocLike);
}
