import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MemoryAuditLog, createAuditReader } from "../src/index.js";
import { ev } from "./helpers.js";

const WRITE_LIKE =
  /append|write|insert|delete|update|save|seal|put|export|checkpoint|set|remove|truncate/i;

function allMethodNames(o: object): string[] {
  const names = new Set<string>();
  for (let p: object | null = o; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
    for (const n of Reflect.ownKeys(p)) names.add(String(n));
  }
  return [...names];
}

describe("AuditReader architecture (AGIL reads only)", () => {
  it("the reader exposes listEvents and nothing else, and is frozen", async () => {
    const store = new MemoryAuditLog();
    const t = randomUUID();
    await store.append(ev(t));
    const reader = createAuditReader(store);
    expect(allMethodNames(reader)).toEqual(["listEvents"]);
    expect(allMethodNames(reader).filter((n) => WRITE_LIKE.test(n))).toEqual([]);
    expect(Object.isFrozen(reader)).toBe(true);
    expect((reader as unknown as Record<string, unknown>)["append"]).toBeUndefined();
    expect(() => {
      (reader as unknown as Record<string, unknown>)["append"] = () => 1;
    }).toThrow(TypeError);
    expect((await reader.listEvents(t, { limit: 10 })).length).toBe(1);
  });

  it("the store itself is not what the reader hands out (the source is not reachable from it)", () => {
    const store = new MemoryAuditLog();
    const reader = createAuditReader(store) as unknown as Record<string, unknown>;
    expect(Object.values(reader).every((v) => v !== store)).toBe(true);
    expect(JSON.stringify(Object.keys(reader))).not.toMatch(/store|source|log/i);
  });

  it("reader.ts imports only the AuditReader type (no store, sink or pg code can leak into it)", () => {
    const src = readFileSync(fileURLToPath(new URL("../src/reader.ts", import.meta.url)), "utf8");
    const imports = [...src.matchAll(/^import .*from "(.*)";$/gm)].map((m) => m[1]);
    expect(imports).toEqual(["./types.js"]);
    expect(src).toMatch(/^import type /m);
  });

  it("types.ts AuditReader declares only listEvents", () => {
    const src = readFileSync(fileURLToPath(new URL("../src/types.ts", import.meta.url)), "utf8");
    const block = /export interface AuditReader \{([\s\S]*?)\n\}/.exec(src)?.[1] ?? "";
    const members = [...block.matchAll(/^\s+(\w+)\(/gm)].map((m) => m[1]);
    expect(members).toEqual(["listEvents"]);
  });

  it("no module outside the stores implements AuditStore/append (sanity: append lives only in memory.ts and pg.ts)", () => {
    const dir = fileURLToPath(new URL("../src/", import.meta.url));
    const withAppend = readdirSync(dir).filter((f) =>
      /\bappend\s*\(/.test(readFileSync(dir + f, "utf8")),
    );
    expect(withAppend.sort()).toEqual(["memory.ts", "pg.ts", "types.ts"]);
  });
});
