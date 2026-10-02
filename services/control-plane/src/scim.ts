import { CpError } from "./errors.js";
import type { DirectoryContext, DirectoryService } from "./directory.js";
import type { Member, ScimGroup } from "./types.js";

export const SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
export const SCIM_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
export const SCIM_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
export const SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
export const SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

export interface ScimRequest {
  method: string;
  /** Path below `/scim/v2`, e.g. `/Users/abc`. */
  path: string;
  query: URLSearchParams;
  body?: unknown;
}
export interface ScimResponse {
  status: number;
  body?: unknown;
}

/** RFC 7644 section 3.12 error body. */
export function scimError(status: number, detail: string, scimType?: string): ScimResponse {
  return {
    status,
    body: {
      schemas: [SCIM_ERROR],
      status: String(status),
      ...(scimType ? { scimType } : {}),
      detail,
    },
  };
}

class ScimFail extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
    readonly scimType?: string,
  ) {
    super(detail);
  }
}

// ---------------------------------------------------------------- filter (subset: eq ne co sw pr, joined by `and`)
export interface FilterTerm {
  attr: string;
  op: "eq" | "ne" | "co" | "sw" | "pr";
  value?: string | boolean;
}

const FILTER_ATTRS = new Set([
  "username",
  "externalid",
  "emails.value",
  "displayname",
  "active",
  "id",
]);
const TERM =
  /^\s*([A-Za-z][A-Za-z.]*)\s+(eq|ne|co|sw|pr)(?:\s+("(?:[^"\\]|\\.)*"|true|false))?\s*$/i;

/** Parses `attr op "value" [and attr op value ...]`. Anything else (or / not / parentheses / unknown attributes) is `invalidFilter`. */
export function parseFilter(filter: string): FilterTerm[] {
  if (filter.length > 512) throw new ScimFail(400, "filter too long", "invalidFilter");
  const parts = splitAnd(filter);
  return parts.map((p) => {
    const m = TERM.exec(p);
    if (!m)
      throw new ScimFail(
        400,
        `unsupported filter expression: ${p.trim().slice(0, 60)}`,
        "invalidFilter",
      );
    const attr = (m[1] as string).toLowerCase();
    const op = (m[2] as string).toLowerCase() as FilterTerm["op"];
    if (!FILTER_ATTRS.has(attr))
      throw new ScimFail(400, `unsupported filter attribute: ${attr}`, "invalidFilter");
    if (op === "pr") {
      if (m[3] !== undefined) throw new ScimFail(400, "pr takes no value", "invalidFilter");
      return { attr, op };
    }
    const raw = m[3];
    if (raw === undefined) throw new ScimFail(400, "missing filter value", "invalidFilter");
    const value = raw === "true" ? true : raw === "false" ? false : (JSON.parse(raw) as string);
    return { attr, op, value };
  });
}

/** Splits on ` and ` outside double quotes. */
function splitAnd(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    if (ch === '"' && s[i - 1] !== "\\") q = !q;
    if (!q && /^\s+and\s+/i.test(s.slice(i)) && /\s/.test(ch)) {
      out.push(cur);
      cur = "";
      i += (/^\s+and\s+/i.exec(s.slice(i)) as RegExpExecArray)[0].length - 1;
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out;
}

function matches(
  terms: FilterTerm[],
  get: (attr: string) => string | boolean | undefined,
): boolean {
  return terms.every((t) => {
    const v = get(t.attr);
    if (t.op === "pr") return v !== undefined && v !== "";
    if (v === undefined) return t.op === "ne";
    if (typeof t.value === "boolean" || typeof v === "boolean") {
      return t.op === "eq" ? v === t.value : t.op === "ne" ? v !== t.value : false;
    }
    const a = v.toLowerCase();
    const b = (t.value as string).toLowerCase(); // SCIM string attributes here are case-insensitive
    return t.op === "eq"
      ? a === b
      : t.op === "ne"
        ? a !== b
        : t.op === "co"
          ? a.includes(b)
          : a.startsWith(b);
  });
}

// ---------------------------------------------------------------- resource shapes
const userResource = (m: Member): Record<string, unknown> => ({
  schemas: [SCIM_USER],
  id: m.id,
  ...(m.externalId ? { externalId: m.externalId } : {}),
  userName: m.email,
  ...(m.displayName ? { displayName: m.displayName } : {}),
  emails: [{ value: m.email, primary: true }],
  active: m.status === "active",
  meta: {
    resourceType: "User",
    created: m.createdAt.toISOString(),
    lastModified: m.updatedAt.toISOString(),
  },
});

const groupResource = (g: ScimGroup, members: string[]): Record<string, unknown> => ({
  schemas: [SCIM_GROUP],
  id: g.id,
  ...(g.externalId ? { externalId: g.externalId } : {}),
  displayName: g.displayName,
  members: members.map((value) => ({ value })),
  meta: { resourceType: "Group", created: g.createdAt.toISOString() },
});

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const boolish = (v: unknown): boolean | undefined =>
  typeof v === "boolean"
    ? v
    : typeof v === "string" && /^(true|false)$/i.test(v)
      ? v.toLowerCase() === "true"
      : undefined;

function emailOf(b: Record<string, unknown>): string | undefined {
  const emails = Array.isArray(b["emails"]) ? b["emails"] : [];
  const primary =
    emails.find((e): e is Record<string, unknown> => isObj(e) && e["primary"] === true) ??
    emails.find(isObj);
  return str(isObj(primary) ? primary["value"] : undefined) ?? str(b["userName"]);
}

function userInput(b: unknown): {
  userName: string;
  email: string;
  externalId?: string;
  displayName?: string;
  active: boolean;
} {
  if (!isObj(b)) throw new ScimFail(400, "body must be a JSON object", "invalidSyntax");
  const userName = str(b["userName"]);
  const email = emailOf(b);
  if (!userName || !email) throw new ScimFail(400, "userName is required", "invalidValue");
  const name = isObj(b["name"]) ? str(b["name"]["formatted"]) : undefined;
  const displayName = str(b["displayName"]) ?? name;
  const externalId = str(b["externalId"]);
  return {
    userName,
    email,
    ...(externalId ? { externalId } : {}),
    ...(displayName ? { displayName } : {}),
    active: boolish(b["active"]) ?? true,
  };
}

/** SCIM 2.0 (RFC 7643/7644) Users and Groups for one authenticated directory. Pure: no I/O besides the DirectoryService. */
export class ScimHandler {
  constructor(private readonly dir: DirectoryService) {}

  async handle(ctx: DirectoryContext, req: ScimRequest): Promise<ScimResponse> {
    try {
      return await this.route(ctx, req);
    } catch (err) {
      if (err instanceof ScimFail) return scimError(err.status, err.detail, err.scimType);
      if (err instanceof CpError) {
        const status =
          err.code === "conflict"
            ? 409
            : err.code === "not_found"
              ? 404
              : err.code === "invalid"
                ? 400
                : err.code === "forbidden"
                  ? 403
                  : 500;
        return scimError(
          status,
          err.message,
          err.code === "conflict"
            ? "uniqueness"
            : err.code === "invalid"
              ? "invalidValue"
              : undefined,
        );
      }
      return scimError(500, "internal error");
    }
  }

  private async route(ctx: DirectoryContext, req: ScimRequest): Promise<ScimResponse> {
    const segs = req.path.split("/").filter(Boolean);
    const [kind, id, ...rest] = segs;
    if (rest.length > 0) throw new ScimFail(404, "not found");
    const m = req.method.toUpperCase();
    if (kind === "ServiceProviderConfig" && id === undefined && m === "GET") {
      return {
        status: 200,
        body: {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
          patch: { supported: true },
          bulk: { supported: false },
          filter: { supported: true, maxResults: 200 },
          changePassword: { supported: false },
          sort: { supported: false },
          etag: { supported: false },
          authenticationSchemes: [
            {
              type: "oauthbearertoken",
              name: "Bearer token",
              description: "Per-directory bearer token",
            },
          ],
        },
      };
    }
    if (kind === "Users") return this.users(ctx, m, id, req);
    if (kind === "Groups") return this.groups(ctx, m, id, req);
    throw new ScimFail(404, "not found");
  }

  private paging(q: URLSearchParams): { start: number; count: number } {
    const start = Math.max(1, Number(q.get("startIndex") ?? "1") || 1);
    const count = Math.min(200, Math.max(0, Number(q.get("count") ?? "100")));
    return { start, count: Number.isFinite(count) ? count : 100 };
  }

  private list(items: unknown[], start: number, count: number): ScimResponse {
    return {
      status: 200,
      body: {
        schemas: [SCIM_LIST],
        totalResults: items.length,
        startIndex: start,
        itemsPerPage: Math.min(count, Math.max(0, items.length - (start - 1))),
        Resources: items.slice(start - 1, start - 1 + count),
      },
    };
  }

  // ---- Users
  private async users(
    ctx: DirectoryContext,
    m: string,
    id: string | undefined,
    req: ScimRequest,
  ): Promise<ScimResponse> {
    if (id === undefined) {
      if (m === "GET") {
        const filter = req.query.get("filter");
        const terms = filter ? parseFilter(filter) : [];
        const all = (await this.dir.listUsers(ctx)).filter((u) =>
          matches(
            terms,
            (a) =>
              ({
                username: u.email,
                "emails.value": u.email,
                externalid: u.externalId,
                displayname: u.displayName,
                active: u.status === "active",
                id: u.id,
              })[a],
          ),
        );
        const { start, count } = this.paging(req.query);
        return this.list(all.map(userResource), start, count);
      }
      if (m === "POST") {
        const u = await this.dir.createUser(ctx, userInput(req.body));
        return { status: 201, body: userResource(u) };
      }
      throw new ScimFail(405, "method not allowed");
    }
    if (m === "GET") {
      const u = await this.dir.getUser(ctx, id);
      if (!u) throw new ScimFail(404, "User not found");
      return { status: 200, body: userResource(u) };
    }
    if (m === "PUT") {
      const i = userInput(req.body);
      const u = await this.dir.updateUser(ctx, id, i);
      return { status: 200, body: userResource(u) };
    }
    if (m === "PATCH") {
      const change = this.userPatch(req.body);
      const u = await this.dir.updateUser(ctx, id, change);
      return { status: 200, body: userResource(u) };
    }
    if (m === "DELETE") {
      if (!(await this.dir.deleteUser(ctx, id))) throw new ScimFail(404, "User not found");
      return { status: 204 };
    }
    throw new ScimFail(405, "method not allowed");
  }

  private ops(body: unknown): { op: string; path?: string; value?: unknown }[] {
    if (
      !isObj(body) ||
      !Array.isArray(body["Operations"]) ||
      body["Operations"].length === 0 ||
      body["Operations"].length > 100
    )
      throw new ScimFail(400, "Operations must be a non-empty array", "invalidSyntax");
    return body["Operations"].map((o) => {
      if (
        !isObj(o) ||
        typeof o["op"] !== "string" ||
        !["add", "replace", "remove"].includes(o["op"].toLowerCase())
      )
        throw new ScimFail(400, "invalid operation", "invalidSyntax");
      const path = str(o["path"]);
      return {
        op: o["op"].toLowerCase(),
        ...(path !== undefined ? { path } : {}),
        value: o["value"],
      };
    });
  }

  private userPatch(body: unknown): {
    userName?: string;
    email?: string;
    displayName?: string;
    active?: boolean;
  } {
    const out: { userName?: string; email?: string; displayName?: string; active?: boolean } = {};
    const apply = (key: string, v: unknown): void => {
      const k = key.toLowerCase();
      if (k === "active") {
        const b = boolish(v);
        if (b === undefined) throw new ScimFail(400, "active must be a boolean", "invalidValue");
        out.active = b;
      } else if (k === "username") {
        const s = str(v);
        if (!s) throw new ScimFail(400, "userName must be a string", "invalidValue");
        out.userName = s;
        out.email = s;
      } else if (k === "displayname" || k === "name.formatted") {
        const s = str(v);
        if (s === undefined)
          throw new ScimFail(400, "displayName must be a string", "invalidValue");
        out.displayName = s;
      } else if (k === "emails" || k.startsWith("emails[") || k === "emails.value") {
        const e = Array.isArray(v) ? emailOf({ emails: v }) : str(v);
        if (e) out.email = e;
      } else throw new ScimFail(400, `unsupported patch path: ${key.slice(0, 60)}`, "invalidPath");
    };
    for (const o of this.ops(body)) {
      if (o.op === "remove")
        throw new ScimFail(400, "remove is not supported for Users", "mutability");
      if (o.path) apply(o.path, o.value);
      else if (isObj(o.value)) for (const [k, v] of Object.entries(o.value)) apply(k, v);
      else throw new ScimFail(400, "value required", "invalidValue");
    }
    return out;
  }

  // ---- Groups
  private async groupResource(
    ctx: DirectoryContext,
    g: ScimGroup,
  ): Promise<Record<string, unknown>> {
    return groupResource(g, await this.dir.groupMembers(ctx, g.id));
  }

  private memberIds(v: unknown): string[] {
    if (!Array.isArray(v)) throw new ScimFail(400, "members must be an array", "invalidValue");
    return v.map((x) => {
      const id = isObj(x) ? str(x["value"]) : undefined;
      if (!id) throw new ScimFail(400, "member value required", "invalidValue");
      return id;
    });
  }

  private async groups(
    ctx: DirectoryContext,
    m: string,
    id: string | undefined,
    req: ScimRequest,
  ): Promise<ScimResponse> {
    if (id === undefined) {
      if (m === "GET") {
        const filter = req.query.get("filter");
        const terms = filter ? parseFilter(filter) : [];
        const all = (await this.dir.listGroups(ctx)).filter((g) =>
          matches(
            terms,
            (a) => ({ displayname: g.displayName, externalid: g.externalId, id: g.id })[a],
          ),
        );
        const { start, count } = this.paging(req.query);
        const res = await Promise.all(all.map((g) => this.groupResource(ctx, g)));
        return this.list(res, start, count);
      }
      if (m === "POST") {
        const b = req.body;
        if (!isObj(b) || !str(b["displayName"]))
          throw new ScimFail(400, "displayName is required", "invalidValue");
        const g = await this.dir.createGroup(ctx, {
          displayName: b["displayName"] as string,
          ...(str(b["externalId"]) ? { externalId: str(b["externalId"]) as string } : {}),
          memberIds: b["members"] === undefined ? [] : this.memberIds(b["members"]),
        });
        return { status: 201, body: await this.groupResource(ctx, g) };
      }
      throw new ScimFail(405, "method not allowed");
    }
    const g0 = await this.dir.getGroup(ctx, id);
    if (!g0) throw new ScimFail(404, "Group not found");
    if (m === "GET") return { status: 200, body: await this.groupResource(ctx, g0) };
    if (m === "DELETE") {
      await this.dir.deleteGroup(ctx, id);
      return { status: 204 };
    }
    if (m === "PUT") {
      const b = req.body;
      if (!isObj(b) || !str(b["displayName"]))
        throw new ScimFail(400, "displayName is required", "invalidValue");
      const g = await this.dir.updateGroup(ctx, id, { displayName: b["displayName"] as string });
      await this.dir.setMembers(
        ctx,
        id,
        b["members"] === undefined ? [] : this.memberIds(b["members"]),
      );
      return { status: 200, body: await this.groupResource(ctx, g) };
    }
    if (m === "PATCH") {
      let members = await this.dir.groupMembers(ctx, id);
      let name: string | undefined;
      for (const o of this.ops(req.body)) {
        const path = o.path?.toLowerCase();
        if (
          path === "displayname" ||
          (path === undefined && isObj(o.value) && "displayName" in o.value)
        ) {
          name = str(
            path === undefined ? (o.value as Record<string, unknown>)["displayName"] : o.value,
          );
          if (!name) throw new ScimFail(400, "displayName must be a string", "invalidValue");
        } else if (
          path === "members" ||
          (path === undefined && isObj(o.value) && "members" in o.value)
        ) {
          const v = path === undefined ? (o.value as Record<string, unknown>)["members"] : o.value;
          if (o.op === "replace") members = this.memberIds(v);
          else if (o.op === "add") members = [...new Set([...members, ...this.memberIds(v)])];
          else if (v === undefined) members = [];
          else {
            const rm = new Set(this.memberIds(v));
            members = members.filter((x) => !rm.has(x));
          }
        } else if (path?.startsWith("members[") && o.op === "remove") {
          const mm = /^members\[value\s+eq\s+"([^"]+)"\]$/i.exec(o.path as string);
          if (!mm) throw new ScimFail(400, "unsupported members path", "invalidPath");
          members = members.filter((x) => x !== mm[1]);
        } else
          throw new ScimFail(
            400,
            `unsupported patch path: ${(o.path ?? "").slice(0, 60)}`,
            "invalidPath",
          );
      }
      const g = name ? await this.dir.updateGroup(ctx, id, { displayName: name }) : g0;
      await this.dir.setMembers(ctx, id, members);
      return { status: 200, body: await this.groupResource(ctx, g) };
    }
    throw new ScimFail(405, "method not allowed");
  }
}
