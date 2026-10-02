"""In-test mock AXIS server generated from the OpenAPI (tests/fixtures/mock-model.json, derived by the generator).

An ``httpx.MockTransport`` handler that authenticates, validates path/query/header parameters and JSON bodies
against the operation schemas (recording violations), and answers with responses synthesized from the schemas.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx

MODEL: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "mock-model.json").read_text()
)
OPS: list[dict[str, Any]] = MODEL["operations"]

_PATTERN_SAMPLES = {
    "^axp_[0-9A-HJKMNP-TV-Z]{26}$": "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "^[0-9a-f]{64}$": "a" * 64,
    "^[0-9a-f]{32}$": "b" * 32,
}
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _types(schema: dict[str, Any]) -> list[str]:
    t = schema.get("type")
    return t if isinstance(t, list) else [t] if t else []


def merged(schema: dict[str, Any]) -> dict[str, Any]:
    if "allOf" not in schema:
        return schema
    out: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
    for part in schema["allOf"]:
        part = merged(part)
        out["properties"].update(part.get("properties", {}))
        out["required"] += part.get("required", [])
    return out


def synthesize(schema: dict[str, Any]) -> Any:
    schema = merged(schema)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    types = _types(schema)
    if "null" in types:
        return None
    t = types[0] if types else None
    if t == "string":
        if schema.get("format") == "uuid":
            return "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"
        if schema.get("format") == "date-time":
            return "2026-01-01T00:00:00.000Z"
        if "pattern" in schema:
            p = schema["pattern"]
            if p in _PATTERN_SAMPLES:
                return _PATTERN_SAMPLES[p]
            if p.startswith("^\\d{4}"):
                return "2026-01-01T00:00:00.000Z"
            raise AssertionError(f"no sample for pattern {p}")
        return "x" * max(1, schema.get("minLength", 1))
    if t == "integer":
        return max(1, schema.get("minimum", 1))
    if t == "number":
        return 1
    if t == "boolean":
        return True
    if t == "array":
        return [synthesize(schema.get("items", {}))]
    if t == "object" or "properties" in schema:
        if "x-external" in schema:
            return {}
        return {k: synthesize(v) for k, v in schema.get("properties", {}).items()}
    return {}


def validate(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    """JSON Schema subset used by the spec."""
    schema = merged(schema)
    errs: list[str] = []
    if "const" in schema and value != schema["const"]:
        return [f"{path}: expected const {schema['const']!r}"]
    if "enum" in schema:
        return [] if value in schema["enum"] else [f"{path}: {value!r} not in enum"]
    types = _types(schema)
    if types:
        ok = any(
            (t == "null" and value is None)
            or (t == "string" and isinstance(value, str))
            or (t == "boolean" and isinstance(value, bool))
            or (t == "integer" and isinstance(value, int) and not isinstance(value, bool))
            or (t == "number" and isinstance(value, int | float) and not isinstance(value, bool))
            or (t == "array" and isinstance(value, list))
            or (t == "object" and isinstance(value, dict))
            for t in types
        )
        if not ok:
            return [f"{path}: expected {types}, got {type(value).__name__}"]
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path}: pattern")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 10**9):
            errs.append(f"{path}: length")
        if schema.get("format") == "uuid" and not _UUID.match(value):
            errs.append(f"{path}: uuid")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if value < schema.get("minimum", float("-inf")) or value > schema.get(
            "maximum", float("inf")
        ):
            errs.append(f"{path}: range")
    if isinstance(value, list):
        for i, item in enumerate(value):
            errs += validate(schema.get("items", {}), item, f"{path}[{i}]")
    if isinstance(value, dict) and "x-external" not in schema:
        props = schema.get("properties", {})
        for r in schema.get("required", []):
            if r not in value:
                errs.append(f"{path}: missing {r}")
        for k, v in value.items():
            if k in props:
                errs += validate(props[k], v, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errs.append(f"{path}: unexpected {k}")
    return errs


def problem(
    status: int, code: str, headers: dict[str, str] | None = None, **extra: Any
) -> httpx.Response:
    body = {
        "type": f"https://axis.example/problems/{code}",
        "title": code.replace("_", " "),
        "status": status,
        "code": code,
        **extra,
    }
    return httpx.Response(
        status, json=body, headers={"content-type": "application/problem+json", **(headers or {})}
    )


def sample_params(operation_id: str) -> dict[str, Any]:
    """Valid path/query/body values for an operation (wire names)."""
    op = next(o for o in OPS if o["operationId"] == operation_id)
    out: dict[str, Any] = {}
    for p in op["parameters"]:
        if p["in"] == "path" or (p["in"] == "query" and p.get("required")):
            out[p["name"]] = synthesize(p["schema"])
    schema = (
        ((op.get("requestBody") or {}).get("content") or {})
        .get("application/json", {})
        .get("schema")
    )
    if schema:
        out["body"] = synthesize(schema)
    return out


@dataclass
class Call:
    operation_id: str
    method: str
    url: httpx.URL
    headers: httpx.Headers
    body: Any


Override = Callable[[Call, int], httpx.Response | None]


@dataclass
class MockServer:
    base_url: str = "https://api.test.axis.example/v1"
    overrides: dict[str, Override] = field(default_factory=dict)
    calls: list[Call] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    _counts: dict[str, int] = field(default_factory=dict)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        base = httpx.URL(self.base_url)
        if (url.scheme, url.host) != (base.scheme, base.host):
            raise httpx.ConnectError(f"mock: unexpected origin {url.host}")
        rel = url.raw_path.decode().split("?")[0][len(base.path) :]
        route = None
        for op in OPS:
            if op["method"] != request.method:
                continue
            rx = "^" + re.sub(r"\\\{[^}]+\\\}", "([^/]+)", re.escape(op["path"])) + "$"
            m = re.match(rx, rel)
            if m:
                route = (op, m)
                break
        if route is None:
            return problem(404, "not_found", detail=f"no route for {request.method} {rel}")
        op, m = route
        body = json.loads(request.content) if request.content else None
        call = Call(op["operationId"], request.method, url, request.headers, body)
        self.calls.append(call)
        n = self._counts.get(op["operationId"], 0) + 1
        self._counts[op["operationId"]] = n

        def bad(msg: str) -> None:
            self.violations.append(f"{op['operationId']}: {msg}")

        ov = self.overrides.get(op["operationId"])
        if ov is not None:
            r = ov(call, n)
            if r is not None:
                return r
        cred = request.headers.get("x-axis-api-key") or re.sub(
            r"^Bearer ", "", request.headers.get("authorization", "")
        )
        if not cred:
            return problem(401, "unauthenticated")
        names = re.findall(r"\{([^}]+)\}", op["path"])
        for name, raw in zip(names, m.groups(), strict=True):
            p = next((x for x in op["parameters"] if x["in"] == "path" and x["name"] == name), None)
            pv: Any = unquote(raw)
            if p is not None and p["schema"].get("type") == "integer" and pv.isdigit():
                pv = int(pv)
            if p is None or validate(p["schema"], pv):
                bad(f"path param {name} invalid")
        declared = {p["name"] for p in op["parameters"] if p["in"] == "query"}
        for p in op["parameters"]:
            if p["in"] == "query":
                raw_v = url.params.get(p["name"])
                if raw_v is None:
                    if p.get("required"):
                        bad(f"missing required query {p['name']}")
                    continue
                t = p["schema"].get("type")
                val: Any = int(raw_v) if t == "integer" and raw_v.lstrip("-").isdigit() else raw_v
                if validate(p["schema"], val):
                    bad(f"query {p['name']}={raw_v} invalid")
            if p["in"] == "header":
                hv = request.headers.get(p["name"])
                if hv is None:
                    if p.get("required"):
                        bad(f"missing header {p['name']}")
                elif validate(p["schema"], hv):
                    bad(f"header {p['name']} invalid")
        for k in url.params:
            if k not in declared:
                bad(f"unknown query {k}")
        rb = op.get("requestBody")
        if rb:
            schema = rb["content"]["application/json"]["schema"]
            if body is None:
                if rb.get("required"):
                    bad("missing required body")
            else:
                errs = validate(schema, body)
                if errs:
                    bad(f"body invalid: {errs[:2]}")
                if request.headers.get("content-type") != "application/json":
                    bad("content-type must be application/json")
        elif body is not None:
            bad("unexpected body")
        status = next(c for c in op["responses"] if re.match(r"^2\d\d$", c))
        content = op["responses"][status].get("content") or {}
        if (
            "text/event-stream" in request.headers.get("accept", "")
            and "text/event-stream" in content
        ):
            ev = synthesize(content["application/json"]["schema"])["items"][0]
            return httpx.Response(
                200,
                text=f"id: {ev['sequence']}\ndata: {json.dumps(ev)}\n\n",
                headers={"content-type": "text/event-stream"},
            )
        schema2 = (content.get("application/json") or {}).get("schema")
        if not schema2:
            return httpx.Response(int(status))
        value = synthesize(schema2)
        assert not validate(schema2, value), f"synthesized response invalid for {op['operationId']}"
        return httpx.Response(
            int(status), json=value, headers={"x-request-id": f"req-{len(self.calls)}"}
        )
