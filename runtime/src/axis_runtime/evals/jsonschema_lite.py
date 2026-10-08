"""A small, strict JSON Schema validator for the ``json_schema`` grader.

The runtime has no JSON Schema dependency and a grader must not execute arbitrary schema features
(remote ``$ref``, unbounded regex). This supports the subset real eval suites use. An unsupported
keyword is a ``SchemaError`` (the grader reports ``error``, scoring 0): silently ignoring a keyword
would make a stricter schema pass more outputs than its author meant.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from axis_runtime.nexus.rules import UnsafePatternError, compile_safe

MAX_DEPTH = 24
MAX_ERRORS = 10

_ANNOTATIONS = frozenset(
    {"$schema", "$id", "title", "description", "default", "examples", "$comment", "format"}
)
_KEYWORDS = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "enum",
        "const",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
        "anyOf",
        "oneOf",
        "allOf",
    }
)
_TYPES = frozenset({"string", "number", "integer", "boolean", "null", "object", "array"})


class SchemaError(ValueError):
    """The schema itself is unusable (unknown keyword, bad regex, too deep)."""


def _is_type(value: Any, name: str) -> bool:
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer()
        )
    if name == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if name == "object":
        return isinstance(value, Mapping)
    return isinstance(value, list)


def _number(schema: Mapping[str, Any], key: str) -> float:
    v = schema[key]
    if isinstance(v, bool) or not isinstance(v, int | float):
        raise SchemaError(f"{key} must be a number")
    return float(v)


def _walk(schema: Any, value: Any, path: str, depth: int, errors: list[str]) -> None:
    if depth > MAX_DEPTH:
        raise SchemaError("schema or instance too deep")
    if schema is True:
        return
    if schema is False:
        errors.append(f"{path}: no value is allowed here")
        return
    if not isinstance(schema, Mapping):
        raise SchemaError("a schema must be an object or a boolean")
    unknown = set(schema) - _KEYWORDS - _ANNOTATIONS
    if unknown:
        raise SchemaError(f"unsupported keyword {sorted(unknown)[0]!r}")
    if "type" in schema:
        t = schema["type"]
        names = [t] if isinstance(t, str) else t
        if not isinstance(names, list) or not names or not set(names) <= _TYPES:
            raise SchemaError("type must name JSON types")
        if not any(_is_type(value, n) for n in names):
            errors.append(f"{path}: wrong type")
            return
    if "const" in schema and schema["const"] != value:
        errors.append(f"{path}: not the required constant")
    if "enum" in schema:
        if not isinstance(schema["enum"], list):
            raise SchemaError("enum must be a list")
        if value not in schema["enum"]:
            errors.append(f"{path}: not one of the allowed values")
    if isinstance(value, int | float) and not isinstance(value, bool):
        for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            if key not in schema:
                continue
            bound = _number(schema, key)
            bad = {
                "minimum": value < bound,
                "maximum": value > bound,
                "exclusiveMinimum": value <= bound,
                "exclusiveMaximum": value >= bound,
            }[key]
            if bad:
                errors.append(f"{path}: violates {key}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < _number(schema, "minLength"):
            errors.append(f"{path}: too short")
        if "maxLength" in schema and len(value) > _number(schema, "maxLength"):
            errors.append(f"{path}: too long")
        if "pattern" in schema:
            pat = schema["pattern"]
            if not isinstance(pat, str):
                raise SchemaError("pattern must be a string")
            try:
                compile_safe(pat)
                compiled = re.compile(pat)
            except (UnsafePatternError, re.error) as exc:
                raise SchemaError("unusable pattern") from exc
            if compiled.search(value[:100_000]) is None:
                errors.append(f"{path}: does not match the pattern")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < _number(schema, "minItems"):
            errors.append(f"{path}: too few items")
        if "maxItems" in schema and len(value) > _number(schema, "maxItems"):
            errors.append(f"{path}: too many items")
        if "items" in schema:
            for i, item in enumerate(value):
                _walk(schema["items"], item, f"{path}[{i}]", depth + 1, errors)
                if len(errors) >= MAX_ERRORS:
                    return
    if isinstance(value, Mapping):
        props = schema.get("properties", {})
        if not isinstance(props, Mapping):
            raise SchemaError("properties must be an object")
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise SchemaError("required must be a list")
        for name in required:
            if name not in value:
                errors.append(f"{path}.{name}: required")
        for name, sub in props.items():
            if name in value:
                _walk(sub, value[name], f"{path}.{name}", depth + 1, errors)
        extra = schema.get("additionalProperties", True)
        for name in value:
            if name not in props:
                if extra is False:
                    errors.append(f"{path}.{name}: additional property")
                elif extra is not True:
                    _walk(extra, value[name], f"{path}.{name}", depth + 1, errors)
    for key in ("allOf", "anyOf", "oneOf"):
        if key not in schema:
            continue
        subs = schema[key]
        if not isinstance(subs, list) or not subs:
            raise SchemaError(f"{key} must be a non-empty list")
        results = []
        for sub in subs:
            sub_errors: list[str] = []
            _walk(sub, value, path, depth + 1, sub_errors)
            results.append(sub_errors)
        ok = sum(1 for r in results if not r)
        if key == "allOf":
            for r in results:
                errors.extend(r)
        elif key == "anyOf" and ok == 0:
            errors.append(f"{path}: matches none of anyOf")
        elif key == "oneOf" and ok != 1:
            errors.append(f"{path}: must match exactly one of oneOf")


def validate(schema: Any, value: Any) -> list[str]:
    """Violations of ``value`` against ``schema`` (empty means valid). Raises ``SchemaError``."""
    errors: list[str] = []
    _walk(schema, value, "$", 0, errors)
    return errors[:MAX_ERRORS]
