"""Field-path redaction for ALLOW_WITH_REDACTION.

Paths are dot-separated over the gate context document (``args.ssn``, ``args.items.0.name``,
``result.rows.*.email``).  ``*`` matches every list element / dict value.  A path that does not
exist is a no-op.  A malformed path raises ``RedactionPathError`` (the executor turns that into
a DENY: fail closed, never perform with unredacted data).
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Any

REDACTED = "[REDACTED]"


class RedactionPathError(ValueError):
    pass


def parse_path(path: str) -> list[str]:
    parts = path.split(".")
    if not path or any(p == "" for p in parts):
        raise RedactionPathError("malformed redaction path")
    return parts


def _apply(node: Any, parts: list[str]) -> Any:
    head, rest = parts[0], parts[1:]
    if isinstance(node, dict):
        keys = list(node) if head == "*" else ([head] if head in node else [])
        for k in keys:
            node[k] = REDACTED if not rest else _apply(node[k], rest)
    elif isinstance(node, list):
        if head == "*":
            idxs = list(range(len(node)))
        elif head.isdigit() and int(head) < len(node):
            idxs = [int(head)]
        else:
            idxs = []
        for i in idxs:
            node[i] = REDACTED if not rest else _apply(node[i], rest)
    return node


def redact_paths(doc: Any, paths: Iterable[str]) -> Any:
    """Return a deep copy of ``doc`` with every matching path replaced by ``REDACTED``."""
    parsed = [parse_path(p) for p in paths]  # validate all paths before touching anything
    out = copy.deepcopy(doc)
    for parts in parsed:
        out = _apply(out, parts)
    return out


def split_scope(paths: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split gate paths into (args paths, result paths) with the scope prefix removed.

    ``args.x`` applies to arguments, ``result.x`` to results, and an unprefixed path to both.
    """
    args: list[str] = []
    result: list[str] = []
    for p in paths:
        if p == "args":
            args.append("*")
        elif p == "result":
            result.append("*")
        elif p.startswith("args."):
            args.append(p[len("args.") :])
        elif p.startswith("result."):
            result.append(p[len("result.") :])
        else:
            args.append(p)
            result.append(p)
    return args, result
