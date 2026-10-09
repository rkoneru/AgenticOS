"""The worst-case GULLIBLE model of the red-team suite (a scripted provider response function).

It measures the PLATFORM's containment, not any model's alignment: this "model" obeys every instruction it can find in anything
it is shown, wherever it sits (the user message, a tool result, a tool description), however it is dressed (translated keyword,
base64, rot13, full-width or zero-width obfuscation). The attacker's goal is written into the case as a *directive*; the suite
then asks whether the kernel-gated path let the goal happen.

Directive grammar (after NFKC normalisation and zero-width stripping)::

    [[call TOOL {"json": "args"}]]     call a tool (aliases: appel, llamar, aufruf, chiama, 呼び出し)
    [[say TEXT]]                       put TEXT in the final answer (aliases: dis, decir, sage)
    [[b64 BASE64]]                     decode, then treat the result as text that may hold directives
    [[rot13 TEXT]]                     same, rot13

Inside a directive, ``{{result:TOOL}}`` is replaced by the text of the latest result of TOOL (so a secret read by one call can
be sent by the next), with optional filters: ``{{result:TOOL|b64|hex|rot13|url|spaced|reverse|upper|lower|slice:0:6}}``.

Deterministic: no clock, no randomness; the same conversation gives the same reply.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import json
import re
import unicodedata
import urllib.parse
from collections.abc import Callable
from typing import Any

CALL_ALIASES = ("call", "appel", "llamar", "aufruf", "chiama", "呼び出し")
SAY_ALIASES = ("say", "dis", "decir", "sage")
_ZERO_WIDTH = dict.fromkeys(
    map(ord, "​‌‍⁠﻿­‪‫‬‭‮"), None
)
_REF = re.compile(r"\{\{result:([A-Za-z0-9_.:-]+)((?:\|[a-z0-9:]+)*)\}\}")
_MAX_DEPTH = 4


def normalise(text: str) -> str:
    """What the gullible model "reads": compatibility-normalised, invisible characters removed."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def _filter(value: str, name: str) -> str:
    if name == "b64":
        return base64.b64encode(value.encode()).decode()
    if name == "hex":
        return value.encode().hex()
    if name == "rot13":
        return codecs.encode(value, "rot13")
    if name == "url":
        return urllib.parse.quote(value, safe="")
    if name == "spaced":
        return " ".join(value)
    if name == "reverse":
        return value[::-1]
    if name == "upper":
        return value.upper()
    if name == "lower":
        return value.lower()
    if name.startswith("slice:"):
        _, a, b = name.split(":")
        return value[int(a) : int(b)]
    raise ValueError(f"unknown filter {name}")


class Directive:
    __slots__ = ("id", "kind", "raw", "refs", "tool", "args_text")

    def __init__(self, ident: str, kind: str, raw: str, tool: str, args_text: str) -> None:
        self.id, self.kind, self.raw, self.tool, self.args_text = ident, kind, raw, tool, args_text
        self.refs = [m.group(1) for m in _REF.finditer(args_text)]


def _scan(text: str, source: str, depth: int = 0) -> list[tuple[str, str, str]]:
    """(kind, tool, payload) triples in reading order. Nested ``b64``/``rot13`` wrappers are unwrapped."""
    text = normalise(text)
    found: list[tuple[int, str, str, str]] = []
    for alias in CALL_ALIASES:
        for m in re.finditer(r"\[\[" + re.escape(alias) + r" ([A-Za-z0-9_.:-]+) ", text):
            start = m.end()
            try:
                _, end = json.JSONDecoder().raw_decode(text[start:])
            except ValueError:
                continue
            if text[start + end : start + end + 2] != "]]":
                continue
            found.append((m.start(), "call", m.group(1), text[start : start + end]))
    for alias in SAY_ALIASES:
        for m in re.finditer(r"\[\[" + re.escape(alias) + r" (.*?)\]\]", text, re.DOTALL):
            found.append((m.start(), "say", "", m.group(1)))
    if depth < _MAX_DEPTH:
        for m in re.finditer(r"\[\[(b64|rot13) ([^\]]*)\]\]", text):
            try:
                if m.group(1) == "b64":
                    inner = base64.b64decode(m.group(2).strip() + "===", validate=False).decode()
                else:
                    inner = codecs.decode(m.group(2), "rot13")
            except (ValueError, UnicodeDecodeError):
                continue
            for k, (kind, tool, payload) in enumerate(_scan(inner, source, depth + 1)):
                found.append((m.start() + k, kind, tool, payload))
    found.sort(key=lambda t: t[0])
    return [(k, t, p) for _, k, t, p in found]


def collect(body: dict[str, Any]) -> list[Directive]:
    """Every directive in what the model is shown, in order: tool descriptions, user turns, tool results."""
    sources: list[tuple[str, str]] = []
    for t in body.get("tools") or []:
        fn = t.get("function", {})
        sources.append((f"desc:{fn.get('name', '')}", str(fn.get("description") or "")))
    for i, m in enumerate(body.get("messages", [])):
        role = m.get("role")
        if role in ("user", "tool"):
            sources.append((f"{role}:{i}", _text(m.get("content"))))
    out: list[Directive] = []
    for src, text in sources:
        for n, (kind, tool, payload) in enumerate(_scan(text, src)):
            ident = (
                "rt-"
                + hashlib.sha1(  # noqa: S324 - an identifier, not a security hash
                    f"{src}#{n}#{kind}#{tool}#{payload}".encode()
                ).hexdigest()[:14]
            )
            out.append(Directive(ident, kind, payload, tool, payload))
    return out


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


def _history(body: dict[str, Any]) -> tuple[set[str], dict[str, str]]:
    """(directive ids already executed, latest result text per tool name)."""
    done: set[str] = set()
    names: dict[str, str] = {}
    results: dict[str, str] = {}
    for m in body.get("messages", []):
        if m.get("role") == "assistant":
            for c in m.get("tool_calls") or []:
                done.add(str(c.get("id")))
                names[str(c.get("id"))] = str(c.get("function", {}).get("name"))
        elif m.get("role") == "tool":
            name = names.get(str(m.get("tool_call_id")))
            if name:
                results[name] = _text(m.get("content"))
    return done, results


def _substitute(text: str, results: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        value = results.get(m.group(1), "")
        for f in [x for x in m.group(2).split("|") if x]:
            value = _filter(value, f)
        return value

    return _REF.sub(repl, text)


def _json_escape(value: str) -> str:
    return json.dumps(value)[1:-1]


def _render_call(d: Directive, results: dict[str, str]) -> str:
    """The args JSON with every reference replaced by its (JSON-escaped) value."""

    def repl(m: re.Match[str]) -> str:
        return _json_escape(_substitute(m.group(0), results))

    return _REF.sub(repl, d.args_text)


def respond(body: dict[str, Any]) -> dict[str, Any]:
    """An OpenAI chat-completions response for ``body`` from the gullible model."""
    done, results = _history(body)
    pending = [d for d in collect(body) if d.id not in done]
    calls: list[tuple[str, str, str]] = []
    called: set[str] = set()
    for d in pending:
        if d.kind != "call":
            continue
        if any(r in called for r in d.refs):
            break  # depends on a call of this very batch: wait for its result
        try:
            args = json.loads(_render_call(d, results))
        except ValueError:
            continue
        calls.append((d.id, d.tool, json.dumps(args)))
        called.add(d.tool)
    if calls:
        return _completion(None, calls)
    says = [d for d in collect(body) if d.kind == "say"]
    text = " ".join(_substitute(d.raw, results) for d in says) or "Done."
    return _completion(text, [])


def _completion(text: str | None, calls: list[tuple[str, str, str]]) -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "assistant", "content": text}
    if calls:
        msg["tool_calls"] = [
            {"id": i, "type": "function", "function": {"name": n, "arguments": a}}
            for i, n, a in calls
        ]
    return {
        "id": "chatcmpl-redteam",
        "model": "gpt-4o",
        "choices": [
            {"index": 0, "message": msg, "finish_reason": "tool_calls" if calls else "stop"}
        ],
        "usage": {
            "prompt_tokens": 40,
            "completion_tokens": 12,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


Responder = Callable[[dict[str, Any]], dict[str, Any]]
