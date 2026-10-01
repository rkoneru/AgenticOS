"""What the Risk Kernel sees of a browser action (and what the event log keeps).

Typed text is NEVER placed in the gate context or the log: only its SHA-256 and length, and not
even those when the text is sensitive (a hash of a password is an offline-guessing oracle).
An action is sensitive when the caller says so (``sensitive: true``) or the selector looks like
a credential field. The backend also refuses to type into a ``type=password`` element that was
not declared sensitive, so the declaration the gate saw is the one that is honoured.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from axis_runtime.browser.policy import canonical_hash, safe_url, sha256_hex

OPERATIONS = ("navigate", "click", "type", "extract", "screenshot")
_SENSITIVE_SELECTOR = re.compile(
    r"pass(word|wd|code)?|pwd|secret|token|otp|cvv|cvc|card|ssn|pin\b|credential|2fa|mfa",
    re.IGNORECASE,
)


def operation_of(args: Mapping[str, Any]) -> str:
    op = args.get("operation")
    if isinstance(op, str) and op:
        return op
    return "navigate" if "url" in args else ""


def is_sensitive(args: Mapping[str, Any]) -> bool:
    if args.get("sensitive") is True:
        return True
    selector = args.get("selector")
    return isinstance(selector, str) and bool(_SENSITIVE_SELECTOR.search(selector))


def target_url_of(args: Mapping[str, Any], target_url: str) -> str:
    """The URL the operation acts on: the navigation target, else the page it runs against."""
    if operation_of(args) == "navigate":
        url = args.get("url")
        return url if isinstance(url, str) else ""
    return target_url


def gate_view(args: Mapping[str, Any], target_url: str) -> dict[str, Any]:
    """The ``args.*`` document of a browser action for the gate."""
    url = target_url_of(args, target_url)
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    op = operation_of(args)
    sensitive = is_sensitive(args)
    doc: dict[str, Any] = {
        "operation": op,
        "url": safe_url(url) if url else "",
        "host": host,
        "sensitive": sensitive,
    }
    selector = args.get("selector")
    if isinstance(selector, str):
        doc["selector"] = selector[:500]
    text = args.get("text")
    hashed = {k: v for k, v in args.items() if not (sensitive and k == "text")}
    if isinstance(text, str):
        doc["text_len"] = None if sensitive else len(text)
        doc["text_sha256"] = None if sensitive else sha256_hex(text)
    doc["args_hash"] = canonical_hash(hashed)
    return doc


def merge_redacted(args: Mapping[str, Any], doc: Mapping[str, Any]) -> dict[str, Any]:
    """Apply a redacted gate view back onto the real arguments (only fields the view carries)."""
    out = dict(args)
    if "selector" in doc and isinstance(args.get("selector"), str):
        out["selector"] = doc["selector"]
    if operation_of(args) == "navigate" and "url" in args and isinstance(doc.get("url"), str):
        # the view holds a sanitised URL; only a redaction marker may replace the real one
        if doc["url"] != safe_url(str(args["url"])):
            out["url"] = doc["url"]
    return out
