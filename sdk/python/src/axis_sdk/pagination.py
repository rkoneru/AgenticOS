"""Cursor pagination iterators."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from typing import Any

PageFn = Callable[[str | None], dict[str, Any]]
AsyncPageFn = Callable[[str | None], Awaitable[dict[str, Any]]]


def paginate(fetch: PageFn, max_items: int | None = None) -> Iterator[Any]:
    """Follow ``next_cursor`` until the server stops returning one (or ``max_items`` is reached)."""
    cursor: str | None = None
    n = 0
    while True:
        page = fetch(cursor)
        items = page.get("items", [])
        for item in items:
            if max_items is not None and n >= max_items:
                return
            n += 1
            yield item
        nxt = page.get("next_cursor")
        if not nxt or (not items and nxt == cursor):
            return
        cursor = nxt


async def apaginate(fetch: AsyncPageFn, max_items: int | None = None) -> AsyncIterator[Any]:
    cursor: str | None = None
    n = 0
    while True:
        page = await fetch(cursor)
        items = page.get("items", [])
        for item in items:
            if max_items is not None and n >= max_items:
                return
            n += 1
            yield item
        nxt = page.get("next_cursor")
        if not nxt or (not items and nxt == cursor):
            return
        cursor = nxt
