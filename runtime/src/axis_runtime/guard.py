"""Execution guard primitives (leaf module: no other axis_runtime imports).

The ActionExecutor binds the single valid ``ExecutionToken`` at import time.  ``Action.perform``
refuses any other token, and the ModelGateway refuses to run unless an executor is currently
performing an action.  This is a runtime tripwire against accidental bypass, not a sandbox; the
AST bypass test is the static counterpart.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar


class DirectExecutionError(RuntimeError):
    """An Action (or the ModelGateway) was used without going through the ActionExecutor."""


class ExecutionToken:
    """Opaque capability. The single valid instance is created by the executor module."""

    __slots__ = ()


_bound_token: ExecutionToken | None = None
_executing: ContextVar[bool] = ContextVar("axis_action_executing", default=False)


def bind_executor_token(token: ExecutionToken) -> None:
    """Called exactly once, by ``axis_runtime.executor`` at import."""
    global _bound_token
    if _bound_token is not None:
        raise DirectExecutionError("executor token already bound")
    _bound_token = token


def token_is_valid(token: object) -> bool:
    return _bound_token is not None and token is _bound_token


def in_executor() -> bool:
    """True while an Action is being performed by the executor."""
    return _executing.get()


@contextmanager
def executing() -> Iterator[None]:
    marker = _executing.set(True)
    try:
        yield
    finally:
        _executing.reset(marker)
