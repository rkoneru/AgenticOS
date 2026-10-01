"""Errors the session maps to a call end reason."""

from __future__ import annotations


class SpeechDeniedError(RuntimeError):
    """The gate (or tenant policy) refused a speech action: the call cannot use that provider."""


class SpeechUnavailableError(RuntimeError):
    """A speech provider failed or could not be reached (never carries credentials)."""
