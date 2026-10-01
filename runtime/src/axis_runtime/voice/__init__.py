"""Voice: streaming STT -> agent -> TTS with barge-in, consent and stage latency.

See docs/spec/voice.md.

This package is deliberately import-light: ``types`` and ``interfaces`` are imported by the model
layer (``axis_runtime.models.speech``) and must not import it back.  Import what you need from the
submodules (``voice.session``, ``voice.fakes``, ``voice.gateway`` ...).
"""
