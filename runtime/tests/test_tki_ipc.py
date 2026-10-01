"""TKI IPC: envelope contract, bounded tenant-isolated mailboxes, audit-before-deliver."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from axis_runtime.process import new_pid
from axis_runtime.tki import Envelope, Kind, ListSink, MessageRouter, TkiEvent, TkiEventType
from axis_runtime.tki.ipc import (
    SCHEMA_VERSION,
    EnvelopeError,
    IpcAuditError,
    IpcDeniedError,
    IpcError,
    Mailbox,
    MailboxFullError,
    new_uuid4,
)
from conftest import FakeClock
from tki_helpers import T1, T2, TRACE, allow_all, env

SCHEMA = (
    Path(__file__).resolve().parents[2] / "packages/contracts/schemas/ipc-envelope-v1.schema.json"
)


def valid_doc(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema_version": 1,
        "id": new_uuid4(),
        "tenant_id": T1,
        "trace_id": TRACE,
        "from": new_pid(),
        "to": new_pid(),
        "kind": "message",
        "ts": "2026-01-01T00:00:00.000Z",
        "payload": {"a": 1},
    }
    doc.update(over)
    return doc


# ---- envelope ------------------------------------------------------------------------------------


def test_envelope_roundtrip_and_contract_constants() -> None:
    schema = json.loads(SCHEMA.read_text())
    assert SCHEMA_VERSION == schema["properties"]["schema_version"]["const"]
    doc = valid_doc(correlation_id=new_uuid4(), ttl_seconds=30, kind="request")
    assert Envelope.from_dict(doc).to_dict() == doc
    assert set(valid_doc(correlation_id=new_uuid4(), ttl_seconds=3)) <= set(schema["properties"])


def test_new_uuid4_is_a_valid_v4() -> None:
    import uuid

    for _ in range(50):
        u = uuid.UUID(new_uuid4())
        assert u.version == 4 and u.variant == uuid.RFC_4122


@pytest.mark.parametrize(
    "over",
    [
        {"schema_version": 2},
        {"id": "nope"},
        {"id": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
        {"tenant_id": "x"},
        {"trace_id": "short"},
        {"from": "axp_short"},
        {"to": "somebody"},
        {"to": "chan:Bad Name"},
        {"kind": "shout"},
        {"payload": "text"},
        {"kind": "response"},  # missing correlation_id
        {"correlation_id": "nope"},
        {"ttl_seconds": 0},
        {"ttl_seconds": 86401},
        {"ttl_seconds": True},
        {"ttl_seconds": "5"},
        {"ts": "yesterday"},
        {"extra": 1},
    ],
)
def test_invalid_envelopes_are_rejected(over: dict[str, Any]) -> None:
    with pytest.raises(EnvelopeError):
        Envelope.from_dict(valid_doc(**over))


def test_missing_fields_rejected() -> None:
    doc = valid_doc()
    del doc["payload"]
    with pytest.raises(EnvelopeError):
        Envelope.from_dict(doc)


def test_channel_and_response_with_correlation_are_valid() -> None:
    Envelope.from_dict(valid_doc(to="chan:alerts.v1"))
    Envelope.from_dict(valid_doc(kind="response", correlation_id=new_uuid4()))


def test_expiry() -> None:
    clock = FakeClock()
    e = Envelope.new(
        tenant_id=T1, trace_id=TRACE, sender=new_pid(), to=new_pid(), kind=Kind.EVENT,
        payload={}, clock=clock, ttl_seconds=10,
    )  # fmt: skip
    assert not e.expired(clock.now() + timedelta(seconds=9))
    assert e.expired(clock.now() + timedelta(seconds=10))
    assert not env(new_pid(), new_pid()).expired(clock.now() + timedelta(days=999))


# ---- mailbox -------------------------------------------------------------------------------------


def make_box(capacity: int = 2, clock: FakeClock | None = None) -> tuple[Mailbox, list[Envelope]]:
    expired: list[Envelope] = []
    return Mailbox(new_pid(), T1, capacity, clock or FakeClock(), expired.append), expired


def test_mailbox_is_bounded_and_fifo() -> None:
    box, _ = make_box(2)
    a, b, c = (env(new_pid(), box.pid, payload={"n": n}) for n in range(3))
    box.put_nowait(a)
    box.put_nowait(b)
    assert box.full and len(box) == 2
    with pytest.raises(MailboxFullError):
        box.put_nowait(c)
    assert box.receive_nowait() is a and box.receive_nowait() is b
    assert box.receive_nowait() is None


def test_mailbox_capacity_must_be_positive() -> None:
    with pytest.raises(ValueError):
        Mailbox(new_pid(), T1, 0, FakeClock(), lambda _e: None)


async def test_mailbox_receive_waits_times_out_and_closes() -> None:
    box, _ = make_box()
    task = asyncio.create_task(box.receive())
    await asyncio.sleep(0.01)
    assert not task.done()
    msg = env(new_pid(), box.pid)
    box.put_nowait(msg)
    assert await task is msg
    with pytest.raises(TimeoutError):
        await box.receive(0.01)
    waiter = asyncio.create_task(box.receive())
    await asyncio.sleep(0.01)
    box.close()
    with pytest.raises(IpcError):
        await waiter
    with pytest.raises(IpcDeniedError):
        box.put_nowait(msg)
    assert box.closed


def test_mailbox_drops_expired_messages_with_a_callback() -> None:
    clock = FakeClock()
    box, expired = make_box(4, clock)
    stale = Envelope.new(
        tenant_id=T1, trace_id=TRACE, sender=new_pid(), to=box.pid, kind=Kind.EVENT,
        payload={}, clock=clock, ttl_seconds=5,
    )  # fmt: skip
    live = env(new_pid(), box.pid)
    box.put_nowait(stale)
    box.put_nowait(live)
    clock.t += timedelta(seconds=6)
    assert box.receive_nowait() is live
    assert expired == [stale]


# ---- router --------------------------------------------------------------------------------------


def make_router(
    authorize: Any = allow_all, capacity: int = 4
) -> tuple[MessageRouter, ListSink, FakeClock]:
    sink, clock = ListSink(), FakeClock()
    return (
        MessageRouter(sink=sink, authorize=authorize, clock=clock, default_capacity=capacity),
        sink,
        clock,
    )


async def test_send_delivers_and_is_audited_first() -> None:
    router, sink, _ = make_router()
    a, b = new_pid(), new_pid()
    router.register(a, T1)
    box = router.register(b, T1)
    msg = env(a, b)
    assert await router.send(msg) == 1
    assert box.receive_nowait() is msg
    (ev,) = sink.of(TkiEventType.IPC_SENT)
    assert ev.pid == a and ev.tenant_id == T1 and ev.data["message_id"] == msg.id
    assert ev.data["recipients"] == [b] and ev.data["trace_id"] == TRACE


async def test_cross_tenant_send_is_denied_and_indistinguishable_from_unknown() -> None:
    router, sink, _ = make_router()
    a, victim, ghost = new_pid(), new_pid(), new_pid()
    router.register(a, T1)
    box = router.register(victim, T2)  # another tenant's process
    with pytest.raises(IpcDeniedError) as cross:
        await router.send(env(a, victim))
    with pytest.raises(IpcDeniedError) as unknown:
        await router.send(env(a, ghost))
    assert str(cross.value) == str(unknown.value) == "recipient unavailable"
    assert len(box) == 0
    assert len(sink.of(TkiEventType.IPC_DENIED)) == 2


async def test_sender_cannot_spoof_another_tenant_or_pid() -> None:
    router, _, _ = make_router()
    a, b, ghost = new_pid(), new_pid(), new_pid()
    router.register(a, T1)
    box = router.register(b, T2)
    with pytest.raises(IpcDeniedError):  # a (tenant 1) claims tenant 2 in the envelope
        await router.send(env(a, b, tenant=T2))
    with pytest.raises(IpcDeniedError):  # unregistered sender
        await router.send(env(ghost, b, tenant=T2))
    assert len(box) == 0


async def test_unregistered_recipient_after_unregister() -> None:
    router, _, _ = make_router()
    a, b = new_pid(), new_pid()
    router.register(a, T1)
    router.register(b, T1)
    router.unregister(b)
    router.unregister(b)  # idempotent
    with pytest.raises(IpcDeniedError):
        await router.send(env(a, b))
    assert router.mailbox(b) is None


async def test_full_mailbox_is_back_pressure_and_audited() -> None:
    router, sink, _ = make_router(capacity=1)
    a, b = new_pid(), new_pid()
    router.register(a, T1)
    router.register(b, T1)
    await router.send(env(a, b))
    with pytest.raises(IpcDeniedError, match="mailbox full"):
        await router.send(env(a, b))
    assert sink.of(TkiEventType.IPC_DENIED)[-1].data["reason"] == "mailbox full"


@pytest.mark.parametrize("mode", ["false", "raises", "truthy-not-true"])
async def test_authorizer_is_fail_closed(mode: str) -> None:
    async def authorize(_e: Envelope) -> Any:
        if mode == "raises":
            raise RuntimeError("gate down")
        return False if mode == "false" else "yes"

    router, sink, _ = make_router(authorize)
    a, b = new_pid(), new_pid()
    router.register(a, T1)
    box = router.register(b, T1)
    with pytest.raises(IpcDeniedError):
        await router.send(env(a, b))
    assert len(box) == 0 and sink.of(TkiEventType.IPC_DENIED)


async def test_recipient_removed_while_authorizing_is_not_delivered() -> None:
    gate_open = asyncio.Event()

    async def slow(_e: Envelope) -> bool:
        await gate_open.wait()
        return True

    router, _, _ = make_router(slow)
    a, b = new_pid(), new_pid()
    router.register(a, T1)
    router.register(b, T1)
    sending = asyncio.create_task(router.send(env(a, b)))
    await asyncio.sleep(0.01)
    router.unregister(b)
    gate_open.set()
    with pytest.raises(IpcDeniedError):
        await sending


async def test_audit_sink_failure_means_no_delivery() -> None:
    class Down(ListSink):
        def emit(self, event: TkiEvent) -> None:
            if event.type is TkiEventType.IPC_SENT:
                raise RuntimeError("down")
            super().emit(event)

    sink, clock = Down(), FakeClock()
    router = MessageRouter(sink=sink, authorize=allow_all, clock=clock)
    a, b = new_pid(), new_pid()
    router.register(a, T1)
    box = router.register(b, T1)
    with pytest.raises(IpcAuditError):
        await router.send(env(a, b))
    assert len(box) == 0


async def test_channels_are_tenant_scoped_pub_sub() -> None:
    router, sink, _ = make_router(capacity=1)
    pub, s1, s2, other = new_pid(), new_pid(), new_pid(), new_pid()
    router.register(pub, T1)
    b1 = router.register(s1, T1)
    b2 = router.register(s2, T1)
    bo = router.register(other, T2)
    for pid in (s1, s2, other):
        router.subscribe(pid, "alerts")
    router.subscribe(s1, "alerts")  # idempotent
    msg = env(pub, "chan:alerts")
    assert await router.send(msg) == 2
    assert b1.receive_nowait() is msg and b2.receive_nowait() is msg and len(bo) == 0
    # a full subscriber is skipped and reported, others still get it
    await router.send(env(pub, "chan:alerts"))
    again = env(pub, "chan:alerts")
    b2.receive_nowait()
    assert await router.send(again) == 1
    assert sink.of(TkiEventType.IPC_SENT)[-1].data["dropped"] == [s1]
    router.unsubscribe(s1, "alerts")
    router.unsubscribe(new_pid(), "alerts")  # unknown pid: no-op
    b1.receive_nowait()
    b2.receive_nowait()
    assert await router.send(env(pub, "chan:alerts")) == 1


async def test_channel_without_subscribers_is_denied_and_unregister_cleans_subscriptions() -> None:
    router, _, _ = make_router()
    pub, sub = new_pid(), new_pid()
    router.register(pub, T1)
    router.register(sub, T1)
    with pytest.raises(IpcDeniedError):
        await router.send(env(pub, "chan:none"))
    router.subscribe(sub, "x")
    router.unregister(sub)
    with pytest.raises(IpcDeniedError):
        await router.send(env(pub, "chan:x"))


def test_registry_validation() -> None:
    router, _, _ = make_router()
    pid = new_pid()
    router.register(pid, T1)
    with pytest.raises(IpcError):
        router.register(pid, T1)
    with pytest.raises(IpcError):
        router.register("not-a-pid", T1)
    with pytest.raises(IpcError):
        router.subscribe(new_pid(), "x")
    with pytest.raises(IpcError):
        router.subscribe(pid, "Bad Channel")


async def test_expired_message_is_audited_as_dropped_on_receive() -> None:
    router, sink, clock = make_router()
    a, b = new_pid(), new_pid()
    router.register(a, T1)
    box = router.register(b, T1)
    msg = Envelope.new(
        tenant_id=T1, trace_id=TRACE, sender=a, to=b, kind=Kind.EVENT, payload={}, clock=clock,
        ttl_seconds=1,
    )  # fmt: skip
    await router.send(msg)
    clock.t += timedelta(seconds=2)
    assert box.receive_nowait() is None
    assert sink.of(TkiEventType.IPC_DROPPED)[0].data["reason"] == "ttl expired"


async def test_request_response_roundtrip() -> None:
    router, _, clock = make_router()
    a, b = new_pid(), new_pid()
    ba = router.register(a, T1)
    bb = router.register(b, T1)
    req = env(a, b, kind=Kind.REQUEST)
    await router.send(req)
    got = bb.receive_nowait()
    assert got is not None
    resp = Envelope.new(
        tenant_id=T1, trace_id=TRACE, sender=b, to=a, kind=Kind.RESPONSE, payload={"ok": True},
        clock=clock, correlation_id=got.id,
    )  # fmt: skip
    await router.send(resp)
    reply = ba.receive_nowait()
    assert reply is not None and reply.correlation_id == req.id
