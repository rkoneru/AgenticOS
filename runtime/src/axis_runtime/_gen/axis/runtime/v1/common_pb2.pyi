import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ProcessState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROCESS_STATE_UNSPECIFIED: _ClassVar[ProcessState]
    PROCESS_STATE_SPAWN: _ClassVar[ProcessState]
    PROCESS_STATE_READY: _ClassVar[ProcessState]
    PROCESS_STATE_RUNNING: _ClassVar[ProcessState]
    PROCESS_STATE_WAITING: _ClassVar[ProcessState]
    PROCESS_STATE_SUSPENDED: _ClassVar[ProcessState]
    PROCESS_STATE_TERMINATED: _ClassVar[ProcessState]

class Signal(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIGNAL_UNSPECIFIED: _ClassVar[Signal]
    SIGNAL_PAUSE: _ClassVar[Signal]
    SIGNAL_RESUME: _ClassVar[Signal]
    SIGNAL_TERM: _ClassVar[Signal]
    SIGNAL_KILL: _ClassVar[Signal]
    SIGNAL_INTERRUPT: _ClassVar[Signal]

class Decision(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DECISION_UNSPECIFIED: _ClassVar[Decision]
    DECISION_ALLOW: _ClassVar[Decision]
    DECISION_DENY: _ClassVar[Decision]
    DECISION_REQUIRE_APPROVAL: _ClassVar[Decision]
    DECISION_ALLOW_WITH_REDACTION: _ClassVar[Decision]

class EnforcementPoint(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENFORCEMENT_POINT_UNSPECIFIED: _ClassVar[EnforcementPoint]
    ENFORCEMENT_POINT_TOOL_CALL: _ClassVar[EnforcementPoint]
    ENFORCEMENT_POINT_MCP_CALL: _ClassVar[EnforcementPoint]
    ENFORCEMENT_POINT_MODEL_CALL: _ClassVar[EnforcementPoint]
    ENFORCEMENT_POINT_MEMORY_WRITE: _ClassVar[EnforcementPoint]
    ENFORCEMENT_POINT_MESSAGE_SEND: _ClassVar[EnforcementPoint]
    ENFORCEMENT_POINT_CODE_EXEC: _ClassVar[EnforcementPoint]
    ENFORCEMENT_POINT_BROWSER_EXEC: _ClassVar[EnforcementPoint]
PROCESS_STATE_UNSPECIFIED: ProcessState
PROCESS_STATE_SPAWN: ProcessState
PROCESS_STATE_READY: ProcessState
PROCESS_STATE_RUNNING: ProcessState
PROCESS_STATE_WAITING: ProcessState
PROCESS_STATE_SUSPENDED: ProcessState
PROCESS_STATE_TERMINATED: ProcessState
SIGNAL_UNSPECIFIED: Signal
SIGNAL_PAUSE: Signal
SIGNAL_RESUME: Signal
SIGNAL_TERM: Signal
SIGNAL_KILL: Signal
SIGNAL_INTERRUPT: Signal
DECISION_UNSPECIFIED: Decision
DECISION_ALLOW: Decision
DECISION_DENY: Decision
DECISION_REQUIRE_APPROVAL: Decision
DECISION_ALLOW_WITH_REDACTION: Decision
ENFORCEMENT_POINT_UNSPECIFIED: EnforcementPoint
ENFORCEMENT_POINT_TOOL_CALL: EnforcementPoint
ENFORCEMENT_POINT_MCP_CALL: EnforcementPoint
ENFORCEMENT_POINT_MODEL_CALL: EnforcementPoint
ENFORCEMENT_POINT_MEMORY_WRITE: EnforcementPoint
ENFORCEMENT_POINT_MESSAGE_SEND: EnforcementPoint
ENFORCEMENT_POINT_CODE_EXEC: EnforcementPoint
ENFORCEMENT_POINT_BROWSER_EXEC: EnforcementPoint

class TraceContext(_message.Message):
    __slots__ = ("trace_id", "span_id")
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    trace_id: str
    span_id: str
    def __init__(self, trace_id: _Optional[str] = ..., span_id: _Optional[str] = ...) -> None: ...

class Actor(_message.Message):
    __slots__ = ("type", "id", "pid")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        TYPE_UNSPECIFIED: _ClassVar[Actor.Type]
        TYPE_HUMAN: _ClassVar[Actor.Type]
        TYPE_AGENT: _ClassVar[Actor.Type]
        TYPE_SYSTEM: _ClassVar[Actor.Type]
    TYPE_UNSPECIFIED: Actor.Type
    TYPE_HUMAN: Actor.Type
    TYPE_AGENT: Actor.Type
    TYPE_SYSTEM: Actor.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    type: Actor.Type
    id: str
    pid: str
    def __init__(self, type: _Optional[_Union[Actor.Type, str]] = ..., id: _Optional[str] = ..., pid: _Optional[str] = ...) -> None: ...

class BlueprintRef(_message.Message):
    __slots__ = ("name", "version")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ...) -> None: ...

class Timestamps(_message.Message):
    __slots__ = ("created_at", "updated_at")
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...
