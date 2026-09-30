from axis_runtime._gen.axis.runtime.v1 import common_pb2 as _common_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EvaluateRequest(_message.Message):
    __slots__ = ("tenant_id", "trace", "actor", "blueprint", "enforcement_point", "action", "context")
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    BLUEPRINT_FIELD_NUMBER: _ClassVar[int]
    ENFORCEMENT_POINT_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    tenant_id: str
    trace: _common_pb2.TraceContext
    actor: _common_pb2.Actor
    blueprint: _common_pb2.BlueprintRef
    enforcement_point: _common_pb2.EnforcementPoint
    action: str
    context: _struct_pb2.Struct
    def __init__(self, tenant_id: _Optional[str] = ..., trace: _Optional[_Union[_common_pb2.TraceContext, _Mapping]] = ..., actor: _Optional[_Union[_common_pb2.Actor, _Mapping]] = ..., blueprint: _Optional[_Union[_common_pb2.BlueprintRef, _Mapping]] = ..., enforcement_point: _Optional[_Union[_common_pb2.EnforcementPoint, str]] = ..., action: _Optional[str] = ..., context: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class EvaluateResponse(_message.Message):
    __slots__ = ("decision", "policy_version", "reason", "matched_rule_ids", "redact_fields", "approval_id", "audit_event_id")
    DECISION_FIELD_NUMBER: _ClassVar[int]
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    MATCHED_RULE_IDS_FIELD_NUMBER: _ClassVar[int]
    REDACT_FIELDS_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_ID_FIELD_NUMBER: _ClassVar[int]
    AUDIT_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    decision: _common_pb2.Decision
    policy_version: str
    reason: str
    matched_rule_ids: _containers.RepeatedScalarFieldContainer[str]
    redact_fields: _containers.RepeatedScalarFieldContainer[str]
    approval_id: str
    audit_event_id: str
    def __init__(self, decision: _Optional[_Union[_common_pb2.Decision, str]] = ..., policy_version: _Optional[str] = ..., reason: _Optional[str] = ..., matched_rule_ids: _Optional[_Iterable[str]] = ..., redact_fields: _Optional[_Iterable[str]] = ..., approval_id: _Optional[str] = ..., audit_event_id: _Optional[str] = ...) -> None: ...

class SetKillSwitchRequest(_message.Message):
    __slots__ = ("tenant_id", "scope", "target", "engaged", "reason")
    class Scope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SCOPE_UNSPECIFIED: _ClassVar[SetKillSwitchRequest.Scope]
        SCOPE_GLOBAL: _ClassVar[SetKillSwitchRequest.Scope]
        SCOPE_TENANT: _ClassVar[SetKillSwitchRequest.Scope]
        SCOPE_AGENT: _ClassVar[SetKillSwitchRequest.Scope]
        SCOPE_TOOL: _ClassVar[SetKillSwitchRequest.Scope]
    SCOPE_UNSPECIFIED: SetKillSwitchRequest.Scope
    SCOPE_GLOBAL: SetKillSwitchRequest.Scope
    SCOPE_TENANT: SetKillSwitchRequest.Scope
    SCOPE_AGENT: SetKillSwitchRequest.Scope
    SCOPE_TOOL: SetKillSwitchRequest.Scope
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    ENGAGED_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    tenant_id: str
    scope: SetKillSwitchRequest.Scope
    target: str
    engaged: bool
    reason: str
    def __init__(self, tenant_id: _Optional[str] = ..., scope: _Optional[_Union[SetKillSwitchRequest.Scope, str]] = ..., target: _Optional[str] = ..., engaged: _Optional[bool] = ..., reason: _Optional[str] = ...) -> None: ...

class SetKillSwitchResponse(_message.Message):
    __slots__ = ("engaged", "audit_event_id")
    ENGAGED_FIELD_NUMBER: _ClassVar[int]
    AUDIT_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    engaged: bool
    audit_event_id: str
    def __init__(self, engaged: _Optional[bool] = ..., audit_event_id: _Optional[str] = ...) -> None: ...
