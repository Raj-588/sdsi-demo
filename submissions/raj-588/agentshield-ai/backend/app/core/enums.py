"""Typed enums shared across IntentLock, the gateway, and the audit log."""
from __future__ import annotations

from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class ReasonCode(str, Enum):
    # Allow
    AUTHORIZED = "AUTHORIZED"
    # Deny
    TASK_NOT_FOUND = "TASK_NOT_FOUND"
    TASK_EXPIRED = "TASK_EXPIRED"
    TASK_NOT_ACTIVE = "TASK_NOT_ACTIVE"
    OWNERSHIP_MISMATCH = "OWNERSHIP_MISMATCH"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"
    RESOURCE_NOT_ALLOWED = "RESOURCE_NOT_ALLOWED"
    ARGUMENT_POLICY_VIOLATION = "ARGUMENT_POLICY_VIOLATION"
    POLICY_VALIDATION_ERROR = "POLICY_VALIDATION_ERROR"
    # Hold
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class TaskStatus(str, Enum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ExecutionStatus(str, Enum):
    NOT_EXECUTED = "NOT_EXECUTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class AgentMode(str, Enum):
    LIVE = "LIVE"
    MOCK = "MOCK"
