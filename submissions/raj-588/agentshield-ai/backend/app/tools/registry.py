"""Sandbox enterprise tool registry.

Every protected capability is an explicit, strongly typed entry here. There is
NO generic SQL tool, NO shell, NO arbitrary Python, and NO outbound network.
Executors operate only on synthetic in-memory/seed data.

The registry is the single source of truth for:
  * which tools exist
  * the logical operation each performs
  * whether a tool is sensitive (approval-gated)
  * the argument schema the gateway validates against
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from app.tools import synthetic_data as sd


@dataclass(frozen=True)
class ToolSpec:
    name: str
    operation: str
    description: str
    is_sensitive: bool
    arg_schema: dict  # {arg_name: {"type": "str", "required": bool}}
    executor: Callable[[str | None, dict], dict] = field(repr=False)


# --------------------------------------------------------------------------- #
# Executors — synthetic only. They never touch real data or external systems.
# --------------------------------------------------------------------------- #
def _exec_read_report(resource: str | None, args: dict) -> dict:
    report = sd.get_report(resource)
    if report is None:
        raise KeyError(f"report '{resource}' not found")
    return {"resource": resource, "content": report["content"], "title": report["title"]}


def _exec_query_customer(resource: str | None, args: dict) -> dict:
    record = sd.get_customer(resource)
    if record is None:
        raise KeyError(f"customer '{resource}' not found")
    # Minimal projection; no sensitive fields beyond the synthetic record.
    return {"resource": resource, "record": record}


def _exec_export_customers(resource: str | None, args: dict) -> dict:
    # Sensitive: simulate only. Never writes a file or transmits data.
    count = len(sd.list_customers())
    return {
        "simulated": True,
        "would_export_count": count,
        "destination": args.get("destination", "APPROVED_INTERNAL_VAULT"),
        "note": "No real customer data was written or transmitted.",
    }


def _exec_delete_record(resource: str | None, args: dict) -> dict:
    # Destructive: simulate only. Default policy denies this before it runs.
    return {
        "simulated": True,
        "would_delete": resource,
        "note": "No record was actually deleted.",
    }


def _exec_send_notification(resource: str | None, args: dict) -> dict:
    # Simulated internal notification only. No email / external message.
    return {
        "simulated": True,
        "destination": args.get("destination", "internal"),
        "message": args.get("message", ""),
        "note": "No real message was sent.",
    }


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
_REGISTRY: dict[str, ToolSpec] = {
    "read_report": ToolSpec(
        name="read_report",
        operation="read",
        description="Read a permitted synthetic sales report.",
        is_sensitive=False,
        arg_schema={},
        executor=_exec_read_report,
    ),
    "query_customer": ToolSpec(
        name="query_customer",
        operation="read",
        description="Read a permitted synthetic customer record.",
        is_sensitive=False,
        arg_schema={},
        executor=_exec_query_customer,
    ),
    "export_customers": ToolSpec(
        name="export_customers",
        operation="export",
        description="Sensitive: simulate a customer-data export (approval-gated).",
        is_sensitive=True,
        arg_schema={"destination": {"type": "str", "required": False}},
        executor=_exec_export_customers,
    ),
    "delete_record": ToolSpec(
        name="delete_record",
        operation="delete",
        description="Sensitive: simulate a destructive record deletion (denied by default).",
        is_sensitive=True,
        arg_schema={},
        executor=_exec_delete_record,
    ),
    "send_notification": ToolSpec(
        name="send_notification",
        operation="notify",
        description="Send a simulated internal notification (never a real message).",
        is_sensitive=False,
        arg_schema={
            "destination": {"type": "str", "required": False},
            "message": {"type": "str", "required": False},
        },
        executor=_exec_send_notification,
    ),
}


def get_tool(name: str) -> ToolSpec | None:
    return _REGISTRY.get(name)


def all_tools() -> list[ToolSpec]:
    return list(_REGISTRY.values())


def validate_arguments(spec: ToolSpec, arguments: dict) -> str | None:
    """Return an error string if arguments violate the schema, else None."""
    if not isinstance(arguments, dict):
        return "arguments must be an object"
    allowed = set(spec.arg_schema.keys())
    extra = set(arguments.keys()) - allowed
    if extra:
        return f"unexpected arguments: {sorted(extra)}"
    for arg, rule in spec.arg_schema.items():
        if rule.get("required") and arg not in arguments:
            return f"missing required argument: {arg}"
        if arg in arguments and rule.get("type") == "str":
            if not isinstance(arguments[arg], str):
                return f"argument '{arg}' must be a string"
    return None
