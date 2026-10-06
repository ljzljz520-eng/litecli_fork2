"""Confirmation dialog rendering for side-effecting plans.

The screen lists every entry whose policy verdict is ``confirm``, grouped in
plan order with its sequence number, the hit capability, a human action label
and the *real* target (file path, table name, external command). Real targets
appear on screen only - they never enter the audit trail.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Protocol

import click

from . import capabilities as caps
from .capabilities import (
    DETAIL_ALTER,
    DETAIL_ATTACH,
    DETAIL_CREATE,
    DETAIL_DELETE,
    DETAIL_DROP,
    DETAIL_EVAL,
    DETAIL_FUNCTION,
    DETAIL_INSERT,
    DETAIL_LOAD_EXTENSION,
    DETAIL_MASTER_WRITE,
    DETAIL_NETWORK_FUNCTION,
    DETAIL_PROCESS_SPECIAL,
    DETAIL_READ_FILE,
    DETAIL_SPECIAL,
    DETAIL_TRUNCATE,
    DETAIL_UPDATE,
    DETAIL_VACUUM_INTO,
    DETAIL_VTABLE,
    DETAIL_WRITABLE_SCHEMA,
    DETAIL_WRITE_FILE,
)
from .plan import ExecutionPlan
from .policy import VERDICT_CONFIRM, Decision

_ACTION_LABELS: dict[str, dict[str | None, str]] = {
    caps.FILESYSTEM: {
        DETAIL_ATTACH: "attach a database file",
        DETAIL_VACUUM_INTO: "write a database copy with VACUUM INTO",
        DETAIL_READ_FILE: "read a file via SQL",
        DETAIL_WRITE_FILE: "write a file via SQL function",
        DETAIL_FUNCTION: "inspect filesystem via SQL function",
        DETAIL_SPECIAL: "access the filesystem",
        None: "access the filesystem",
    },
    caps.PROCESS: {
        DETAIL_EVAL: "execute a shell command via eval()",
        DETAIL_PROCESS_SPECIAL: "run an external process",
        DETAIL_SPECIAL: "run an external process",
        None: "run an external process",
    },
    caps.EXTENSION: {
        DETAIL_LOAD_EXTENSION: "load a native SQLite extension",
        DETAIL_SPECIAL: "load a native SQLite extension",
        None: "load a native SQLite extension",
    },
    caps.NETWORK: {
        DETAIL_NETWORK_FUNCTION: "call a network SQL function",
        DETAIL_SPECIAL: "make a network request",
        None: "make a network request",
    },
    caps.WRITE_SCHEMA: {
        DETAIL_CREATE: "create a schema object",
        DETAIL_DROP: "drop a schema object",
        DETAIL_ALTER: "alter a schema object",
        DETAIL_TRUNCATE: "truncate a schema object",
        DETAIL_VTABLE: "create a virtual table (may load module code)",
        DETAIL_WRITABLE_SCHEMA: "enable direct writes to the schema catalog",
        DETAIL_MASTER_WRITE: "write directly to the schema catalog (sqlite_master)",
        None: "modify the database schema",
    },
    caps.WRITE_DATA: {
        DETAIL_INSERT: "insert rows",
        DETAIL_UPDATE: "update rows",
        DETAIL_DELETE: "delete rows",
        None: "modify table data",
    },
}

_HEADER = "This plan contains operations with side effects requiring confirmation:"
_FOOTER = "Proceed with the whole plan?"


@dataclass(frozen=True)
class ConfirmationItem:
    seq: int
    capability: str
    detail: str | None
    action: str
    target: str


def action_label(capability: str, detail: str | None) -> str:
    return _ACTION_LABELS.get(capability, {}).get(detail) or _ACTION_LABELS.get(capability, {}).get(None) or capability


def confirmation_items(plan: ExecutionPlan, decision: Decision) -> list[ConfirmationItem]:
    entries_by_seq = {entry.seq: entry for entry in plan.entries}
    items: list[ConfirmationItem] = []
    for entry_decision in decision.entries:
        if entry_decision.verdict != VERDICT_CONFIRM:
            continue
        entry = entries_by_seq[entry_decision.seq]
        for point in entry_decision.points:
            if point.verdict != VERDICT_CONFIRM or point.capability == "*":
                continue
            items.append(
                ConfirmationItem(
                    seq=entry.seq,
                    capability=point.capability,
                    detail=point.detail,
                    action=action_label(point.capability, point.detail),
                    target=entry.target or entry.normalized_template,
                )
            )
    return items


def render_confirmation(plan: ExecutionPlan, decision: Decision) -> str:
    items = confirmation_items(plan, decision)
    lines = [_HEADER]
    for index, item in enumerate(items, start=1):
        lines.append(f"  [{index}] (entry #{item.seq}) {item.capability:<12} {item.action}")
        lines.append(f"        target: {item.target}")
    lines.append("")
    lines.append(_FOOTER)
    return "\n".join(lines)


class Confirmer(Protocol):
    """Asks the user to approve a plan. Availability gates batch escalation."""

    @property
    def available(self) -> bool: ...

    def confirm(self, plan: ExecutionPlan, decision: Decision) -> bool: ...


class AutoConfirmer:
    """Programmatic confirmer for tests and injection."""

    available = True

    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.calls: list[str] = []

    def confirm(self, plan: ExecutionPlan, decision: Decision) -> bool:
        self.calls.append(render_confirmation(plan, decision))
        return self.answer


class ClickConfirmer:
    """Default interactive confirmer; unavailable without a TTY."""

    def __init__(self, is_tty: bool | None = None) -> None:
        self._is_tty = sys.stdin.isatty() if is_tty is None else is_tty

    @property
    def available(self) -> bool:
        return self._is_tty

    def confirm(self, plan: ExecutionPlan, decision: Decision) -> bool:
        if not self.available:
            return False
        rendered = render_confirmation(plan, decision)
        try:
            return bool(click.confirm(rendered, default=False))
        except click.Abort:
            return False
