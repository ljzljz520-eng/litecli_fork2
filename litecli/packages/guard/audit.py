"""JSONL policy audit trail.

Every top-level execution appends one record containing the plan hash,
redacted plan entries, the policy decision with its rules snapshot, the
authorizer events observed at runtime, the outcome and timing.

Privacy invariants:
* raw SQL is never written - only normalized templates with ``?`` literals;
* real targets (file paths, literal values) never leave the interactive UI;
* only classifier names (function/pragma/favorite names) are retained.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from ...config import config_location
from .authorizer import AuthorizerEvent
from .plan import ExecutionPlan, hash_redacted_entries
from .policy import Decision, replay

log = logging.getLogger(__name__)

DEFAULT_AUDIT_BASENAME = "policy-audit.jsonl"
AUDIT_OFF = frozenset({"", "off", "none", "0", "false", "no"})

# Outcomes.
OUTCOME_ALLOWED = "allowed"
OUTCOME_CONFIRMED = "confirmed"
OUTCOME_DENIED_POLICY = "denied_policy"
OUTCOME_DENIED_AUTHORIZER = "denied_authorizer"
OUTCOME_ERROR = "error"


def default_audit_path() -> str:
    return os.path.join(config_location(), DEFAULT_AUDIT_BASENAME)


def resolve_audit_path(setting: str | None) -> str | None:
    """Translate the [policy] audit_log setting into a path or None."""
    if setting is None:
        return default_audit_path()
    value = setting.strip()
    if value.lower() in AUDIT_OFF:
        return None
    if value.lower() == "default":
        return default_audit_path()
    return os.path.expanduser(value)


def build_record(
    plan: ExecutionPlan,
    decision: Decision,
    outcome: str,
    duration_ms: float | None = None,
    authorizer_events: list[AuthorizerEvent] | None = None,
    ts: float | None = None,
) -> dict[str, Any]:
    """Assemble the redacted JSON-serializable audit record."""
    return {
        "ts": ts if ts is not None else time.time(),
        "plan_hash": plan.plan_hash,
        "source_signature": plan.source_signature,
        "mode": decision.mode,
        "policy_version": decision.policy_version,
        "policy_digest": decision.policy_digest,
        "rules_snapshot": decision.rules_snapshot,
        "entries": plan.audit_entries(),
        "decision": decision.audit_dict(),
        "authorizer_events": [event.audit_dict() for event in (authorizer_events or [])],
        "outcome": outcome,
        "duration_ms": round(duration_ms, 3) if duration_ms is not None else None,
    }


@dataclass
class ReplayResult:
    hash_ok: bool
    verdict_match: bool
    recorded_verdict: str
    replayed_verdict: str
    replayed: dict[str, Any]
    # None for legacy records that predate the rules digest field.
    snapshot_ok: bool | None = None

    @property
    def ok(self) -> bool:
        return self.hash_ok and self.verdict_match and self.snapshot_ok is not False

    def audit_dict(self) -> dict[str, Any]:
        return {
            "hash_ok": self.hash_ok,
            "verdict_match": self.verdict_match,
            "snapshot_ok": self.snapshot_ok,
            "recorded_verdict": self.recorded_verdict,
            "replayed_verdict": self.replayed_verdict,
            "replay": self.replayed,
        }


def replay_record(record: dict[str, Any]) -> ReplayResult:
    """Verify the plan hash and replay the decision from redacted data only."""
    redacted = record.get("entries", [])
    recomputed_hash = hash_redacted_entries(redacted)
    recorded_decision = record.get("decision", {})
    replayed = replay(
        redacted,
        str(record.get("mode", recorded_decision.get("mode", "interactive"))),
        record.get("rules_snapshot", recorded_decision.get("rules_snapshot", [])),
    )
    recorded_verdict = recorded_decision.get("verdict", record.get("outcome", ""))
    recorded_rules_digest = recorded_decision.get("rules_digest", record.get("rules_digest"))
    snapshot_ok = None if not recorded_rules_digest else replayed.get("rules_digest") == recorded_rules_digest
    return ReplayResult(
        hash_ok=(recomputed_hash == record.get("plan_hash")),
        verdict_match=(replayed["verdict"] == recorded_verdict),
        recorded_verdict=str(recorded_verdict),
        replayed_verdict=replayed["verdict"],
        replayed=replayed,
        snapshot_ok=snapshot_ok,
    )


class AuditLog:
    """Append-only JSONL audit log with fail-safe writes."""

    def __init__(self, path: str | None, clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self.clock = clock
        self.last_error: str | None = None
        self.write_count = 0

    @classmethod
    def from_setting(cls, setting: str | None, clock: Callable[[], float] = time.time) -> AuditLog:
        return cls(resolve_audit_path(setting), clock=clock)

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def append(self, record: dict[str, Any]) -> bool:
        if self.path is None:
            return False
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
            self.write_count += 1
            self.last_error = None
            return True
        except OSError as exc:
            # Fail safe: auditing must never block the user's workflow.
            self.last_error = f"{type(exc).__name__}: {exc}"
            log.warning("policy audit write failed: %s", self.last_error)
            return False

    def iter_records(self) -> Iterator[dict[str, Any]]:
        if self.path is None or not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    log.warning("skipping malformed audit line")

    def find_by_hash(self, plan_hash: str) -> list[dict[str, Any]]:
        return [record for record in self.iter_records() if record.get("plan_hash") == plan_hash]
