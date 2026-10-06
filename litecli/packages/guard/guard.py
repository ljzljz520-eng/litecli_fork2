"""ExecutionGuard: the single gate every execution must pass through.

Pipeline: compile (ExecutionPlan) -> decide (Policy) -> confirm (interactive)
-> arm authorizer scope -> execute -> record audit.

The same pipeline is used no matter where input comes from (prompt, ``.read``,
startup, favorite, LLM, ``-e``, stdin). Nested executions (a ``.read`` file or
favorite template running through ``run()`` again) re-enter the guard and may
only use capabilities already authorized for the parent plan.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from . import capabilities as caps
from .audit import (
    OUTCOME_ALLOWED,
    OUTCOME_CONFIRMED,
    OUTCOME_DENIED_AUTHORIZER,
    OUTCOME_DENIED_POLICY,
    OUTCOME_ERROR,
    AuditLog,
    build_record,
)
from .authorizer import ALL_DETAILS, AuthorizerController, AuthorizerScope
from .confirm import Confirmer, action_label
from .plan import ExecutionPlan, PlanCompiler, PlanEntry, SourceOrigin
from .policy import (
    MODE_BATCH,
    VERDICT_ALLOW,
    VERDICT_CONFIRM,
    VERDICT_DENY,
    Decision,
    Policy,
    decide,
)

# Stack of guards currently executing a top-level scope. Special-command
# handlers use this to know whether capability enforcement is active.
_ACTIVE_GUARDS: list[ExecutionGuard] = []


def current_guard() -> ExecutionGuard | None:
    return _ACTIVE_GUARDS[-1] if _ACTIVE_GUARDS else None


class PolicyDenied(Exception):
    """Raised before execution when policy denies an operation."""

    def __init__(
        self,
        message: str,
        *,
        capability: str | None = None,
        detail: str | None = None,
        rule_id: str | None = None,
        seq: int | None = None,
        mode: str | None = None,
        target: str | None = None,
    ) -> None:
        super().__init__(message)
        self.capability = capability
        self.detail = detail
        self.rule_id = rule_id
        self.seq = seq
        self.mode = mode
        self.target = target

    @classmethod
    def from_point(
        cls,
        capability: str,
        detail: str | None,
        rule_id: str,
        mode: str,
        seq: int | None,
        target: str | None,
        reason: str | None = None,
    ) -> PolicyDenied:
        action = action_label(capability, detail)
        location = f" (entry #{seq})" if seq is not None else ""
        target_line = f"\n  target: {target}" if target else ""
        message = f"Policy denied{location}: {capability}/{detail or '-'} ({action}) by rule {rule_id} in {mode} mode.{target_line}"
        if reason:
            message += f"\n  reason: {reason}"
        return cls(
            message,
            capability=capability,
            detail=detail,
            rule_id=rule_id,
            seq=seq,
            mode=mode,
            target=target,
        )


@dataclass
class PreparedExecution:
    plan: ExecutionPlan
    decision: Decision
    grants: dict[str, frozenset[str]]
    outcome: str
    confirmed: bool = False
    top_level: bool = True


@dataclass
class _ActiveExecution:
    prepared: PreparedExecution
    scope: AuthorizerScope
    started: float


_DDL_WITH_DATA_EFFECTS = frozenset({caps.DETAIL_DROP, caps.DETAIL_ALTER, caps.DETAIL_TRUNCATE})


def _grants_from_decision(decision: Decision) -> dict[str, frozenset[str]]:
    """Grant every capability whose verdict is allow or confirmed."""
    grants: dict[str, set[str]] = {}
    destructive_ddl = False
    for entry in decision.entries:
        if entry.verdict == VERDICT_DENY:
            continue
        for point in entry.points:
            if point.verdict in {VERDICT_ALLOW, VERDICT_CONFIRM} and point.capability != "*":
                grants.setdefault(point.capability, set())
                if point.detail:
                    grants[point.capability].add(point.detail)
                if point.capability == caps.WRITE_SCHEMA and point.detail in _DDL_WITH_DATA_EFFECTS:
                    destructive_ddl = True
    # DROP/ALTER/TRUNCATE run internal DML (catalog/index/table DELETEs and
    # rewrites) that shows up as write-data authorizer events. Grant those for
    # the scope whenever the DDL itself was authorized.
    if destructive_ddl:
        grants.setdefault(caps.WRITE_DATA, set()).add(ALL_DETAILS)
    return {cap: frozenset(details) for cap, details in grants.items()}


def _grants_contain(grants: dict[str, frozenset[str]], capability: str, detail: str | None) -> bool:
    details = grants.get(capability)
    if details is None:
        return False
    if ALL_DETAILS in details:
        return True
    return detail is None or detail in details


class ExecutionGuard:
    def __init__(
        self,
        compiler: PlanCompiler,
        policy: Policy | None,
        controller: AuthorizerController,
        audit_log: AuditLog,
        confirmer: Confirmer | None,
        mode: str,
        clock: Any = time.perf_counter,
    ) -> None:
        self.compiler = compiler
        self.policy = policy
        self.controller = controller
        self.audit_log = audit_log
        self.confirmer = confirmer
        self.mode = mode
        self.clock = clock
        self._active: _ActiveExecution | None = None
        self._restart_flushed = False

    @property
    def enabled(self) -> bool:
        return self.policy is not None and self.policy.enabled

    @property
    def current_origin(self) -> SourceOrigin | None:
        """Origin of the executing top-level plan (parent for nested runs)."""
        return self._active.prepared.plan.entries[0].origin if self._active and self._active.prepared.plan.entries else None

    def attach_connection(self, conn: Any) -> None:
        """Install the authorizer callback on a newly opened connection."""
        self.controller.install(conn)

    # -- preparation ---------------------------------------------------------

    def prepare(self, text: str, origin: SourceOrigin) -> PreparedExecution:
        if not self.enabled:
            return self._prepare_passthrough(text, origin)

        assert self.policy is not None  # ensured by self.enabled
        policy = self.policy
        plan = self.compiler.compile(text, origin)
        decision = decide(plan, self.mode, policy)
        nested = self._active is not None
        parent = self._active.prepared if nested else None

        if decision.verdict == VERDICT_DENY:
            point = self._first_verdict(decision, VERDICT_DENY)
            self._denial_record(plan, decision, nested, OUTCOME_DENIED_POLICY)
            raise PolicyDenied.from_point(
                point.capability,
                point.detail,
                point.rule_id,
                self.mode,
                point.seq,
                self._target_for_seq(plan, point.seq),
                reason=point.reason,
            )

        grants = _grants_from_decision(decision)

        if nested:
            # Nested sources never prompt again: they may only use grants the
            # parent plan already obtained. Same text, same policy, same fate.
            assert parent is not None
            missing = self._missing_grants(plan, parent.grants)
            if missing:
                cap, detail, seq = missing[0]
                self._denial_record(plan, decision, nested, OUTCOME_DENIED_POLICY)
                raise PolicyDenied.from_point(
                    cap,
                    detail,
                    "NESTED-GRANT",
                    self.mode,
                    seq,
                    self._target_for_seq(plan, seq),
                    reason="nested source requested a capability not authorized for the parent plan",
                )
            outcome = parent.outcome
        elif decision.verdict == VERDICT_CONFIRM:
            if self.confirmer is None or not getattr(self.confirmer, "available", False):
                point = self._first_verdict(decision, VERDICT_CONFIRM)
                self._denial_record(plan, decision, nested, OUTCOME_DENIED_POLICY)
                raise PolicyDenied.from_point(
                    point.capability,
                    point.detail,
                    point.rule_id,
                    MODE_BATCH,
                    point.seq,
                    self._target_for_seq(plan, point.seq),
                    reason="confirmation unavailable in non-interactive mode",
                )
            accepted = self.confirmer.confirm(plan, decision)
            if not accepted:
                point = self._first_verdict(decision, VERDICT_CONFIRM)
                self._denial_record(plan, decision, nested, OUTCOME_DENIED_POLICY)
                raise PolicyDenied.from_point(
                    point.capability,
                    point.detail,
                    point.rule_id,
                    self.mode,
                    point.seq,
                    self._target_for_seq(plan, point.seq),
                    reason="user declined the confirmation",
                )
            outcome = OUTCOME_CONFIRMED
        else:
            outcome = OUTCOME_ALLOWED

        return PreparedExecution(
            plan=plan,
            decision=decision,
            grants=grants,
            outcome=outcome,
            confirmed=outcome == OUTCOME_CONFIRMED,
            top_level=not nested,
        )

    def _prepare_passthrough(self, text: str, origin: SourceOrigin) -> PreparedExecution:
        plan = self.compiler.compile(text, origin)
        decision = decide(plan, self.mode, Policy.default())
        return PreparedExecution(
            plan=plan,
            decision=decision,
            grants={},
            outcome=OUTCOME_ALLOWED,
            top_level=self._active is None,
        )

    # -- execution scope -----------------------------------------------------

    @contextmanager
    def scope(self, prepared: PreparedExecution) -> Iterator[AuthorizerScope]:
        if not self.enabled:
            # Policy disabled: controller callback stays permissive.
            yield AuthorizerScope(grants={})
            return

        if self._active is not None:
            # Nested execution shares the parent's armed scope and events.
            yield self._active.scope
            return

        started = self.clock()
        # Persistent/attached file-backed virtual tables must be known before
        # the first READ events of this scope fires.
        self.controller.refresh_table_index()
        with self.controller.scope(prepared.grants) as authorizer_scope:
            active = _ActiveExecution(prepared=prepared, scope=authorizer_scope, started=started)
            self._active = active
            _ACTIVE_GUARDS.append(self)
            outcome = prepared.outcome
            try:
                yield authorizer_scope
            except PolicyDenied as exc:
                # Policy denial from a nested prepare/entry check.
                outcome = OUTCOME_DENIED_POLICY
                self._record(prepared.plan, prepared.decision, outcome, authorizer_scope.events, started, extra_denied=exc)
                raise
            except Exception as exc:
                denial = self.controller.last_denial
                if denial is not None and denial.capability is not None:
                    self._record(
                        prepared.plan,
                        prepared.decision,
                        OUTCOME_DENIED_AUTHORIZER,
                        authorizer_scope.events,
                        started,
                    )
                    translated = PolicyDenied.from_point(
                        denial.capability,
                        denial.detail,
                        "AUTHORIZER",
                        self.mode,
                        None,
                        None,
                        reason=f"SQLite authorizer rejected {denial.action_name}"
                        + (" before any side effect" if denial.outside_scope else " inside the authorized scope"),
                    )
                    raise translated from exc
                self._record(prepared.plan, prepared.decision, OUTCOME_ERROR, authorizer_scope.events, started)
                raise
            else:
                if not self._restart_flushed:
                    self._record(prepared.plan, prepared.decision, outcome, authorizer_scope.events, started)
            finally:
                self._active = None
                self._restart_flushed = False
                _ACTIVE_GUARDS.pop()

    def flush_active_for_restart(self) -> None:
        """Persist the active audit record before a process image restart.

        Commands such as ``\\llm install`` replace the process via
        ``os.execv`` on success, so the scope context manager never exits and
        its normal audit write would be lost. This finalizes the record
        eagerly and suppresses the duplicate write if execv is stubbed (e.g.
        in tests).
        """
        active = self._active
        if not self.enabled or active is None or self._restart_flushed:
            return
        self._record(
            active.prepared.plan,
            active.prepared.decision,
            active.prepared.outcome,
            active.scope.events,
            active.started,
        )
        self._restart_flushed = True

    def authorize_entry(self, entry: PlanEntry) -> None:
        """Defense-in-depth check right before a plan entry handler runs."""
        if not self.enabled or self._active is None:
            return
        # A previous entry may have ATTACHed a schema carrying persistent
        # file-backed virtual tables; re-index before each statement.
        self.controller.refresh_table_index()
        grants = self._active.prepared.grants
        for capability, details in entry.capabilities.items():
            for detail in details or {None}:
                if not _grants_contain(grants, capability, detail):
                    raise PolicyDenied.from_point(
                        capability,
                        detail,
                        "NESTED-GRANT",
                        self.mode,
                        entry.seq,
                        entry.target,
                        reason="special command requested a capability not in the authorized plan",
                    )

    def translate_error(self, exc: Exception) -> PolicyDenied | None:
        """Turn a SQLite 'not authorized' error into a PolicyDenied."""
        denial = self.controller.last_denial
        if denial is None or denial.capability is None:
            return None
        return PolicyDenied.from_point(
            denial.capability,
            denial.detail,
            "AUTHORIZER",
            self.mode,
            None,
            None,
            reason=f"SQLite authorizer rejected {denial.action_name}",
        )

    # -- helpers -------------------------------------------------------------

    def _denial_record(
        self,
        plan: ExecutionPlan,
        decision: Decision,
        nested: bool,
        outcome: str,
    ) -> None:
        # Only the top-level execution owns an audit record; nested denials
        # are recorded when they unwind through the top-level scope.
        if not nested:
            self._record(plan, decision, outcome)

    def _record(
        self,
        plan: ExecutionPlan,
        decision: Decision,
        outcome: str,
        events: list | None = None,
        started: float | None = None,
        extra_denied: PolicyDenied | None = None,
    ) -> None:
        if not self.enabled or not self.audit_log.enabled:
            return
        duration_ms = (self.clock() - started) * 1000.0 if started is not None else None
        record = build_record(plan, decision, outcome, duration_ms=duration_ms, authorizer_events=events)
        if extra_denied is not None:
            record["guard_denial"] = {
                "capability": extra_denied.capability,
                "detail": extra_denied.detail,
                "rule_id": extra_denied.rule_id,
                "seq": extra_denied.seq,
                "mode": extra_denied.mode,
            }
        self.audit_log.append(record)

    @staticmethod
    def _first_verdict(decision: Decision, verdict: str):
        for entry in decision.entries:
            for point in entry.points:
                if point.verdict == verdict:
                    return point
        raise ValueError(f"decision has no {verdict} point")

    @staticmethod
    def _target_for_seq(plan: ExecutionPlan, seq: int) -> str | None:
        for entry in plan.entries:
            if entry.seq == seq:
                return entry.target or entry.normalized_template
        return None

    @staticmethod
    def _missing_grants(plan: ExecutionPlan, grants: dict[str, frozenset[str]]) -> list[tuple[str, str | None, int]]:
        missing: list[tuple[str, str | None, int]] = []
        for entry in plan.entries:
            if entry.unresolved:
                # Already denied at decision time; nothing to add here.
                continue
            for capability, details in entry.capabilities.items():
                for detail in details or {None}:
                    if not _grants_contain(grants, capability, detail):
                        missing.append((capability, detail, entry.seq))
        return missing
