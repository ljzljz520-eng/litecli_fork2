"""ExecutionGuard end-to-end orchestration (prepare/scope/audit/nesting)."""

import os
import sqlite3

import pytest

from litecli.main import LiteCli
from litecli.packages.guard.audit import OUTCOME_ALLOWED, OUTCOME_CONFIRMED, OUTCOME_DENIED_POLICY, AuditLog
from litecli.packages.guard.authorizer import AuthorizerController
from litecli.packages.guard.confirm import AutoConfirmer
from litecli.packages.guard.guard import ExecutionGuard, PolicyDenied
from litecli.packages.guard.plan import PlanCompiler, SourceOrigin
from litecli.packages.guard.policy import MODE_BATCH, MODE_INTERACTIVE, Policy

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")
ORIGINS = [SourceOrigin("prompt"), SourceOrigin("read"), SourceOrigin("startup"), SourceOrigin("llm")]


@pytest.fixture(scope="module", autouse=True)
def _dynamic_commands():
    return LiteCli(liteclirc=_TEST_CONFIG)


@pytest.fixture
def controller():
    ctrl = AuthorizerController(sqlite3)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE keep(id INTEGER)")
    ctrl.install(conn)
    yield ctrl, conn
    conn.close()


@pytest.fixture
def audit(tmp_path):
    return AuditLog(str(tmp_path / "audit.jsonl"))


def _missing_reader(path):
    raise FileNotFoundError(path)


def _guard(controller, audit, mode=MODE_INTERACTIVE, confirmer=None, policy=None):
    ctrl, _conn = controller
    compiler = PlanCompiler(file_reader=_missing_reader, favorite_provider=lambda n: None)
    return ExecutionGuard(
        compiler=compiler,
        policy=policy or Policy.default(),
        controller=ctrl,
        audit_log=audit,
        confirmer=confirmer,
        mode=mode,
    )


# -- policy verdicts ----------------------------------------------------------


def test_allow_plan_passes_and_audits(controller, audit):
    guard = _guard(controller, audit)
    prepared = guard.prepare("SELECT 1", SourceOrigin("prompt"))
    with guard.scope(prepared):
        pass
    assert prepared.outcome == OUTCOME_ALLOWED
    records = list(audit.iter_records())
    assert len(records) == 1 and records[0]["outcome"] == "allowed"


def test_deny_in_batch_happens_before_side_effects(controller, audit):
    _ctrl, conn = controller
    guard = _guard(controller, audit, mode=MODE_BATCH)
    with pytest.raises(PolicyDenied) as info:
        guard.prepare("DROP TABLE keep", SourceOrigin("prompt"))
    denied = info.value
    assert denied.capability == "write-schema" and denied.detail == "drop"
    assert "write-schema/drop" in str(denied)
    # The table is still there: nothing was executed.
    assert conn.execute("SELECT count(*) FROM keep").fetchone() == (0,)
    record = list(audit.iter_records())
    assert len(record) == 1 and record[0]["outcome"] == OUTCOME_DENIED_POLICY


def test_confirm_interactive_yes_grants_and_audits(controller, audit):
    guard = _guard(controller, audit, confirmer=AutoConfirmer(True))
    prepared = guard.prepare("DROP TABLE keep", SourceOrigin("prompt"))
    assert prepared.outcome == OUTCOME_CONFIRMED
    assert prepared.grants.get("write-schema")
    with guard.scope(prepared):
        pass
    assert next(iter(audit.iter_records()))["outcome"] == "confirmed"


def test_confirm_interactive_no_denies_and_audits(controller, audit):
    guard = _guard(controller, audit, confirmer=AutoConfirmer(False))
    with pytest.raises(PolicyDenied):
        guard.prepare("DROP TABLE keep", SourceOrigin("prompt"))
    assert next(iter(audit.iter_records()))["outcome"] == OUTCOME_DENIED_POLICY


def test_confirm_without_confirmer_in_interactive_denies(controller, audit):
    guard = _guard(controller, audit, mode=MODE_INTERACTIVE, confirmer=None)
    with pytest.raises(PolicyDenied) as info:
        guard.prepare("ATTACH '/tmp/x.db' AS x", SourceOrigin("prompt"))
    assert "non-interactive" in str(info.value)


# -- same operation, every origin ---------------------------------------------


@pytest.mark.parametrize("origin", ORIGINS)
def test_same_verdict_regardless_of_origin(controller, audit, origin):
    guard_yes = _guard(controller, AuditLog(None), confirmer=AutoConfirmer(True))
    prepared_a = guard_yes.prepare("ATTACH '/tmp/x.db' AS x", origin)
    origin_b = SourceOrigin(origin.kind, parent=origin)
    prepared_b = guard_yes.prepare("ATTACH '/tmp/x.db' AS x", origin_b)
    assert prepared_a.decision.verdict == prepared_b.decision.verdict
    assert prepared_a.grants == prepared_b.grants


def test_origin_only_affects_signature_not_decision(controller, audit):
    guard = _guard(controller, audit, mode=MODE_BATCH)
    verdicts = set()
    for origin in ORIGINS:
        try:
            guard.prepare("system echo hi", origin)
        except PolicyDenied:
            verdicts.add("deny")
        else:
            verdicts.add("allow")
    assert verdicts == {"deny"}


# -- authorizer backstop ------------------------------------------------------


def test_unplanned_side_effect_inside_scope_translated(controller, audit):
    _ctrl, conn = controller
    guard = _guard(controller, audit, confirmer=AutoConfirmer(True))
    prepared = guard.prepare("SELECT 1", SourceOrigin("prompt"))
    with pytest.raises(PolicyDenied) as info, guard.scope(prepared):
        conn.execute("ATTACH '/tmp/none.db' AS x")
    denied = info.value
    assert denied.rule_id == "AUTHORIZER" and denied.capability == "filesystem"
    records = list(audit.iter_records())
    assert records[-1]["outcome"] == "denied_authorizer"
    events = records[-1]["authorizer_events"]
    assert any(event["verdict"] == "deny" and event["capability"] == "filesystem" for event in events)
    # Filename never reaches the audit trail.
    with open(audit.path, encoding="utf-8") as handle:
        assert "/tmp/none.db" not in handle.read()


def test_planned_granted_side_effect_runs(controller, audit):
    _ctrl, conn = controller
    path = os.path.join(os.path.dirname(audit.path), "attached.db")
    guard = _guard(controller, audit, confirmer=AutoConfirmer(True))
    prepared = guard.prepare(f"ATTACH '{path}' AS ext", SourceOrigin("prompt"))
    with guard.scope(prepared):
        conn.execute(f"ATTACH '{path}' AS ext")
    assert next(iter(audit.iter_records()))["outcome"] == "confirmed"


# -- nested re-entry -----------------------------------------------------------


def test_nested_plan_within_parent_grants_passes(controller, audit):
    guard = _guard(controller, audit, confirmer=AutoConfirmer(True))
    top = guard.prepare("ATTACH '/tmp/a.db' AS a", SourceOrigin("prompt"))
    with guard.scope(top):
        nested = guard.prepare("ATTACH '/tmp/b.db' AS b", SourceOrigin("read", parent=SourceOrigin("prompt")))
        assert nested.top_level is False
        with guard.scope(nested):
            pass


def test_nested_plan_expanding_capabilities_denied(controller, audit):
    guard = _guard(controller, audit, confirmer=AutoConfirmer(True))
    top = guard.prepare("ATTACH '/tmp/a.db' AS a", SourceOrigin("prompt"))
    with pytest.raises(PolicyDenied) as info, guard.scope(top):
        guard.prepare("DROP TABLE keep", SourceOrigin("read", parent=SourceOrigin("prompt")))
    denied = info.value
    assert denied.rule_id == "NESTED-GRANT" and denied.capability == "write-schema"
    # The top-level execution records the nested denial.
    records = list(audit.iter_records())
    assert len(records) == 1 and records[0]["outcome"] == OUTCOME_DENIED_POLICY


def test_nested_deny_does_not_prompt(controller, audit):
    calls = AutoConfirmer(True)
    guard = _guard(controller, audit, confirmer=calls)
    top = guard.prepare("ATTACH '/tmp/a.db' AS a", SourceOrigin("prompt"))
    assert len(calls.calls) == 1
    with pytest.raises(PolicyDenied), guard.scope(top):
        guard.prepare("system rm -rf /", SourceOrigin("read", parent=SourceOrigin("prompt")))
    assert len(calls.calls) == 1


# -- disabled policy -----------------------------------------------------------


def test_disabled_policy_is_passthrough(tmp_path, audit):
    # When policy is disabled the controller is installed permissive too.
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE keep(id INTEGER)")
    ctrl = AuthorizerController(sqlite3, enabled=False)
    ctrl.install(conn)
    try:
        guard = ExecutionGuard(
            compiler=PlanCompiler(file_reader=_missing_reader, favorite_provider=lambda n: None),
            policy=Policy.from_config({"enabled": "false"}),
            controller=ctrl,
            audit_log=audit,
            confirmer=None,
            mode=MODE_INTERACTIVE,
        )
        prepared = guard.prepare("DROP TABLE keep", SourceOrigin("prompt"))
        with guard.scope(prepared):
            conn.execute("DROP TABLE keep")
        assert audit.write_count == 0
    finally:
        conn.close()


# -- process image restart (\\llm install) ------------------------------------


def test_flush_active_for_restart_writes_audit_exactly_once(controller, audit):
    guard = _guard(controller, audit)
    prepared = guard.prepare("SELECT 1", SourceOrigin("llm"))
    with guard.scope(prepared):
        guard.flush_active_for_restart()
        # Idempotent: the real os.execv replacement makes scope exit moot,
        # but a stubbed execv must not produce a duplicate record.
        guard.flush_active_for_restart()
    records = list(audit.iter_records())
    assert len(records) == 1
    assert records[0]["outcome"] == OUTCOME_ALLOWED
    assert audit.write_count == 1


def test_run_external_cmd_invokes_restart_hooks(monkeypatch):
    from litecli.packages.special import llm as special_llm

    calls: list[str] = []
    special_llm.before_restart_hooks.append(lambda: calls.append("flushed"))
    executed: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        special_llm.os,
        "execv",
        lambda exe, argv: executed.append((exe, argv)),
    )
    try:
        code, _ = special_llm.run_external_cmd("this", restart_cli=True, raise_exception=False)
    finally:
        special_llm.before_restart_hooks.pop()
    assert code == 0
    assert calls == ["flushed"]
    assert len(executed) == 1
