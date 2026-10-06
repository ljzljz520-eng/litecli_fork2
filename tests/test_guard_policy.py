"""Policy engine: default baseline, config parsing, source parity, replay."""

import os

import pytest

from litecli.main import LiteCli
from litecli.packages.guard import capabilities as caps
from litecli.packages.guard.plan import PlanCompiler, SourceOrigin
from litecli.packages.guard.policy import (
    MODE_BATCH,
    MODE_INTERACTIVE,
    RULE_FS,
    RULE_NET,
    RULE_UNRESOLVED,
    RULE_WD,
    RULE_WS,
    RULE_WS_CREATE,
    VERDICT_ALLOW,
    VERDICT_CONFIRM,
    VERDICT_DENY,
    Policy,
    PolicyRule,
    decide,
    replay,
    strictest,
)


@pytest.fixture
def policy():
    return Policy.default()


_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")


@pytest.fixture(scope="module", autouse=True)
def _dynamic_commands():
    return LiteCli(liteclirc=_TEST_CONFIG)


def _missing_file(path):
    raise FileNotFoundError(path)


@pytest.fixture
def compiler():
    return PlanCompiler(file_reader=_missing_file, favorite_provider=lambda n: None)


# -- default baseline ---------------------------------------------------------


@pytest.mark.parametrize(
    "sql, capability, detail, interactive, batch",
    [
        ("ATTACH '/x' AS a", caps.FILESYSTEM, caps.DETAIL_ATTACH, VERDICT_CONFIRM, VERDICT_DENY),
        ("VACUUM INTO '/x'", caps.FILESYSTEM, caps.DETAIL_VACUUM_INTO, VERDICT_CONFIRM, VERDICT_DENY),
        ("SELECT writefile('/x','y')", caps.FILESYSTEM, caps.DETAIL_WRITE_FILE, VERDICT_CONFIRM, VERDICT_DENY),
        ("SELECT eval('x')", caps.PROCESS, caps.DETAIL_EVAL, VERDICT_CONFIRM, VERDICT_DENY),
        ("SELECT load_extension('/x')", caps.EXTENSION, caps.DETAIL_LOAD_EXTENSION, VERDICT_CONFIRM, VERDICT_DENY),
        ("SELECT http_get('http://x')", caps.NETWORK, caps.DETAIL_NETWORK_FUNCTION, VERDICT_CONFIRM, VERDICT_DENY),
        ("DROP TABLE t", caps.WRITE_SCHEMA, caps.DETAIL_DROP, VERDICT_CONFIRM, VERDICT_DENY),
        ("ALTER TABLE t RENAME TO x", caps.WRITE_SCHEMA, caps.DETAIL_ALTER, VERDICT_CONFIRM, VERDICT_DENY),
        ("PRAGMA writable_schema=ON", caps.WRITE_SCHEMA, caps.DETAIL_WRITABLE_SCHEMA, VERDICT_CONFIRM, VERDICT_DENY),
        ("CREATE VIRTUAL TABLE ft USING fts5(x)", caps.WRITE_SCHEMA, caps.DETAIL_VTABLE, VERDICT_CONFIRM, VERDICT_DENY),
        ("CREATE TABLE t(x)", caps.WRITE_SCHEMA, caps.DETAIL_CREATE, VERDICT_ALLOW, VERDICT_ALLOW),
        ("INSERT INTO t VALUES (1)", caps.WRITE_DATA, caps.DETAIL_INSERT, VERDICT_ALLOW, VERDICT_ALLOW),
        ("UPDATE t SET x=1", caps.WRITE_DATA, caps.DETAIL_UPDATE, VERDICT_ALLOW, VERDICT_ALLOW),
        ("DELETE FROM t", caps.WRITE_DATA, caps.DETAIL_DELETE, VERDICT_ALLOW, VERDICT_ALLOW),
    ],
)
def test_default_baseline_matrix(policy, compiler, sql, capability, detail, interactive, batch):
    plan = compiler.compile(sql, SourceOrigin("prompt"))
    entry = plan.entries[0]
    point_verdict = {p.detail: p.verdict for p in decide(plan, MODE_INTERACTIVE, policy).entries[0].points}
    assert point_verdict[detail] == interactive, sql
    point_verdict = {p.detail: p.verdict for p in decide(plan, MODE_BATCH, policy).entries[0].points}
    assert point_verdict[detail] == batch, sql
    assert detail in entry.capabilities.get(capability, set())


def test_batch_confirms_escalate_to_deny(compiler, policy):
    plan = compiler.compile("system ls", SourceOrigin("prompt"))
    decision = decide(plan, MODE_BATCH, policy)
    assert decision.verdict == VERDICT_DENY
    assert decision.entries[0].points[0].rule_id == "PROC-DEFAULT"


def test_multiple_caps_entry_takes_strictest(policy, compiler):
    # writefile (filesystem=confirm) inside plain SELECT
    plan = compiler.compile("SELECT writefile('/x','y')", SourceOrigin("prompt"))
    decision = decide(plan, MODE_INTERACTIVE, policy)
    assert decision.verdict == VERDICT_CONFIRM


def test_multi_statement_any_deny_denies_whole_plan(policy, compiler):
    plan = compiler.compile("SELECT 1; DROP TABLE t; INSERT INTO t VALUES (1)", SourceOrigin("prompt"))
    decision = decide(plan, MODE_BATCH, policy)
    assert decision.verdict == VERDICT_DENY
    assert [e.verdict for e in decision.entries] == [VERDICT_ALLOW, VERDICT_DENY, VERDICT_ALLOW]


def test_unresolved_entry_denies(policy, compiler):
    plan = compiler.compile(".read missing.sql", SourceOrigin("prompt"))
    decision = decide(plan, MODE_INTERACTIVE, policy)
    assert decision.verdict == VERDICT_DENY
    assert decision.entries[0].points[0].rule_id == RULE_UNRESOLVED


# -- source parity ------------------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        SourceOrigin("prompt"),
        SourceOrigin("read", label="x.sql"),
        SourceOrigin("startup"),
        SourceOrigin("favorite", label="q"),
        SourceOrigin("llm"),
        SourceOrigin("stdin"),
        SourceOrigin("execute"),
    ],
)
def test_same_operation_same_verdict_across_origins(policy, compiler, origin):
    plan = compiler.compile("DROP TABLE t", origin)
    interactive = decide(plan, MODE_INTERACTIVE, policy)
    batch = decide(plan, MODE_BATCH, policy)
    # verdict and rule id are independent of origin
    point = interactive.entries[0].points[0]
    assert (point.verdict, point.rule_id) == (VERDICT_CONFIRM, RULE_WS)
    point = batch.entries[0].points[0]
    assert (point.verdict, point.rule_id) == (VERDICT_DENY, RULE_WS)
    # origins are still recorded
    assert plan.entries[0].origin.kind == origin.kind


def test_decision_never_references_origin(policy, compiler):
    plan = compiler.compile("DROP TABLE t", SourceOrigin("llm"))
    blob = repr(decide(plan, MODE_INTERACTIVE, policy))
    assert "llm" not in blob and "favorite" not in blob


# -- config parsing -----------------------------------------------------------


def test_custom_config_overrides_defaults():
    policy = Policy.from_config({"filesystem": "allow, allow", "write_schema": "deny,deny"})
    assert policy.decide_point(caps.FILESYSTEM, caps.DETAIL_ATTACH, MODE_INTERACTIVE) == (VERDICT_ALLOW, RULE_FS)
    assert policy.decide_point(caps.WRITE_SCHEMA, caps.DETAIL_DROP, MODE_INTERACTIVE) == (VERDICT_DENY, RULE_WS)
    # create override remains independent
    assert policy.decide_point(caps.WRITE_SCHEMA, caps.DETAIL_CREATE, MODE_BATCH) == (VERDICT_ALLOW, RULE_WS_CREATE)


def test_invalid_config_value_falls_back(caplog):
    policy = Policy.from_config({"network": "maybe,deny"})
    assert policy.decide_point(caps.NETWORK, caps.DETAIL_NETWORK_FUNCTION, MODE_INTERACTIVE) == (
        VERDICT_CONFIRM,
        RULE_NET,
    )


def test_write_schema_create_override():
    policy = Policy.from_config({"write_schema_create": "confirm,deny"})
    assert policy.decide_point(caps.WRITE_SCHEMA, caps.DETAIL_CREATE, MODE_BATCH) == (VERDICT_DENY, RULE_WS_CREATE)


def test_destructive_warning_false_allows_schema_destruction():
    policy = Policy.from_config({}, destructive_warning=False)
    assert policy.decide_point(caps.WRITE_SCHEMA, caps.DETAIL_DROP, MODE_BATCH) == (VERDICT_ALLOW, RULE_WS)
    # create and write-data unaffected
    assert policy.decide_point(caps.WRITE_SCHEMA, caps.DETAIL_CREATE, MODE_BATCH) == (VERDICT_ALLOW, RULE_WS_CREATE)
    assert policy.decide_point(caps.WRITE_DATA, caps.DETAIL_INSERT, MODE_BATCH) == (VERDICT_ALLOW, RULE_WD)


def test_disabled_policy_flag():
    policy = Policy.from_config({"enabled": "false"})
    assert policy.enabled is False


def test_network_functions_config_and_depth():
    policy = Policy.from_config({"network_functions": "my_http, other_net", "max_nest_depth": "3"})
    assert policy.network_functions == frozenset({"my_http", "other_net"})
    assert policy.max_nest_depth == 3


def test_digest_changes_with_rules():
    a = Policy.default()
    b = Policy.from_config({"filesystem": "deny,deny"})
    assert a.digest != b.digest


def test_exact_detail_rule_wins_over_generic():
    rules = [
        PolicyRule("G", caps.FILESYSTEM, MODE_INTERACTIVE, VERDICT_DENY),
        PolicyRule("E", caps.FILESYSTEM, MODE_INTERACTIVE, VERDICT_ALLOW, detail=caps.DETAIL_ATTACH),
    ]
    policy = Policy(rules=rules)
    assert policy.decide_point(caps.FILESYSTEM, caps.DETAIL_ATTACH, MODE_INTERACTIVE) == (VERDICT_ALLOW, "E")
    assert policy.decide_point(caps.FILESYSTEM, caps.DETAIL_READ_FILE, MODE_INTERACTIVE) == (VERDICT_DENY, "G")


# -- replay -------------------------------------------------------------------


def test_replay_matches_recorded_decision(policy, compiler):
    plan = compiler.compile("DROP TABLE t; INSERT INTO t VALUES (1)", SourceOrigin("llm"))
    decision = decide(plan, MODE_BATCH, policy)
    redacted = plan.audit_entries()
    result = replay(redacted, MODE_BATCH, decision.rules_snapshot)
    assert result["verdict"] == decision.verdict == VERDICT_DENY
    for recorded, replayed in zip(decision.entries, result["entries"]):
        assert recorded.verdict == replayed["verdict"]
        recorded_points = {(p.capability, p.detail, p.verdict, p.rule_id) for p in recorded.points}
        replayed_points = {(p["capability"], p["detail"], p["verdict"], p["rule_id"]) for p in replayed["points"]}
        assert recorded_points == replayed_points


def test_replay_flags_falsified_recorded_verdict(policy, compiler):
    # An attacker edits the audit record's stored verdict from deny to allow.
    plan = compiler.compile("DROP TABLE t", SourceOrigin("prompt"))
    decision = decide(plan, MODE_BATCH, policy)
    assert decision.verdict == VERDICT_DENY
    falsified = decision.audit_dict()
    falsified["verdict"] = VERDICT_ALLOW
    falsified["entries"][0]["verdict"] = VERDICT_ALLOW
    result = replay(plan.audit_entries(), MODE_BATCH, decision.rules_snapshot)
    assert result["verdict"] == VERDICT_DENY
    assert result["verdict"] != falsified["verdict"]


def test_replay_flags_tampered_rules_snapshot(policy, compiler):
    plan = compiler.compile("DROP TABLE t", SourceOrigin("prompt"))
    decision = decide(plan, MODE_BATCH, policy)
    # Snapshot altered so WS-DEFAULT becomes allow.
    tampered_snapshot = [dict(rule) for rule in decision.rules_snapshot]
    for rule in tampered_snapshot:
        if rule["id"] == RULE_WS and rule["mode"] == MODE_BATCH:
            rule["verdict"] = VERDICT_ALLOW
    result = replay(plan.audit_entries(), MODE_BATCH, tampered_snapshot)
    assert result["verdict"] == VERDICT_ALLOW
    assert result["verdict"] != decision.verdict


def test_replay_needs_no_raw_sql(policy, compiler):
    plan = compiler.compile("DROP TABLE SUPERSECRETTABLE", SourceOrigin("prompt"))
    decision = decide(plan, MODE_BATCH, policy)
    redacted = plan.audit_entries()
    blob = repr(redacted)
    assert "SUPERSECRETTABLE" in blob  # identifier kept (structural), no literals exist here
    result = replay(redacted, MODE_BATCH, decision.rules_snapshot)
    assert result["verdict"] == VERDICT_DENY


def test_strictest_ordering():
    assert strictest(VERDICT_ALLOW, VERDICT_CONFIRM) == VERDICT_CONFIRM
    assert strictest(VERDICT_CONFIRM, VERDICT_DENY) == VERDICT_DENY
    assert strictest(VERDICT_ALLOW) == VERDICT_ALLOW
