"""JSONL audit trail: records, redaction, lookup and hash-verified replay."""

import json
import os

import pytest

from litecli.main import LiteCli
from litecli.packages.guard import capabilities as caps
from litecli.packages.guard.audit import (
    AUDIT_OFF,
    OUTCOME_ALLOWED,
    OUTCOME_CONFIRMED,
    OUTCOME_DENIED_AUTHORIZER,
    OUTCOME_DENIED_POLICY,
    AuditLog,
    build_record,
    default_audit_path,
    replay_record,
    resolve_audit_path,
)
from litecli.packages.guard.authorizer import AuthorizerEvent
from litecli.packages.guard.plan import PlanCompiler, SourceOrigin
from litecli.packages.guard.policy import MODE_BATCH, MODE_INTERACTIVE, Policy, decide

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")
SECRET = "ZZ-AUDIT-SECRET-424242"


@pytest.fixture(scope="module", autouse=True)
def _dynamic_commands():
    return LiteCli(liteclirc=_TEST_CONFIG)


@pytest.fixture
def policy():
    return Policy.default()


@pytest.fixture
def compiler():
    def missing(path):
        raise FileNotFoundError(path)

    return PlanCompiler(file_reader=missing, favorite_provider=lambda n: None)


def _make_record(compiler, policy, sql, mode, outcome, events=None, origin=None):
    plan = compiler.compile(sql, origin or SourceOrigin("prompt"))
    decision = decide(plan, mode, policy)
    return build_record(plan, decision, outcome, duration_ms=1.5, authorizer_events=events, ts=1000.0)


def test_default_and_off_path_resolution():
    assert resolve_audit_path("default") == default_audit_path()
    assert resolve_audit_path(None) == default_audit_path()
    for off in AUDIT_OFF:
        assert resolve_audit_path(off) is None
    assert resolve_audit_path("~/x.jsonl").endswith("x.jsonl")


def test_record_contains_required_fields(compiler, policy):
    record = _make_record(compiler, policy, "CREATE TABLE t(x)", MODE_INTERACTIVE, OUTCOME_ALLOWED)
    for field in (
        "ts",
        "plan_hash",
        "source_signature",
        "mode",
        "policy_version",
        "policy_digest",
        "rules_snapshot",
        "entries",
        "decision",
        "authorizer_events",
        "outcome",
        "duration_ms",
    ):
        assert field in record
    assert record["outcome"] == OUTCOME_ALLOWED
    assert record["duration_ms"] == 1.5
    assert len(record["plan_hash"]) == 64
    assert record["rules_snapshot"]


@pytest.mark.parametrize(
    "outcome",
    [OUTCOME_ALLOWED, OUTCOME_CONFIRMED, OUTCOME_DENIED_POLICY, OUTCOME_DENIED_AUTHORIZER],
)
def test_all_outcomes_append_valid_jsonl(tmp_path, compiler, policy, outcome):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    record = _make_record(compiler, policy, "DROP TABLE t", MODE_BATCH, outcome)
    assert log.append(record) is True
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["outcome"] == outcome


def test_authorizer_events_serialized_redacted(tmp_path, compiler, policy):
    events = [
        AuthorizerEvent(
            action=31,
            action_name="FUNCTION",
            capability=caps.FILESYSTEM,
            detail=caps.DETAIL_WRITE_FILE,
            target="writefile",
            verdict="deny",
            outside_scope=True,
        ),
        AuthorizerEvent(action=24, action_name="ATTACH", capability=caps.FILESYSTEM, detail="attach", verdict="deny"),
    ]
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    record = _make_record(
        compiler,
        policy,
        f"SELECT writefile('/vault/{SECRET}.txt', '{SECRET}')",
        MODE_BATCH,
        OUTCOME_DENIED_AUTHORIZER,
        events=events,
    )
    log.append(record)
    serialized = next(iter(log.iter_records()))
    names = [e["action"] for e in serialized["authorizer_events"]]
    assert names == ["FUNCTION", "ATTACH"]
    attach_event = serialized["authorizer_events"][1]
    assert "target" not in attach_event  # ATTACH carries the filename, dropped


def test_no_sensitive_values_in_audit_file(tmp_path, compiler, policy):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    sql = (
        f"ATTACH '/secretvault/{SECRET}.db' AS a; "
        # SQLite also accepts double-quoted string literals.
        f'INSERT INTO t VALUES ("{SECRET}"); '
        # Comments must not leak either.
        f"/* token {SECRET} */ -- line {SECRET}\n"
        f"INSERT INTO t VALUES ('{SECRET}'); DROP TABLE t"
    )
    record = _make_record(compiler, policy, sql, MODE_BATCH, OUTCOME_DENIED_POLICY)
    log.append(record)
    blob = (tmp_path / "audit.jsonl").read_text()
    # Literals and file paths never land in audit, regardless of quote style.
    assert SECRET not in blob
    assert "secretvault" not in blob
    assert "/secretvault/" not in blob
    # Structural identifiers and keywords remain.
    assert "DROP TABLE t" in blob


def test_target_and_raw_fields_absent(compiler, policy):
    record = _make_record(compiler, policy, f"ATTACH '/{SECRET}.db' AS a", MODE_BATCH, OUTCOME_DENIED_POLICY)
    blob = json.dumps(record)
    assert '"target"' not in blob
    assert '"raw"' not in blob
    assert SECRET not in blob


def test_find_by_hash(tmp_path, compiler, policy):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    first = _make_record(compiler, policy, "DROP TABLE a", MODE_BATCH, OUTCOME_DENIED_POLICY)
    second = _make_record(compiler, policy, "DROP TABLE b", MODE_BATCH, OUTCOME_ALLOWED)
    log.append(first)
    log.append(second)
    found = log.find_by_hash(first["plan_hash"])
    assert len(found) == 1
    assert found[0]["plan_hash"] == first["plan_hash"]


def test_replay_roundtrip(tmp_path, compiler, policy):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    record = _make_record(compiler, policy, "DROP TABLE t; INSERT INTO t VALUES (1)", MODE_BATCH, OUTCOME_DENIED_POLICY)
    log.append(record)
    stored = log.find_by_hash(record["plan_hash"])[0]
    result = replay_record(stored)
    assert result.ok is True
    assert result.hash_ok is True
    assert result.verdict_match is True
    assert result.replayed_verdict == "deny"


def test_replay_detects_tampered_template(tmp_path, compiler, policy):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    record = _make_record(compiler, policy, "CREATE TABLE t(x)", MODE_BATCH, OUTCOME_ALLOWED)
    log.append(record)
    stored = log.find_by_hash(record["plan_hash"])[0]
    stored["entries"][0]["template"] = "DROP TABLE t"
    result = replay_record(stored)
    assert result.hash_ok is False
    assert result.ok is False


def test_replay_detects_falsified_verdict(tmp_path, compiler, policy):
    record = _make_record(compiler, policy, "DROP TABLE t", MODE_BATCH, OUTCOME_DENIED_POLICY)
    record["decision"]["verdict"] = "allow"
    record["decision"]["entries"][0]["verdict"] = "allow"
    result = replay_record(record)
    assert result.verdict_match is False
    assert result.replayed_verdict == "deny"


def test_replay_detects_tampered_rules_snapshot(compiler, policy):
    record = _make_record(compiler, policy, "DROP TABLE t", MODE_BATCH, OUTCOME_DENIED_POLICY)
    # Forge a rule that would allow the denied operation while leaving the
    # recorded rules digest untouched (naive tampering of the audit line).
    record["rules_snapshot"] = [{"id": "WS-DEFAULT", "capability": "write-schema", "mode": "batch", "verdict": "allow", "detail": None}]
    record["decision"]["rules_snapshot"] = record["rules_snapshot"]
    result = replay_record(record)
    assert result.snapshot_ok is False
    assert result.ok is False


def test_replay_requires_no_raw_sql(compiler, policy):
    record = _make_record(compiler, policy, f"INSERT INTO t VALUES ('{SECRET}')", MODE_BATCH, OUTCOME_ALLOWED)
    assert SECRET not in json.dumps(record)
    result = replay_record(record)
    assert result.ok is True


def test_unwritable_path_is_fail_safe(tmp_path, compiler, policy):
    # Pointing the log at an existing directory makes open() fail.
    log = AuditLog(str(tmp_path))
    record = _make_record(compiler, policy, "SELECT 1", MODE_INTERACTIVE, OUTCOME_ALLOWED)
    assert log.append(record) is False
    assert log.last_error is not None
    # main flow continues: another in-memory append conceptually still works
    assert record["outcome"] == OUTCOME_ALLOWED


def test_disabled_log_does_nothing(compiler, policy):
    log = AuditLog(None)
    assert log.enabled is False
    record = _make_record(compiler, policy, "SELECT 1", MODE_INTERACTIVE, OUTCOME_ALLOWED)
    assert log.append(record) is False
    assert list(log.iter_records()) == []
