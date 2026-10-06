"""Tests for the policyaudit special command."""

import json
import os
import sqlite3

import pytest

from litecli.main import LiteCli
from litecli.packages import special
from litecli.packages.guard.audit import AuditLog, build_record
from litecli.packages.guard.authorizer import AuthorizerController
from litecli.packages.guard.confirm import AutoConfirmer
from litecli.packages.guard.guard import ExecutionGuard
from litecli.packages.guard.plan import PlanCompiler, SourceOrigin
from litecli.packages.guard.policy import MODE_INTERACTIVE, Policy, decide
from litecli.packages.special.main import command_capabilities

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")


def _missing_reader(path):
    raise FileNotFoundError(path)


@pytest.fixture
def cli(tmp_path):
    app = LiteCli(liteclirc=_TEST_CONFIG)
    audit = AuditLog(str(tmp_path / "policy-audit.jsonl"))
    controller = AuthorizerController(sqlite3, enabled=False)
    compiler = PlanCompiler(file_reader=_missing_reader, favorite_provider=lambda n: None)
    app.guard = ExecutionGuard(
        compiler=compiler,
        policy=Policy.default(),
        controller=controller,
        audit_log=audit,
        confirmer=AutoConfirmer(True),
        mode=MODE_INTERACTIVE,
    )
    return app


def _append_record(cli, sql="DROP TABLE t"):
    plan = cli.guard.compiler.compile(sql, SourceOrigin("prompt"))
    decision = decide(plan, MODE_INTERACTIVE, cli.guard.policy)
    record = build_record(plan, decision, "denied_policy")
    cli.guard.audit_log.append(record)
    return record


def test_policyaudit_declared_without_capabilities():
    # Dynamic registration happens in LiteCli.__init__.
    LiteCli(liteclirc=_TEST_CONFIG)
    assert command_capabilities("policyaudit") == frozenset()


def test_policyaudit_empty(cli):
    result = list(special.execute(None, "policyaudit"))
    assert result == [(None, None, None, "No policy audit records found.")]


def test_policyaudit_lists_records(cli):
    _append_record(cli)
    result = list(special.execute(None, "policyaudit"))
    title, rows, headers, status = result[0]
    assert title == "Policy audit"
    assert headers == ["ts", "plan_hash", "mode", "verdict", "outcome"]
    assert rows[0][3] == "confirm" and rows[0][4] == "denied_policy"
    assert "1 record" in status


def test_policyaudit_hash_verifies_match(cli):
    record = _append_record(cli)
    result = list(special.execute(None, f"policyaudit {record['plan_hash']}"))
    fields = dict(result[0][1])
    assert fields["status"] == "MATCH" and fields["hash_ok"] and fields["verdict_match"]


def test_policyaudit_hash_prefix(cli):
    record = _append_record(cli)
    result = list(special.execute(None, f"policyaudit {record['plan_hash'][:8]}"))
    assert dict(result[0][1])["status"] == "MATCH"


def test_policyaudit_unknown_hash(cli):
    _append_record(cli)
    result = list(special.execute(None, "policyaudit deadbeef"))
    assert "No audit record" in result[0][3]


def test_policyaudit_detects_tampering(cli):
    record = _append_record(cli)
    path = cli.guard.audit_log.path
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    tampered = json.loads(lines[0])
    tampered["decision"]["verdict"] = "allow"
    lines[0] = json.dumps(tampered) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    result = list(special.execute(None, f"policyaudit {record['plan_hash']}"))
    fields = dict(result[0][1])
    assert fields["status"] == "MISMATCH" and fields["verdict_match"] is False
