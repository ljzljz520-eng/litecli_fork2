"""End-to-end guard tests through SQLExecute.run() (real file DB)."""

import os

import pytest

from litecli.main import LiteCli
from litecli.packages.guard.audit import AuditLog
from litecli.packages.guard.authorizer import AuthorizerController
from litecli.packages.guard.confirm import AutoConfirmer
from litecli.packages.guard.guard import ExecutionGuard, PolicyDenied
from litecli.packages.guard.plan import ORIGIN_PROMPT, ORIGIN_READ, PlanCompiler, SourceOrigin
from litecli.packages.guard.policy import MODE_BATCH, MODE_INTERACTIVE, Policy
from litecli.sqlexecute import SQLExecute
from litecli.sqlexecute import sqlite3 as backend

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")


@pytest.fixture(scope="module", autouse=True)
def _dynamic_commands():
    return LiteCli(liteclirc=_TEST_CONFIG)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    executor = SQLExecute(path)
    list(executor.run("CREATE TABLE t(id INTEGER)"))
    executor.conn.close()
    return path


def _guard(tmp_path, mode, answer=None, policy=None, favorites=None):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    controller = AuthorizerController(backend, enabled=True)
    confirmer = AutoConfirmer(answer) if mode == MODE_INTERACTIVE else None
    favorite_provider = (lambda name: (favorites or {}).get(name)) if favorites is not None else None
    compiler = PlanCompiler(favorite_provider=favorite_provider) if favorite_provider is not None else PlanCompiler()
    return ExecutionGuard(
        compiler=compiler,
        policy=policy or Policy.default(),
        controller=controller,
        audit_log=audit,
        confirmer=confirmer,
        mode=mode,
    )


def _table_exists(executor, name="t"):
    row = executor.conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row[0] == 1


# -- interactive ---------------------------------------------------------------


def test_interactive_confirm_yes_executes_and_audits(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_INTERACTIVE, answer=True)
    executor = SQLExecute(db_path, guard=guard)
    list(executor.run("DROP TABLE t", SourceOrigin(ORIGIN_PROMPT)))
    assert not _table_exists(executor)
    assert guard.confirmer.calls and "write-schema" in guard.confirmer.calls[0]
    records = list(guard.audit_log.iter_records())
    assert records[0]["outcome"] == "confirmed"


def test_interactive_confirm_no_blocks_before_side_effect(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_INTERACTIVE, answer=False)
    executor = SQLExecute(db_path, guard=guard)
    with pytest.raises(PolicyDenied):
        executor.run("DROP TABLE t", SourceOrigin(ORIGIN_PROMPT))
    assert _table_exists(executor)


def test_interactive_create_runs_without_prompt(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_INTERACTIVE, answer=True)
    executor = SQLExecute(db_path, guard=guard)
    list(executor.run("CREATE TABLE t2(id INTEGER)", SourceOrigin(ORIGIN_PROMPT)))
    assert _table_exists(executor, "t2")
    assert guard.confirmer.calls == []


def test_multi_statement_single_confirmation(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_INTERACTIVE, answer=True)
    executor = SQLExecute(db_path, guard=guard)
    attach_path = str(tmp_path / "extra.db")
    list(executor.run(f"DROP TABLE t; ATTACH '{attach_path}' AS x", SourceOrigin(ORIGIN_PROMPT)))
    assert len(guard.confirmer.calls) == 1
    assert not _table_exists(executor)


# -- batch ---------------------------------------------------------------------


def test_batch_denies_before_side_effect(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_BATCH)
    executor = SQLExecute(db_path, guard=guard)
    with pytest.raises(PolicyDenied) as info:
        executor.run("DROP TABLE t", SourceOrigin(ORIGIN_READ))
    assert info.value.capability == "write-schema"
    assert _table_exists(executor)
    record = next(iter(guard.audit_log.iter_records()))
    assert record["outcome"] == "denied_policy"
    assert record["source_signature"] == "read"


@pytest.mark.parametrize(
    "origin",
    [
        SourceOrigin("prompt"),
        SourceOrigin("read"),
        SourceOrigin("startup"),
        SourceOrigin("llm"),
        SourceOrigin("execute"),
        SourceOrigin("stdin"),
    ],
)
def test_same_danger_same_verdict_every_origin(tmp_path, db_path, origin):
    executor = SQLExecute(db_path, guard=_guard(tmp_path, MODE_BATCH))
    with pytest.raises(PolicyDenied) as info:
        executor.run("DROP TABLE t", origin)
    assert info.value.rule_id == "WS-DEFAULT"


# -- nested sources -------------------------------------------------------------


def test_read_nested_content_confirmed_once(tmp_path, db_path, _dynamic_commands):
    sql_file = tmp_path / "nested.sql"
    sql_file.write_text("DROP TABLE t;\n", encoding="utf-8")
    guard = _guard(tmp_path, MODE_INTERACTIVE, answer=True)
    executor = SQLExecute(db_path, guard=guard)
    _dynamic_commands.sqlexecute = executor
    list(executor.run(f".read {sql_file}", SourceOrigin(ORIGIN_PROMPT)))
    assert not _table_exists(executor)
    assert len(guard.confirmer.calls) == 1
    record = next(iter(guard.audit_log.iter_records()))
    signatures = {tuple(node["kind"] for node in e["origin"]) for e in record["entries"]}
    assert ("prompt", "read") in signatures


def test_read_nested_denied_in_batch(tmp_path, db_path, _dynamic_commands):
    sql_file = tmp_path / "nested.sql"
    sql_file.write_text("DROP TABLE t;\n", encoding="utf-8")
    guard = _guard(tmp_path, MODE_BATCH)
    executor = SQLExecute(db_path, guard=guard)
    _dynamic_commands.sqlexecute = executor
    with pytest.raises(PolicyDenied):
        executor.run(f".read {sql_file}", SourceOrigin(ORIGIN_PROMPT))
    assert _table_exists(executor)


def test_unresolved_read_denied(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_BATCH)
    executor = SQLExecute(db_path, guard=guard)
    with pytest.raises(PolicyDenied) as info:
        executor.run(".read /no/such/file.sql", SourceOrigin(ORIGIN_PROMPT))
    assert info.value.rule_id == "PLAN-UNRESOLVED"


def test_nested_expansion_cannot_gain_capabilities(tmp_path, db_path, _dynamic_commands):
    # TOCTOU: at compile time the reader sees a benign file (only the .read
    # filesystem grant is confirmed); on disk the file actually attaches a
    # database. The nested re-entry must not gain the extra capability.
    sql_file = tmp_path / "nested.sql"
    attach_path = str(tmp_path / "extra.db")
    sql_file.write_text(f"ATTACH '{attach_path}' AS x;\n", encoding="utf-8")

    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    controller = AuthorizerController(backend, enabled=True)
    stale_compiler = PlanCompiler(file_reader=lambda _p: "SELECT 1;")
    guard = ExecutionGuard(
        compiler=stale_compiler,
        policy=Policy.default(),
        controller=controller,
        audit_log=audit,
        confirmer=AutoConfirmer(True),
        mode=MODE_INTERACTIVE,
    )
    executor = SQLExecute(db_path, guard=guard)
    _dynamic_commands.sqlexecute = executor
    with pytest.raises(PolicyDenied) as info:
        list(executor.run(f".read {sql_file}", SourceOrigin(ORIGIN_PROMPT)))
    assert info.value.rule_id == "NESTED-GRANT" and info.value.capability == "filesystem"


# -- favorites ------------------------------------------------------------------


def test_favorite_template_enforced_equally(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_BATCH, favorites={"danger": "DROP TABLE t"})
    executor = SQLExecute(db_path, guard=guard)
    with pytest.raises(PolicyDenied) as info:
        executor.run("\\f danger", SourceOrigin(ORIGIN_PROMPT))
    assert info.value.capability == "write-schema"
    assert _table_exists(executor)


# -- commands intercepted by the REPL --------------------------------------------


@pytest.mark.parametrize("text", ["\\llm drop table t", "\\ai anything", ".llm x"])
def test_llm_command_gated_before_subprocess(tmp_path, db_path, text):
    guard = _guard(tmp_path, MODE_BATCH)
    with pytest.raises(PolicyDenied) as info:
        guard.prepare(text, SourceOrigin(ORIGIN_PROMPT))
    assert info.value.capability in {"process", "network"}


def test_llm_command_confirmed_interactive(tmp_path, db_path):
    guard = _guard(tmp_path, MODE_INTERACTIVE, answer=True)
    prepared = guard.prepare("\\llm select 1", SourceOrigin(ORIGIN_PROMPT))
    assert prepared.outcome == "confirmed"
    assert "process" in prepared.grants and "network" in prepared.grants


@pytest.mark.parametrize("marker", ["\\e"])
def test_external_editor_command_gated(tmp_path, db_path, marker):
    guard = _guard(tmp_path, MODE_BATCH)
    with pytest.raises(PolicyDenied) as info:
        guard.prepare(marker, SourceOrigin(ORIGIN_PROMPT))
    assert info.value.capability in {"process", "filesystem"}


# -- special handlers ------------------------------------------------------------


def test_import_runs_after_confirmation_with_runtime_insert_grant(tmp_path, db_path, _dynamic_commands):
    # The .import handler performs ordinary INSERTs; the special detail alone
    # would make the authorizer reject them mid-import.
    executor = SQLExecute(db_path, guard=None)
    list(executor.run("CREATE TABLE imp(a TEXT, b TEXT)"))
    executor.conn.close()

    csv_file = tmp_path / "data.csv"
    csv_file.write_text("v1,v2\nv3,v4\n", encoding="utf-8")

    guard = _guard(tmp_path, MODE_INTERACTIVE, answer=True)
    executor = SQLExecute(db_path, guard=guard)
    _dynamic_commands.sqlexecute = executor
    list(executor.run(f".import {csv_file} imp", SourceOrigin(ORIGIN_PROMPT)))
    rows = executor.conn.execute("SELECT a, b FROM imp ORDER BY a").fetchall()
    assert rows == [("v1", "v2"), ("v3", "v4")]
    assert len(guard.confirmer.calls) == 1  # one confirmation for the whole import


def test_import_denied_in_batch_before_file_is_read(tmp_path, db_path, _dynamic_commands):
    csv_file = tmp_path / "data.csv"
    csv_file.write_text("h1,h2\nv1,v2\n", encoding="utf-8")
    guard = _guard(tmp_path, MODE_BATCH)
    executor = SQLExecute(db_path, guard=guard)
    _dynamic_commands.sqlexecute = executor
    with pytest.raises(PolicyDenied) as info:
        executor.run(f".import {csv_file} t", SourceOrigin(ORIGIN_PROMPT))
    assert info.value.capability == "filesystem"
    assert executor.conn.execute("SELECT count(*) FROM t").fetchone()[0] == 0


# -- authorizer backstop through real run --------------------------------------


def test_sqlean_file_functions_gated(tmp_path, db_path):
    # writefile exists only with sqlean extensions loaded.
    supports = False
    probe = SQLExecute(db_path)
    try:
        probe.conn.execute("SELECT writefile(?, 'x')", (str(tmp_path / "probe.txt"),))
        supports = True
    except backend.Error:
        supports = False
    finally:
        probe.conn.close()
    if not supports:
        pytest.skip("writefile() unavailable (sqlean extensions not loaded)")

    target = str(tmp_path / "out.txt")
    guard = _guard(tmp_path, MODE_BATCH)
    executor = SQLExecute(db_path, guard=guard)
    with pytest.raises(PolicyDenied):
        executor.run(f"SELECT writefile('{target}', 'x')", SourceOrigin(ORIGIN_PROMPT))
    assert not os.path.exists(target)


def test_sqlean_fileio_prefixed_aliases_gated(tmp_path, db_path):
    probe = SQLExecute(db_path)
    target = str(tmp_path / "alias.txt")
    try:
        probe.conn.execute("SELECT fileio_write(?, 'x')", (target,))
    except backend.Error:
        probe.conn.close()
        pytest.skip("fileio_write() unavailable (sqlean extensions not loaded)")
    else:
        probe.conn.close()
    if os.path.exists(target):
        os.remove(target)

    guard = _guard(tmp_path, MODE_BATCH)
    executor = SQLExecute(db_path, guard=guard)
    with pytest.raises(PolicyDenied) as info:
        executor.run(f"SELECT fileio_write('{target}', 'x')", SourceOrigin(ORIGIN_PROMPT))
    assert info.value.capability == "filesystem"
    assert not os.path.exists(target)
    record = next(iter(guard.audit_log.iter_records()))
    assert record["decision"]["verdict"] == "deny"
