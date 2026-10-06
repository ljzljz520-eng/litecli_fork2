"""Confirmation rendering and confirmer behavior."""

import os

import pytest

from litecli.main import LiteCli
from litecli.packages.guard.confirm import (
    AutoConfirmer,
    ClickConfirmer,
    action_label,
    confirmation_items,
    render_confirmation,
)
from litecli.packages.guard.plan import PlanCompiler, SourceOrigin
from litecli.packages.guard.policy import MODE_BATCH, MODE_INTERACTIVE, Policy, decide

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")


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


def _render(compiler, policy, sql, mode=MODE_INTERACTIVE):
    plan = compiler.compile(sql, SourceOrigin("prompt"))
    decision = decide(plan, mode, policy)
    return plan, decision, render_confirmation(plan, decision)


def test_render_lists_seq_capability_action_real_target(compiler, policy):
    _plan, decision, text = _render(
        compiler,
        policy,
        "system rm -rf /tmp/x; ATTACH '/real/secret.db' AS a; DROP TABLE users",
    )
    assert decision.verdict == "confirm"
    # one line per confirm point, with entry sequence numbers
    assert "entry #1" in text and "entry #2" in text and "entry #3" in text
    assert "process" in text and "filesystem" in text and "write-schema" in text
    # real targets are shown on screen
    assert "rm -rf /tmp/x" in text
    assert "/real/secret.db" in text
    assert "DROP users" in text


def test_render_for_various_capabilities(policy):
    def reader(path):
        if path == "/sql/secret.sql":
            return "SELECT 1"
        raise FileNotFoundError(path)

    compiler = PlanCompiler(file_reader=reader, favorite_provider=lambda n: None)
    sql = ".load /ext/evil.so; .read /sql/secret.sql; SELECT writefile('/o.txt','x'); PRAGMA writable_schema=ON"
    _, _, text = _render(compiler, policy, sql)
    for phrase in [
        "native SQLite extension",
        "read a file",
        "write a file via SQL function",
        "schema catalog",
        "/ext/evil.so",
        "/sql/secret.sql",
        "/o.txt",
    ]:
        assert phrase in text


def test_only_confirm_points_rendered(compiler, policy):
    plan, decision, _text = _render(compiler, policy, "SELECT 1; CREATE TABLE t(x); INSERT INTO t VALUES (1); DROP TABLE t")
    items = confirmation_items(plan, decision)
    assert len(items) == 1
    assert items[0].capability == "write-schema" and items[0].detail == "drop"


def test_no_items_for_allow_or_deny_plans(compiler, policy):
    plan = compiler.compile("SELECT 1", SourceOrigin("prompt"))
    decision = decide(plan, MODE_INTERACTIVE, policy)
    assert confirmation_items(plan, decision) == []
    plan = compiler.compile("DROP TABLE t", SourceOrigin("prompt"))
    decision = decide(plan, MODE_BATCH, policy)
    assert confirmation_items(plan, decision) == []


def test_action_labels_cover_known_pairs():
    assert action_label("filesystem", "attach")
    assert action_label("write-schema", "master_write")
    assert action_label("write-data", "delete")
    assert action_label("network", "network_function")


def test_auto_confirmer_records_render_and_answer(compiler, policy):
    plan = compiler.compile("DROP TABLE t", SourceOrigin("prompt"))
    decision = decide(plan, MODE_INTERACTIVE, policy)
    yes = AutoConfirmer(True)
    no = AutoConfirmer(False)
    assert yes.confirm(plan, decision) is True
    assert no.confirm(plan, decision) is False
    assert "write-schema" in yes.calls[0]


def test_click_confirmer_unavailable_without_tty():
    confirmer = ClickConfirmer(is_tty=False)
    assert confirmer.available is False
    plan = PlanCompiler().compile("DROP TABLE t", SourceOrigin("prompt"))
    decision = decide(plan, MODE_INTERACTIVE, Policy.default())
    assert confirmer.confirm(plan, decision) is False
