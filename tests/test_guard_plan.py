"""PlanCompiler: static analysis, nesting, normalization and hashing."""

import os

import pytest

from litecli.main import LiteCli
from litecli.packages.guard import capabilities as caps
from litecli.packages.guard.plan import (
    ORIGIN_FAVORITE,
    ORIGIN_LLM,
    ORIGIN_PROMPT,
    ORIGIN_STARTUP,
    PlanCompiler,
    SourceOrigin,
    analyze_sql,
    normalize_sql,
)

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")


@pytest.fixture(scope="module", autouse=True)
def _dynamic_commands():
    return LiteCli(liteclirc=_TEST_CONFIG)


@pytest.fixture
def favorites():
    return {
        "dropq": "DROP TABLE x",
        "selectq": "SELECT * FROM t WHERE id = :id",
        "multi": "INSERT INTO t VALUES (1); .read inner.sql",
    }


@pytest.fixture
def files():
    return {
        "a.sql": "DROP TABLE y;\n.read b.sql",
        "b.sql": "SELECT writefile('/z', 'v')",
        "cycle.sql": ".read cycle.sql",
        "inner.sql": "SELECT 1",
        "deep1.sql": ".read deep2.sql",
        "deep2.sql": ".read deep3.sql",
        "deep3.sql": "DROP TABLE d",
    }


@pytest.fixture
def compiler(favorites, files):
    def read_file(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]

    return PlanCompiler(
        file_reader=read_file,
        favorite_provider=lambda name: favorites.get(name),
        max_nest_depth=2,
    )


# -- static analysis ---------------------------------------------------------


@pytest.mark.parametrize(
    "sql, expected",
    [
        ("CREATE TABLE t(x)", (caps.WRITE_SCHEMA, caps.DETAIL_CREATE)),
        ("CREATE TEMP TRIGGER trg BEGIN SELECT 1; END", (caps.WRITE_SCHEMA, caps.DETAIL_CREATE)),
        ("CREATE VIRTUAL TABLE ft USING fts5(x)", (caps.WRITE_SCHEMA, caps.DETAIL_VTABLE)),
        ("DROP INDEX idx", (caps.WRITE_SCHEMA, caps.DETAIL_DROP)),
        ("ALTER TABLE t RENAME TO t2", (caps.WRITE_SCHEMA, caps.DETAIL_ALTER)),
        ("PRAGMA writable_schema=ON", (caps.WRITE_SCHEMA, caps.DETAIL_WRITABLE_SCHEMA)),
        ("DELETE FROM sqlite_master", (caps.WRITE_SCHEMA, caps.DETAIL_MASTER_WRITE)),
        ("UPDATE main.sqlite_schema SET sql='x'", (caps.WRITE_SCHEMA, caps.DETAIL_MASTER_WRITE)),
        ("INSERT INTO sqlite_master(type,name) VALUES('table','a')", (caps.WRITE_SCHEMA, caps.DETAIL_MASTER_WRITE)),
        ("ATTACH '/x.db' AS a", (caps.FILESYSTEM, caps.DETAIL_ATTACH)),
        ("VACUUM INTO '/o.db'", (caps.FILESYSTEM, caps.DETAIL_VACUUM_INTO)),
        ("SELECT writefile('/x','y')", (caps.FILESYSTEM, caps.DETAIL_WRITE_FILE)),
        ("SELECT readfile('/x')", (caps.FILESYSTEM, caps.DETAIL_READ_FILE)),
        ("SELECT eval('ls')", (caps.PROCESS, caps.DETAIL_EVAL)),
        ("SELECT load_extension('/e.so')", (caps.EXTENSION, caps.DETAIL_LOAD_EXTENSION)),
        ("SELECT http_get('http://x')", (caps.NETWORK, caps.DETAIL_NETWORK_FUNCTION)),
        ("INSERT INTO t VALUES (1)", (caps.WRITE_DATA, caps.DETAIL_INSERT)),
        ("REPLACE INTO t VALUES (1)", (caps.WRITE_DATA, caps.DETAIL_INSERT)),
        ("UPDATE t SET x=1", (caps.WRITE_DATA, caps.DETAIL_UPDATE)),
        ("DELETE FROM t", (caps.WRITE_DATA, caps.DETAIL_DELETE)),
    ],
)
def test_analyze_sql_detects_capability(sql, expected):
    capability, detail = expected
    _verb, found, target = analyze_sql(sql)
    assert detail in found.get(capability, set()), sql
    assert target  # every dangerous statement yields a UI target


def test_benign_statements_have_no_capability():
    for sql in [
        "SELECT * FROM t",
        "PRAGMA table_info(t)",
        "PRAGMA writable_schema=OFF",
        "PRAGMA writable_schema",
        "BEGIN",
        "DETACH DATABASE a",
        "REINDEX t",
    ]:
        _verb, found, _ = analyze_sql(sql)
        assert found == {}, sql


def test_function_detection_inside_subquery():
    _, found, _ = analyze_sql("SELECT * FROM t WHERE x IN (SELECT readfile('/f'))")
    assert caps.DETAIL_READ_FILE in found[caps.FILESYSTEM]


@pytest.mark.parametrize(
    "sql,detail",
    [
        ("SELECT fileio_write('/x', 'y')", caps.DETAIL_WRITE_FILE),
        ("SELECT fileio_append('/x', 'y')", caps.DETAIL_WRITE_FILE),
        ("SELECT fileio_mkdir('/d')", caps.DETAIL_WRITE_FILE),
        ("SELECT fileio_symlink('/a', '/b')", caps.DETAIL_WRITE_FILE),
        ("SELECT fileio_mode('/x', 420)", caps.DETAIL_WRITE_FILE),
        ("SELECT fileio_read('/x')", caps.DETAIL_READ_FILE),
        ("SELECT lsmode('/x')", caps.DETAIL_FUNCTION),
        ("SELECT * FROM lsdir('/tmp')", caps.DETAIL_READ_FILE),
        ("SELECT * FROM fileio_scan('/x')", caps.DETAIL_READ_FILE),
    ],
)
def test_analyze_detects_sqlean_fileio_entry_points(sql, detail):
    _verb, found, target = analyze_sql(sql)
    assert detail in found[caps.FILESYSTEM], sql
    assert target


@pytest.mark.parametrize("module", sorted(caps.FILE_READING_VTABLE_MODULES))
def test_analyze_flags_file_reading_virtual_tables(module):
    sql = f"CREATE VIRTUAL TABLE t USING {module}(filename='/etc/secret')"
    _verb, found, target = analyze_sql(sql)
    assert caps.DETAIL_VTABLE in found[caps.WRITE_SCHEMA]
    assert caps.DETAIL_READ_FILE in found[caps.FILESYSTEM]
    assert module in (target or "")


def test_analyze_plain_virtual_table_has_no_filesystem():
    _verb, found, _ = analyze_sql("CREATE VIRTUAL TABLE ft USING fts5(x)")
    assert caps.FILESYSTEM not in found
    assert caps.DETAIL_VTABLE in found[caps.WRITE_SCHEMA]


def test_normalization_masks_every_literal_kind():
    normalized = normalize_sql("INSERT INTO t VALUES ('a', 'it''s', 42, 3.14, X'0aff', :name, @p, $q, ?)")
    assert normalized == "INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    for secret in ["'a'", "it's", "42", "3.14", "0aff", "name"]:
        assert secret not in normalized.replace("?", "")


def test_normalization_stable_across_literal_values():
    a = normalize_sql("SELECT * FROM t WHERE x = 'alpha' AND y = 1")
    b = normalize_sql("SELECT * FROM t WHERE x = 'beta'  AND y = 2")
    assert a == b


def test_normalization_masks_double_quoted_strings_and_comments():
    secret = "ZZ-MASK-ME-9999"
    sql = f'SELECT "{secret}" /* {secret} block */ FROM t -- {secret} line'
    normalized = normalize_sql(sql)
    assert secret not in normalized
    assert normalized == "SELECT ? FROM t"
    # Double-quoted identifiers also normalize consistently (values only).
    assert normalize_sql('SELECT "a" FROM t') == normalize_sql('SELECT "b" FROM t')


def test_normalization_comment_markers_inside_strings_are_literal():
    # A password-shaped value containing -- or /* must be masked as one
    # literal instead of being treated as a comment and leaking a fragment.
    normalized = normalize_sql("SELECT 'abc--SECRET-TOKEN', 'x/*y*/z'")
    assert "SECRET" not in normalized
    assert normalized == "SELECT ?, ?"
    # Unterminated block comment is stripped to EOF.
    assert normalize_sql("SELECT 1 /* leaked SECRET") == "SELECT ?"
    # Unterminated quote masks to EOF.
    assert "SECRET" not in normalize_sql("SELECT 'abcSECRET")


# -- compilation -------------------------------------------------------------


def test_multi_statement_order_and_kinds(compiler):
    plan = compiler.compile("SELECT 1; DROP TABLE t; .tables", SourceOrigin(ORIGIN_PROMPT))
    assert [e.kind for e in plan.entries] == ["sql", "sql", "special"]
    assert [e.seq for e in plan.entries] == [1, 2, 3]
    assert plan.entries[1].capabilities.get(caps.WRITE_SCHEMA) == {caps.DETAIL_DROP}


def test_special_commands_carry_registry_capabilities(compiler):
    plan = compiler.compile("system rm -rf /; .load /x.so; .import f.csv t; .read a.sql", SourceOrigin(ORIGIN_PROMPT))
    by_verb = {e.verb: e for e in plan.entries if e.kind == "special"}
    assert by_verb["system"].capabilities == {caps.PROCESS: {caps.DETAIL_PROCESS_SPECIAL}}
    assert by_verb[".load"].capabilities == {caps.EXTENSION: {caps.DETAIL_LOAD_EXTENSION}}
    assert by_verb[".import"].capabilities == {
        caps.FILESYSTEM: {caps.DETAIL_READ_FILE},
        # The handler performs ordinary INSERTs, so the runtime insert detail
        # must be part of the grant.
        caps.WRITE_DATA: {caps.DETAIL_SPECIAL, caps.DETAIL_INSERT},
    }
    read_entry = by_verb[".read"]
    assert read_entry.capabilities == {caps.FILESYSTEM: {caps.DETAIL_READ_FILE}}


def test_read_recursive_expansion_and_origin_chain(compiler):
    plan = compiler.compile(".read a.sql", SourceOrigin(ORIGIN_PROMPT))
    verbs = [(e.kind, e.verb, e.origin.type_chain()) for e in plan.entries]
    assert verbs == [
        ("special", ".read", ["prompt"]),
        ("sql", "DROP", ["prompt", "read"]),
        ("special", ".read", ["prompt", "read"]),
        ("sql", "SELECT", ["prompt", "read", "read"]),
    ]
    # filesystem cap of the .read entry plus writefile cap of nested content.
    caps_in_plan = plan.capabilities()
    assert caps.FILESYSTEM in caps_in_plan
    assert caps.DETAIL_WRITE_FILE in caps_in_plan[caps.FILESYSTEM]


def test_read_cycle_is_unresolved_not_infinite(compiler):
    plan = compiler.compile(".read cycle.sql", SourceOrigin(ORIGIN_PROMPT))
    errors = {e.error for e in plan.entries if e.unresolved}
    assert "read cycle detected" in errors
    assert all(e.unresolved for e in plan.entries)
    assert not [e for e in plan.entries if e.kind == "sql"]


def test_read_max_depth(compiler):
    plan = compiler.compile(".read deep1.sql", SourceOrigin(ORIGIN_PROMPT))
    unresolved = [e for e in plan.entries if e.unresolved]
    assert unresolved and unresolved[-1].error == "max nest depth exceeded"
    # deepest DROP (depth 3) must not be compiled
    assert all(e.verb != "DROP" for e in plan.entries)


def test_read_missing_file_is_unresolved(compiler):
    plan = compiler.compile(".read nope.sql", SourceOrigin(ORIGIN_PROMPT))
    entry = plan.entries[0]
    assert entry.unresolved is True
    assert entry.error == "FileNotFoundError"


def test_favorite_expansion_chain_and_placeholder_preserved(compiler):
    plan = compiler.compile("\\f selectq", SourceOrigin(ORIGIN_PROMPT))
    assert plan.entries[0].expansion_key == "favorite:selectq"
    child = plan.entries[1]
    assert child.origin.kind == ORIGIN_FAVORITE
    assert child.origin.label == "selectq"
    assert child.normalized_template == "SELECT * FROM t WHERE id = ?"
    assert child.origin.type_chain() == ["prompt", "favorite"]


def test_missing_favorite_is_unresolved(compiler):
    plan = compiler.compile("\\f ghost", SourceOrigin(ORIGIN_PROMPT))
    assert plan.entries[0].unresolved is True
    assert plan.entries[0].error == "favorite not found"


def test_watch_payload_is_analyzed(compiler):
    plan = compiler.compile("watch 2 -c DROP TABLE t", SourceOrigin(ORIGIN_PROMPT))
    assert plan.entries[0].verb == "watch"
    inner = plan.entries[1]
    assert inner.kind == "sql" and inner.verb == "DROP"
    assert caps.DETAIL_DROP in inner.capabilities[caps.WRITE_SCHEMA]


@pytest.mark.parametrize("origin_kind", [ORIGIN_PROMPT, ORIGIN_STARTUP, ORIGIN_LLM])
def test_origin_chains_propagate(compiler, origin_kind):
    origin = SourceOrigin(origin_kind)
    plan = compiler.compile("\\f dropq", origin)
    child = plan.entries[-1]
    assert child.origin.type_chain() == [origin_kind, ORIGIN_FAVORITE]


# -- hashing / redaction -----------------------------------------------------


def test_hash_identical_for_literal_only_differences(compiler):
    a = compiler.compile("INSERT INTO t VALUES ('SECRET-A', 1)", SourceOrigin(ORIGIN_PROMPT))
    b = compiler.compile("INSERT INTO t VALUES ('SECRET-B', 2)", SourceOrigin(ORIGIN_PROMPT))
    assert a.plan_hash == b.plan_hash


def test_hash_differs_for_structural_differences(compiler):
    a = compiler.compile("INSERT INTO t VALUES (1)", SourceOrigin(ORIGIN_PROMPT))
    b = compiler.compile("INSERT INTO u VALUES (1)", SourceOrigin(ORIGIN_PROMPT))
    assert a.plan_hash != b.plan_hash


def test_hash_independent_of_target_but_includes_origin_chain(compiler):
    a = compiler.compile("ATTACH '/path/a.db' AS a", SourceOrigin(ORIGIN_PROMPT))
    same = compiler.compile("ATTACH '/totally/other.db' AS a", SourceOrigin(ORIGIN_PROMPT))
    llm = compiler.compile("ATTACH '/path/a.db' AS a", SourceOrigin(ORIGIN_LLM))
    assert a.plan_hash == same.plan_hash
    assert a.plan_hash != llm.plan_hash


def test_hash_recomputable_from_redacted_audit_form(compiler):
    import json

    plan = compiler.compile("DROP TABLE t; INSERT INTO t VALUES ('leak')", SourceOrigin(ORIGIN_PROMPT))
    redacted = [
        {
            "kind": e.kind,
            "verb": e.verb,
            "template": e.normalized_template,
            "caps": {cap: sorted(details) for cap, details in sorted(e.capabilities.items())},
            "origin": e.origin.type_chain(),
        }
        for e in plan.entries
    ]
    import hashlib

    recomputed = hashlib.sha256(json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert recomputed == plan.plan_hash


def test_audit_serialization_has_no_literals_or_paths(compiler):
    import json

    secret = "ZZ-SECRET-778899"
    plan = compiler.compile(
        f"ATTACH '/secretvault/{secret}.db' AS a; INSERT INTO t VALUES ('{secret}'); .read /vault/{secret}.sql",
        SourceOrigin(ORIGIN_PROMPT),
    )
    blob = json.dumps(plan.audit_entries())
    assert secret not in blob
    assert "secretvault" not in blob and "vault" not in blob
    # UI-only target does carry the real value
    attach_entry = next(e for e in plan.entries if e.verb == "ATTACH")
    assert secret in (attach_entry.target or "")


def test_target_field_not_in_audit_dict(compiler):
    plan = compiler.compile("ATTACH '/x/secret.db' AS a", SourceOrigin(ORIGIN_PROMPT))
    audit = plan.entries[0].audit_dict()
    assert "target" not in audit
    assert "raw" not in audit


def test_read_nested_from_favorite(compiler):
    # favorite template itself contains .read; chain must be prompt>favorite>read
    plan = compiler.compile("\\f multi", SourceOrigin(ORIGIN_PROMPT))
    chains = [e.origin.type_chain() for e in plan.entries]
    assert ["prompt", "favorite", "read"] in chains
