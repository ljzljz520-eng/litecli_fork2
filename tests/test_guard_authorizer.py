"""AuthorizerController tests on both sqlite3 and sqlean backends."""

import os

import pytest

from litecli.packages.guard import capabilities as caps
from litecli.packages.guard.authorizer import (
    ACTION_NAMES,
    ALL_DETAILS,
    AuthorizerController,
    grants_from_capabilities,
)

try:
    import sqlean as _sqlean

    _sqlean.extensions.enable_all()
    HAS_SQLEAN = True
except ImportError:  # pragma: no cover
    _sqlean = None
    HAS_SQLEAN = False

import sqlite3 as _stdlib

BACKENDS = [_stdlib]
BACKEND_IDS = ["sqlite3"]
if HAS_SQLEAN:
    BACKENDS.append(_sqlean)
    BACKEND_IDS.append("sqlean")


@pytest.fixture(params=BACKENDS, ids=BACKEND_IDS)
def backend(request):
    return request.param


@pytest.fixture
def conn(backend, tmp_path):
    db = str(tmp_path / "auth.db")
    connection = backend.connect(db)
    connection.execute("create table t(x)")
    connection.execute("insert into t values (1)")
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def controller(backend):
    return AuthorizerController(backend)


@pytest.fixture
def db_error(backend):
    return backend.Error


def _install(controller, conn):
    controller.install(conn)


def test_select_allowed_without_scope(controller, conn):
    _install(controller, conn)
    rows = conn.execute("select * from t").fetchall()
    assert rows == [(1,)]


def test_create_denied_without_scope(controller, conn):
    _install(controller, conn)
    with pytest.raises(Exception, match="not authorized"):
        conn.execute("create table secret(a)")
    names = {r[0] for r in conn.execute("select name from sqlite_master where type='table'")}
    assert "secret" not in names
    denial = controller.last_denial
    assert denial is not None
    assert denial.capability == caps.WRITE_SCHEMA
    assert denial.detail in {caps.DETAIL_CREATE, caps.DETAIL_MASTER_WRITE}
    assert denial.outside_scope is True


def test_drop_denied_without_scope(controller, conn):
    _install(controller, conn)
    with pytest.raises(Exception, match="authorized"):
        conn.execute("drop table t")
    rows = conn.execute("select * from t").fetchall()
    assert rows == [(1,)]
    assert controller.last_denial.capability == caps.WRITE_SCHEMA
    assert controller.last_denial.detail in {caps.DETAIL_DROP, caps.DETAIL_MASTER_WRITE}


def test_writable_schema_pragma_denied_without_scope(controller, conn, db_error):
    _install(controller, conn)
    with pytest.raises(db_error):
        conn.execute("PRAGMA writable_schema=ON")
    assert controller.last_denial.capability == caps.WRITE_SCHEMA
    assert controller.last_denial.detail == caps.DETAIL_WRITABLE_SCHEMA
    assert controller.last_denial.target == "writable_schema"
    # OFF and query forms are benign.
    assert controller.classify(19, "writable_schema", "OFF", "main")[0] is None
    assert controller.classify(19, "writable_schema", None, "main")[0] is None


def test_writable_schema_resets_after_scope(backend, tmp_path):
    controller = AuthorizerController(backend)
    c = backend.connect(":memory:")
    controller.install(c)
    grants = grants_from_capabilities({caps.WRITE_SCHEMA: frozenset({ALL_DETAILS})})
    with controller.scope(grants):
        c.execute("PRAGMA writable_schema=ON")
        assert c.execute("PRAGMA writable_schema").fetchone()[0] == 1
    assert c.execute("PRAGMA writable_schema").fetchone()[0] == 0
    c.close()


def test_attach_denied_without_scope(controller, conn, tmp_path):
    _install(controller, conn)
    target = str(tmp_path / "attached.db")
    with pytest.raises(Exception, match="not authorized"):
        conn.execute("ATTACH ? AS a", (target,))
    assert not os.path.exists(target)
    assert controller.last_denial.capability == caps.FILESYSTEM
    assert controller.last_denial.detail == caps.DETAIL_ATTACH
    # filename value must not be retained on the event
    assert controller.last_denial.target is None


def test_scope_grants_allow_and_collect_events(controller, conn):
    _install(controller, conn)
    grants = grants_from_capabilities({caps.WRITE_SCHEMA: frozenset({ALL_DETAILS}), caps.WRITE_DATA: frozenset({ALL_DETAILS})})
    with controller.scope(grants) as scope:
        conn.execute("create table allowed(a)")
        conn.execute("insert into allowed values (2)")
    names = {r[0] for r in conn.execute("select name from sqlite_master where type='table'")}
    assert "allowed" in names
    capabilities_seen = {e.capability for e in scope.events}
    assert caps.WRITE_SCHEMA in capabilities_seen
    assert caps.WRITE_DATA in capabilities_seen
    # scope released -> fail closed again
    with pytest.raises(Exception, match="not authorized"):
        conn.execute("drop table allowed")


def test_vacuum_into_denied_then_allowed_with_filesystem_grant(backend, controller, tmp_path):
    source = str(tmp_path / "src.db")
    c = backend.connect(source)
    c.execute("create table t(x)")
    c.execute("insert into t values (1)")
    c.commit()
    controller.install(c)
    out = str(tmp_path / "out.db")
    with pytest.raises(Exception, match="authoriz"):
        c.execute("VACUUM INTO ?", (out,))
    assert not os.path.exists(out)
    grants = grants_from_capabilities({caps.FILESYSTEM: frozenset({caps.DETAIL_VACUUM_INTO})})
    with controller.scope(grants):
        c.execute("VACUUM INTO ?", (out,))
    assert os.path.exists(out)
    c.close()


def test_catalog_attack_without_writable_schema_grant_still_denied(controller, conn, db_error):
    # Catalog writes only accompany authorized DDL; a bare catalog write is
    # rejected even when write-schema create is granted.
    grants = grants_from_capabilities({caps.WRITE_SCHEMA: frozenset({caps.DETAIL_CREATE})})
    with controller.scope(grants), pytest.raises(db_error):
        conn.execute("insert into sqlite_master(type, name) values ('table', 'x')")
    # SQLite itself rejects catalog writes unless writable_schema is on.


def test_scope_with_partial_detail_denies_other_detail(controller, conn):
    _install(controller, conn)
    grants = grants_from_capabilities({caps.WRITE_SCHEMA: frozenset({caps.DETAIL_CREATE})})
    with controller.scope(grants):
        conn.execute("create table partial(a)")
        with pytest.raises(Exception, match="not authorized"):
            conn.execute("drop table t")
    assert controller.last_denial.detail == caps.DETAIL_DROP


def test_insert_function_writefile_denied_before_side_effect(backend, controller, tmp_path):
    if backend is _stdlib:
        pytest.skip("writefile() is provided by the sqlean fileio extension")
    conn = backend.connect(":memory:")
    controller.install(conn)
    out = str(tmp_path / "wf.txt")
    with pytest.raises(Exception, match="not authorized"):
        conn.execute("select writefile(?, 'x')", (out,))
    assert not os.path.exists(out)
    assert controller.last_denial.capability == caps.FILESYSTEM
    assert controller.last_denial.target == "writefile"
    conn.close()


def test_eval_denied_without_scope(backend, controller):
    if backend is _stdlib:
        pytest.skip("eval() is provided by sqlean")
    conn = backend.connect(":memory:")
    controller.install(conn)
    with pytest.raises(Exception, match="not authorized"):
        conn.execute("select eval('select 1')")
    assert controller.last_denial.capability == caps.PROCESS
    assert controller.last_denial.target == "eval"
    conn.close()


def test_network_function_classification(backend, tmp_path):
    controller = AuthorizerController(backend, network_functions=frozenset({"http_get"}))
    conn = backend.connect(":memory:")
    controller.install(conn)
    cap, detail, target = controller.classify(31, None, "http_get", None)
    assert (cap, detail, target) == (caps.NETWORK, caps.DETAIL_NETWORK_FUNCTION, "http_get")
    conn.close()


def test_data_write_on_catalog_is_schema_attack(controller):
    cap, detail, _target = controller.classify(18, "sqlite_master", None, "main")
    assert cap == caps.WRITE_SCHEMA and detail == caps.DETAIL_MASTER_WRITE
    cap, detail, _ = controller.classify(18, "t", None, "main")
    assert cap == caps.WRITE_DATA and detail == caps.DETAIL_INSERT


def test_disabled_controller_allows_everything(backend, tmp_path):
    controller = AuthorizerController(backend, enabled=False)
    conn = backend.connect(":memory:")
    controller.install(conn)
    conn.execute("create table a(x)")
    conn.execute("drop table a")
    conn.close()


def test_action_name_table_covers_known_codes(controller):
    # Codes 1..33 minus deprecated COPY(0) must have names; constants used by
    # the running backend must agree with the numeric table.
    for code, name in ACTION_NAMES.items():
        constant = getattr(controller.backend, "SQLITE_" + name, None)
        if constant is not None:
            assert constant == code, name


def test_unknown_action_is_fail_closed(controller):
    # A hypothetical future action code from a newer SQLite must be classified
    # explicitly before it is allowed.
    assert controller.classify(999, None, None, None) == (None, None, None)
    # No active scope: denied outright.
    assert controller._authorizer_callback(999, None, None, None) == controller._deny
    # Inside a scope: still denied, and the event is recorded for audit.
    with controller.scope(grants_from_capabilities({caps.FILESYSTEM: ALL_DETAILS})) as scope:
        assert controller._authorizer_callback(999, None, None, None) == controller._deny
    assert scope.events[-1].action_name == "UNKNOWN_999"
    assert scope.events[-1].verdict == "deny"


@pytest.mark.parametrize(
    "table",
    ["lsdir", "fileio_ls", "scanfile", "fileio_scan"],
)
def test_file_table_read_classified_as_filesystem(controller, table):
    assert controller.classify(20, table, "name", "main") == (caps.FILESYSTEM, caps.DETAIL_READ_FILE, table)


def test_file_reading_vtable_create_classified_as_filesystem(controller):
    assert controller.classify(29, "t", "vsv", "main") == (caps.FILESYSTEM, caps.DETAIL_READ_FILE, "vsv")
    assert controller.classify(29, "ft", "fts5", "main") == (caps.WRITE_SCHEMA, caps.DETAIL_VTABLE, "ft")


def test_sqlean_lsdir_denied_without_scope(controller, conn, backend):
    available = conn.execute("SELECT 1 FROM pragma_module_list WHERE name='lsdir'").fetchall()
    if not available:
        pytest.skip("lsdir table-valued module unavailable")
    _install(controller, conn)
    with pytest.raises(Exception, match="not authorized|prohibited"):
        conn.execute("SELECT * FROM lsdir('.')").fetchall()


def test_regular_table_named_like_file_module_is_not_filesystem(backend, tmp_path):
    # A real user table called "lsdir" must not be mistaken for the sqlean
    # table-valued file reader.
    db = str(tmp_path / "named.db")
    conn = backend.connect(db)
    conn.execute("create table lsdir(name text)")
    conn.execute("insert into lsdir values ('x')")
    conn.commit()
    controller = AuthorizerController(backend)
    controller.install(conn)
    assert controller.classify(20, "lsdir", "name", "main") == (None, None, None)
    # Plain read works even without a scope.
    assert conn.execute("select name from lsdir").fetchall() == [("x",)]
    conn.close()


def test_persistent_file_vtable_read_denied_in_later_scope(backend, tmp_path):
    available = False
    probe = backend.connect(":memory:")
    try:
        probe.execute("create virtual table _probe using vsv(filename='/dev/null')")
    except Exception:  # noqa: BLE001,S110 - capability probe: any failure means unavailable
        pass
    else:
        available = True
    probe.close()
    if not available:
        pytest.skip("vsv virtual table module unavailable")

    db = str(tmp_path / "vtab.db")
    data = tmp_path / "data.csv"
    data.write_text("v1,v2\nv3,v4\n")
    conn = backend.connect(db)
    controller = AuthorizerController(backend)
    controller.install(conn)

    create_grants = grants_from_capabilities(
        {
            caps.WRITE_SCHEMA: frozenset({caps.DETAIL_VTABLE, caps.DETAIL_MASTER_WRITE}),
            caps.FILESYSTEM: frozenset({caps.DETAIL_READ_FILE}),
        }
    )
    with controller.scope(create_grants):
        conn.execute(f"create virtual table v using vsv(filename='{data.as_posix()}', columns=2)")
    conn.commit()
    controller.refresh_table_index()
    assert "v" in controller._file_vtables
    # A fresh scope with no filesystem grant (e.g. a later batch run of a
    # seemingly harmless SELECT) must be blocked before the file is read.
    empty_grants = grants_from_capabilities({})
    with controller.scope(empty_grants), pytest.raises(Exception, match="not authorized|prohibited"):
        conn.execute("select * from v").fetchall()
    assert controller.last_denial.capability == caps.FILESYSTEM
    assert controller.last_denial.detail == caps.DETAIL_READ_FILE
    conn.close()


def test_missing_backend_constants_use_builtin_codes():
    # A backend binding without SQLITE_* constants exposed must still work via
    # the built-in numeric table.
    controller = AuthorizerController(object())
    assert controller._ok == 0
    assert controller._deny == 1
    assert controller.classify(2, "x", None, "main")[0] == caps.WRITE_SCHEMA
    assert controller.classify(31, None, "eval", None)[0] == caps.PROCESS
