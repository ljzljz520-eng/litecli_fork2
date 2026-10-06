from __future__ import annotations

import logging
import os.path
from collections.abc import Generator, Iterable
from contextlib import closing
from typing import Any, cast
from urllib.parse import urlparse

import sqlparse

try:
    import sqlean as _sqlite3

    _sqlite3.extensions.enable_all()
except ImportError:
    import sqlite3 as _sqlite3

from litecli.packages import special
from litecli.packages.guard.guard import ExecutionGuard, PreparedExecution
from litecli.packages.guard.plan import ORIGIN_EXECUTE, SourceOrigin
from litecli.packages.special.utils import check_if_sqlitedotcommand

sqlite3 = cast(Any, _sqlite3)
OperationalError = sqlite3.OperationalError

_logger = logging.getLogger(__name__)

# FIELD_TYPES = decoders.copy()
# FIELD_TYPES.update({
#     FIELD_TYPE.NULL: type(None)
# })


class SQLExecute:
    databases_query = """
        PRAGMA database_list
    """

    tables_query = """
        SELECT name
        FROM sqlite_master
        WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'sqlean_%'
        ORDER BY 1
    """

    table_columns_query = """
        SELECT m.name as tableName, p.name as columnName
        FROM sqlite_master m
        JOIN pragma_table_info((m.name)) p
        WHERE m.type IN ('table','view') AND m.name NOT LIKE 'sqlite_%' AND m.name NOT LIKE 'sqlean_%'
        ORDER BY tableName, columnName
    """

    indexes_query = """
        SELECT name, sql
        FROM sqlite_master
        WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
        ORDER BY 1
    """

    functions_query = '''SELECT ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES
    WHERE ROUTINE_TYPE="FUNCTION" AND ROUTINE_SCHEMA = "%s"'''

    def __init__(self, database: str | None, guard: ExecutionGuard | None = None):
        self.dbname: str | None = database
        self._server_type: tuple[str, str] | None = None
        # Connection can be sqlite3.Connection or sqlean.sqlite3 connection.
        self.conn: Any | None = None
        self.guard = guard
        if not database:
            _logger.debug("Database is not specified. Skip connection.")
            return
        self.connect()

    def connect(self, database: str | None = None) -> None:
        db = database or self.dbname
        _logger.debug("Connection DB Params: \n\tdatabase: %r", db)
        if db is None:
            # Nothing to connect to.
            return

        location = urlparse(db)
        if location.scheme and location.scheme == "file":
            uri = True
            db_name = db
            db_filename = location.path
        else:
            uri = False
            db_filename = db_name = os.path.expanduser(db)
            db_dir_name = os.path.dirname(os.path.abspath(db_filename))
            if not os.path.exists(db_dir_name):
                raise Exception(f"Path does not exist: {db_dir_name}")

        conn = sqlite3.connect(database=db_name, isolation_level=None, uri=uri)
        conn.text_factory = lambda x: x.decode("utf-8", "backslashreplace")
        if self.conn:
            self.conn.close()

        self.conn = conn
        if self.guard is not None:
            self.guard.attach_connection(conn)
        # Update them after the connection is made to ensure that it was a
        # successful connection.
        self.dbname = db_filename

    def run(self, statement: str, origin: SourceOrigin | None = None) -> Iterable[tuple]:
        """Execute the sql in the database and return the results. The results
        are a list of tuples. Each tuple has 4 values
        (title, rows, headers, status).

        With a guard attached, compilation, policy decision and confirmation
        happen eagerly (before the first iteration of the returned generator),
        so a denial never races with a side effect.
        """
        statement = statement.strip()
        if self.guard is None or not self.guard.enabled:
            return self._run_legacy(statement)

        if origin is None:
            origin = SourceOrigin(ORIGIN_EXECUTE, parent=self.guard.current_origin)
        # Raises PolicyDenied before any generator body runs.
        prepared = self.guard.prepare(statement, origin)
        return self._run_guarded(statement, prepared)

    def _split_components(self, statement: str) -> list[tuple[str, bool]]:
        """Return [(sql, expanded_output)] mirroring the legacy splitting."""
        if statement.startswith("\\fs"):
            raw_components = [statement]
        else:
            raw_components = sqlparse.split(statement)
        components: list[tuple[str, bool]] = []
        for component in raw_components:
            sql = component.rstrip(";")
            expanded = False
            # \G is treated specially since we have to set the expanded output.
            if sql.endswith("\\G"):
                expanded = True
                sql = sql[:-2].strip()
            if sql.strip():
                components.append((sql.strip(), expanded))
        return components

    @staticmethod
    def _runs_without_connection(sql: str) -> bool:
        return sql.lower().startswith("use") or sql.startswith((".open", "\\u", "\\?", "\\q", "help", "exit", "quit"))

    def _run_legacy(self, statement: str) -> Iterable[tuple]:
        if not statement:  # Empty string
            yield (None, None, None, None)

        for sql, expanded in self._split_components(statement):
            if expanded:
                special.set_expanded_output(True)

            if not self.conn and not self._runs_without_connection(sql):
                _logger.debug("Not connected to database. Will not run statement: %s.", sql)
                raise OperationalError("Not connected to database.")

            cur = self.conn.cursor() if self.conn else None
            try:  # Special command
                _logger.debug("Trying a dbspecial command. sql: %r", sql)
                yield from special.execute(cur, sql)
            except special.CommandNotFound:  # Regular SQL
                if check_if_sqlitedotcommand(sql):
                    yield ("dot command not implemented", None, None, None)
                else:
                    _logger.debug("Regular sql statement. sql: %r", sql)
                    assert cur is not None
                    cur.execute(sql)
                    yield self.get_result(cur)

    def _run_guarded(self, statement: str, prepared: PreparedExecution) -> Iterable[tuple]:
        guard = self.guard
        assert guard is not None
        roots = [entry for entry in prepared.plan.entries if entry.is_root]
        components = self._split_components(statement)
        if not components:
            yield (None, None, None, None)
            return
        if len(roots) != len(components):
            # Should never happen: compiler and runner share the same splitter.
            raise RuntimeError("plan root entries do not match executed statements")

        with guard.scope(prepared):
            for entry, (sql, expanded) in zip(roots, components):
                if expanded:
                    special.set_expanded_output(True)

                if not self.conn and not self._runs_without_connection(sql):
                    _logger.debug("Not connected to database. Will not run statement: %s.", sql)
                    raise OperationalError("Not connected to database.")

                guard.authorize_entry(entry)
                cur = self.conn.cursor() if self.conn else None
                try:  # Special command
                    _logger.debug("Trying a dbspecial command. sql: %r", sql)
                    yield from special.execute(cur, sql)
                except special.CommandNotFound:  # Regular SQL
                    if check_if_sqlitedotcommand(sql):
                        yield ("dot command not implemented", None, None, None)
                    else:
                        _logger.debug("Regular sql statement. sql: %r", sql)
                        assert cur is not None
                        cur.execute(sql)
                        yield self.get_result(cur)

    def get_result(self, cursor: Any) -> tuple[str | None, list | None, list | None, str]:
        """Get the current result's data from the cursor."""
        title = headers = None

        # cursor.description is not None for queries that return result sets,
        # e.g. SELECT.
        if cursor.description is not None:
            headers = [x[0] for x in cursor.description]
            status = "{count} row{s} in set"
            cursor = list(cursor)
            rowcount = len(cursor)
        else:
            _logger.debug("No rows in result.")
            if cursor.rowcount == -1:
                status = "Query OK"
            else:
                status = "Query OK, {count} row{s} affected"
            rowcount = cursor.rowcount
            cursor = None

        status = status.format(count=rowcount, s="" if rowcount == 1 else "s")

        return (title, cursor, headers, status)

    def tables(self) -> Generator[tuple[str], None, None]:
        """Yields table names"""
        if not self.conn:
            return
        with closing(self.conn.cursor()) as cur:
            _logger.debug("Tables Query. sql: %r", self.tables_query)
            cur.execute(self.tables_query)
            for row in cur:
                yield row

    def table_columns(self) -> Generator[tuple[str, str], None, None]:
        """Yields column names"""
        if not self.conn:
            return
        with closing(self.conn.cursor()) as cur:
            _logger.debug("Columns Query. sql: %r", self.table_columns_query)
            cur.execute(self.table_columns_query)
            for row in cur:
                yield row

    def databases(self) -> Generator[str, None, None]:
        if not self.conn:
            return

        with closing(self.conn.cursor()) as cur:
            _logger.debug("Databases Query. sql: %r", self.databases_query)
            for row in cur.execute(self.databases_query):
                yield row[1]

    def functions(self) -> Iterable[tuple]:
        """Yields tuples of (schema_name, function_name)"""
        if not self.conn:
            return
        with closing(self.conn.cursor()) as cur:
            _logger.debug("Functions Query. sql: %r", self.functions_query)
            cur.execute(self.functions_query % self.dbname)
            for row in cur:
                yield row

    def server_type(self) -> tuple[str, str]:
        self._server_type = ("sqlite3", "3")
        return self._server_type
