"""SQLite authorizer controller: the runtime enforcement backstop.

Every connection owned by litecli installs the controller's callback. The
callback maps SQLite action codes to capabilities and only allows dangerous
events while an :class:`AuthorizerScope` with matching grants is active. It
works with both the standard library ``sqlite3`` module and ``sqlean``.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from . import capabilities as caps
from .capabilities import (
    DETAIL_ALTER,
    DETAIL_ATTACH,
    DETAIL_CREATE,
    DETAIL_DELETE,
    DETAIL_DROP,
    DETAIL_EVAL,
    DETAIL_INSERT,
    DETAIL_LOAD_EXTENSION,
    DETAIL_MASTER_WRITE,
    DETAIL_NETWORK_FUNCTION,
    DETAIL_PROCESS_SPECIAL,
    DETAIL_READ_FILE,
    DETAIL_UPDATE,
    DETAIL_VACUUM_INTO,
    DETAIL_VTABLE,
    DETAIL_WRITABLE_SCHEMA,
    DETAIL_WRITE_FILE,
    FILESYSTEM,
    WRITE_DATA,
    WRITE_SCHEMA,
    function_capability,
)

log = logging.getLogger(__name__)

# Numeric SQLite authorizer action codes (stable ABI, valid across versions).
# https://www.sqlite.org/c3ref/c_alter_table.html
ACTION_NAMES: dict[int, str] = {
    1: "CREATE_INDEX",
    2: "CREATE_TABLE",
    3: "CREATE_TEMP_INDEX",
    4: "CREATE_TEMP_TABLE",
    5: "CREATE_TEMP_TRIGGER",
    6: "CREATE_TEMP_VIEW",
    7: "CREATE_TRIGGER",
    8: "CREATE_VIEW",
    9: "DELETE",
    10: "DROP_INDEX",
    11: "DROP_TABLE",
    12: "DROP_TEMP_INDEX",
    13: "DROP_TEMP_TABLE",
    14: "DROP_TEMP_TRIGGER",
    15: "DROP_TEMP_VIEW",
    16: "DROP_TRIGGER",
    17: "DROP_VIEW",
    18: "INSERT",
    19: "PRAGMA",
    20: "READ",
    21: "SELECT",
    22: "TRANSACTION",
    23: "UPDATE",
    24: "ATTACH",
    25: "DETACH",
    26: "ALTER_TABLE",
    27: "REINDEX",
    28: "ANALYZE",
    29: "CREATE_VTABLE",
    30: "DROP_VTABLE",
    31: "FUNCTION",
    32: "SAVEPOINT",
    33: "RECURSIVE",
}

_CREATE_CODES = frozenset({1, 2, 3, 4, 5, 6, 7, 8})
_DROP_CODES = frozenset({10, 11, 12, 13, 14, 15, 16, 17})
_SCHEMA_OBJECT_CODES = _CREATE_CODES | _DROP_CODES | {26}
_DATA_WRITE_CODES = frozenset({9, 18, 23})

# Schema catalog tables (any direct write is a writable-schema style attack).
_SCHEMA_CATALOGS = frozenset({"sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema"})

# Pragmas that themselves carry a dangerous capability.
_DANGEROUS_PRAGMAS: Mapping[str, tuple[str, str]] = {
    "writable_schema": (WRITE_SCHEMA, DETAIL_WRITABLE_SCHEMA),
}

# Table-valued functions / virtual tables backed by arbitrary files (sqlean
# fileio extension). Reading them is a filesystem read even though SQLite
# reports it as ordinary READ events.
_FILESYSTEM_TABLES = frozenset({"lsdir", "fileio_ls", "scanfile", "fileio_scan"})

# Extracts the module name from stored CREATE VIRTUAL TABLE SQL.
_USING_MODULE_RE = re.compile(r"\bUSING\s+[\"\[`]?([A-Za-z_]\w*)", re.IGNORECASE)

VERDICT_OK = "ok"
VERDICT_DENY = "deny"


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


# Grant detail wildcard.
ALL_DETAILS = "*"


@dataclass
class AuthorizerEvent:
    """One capability-bearing authorizer decision (audit safe)."""

    action: int
    action_name: str
    capability: str | None = None
    detail: str | None = None
    # Classifier name only: function/pragma/object name. Never literal values
    # (e.g. ATTACH filenames) - those stay in the interactive UI, not audit.
    target: str | None = None
    verdict: str = VERDICT_OK
    outside_scope: bool = False

    def audit_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"action": self.action_name, "verdict": self.verdict}
        if self.capability:
            result["capability"] = self.capability
        if self.detail:
            result["detail"] = self.detail
        if self.target:
            result["target"] = self.target
        if self.outside_scope:
            result["outside_scope"] = True
        return result


@dataclass
class AuthorizerScope:
    """Capabilities authorized for one top-level execution."""

    grants: Mapping[str, frozenset[str]]
    events: list[AuthorizerEvent] = field(default_factory=list)

    def has_grant(self, capability: str) -> bool:
        return bool(self.grants.get(capability))

    def allows(self, capability: str, detail: str | None) -> bool:
        details = self.grants.get(capability)
        if details is None:
            return False
        if ALL_DETAILS in details:
            return True
        return detail is None or detail in details


# Preference order for which denial to surface in the translated error:
# user-intended verbs beat internal catalog effects beat data writes.
_DENIAL_PRIORITY: dict[str | None, int] = {
    DETAIL_ATTACH: 4,
    DETAIL_LOAD_EXTENSION: 4,
    DETAIL_WRITABLE_SCHEMA: 4,
    DETAIL_NETWORK_FUNCTION: 4,
    DETAIL_EVAL: 4,
    DETAIL_READ_FILE: 4,
    DETAIL_WRITE_FILE: 4,
    DETAIL_PROCESS_SPECIAL: 4,
    DETAIL_CREATE: 3,
    DETAIL_DROP: 3,
    DETAIL_ALTER: 3,
    DETAIL_VTABLE: 3,
    DETAIL_MASTER_WRITE: 2,
    DETAIL_INSERT: 1,
    DETAIL_UPDATE: 1,
    DETAIL_DELETE: 1,
    None: 0,
}


def grants_from_capabilities(capabilities: Mapping[str, frozenset[str] | str]) -> dict[str, frozenset[str]]:
    """Build a grants mapping accepting sets or the '*' wildcard."""
    grants: dict[str, frozenset[str]] = {}
    for capability, details in capabilities.items():
        if isinstance(details, str):
            grants[capability] = frozenset({details})
        else:
            grants[capability] = frozenset(details)
    return grants


class AuthorizerController:
    """Installs and drives the authorizer callback on one or more connections."""

    def __init__(
        self,
        backend: Any,
        network_functions: frozenset[str] = caps._DEFAULT_NETWORK_LOWER,
        enabled: bool = True,
    ) -> None:
        self.backend = backend
        self.network_functions = frozenset(n.lower() for n in network_functions)
        self.enabled = enabled
        self._scope: AuthorizerScope | None = None
        self.last_denial: AuthorizerEvent | None = None
        # Fallback constants for very old bindings.
        self._ok = getattr(backend, "SQLITE_OK", 0)
        self._deny = getattr(backend, "SQLITE_DENY", 1)
        self._install_count = 0
        self._conns: list[Any] = []
        # Index of virtual tables backed by files and of ordinary tables
        # (the latter prevents false positives for user tables named like a
        # file-reading module, e.g. a real table called "lsdir").
        self._file_vtables: set[str] = set()
        self._regular_tables: set[str] = set()
        backend_error = getattr(backend, "Error", None)
        self._error_types: tuple[type[BaseException], ...] = (
            (sqlite3.Error, backend_error) if backend_error and backend_error is not sqlite3.Error else (sqlite3.Error,)
        )

    # -- wiring -------------------------------------------------------------

    def install(self, conn: Any) -> None:
        """Install (or reinstall) this controller's callback on *conn*."""
        conn.set_authorizer(self._authorizer_callback)
        self._conns.append(conn)
        self._install_count += 1
        self.refresh_table_index()

    def refresh_table_index(self) -> None:
        """Rebuild the file-backed-virtual-table index from every schema.

        A persistent virtual table (or one carried in by ATTACH) keeps
        reading files on every plain SELECT afterwards. SQLite reports those
        as ordinary READ events carrying the instance table name, so we must
        resolve table names back to their module via the stored schema.
        """
        file_tables: set[str] = set()
        regular_tables: set[str] = set()
        for conn in list(self._conns):
            try:
                databases = [str(row[1]) for row in conn.execute("PRAGMA database_list").fetchall()]
            except self._error_types:
                log.debug("policy: cannot list databases for vtable index", exc_info=True)
                continue
            for database in databases:
                quoted = _quote_identifier(database)
                catalogs = [f"{quoted}.sqlite_master"]
                if database == "main":
                    catalogs.append(f"{quoted}.sqlite_temp_master")
                for catalog in catalogs:
                    try:
                        rows = conn.execute(f"SELECT name, sql, rootpage FROM {catalog} WHERE type = 'table'").fetchall()
                    except self._error_types:
                        log.debug("policy: cannot read %s for vtable index", catalog, exc_info=True)
                        continue
                    for name, sql_text, rootpage in rows:
                        if not name:
                            continue
                        bare = str(name).split(".")[-1].lower()
                        match = _USING_MODULE_RE.search(sql_text or "")
                        if match and match.group(1).lower() in caps.FILE_READING_VTABLE_MODULES:
                            file_tables.add(bare)
                        elif rootpage and int(rootpage) > 0:
                            regular_tables.add(bare)
        self._file_vtables = file_tables
        self._regular_tables = regular_tables

    @contextmanager
    def scope(self, grants: Mapping[str, frozenset[str]]) -> Iterator[AuthorizerScope]:
        """Activate grants for the duration of an execution."""
        new_scope = AuthorizerScope(grants=dict(grants))
        previous = self._scope
        self._scope = new_scope
        self.last_denial = None
        try:
            yield new_scope
        finally:
            self._scope = previous
            # Defense in depth: writable_schema is connection-sticky, so a
            # granted statement that enabled it must not leak past the scope.
            for conn in self._conns:
                try:
                    conn.execute("PRAGMA writable_schema=OFF")
                except Exception:  # pragma: no cover - best effort
                    log.debug("could not reset writable_schema after scope", exc_info=True)

    @property
    def active_scope(self) -> AuthorizerScope | None:
        return self._scope

    # -- mapping ------------------------------------------------------------

    def classify(self, action: int, arg1: str | None, arg2: str | None, dbname: str | None) -> tuple[str | None, str | None, str | None]:
        """Map an authorizer event to (capability, detail, classifier target).

        target is a non-literal classifier name safe for audit. Literal
        values such as ATTACH filenames are deliberately dropped.
        """
        if action == 31:  # SQLITE_FUNCTION
            if arg2:
                found = function_capability(arg2, self.network_functions)
                if found:
                    capability, detail = found
                    return capability, detail, arg2
            return None, None, None

        if action == 24:  # SQLITE_ATTACH (also VACUUM INTO)
            # arg1 is a filename - a value, never stored.
            return FILESYSTEM, DETAIL_ATTACH, None

        if action == 19:  # SQLITE_PRAGMA
            if arg1:
                dangerous = _DANGEROUS_PRAGMAS.get(arg1.lower())
                # Only enabling values are dangerous; OFF/query forms are safe.
                if dangerous and (arg2 or "").strip().lower() in {"on", "1", "true", "yes"}:
                    capability, detail = dangerous
                    return capability, detail, arg1.lower()
            return None, None, None

        if action == 29:  # SQLITE_CREATE_VTABLE: arg2 is the module name
            module = (arg2 or "").lower()
            if module in caps.FILE_READING_VTABLE_MODULES:
                return FILESYSTEM, DETAIL_READ_FILE, module
            return WRITE_SCHEMA, DETAIL_VTABLE, arg1

        if action in _CREATE_CODES:
            return WRITE_SCHEMA, DETAIL_CREATE, arg1

        if action == 20:  # SQLITE_READ
            table = (arg1 or "").lower()
            # Persistent/attached file-backed virtual tables (resolved via
            # sqlite_master), then table-valued function calls whose name is
            # not that of a real table.
            if table in self._file_vtables:
                return FILESYSTEM, DETAIL_READ_FILE, arg1
            if table in _FILESYSTEM_TABLES and table not in self._regular_tables:
                return FILESYSTEM, DETAIL_READ_FILE, arg1
            return None, None, None

        if action in _DROP_CODES or action == 30:
            return WRITE_SCHEMA, DETAIL_DROP if action != 30 else DETAIL_VTABLE, arg1

        if action == 26:  # SQLITE_ALTER_TABLE
            return WRITE_SCHEMA, DETAIL_ALTER, arg2

        if action in _DATA_WRITE_CODES:
            # Direct writes to schema catalogs count as schema attacks.
            catalog = (arg1 or "").lower()
            if catalog in _SCHEMA_CATALOGS:
                return WRITE_SCHEMA, DETAIL_MASTER_WRITE, arg1
            detail = {9: DETAIL_DELETE, 18: DETAIL_INSERT, 23: DETAIL_UPDATE}[action]
            return WRITE_DATA, detail, arg1

        return None, None, None

    # -- callback -----------------------------------------------------------

    @staticmethod
    def _is_internal_vacuum_db(dbname: str | None) -> bool:
        # SQLite names the transient schema used by VACUUM INTO "vacuum_"
        # followed by 16 lowercase hex characters.
        if not dbname or not dbname.startswith("vacuum_"):
            return False
        suffix = dbname[len("vacuum_") :]
        return len(suffix) == 16 and all(c in "0123456789abcdef" for c in suffix)

    def _is_allowed(
        self,
        active: AuthorizerScope,
        action: int,
        capability: str,
        detail: str | None,
        dbname: str | None,
    ) -> bool:
        if active.allows(capability, detail):
            return True
        # VACUUM INTO presents as a raw ATTACH event; grant on either detail.
        if capability == FILESYSTEM and detail == DETAIL_ATTACH and active.allows(FILESYSTEM, DETAIL_VACUUM_INTO):
            return True
        # DDL internally writes the schema catalog (INSERT/UPDATE/DELETE on
        # sqlite_master). Direct catalog attacks require writable_schema=ON,
        # which carries its own grant, so this only covers internal effects.
        if capability == WRITE_SCHEMA and detail == DETAIL_MASTER_WRITE and active.has_grant(WRITE_SCHEMA):
            return True
        # VACUUM INTO also runs internal DDL/data writes inside its transient
        # schema.
        return self._is_internal_vacuum_db(dbname) and capability in {WRITE_SCHEMA, WRITE_DATA} and active.has_grant(FILESYSTEM)

    def _authorizer_callback(
        self,
        action: int,
        arg1: str | None = None,
        arg2: str | None = None,
        dbname: str | None = None,
        source: str | None = None,
    ) -> int:
        if not self.enabled:
            return self._ok
        action_name = ACTION_NAMES.get(action, f"UNKNOWN_{action}")
        capability, detail, target = self.classify(action, arg1, arg2, dbname)
        if action == 24:  # SQLITE_ATTACH: new schema may carry file vtables
            self.refresh_table_index()
        if capability is None:
            if action_name.startswith("UNKNOWN_"):
                # Fail closed: a SQLite version introducing a new side-effect
                # action must be classified explicitly before it can run.
                active = self._scope
                event = AuthorizerEvent(
                    action=action,
                    action_name=action_name,
                    verdict=VERDICT_DENY,
                    outside_scope=active is None,
                )
                if active is not None:
                    active.events.append(event)
                log.warning("authorizer: unclassified action code %s -> deny", action)
                return self._deny
            return self._ok

        active = self._scope
        allowed = active is not None and self._is_allowed(active, action, capability, detail, dbname)
        event = AuthorizerEvent(
            action=action,
            action_name=action_name,
            capability=capability,
            detail=detail,
            target=target,
            verdict=VERDICT_OK if allowed else VERDICT_DENY,
            outside_scope=active is None,
        )
        if active is not None:
            active.events.append(event)
        if allowed:
            return self._ok

        # Surface the user-intended verb (CREATE/DROP/ATTACH/...) rather than
        # an internal catalog effect when several events are denied together.
        if self.last_denial is None or _DENIAL_PRIORITY.get(detail, 0) > _DENIAL_PRIORITY.get(self.last_denial.detail, 0):
            self.last_denial = event
        log.debug("authorizer DENY %s (%s/%s)", action_name, capability, detail)
        return self._deny
