"""Capability identifiers and action-detail labels.

Capabilities are facts about side effects an execution may have. They are
declared by special commands in the command registry and derived for SQL by
the static planner and the SQLite authorizer. Policy decisions only ever
operate on these identifiers (plus optional detail labels), never on raw SQL.
"""

from __future__ import annotations

from collections.abc import Iterable

# -- Capabilities -----------------------------------------------------------

FILESYSTEM = "filesystem"
PROCESS = "process"
EXTENSION = "extension"
NETWORK = "network"
WRITE_SCHEMA = "write-schema"
WRITE_DATA = "write-data"

ALL_CAPABILITIES: frozenset[str] = frozenset({FILESYSTEM, PROCESS, EXTENSION, NETWORK, WRITE_SCHEMA, WRITE_DATA})

# Capabilities that are dangerous by default and therefore fail closed in the
# authorizer whenever no execution scope is active.
DANGEROUS_CAPABILITIES: frozenset[str] = frozenset({FILESYSTEM, PROCESS, EXTENSION, NETWORK, WRITE_SCHEMA, WRITE_DATA})

# -- Action detail labels ----------------------------------------------------
#
# Details refine a capability for confirmation messages, audit records and
# fine-grained policy rules (e.g. allow CREATE while requiring confirmation
# for DROP under the same write-schema capability).

# filesystem
DETAIL_ATTACH = "attach"
DETAIL_VACUUM_INTO = "vacuum_into"
DETAIL_FUNCTION = "function"
DETAIL_SPECIAL = "special"
DETAIL_READ_FILE = "read_file"
DETAIL_WRITE_FILE = "write_file"

# extension
DETAIL_LOAD_EXTENSION = "load_extension"

# write-schema
DETAIL_CREATE = "create"
DETAIL_DROP = "drop"
DETAIL_ALTER = "alter"
DETAIL_TRUNCATE = "truncate"
DETAIL_WRITABLE_SCHEMA = "writable_schema"
DETAIL_MASTER_WRITE = "master_write"
DETAIL_VTABLE = "vtable"

# write-data
DETAIL_INSERT = "insert"
DETAIL_UPDATE = "update"
DETAIL_DELETE = "delete"

# network
DETAIL_NETWORK_FUNCTION = "network_function"

# process
DETAIL_EVAL = "eval"
DETAIL_PROCESS_SPECIAL = "process_special"

# Default mapping of SQL function names to (capability, detail). Function
# names are case-insensitive in SQLite. Network function names are
# configurable via [policy] network_functions.
DEFAULT_FUNCTION_CAPABILITIES: dict[str, tuple[str, str]] = {
    "load_extension": (EXTENSION, DETAIL_LOAD_EXTENSION),
    # stdlib-friendly names (also provided by sqlean's fileio extension).
    "readfile": (FILESYSTEM, DETAIL_READ_FILE),
    "readfile_chunk": (FILESYSTEM, DETAIL_READ_FILE),
    "writefile": (FILESYSTEM, DETAIL_WRITE_FILE),
    "lstat": (FILESYSTEM, DETAIL_FUNCTION),
    "mkdir": (FILESYSTEM, DETAIL_WRITE_FILE),
    "symlink": (FILESYSTEM, DETAIL_WRITE_FILE),
    "eval": (PROCESS, DETAIL_EVAL),
    # sqlean fileio extension also registers fileio_-prefixed aliases and a
    # few extra entry points. They bypass the SQLITE_FUNCTION allowlist only
    # if they are missing here, so every name must be mapped.
    "fileio_read": (FILESYSTEM, DETAIL_READ_FILE),
    "fileio_write": (FILESYSTEM, DETAIL_WRITE_FILE),
    "fileio_append": (FILESYSTEM, DETAIL_WRITE_FILE),
    "fileio_mkdir": (FILESYSTEM, DETAIL_WRITE_FILE),
    "fileio_symlink": (FILESYSTEM, DETAIL_WRITE_FILE),
    "fileio_mode": (FILESYSTEM, DETAIL_WRITE_FILE),  # chmod
    "lsmode": (FILESYSTEM, DETAIL_FUNCTION),  # stat-style metadata read
    "fileio_ls": (FILESYSTEM, DETAIL_READ_FILE),
    "lsdir": (FILESYSTEM, DETAIL_READ_FILE),
    "fileio_scan": (FILESYSTEM, DETAIL_READ_FILE),
    "scanfile": (FILESYSTEM, DETAIL_READ_FILE),
}

# sqlean virtual table modules whose constructor takes a filename and reads
# arbitrary files (CREATE VIRTUAL TABLE ... USING <module>).
FILE_READING_VTABLE_MODULES: frozenset[str] = frozenset({"vsv", "scanfile", "fileio_scan", "lsdir", "fileio_ls"})

DEFAULT_NETWORK_FUNCTIONS = frozenset(
    {
        "http_get",
        "http_post",
        "http_head",
        "http3_get",
        "http3_post",
        "http3_head",
    }
)


def normalize_capabilities(values: object) -> frozenset[str]:
    """Coerce a capability declaration into a validated frozenset."""
    if not values:
        return frozenset()
    if isinstance(values, str) or not isinstance(values, Iterable):
        raise TypeError(f"Capabilities must be an iterable of strings, got {values!r}")
    result = set()
    for value in values:
        if value not in ALL_CAPABILITIES:
            raise ValueError(f"Unknown capability: {value!r}")
        result.add(value)
    return frozenset(result)


_DEFAULT_NETWORK_LOWER = frozenset(n.lower() for n in DEFAULT_NETWORK_FUNCTIONS)


def function_capability(name: str, network_functions: frozenset[str] = _DEFAULT_NETWORK_LOWER) -> tuple[str, str] | None:
    """Return (capability, detail) for a SQL function name, or None.

    ``network_functions`` must contain lower-cased names.
    """
    key = name.lower()
    if key in DEFAULT_FUNCTION_CAPABILITIES:
        return DEFAULT_FUNCTION_CAPABILITIES[key]
    if key in network_functions:
        return (NETWORK, DETAIL_NETWORK_FUNCTION)
    return None
