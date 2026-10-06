"""ExecutionPlan compiler.

Compiles raw input text (possibly containing multiple statements and nested
sources such as ``.read`` files and favorite templates) into an ordered,
normalized :class:`ExecutionPlan` *before* anything is executed.

The plan is the only thing the policy layer decides on. Literal values are
masked in the normalized template and never enter the plan hash or the audit
trail; real targets (paths, table names) are kept in a separate UI-only field.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import sqlparse
from sqlparse.sql import Function, Identifier, TokenList
from sqlparse.tokens import DDL, DML, Comment, Keyword, Literal, Name, Punctuation, Whitespace

from ..special.main import Verbosity, command_capabilities, lookup_command, parse_special_command
from . import capabilities as caps
from .capabilities import (
    DETAIL_ALTER,
    DETAIL_ATTACH,
    DETAIL_CREATE,
    DETAIL_DELETE,
    DETAIL_DROP,
    DETAIL_INSERT,
    DETAIL_LOAD_EXTENSION,
    DETAIL_MASTER_WRITE,
    DETAIL_PROCESS_SPECIAL,
    DETAIL_READ_FILE,
    DETAIL_SPECIAL,
    DETAIL_TRUNCATE,
    DETAIL_UPDATE,
    DETAIL_VACUUM_INTO,
    DETAIL_VTABLE,
    DETAIL_WRITABLE_SCHEMA,
    DETAIL_WRITE_FILE,
    FILESYSTEM,
    NETWORK,
    PROCESS,
    WRITE_DATA,
    WRITE_SCHEMA,
    function_capability,
)

log = logging.getLogger(__name__)

# -- origin kinds ------------------------------------------------------------

ORIGIN_PROMPT = "prompt"
ORIGIN_READ = "read"
ORIGIN_STARTUP = "startup"
ORIGIN_FAVORITE = "favorite"
ORIGIN_LLM = "llm"
ORIGIN_EXECUTE = "execute"
ORIGIN_STDIN = "stdin"

ORIGIN_KINDS = frozenset({ORIGIN_PROMPT, ORIGIN_READ, ORIGIN_STARTUP, ORIGIN_FAVORITE, ORIGIN_LLM, ORIGIN_EXECUTE, ORIGIN_STDIN})

KIND_SQL = "sql"
KIND_SPECIAL = "special"

DEFAULT_MAX_NEST_DEPTH = 8

# Verbs that start a statement we care about.
_WRITE_VERBS = {"INSERT", "UPDATE", "DELETE", "REPLACE"}
_SCHEMA_VERBS = {"CREATE", "DROP", "ALTER", "TRUNCATE"}
_LEADING_VERBS = (
    _WRITE_VERBS
    | _SCHEMA_VERBS
    | {
        "SELECT",
        "ATTACH",
        "DETACH",
        "VACUUM",
        "PRAGMA",
        "REINDEX",
        "ANALYZE",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
        "WITH",
        "EXPLAIN",
    }
)

_SCHEMA_CATALOGS = frozenset({"sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema"})
_PRAGMA_ENABLE_VALUES = {"on", "1", "true", "yes"}

# Literal masking is done by the stateful scanner in
# _mask_strings_and_comments(); the regexes below cover numbers/placeholders.
_PRAGMA_RE = re.compile(r"PRAGMA\s+(?:(?P<schema>[\w\"]+)\s*\.\s*)?(?P<name>[\w\"]+)(?:\s*=\s*(?P<value>.+))?$", re.IGNORECASE)
_SINGLE_QUOTED_RE = re.compile(r"(?:[xXbB](?='))?'(?:''|[^'])*'")
_NUMBER_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])")
_PLACEHOLDER_RE = re.compile(r"\?|[:@$][A-Za-z_]\w*")
_WS_RE = re.compile(r"\s+")
_USING_MODULE_RE = re.compile(r"\bUSING\s+([A-Za-z_]\w*)", re.IGNORECASE)

# Per-command detail overrides, keyed by the canonical registry command name.
_COMMAND_DETAIL_OVERRIDES: dict[str, dict[str, str | tuple[str, ...]]] = {
    ".read": {FILESYSTEM: DETAIL_READ_FILE},
    ".output": {FILESYSTEM: DETAIL_WRITE_FILE},
    ".once": {FILESYSTEM: DETAIL_WRITE_FILE},
    ".open": {FILESYSTEM: DETAIL_SPECIAL},
    # .import reads a file and runs ordinary INSERT statements at runtime.
    ".import": {FILESYSTEM: DETAIL_READ_FILE, WRITE_DATA: (DETAIL_SPECIAL, DETAIL_INSERT)},
    ".load": {caps.EXTENSION: DETAIL_LOAD_EXTENSION},
    "\\llm": {PROCESS: DETAIL_PROCESS_SPECIAL, NETWORK: DETAIL_SPECIAL},
    "system": {PROCESS: DETAIL_PROCESS_SPECIAL},
    "\\pipe_once": {PROCESS: DETAIL_PROCESS_SPECIAL},
    "pager": {PROCESS: DETAIL_PROCESS_SPECIAL},
    "\\e": {PROCESS: DETAIL_PROCESS_SPECIAL, FILESYSTEM: DETAIL_SPECIAL},
}

FileReader = Callable[[str], str]
FavoriteProvider = Callable[[str], str | None]


def _default_file_reader(path: str) -> str:
    expanded = os.path.expanduser(path)
    with open(expanded, encoding="utf-8") as f:
        return f.read()


def _default_favorite_provider(name: str) -> str | None:
    from ..special.iocommands import favoritequeries

    return favoritequeries.get(name)


# -- model -------------------------------------------------------------------


@dataclass
class SourceOrigin:
    """Where a plan entry came from. Only the kind chain enters hash/audit."""

    kind: str
    label: str | None = None
    parent: SourceOrigin | None = None

    def __post_init__(self) -> None:
        if self.kind not in ORIGIN_KINDS:
            raise ValueError(f"Unknown origin kind: {self.kind!r}")

    def chain(self) -> list[SourceOrigin]:
        result: list[SourceOrigin] = []
        node: SourceOrigin | None = self
        while node is not None:
            result.append(node)
            node = node.parent
        result.reverse()
        return result

    def type_chain(self) -> list[str]:
        return [node.kind for node in self.chain()]

    def signature(self) -> str:
        return ">".join(self.type_chain())

    def audit_chain(self) -> list[dict[str, str]]:
        # Favorite names are query identifiers, not values, and required by the
        # spec; file labels (paths) never leave the interactive UI.
        result = []
        for node in self.chain():
            item = {"kind": node.kind}
            if node.kind == ORIGIN_FAVORITE and node.label:
                item["label"] = node.label
            result.append(item)
        return result


@dataclass
class PlanEntry:
    seq: int
    kind: str
    origin: SourceOrigin
    verb: str
    normalized_template: str
    capabilities: dict[str, set[str]] = field(default_factory=dict)
    # Real target for the confirmation UI only; never hashed or audited.
    target: str | None = None
    expansion_key: str | None = None
    unresolved: bool = False
    error: str | None = None
    command: str | None = None
    verbosity: str | None = None
    # Original executable text; internal use only, never serialized.
    raw: str = field(default="", repr=False)
    # True for entries produced directly by the top-level compile() call.
    # Expansion children (.read/favorite/watch payloads) are False; they are
    # executed recursively by their handler, not by the top-level run loop.
    # Internal execution marker only: never hashed or audited.
    is_root: bool = False

    def add_capability(self, capability: str, detail: str | None = None) -> None:
        self.capabilities.setdefault(capability, set())
        if detail:
            self.capabilities[capability].add(detail)

    def audit_dict(self) -> dict[str, object]:
        """Redacted serialization. Must never contain literal values."""
        result: dict[str, object] = {
            "seq": self.seq,
            "kind": self.kind,
            "verb": self.verb,
            "template": self.normalized_template,
            "origin": self.origin.audit_chain(),
            "capabilities": {cap: sorted(details) for cap, details in sorted(self.capabilities.items())},
        }
        if self.unresolved:
            result["unresolved"] = True
        if self.error:
            result["error"] = self.error
        return result


@dataclass
class ExecutionPlan:
    entries: list[PlanEntry]
    source_signature: str
    plan_hash: str
    created_at: float

    def audit_entries(self) -> list[dict[str, object]]:
        return [entry.audit_dict() for entry in self.entries]

    def capabilities(self) -> dict[str, set[str]]:
        merged: dict[str, set[str]] = {}
        for entry in self.entries:
            for cap, details in entry.capabilities.items():
                merged.setdefault(cap, set()).update(details)
        return merged


# -- normalization -----------------------------------------------------------


def _mask_strings_and_comments(sql: str) -> str:
    """Mask quoted literals and strip comments with a single state machine.

    Layered regexes get fooled by ``--`` or ``/*`` appearing *inside* a string
    literal (e.g. a password-shaped value), which would leave fragments of the
    value behind. The scanner tracks quoting state so comment markers inside
    literals are treated as literal text.
    """
    out: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if ch == "-" and nxt == "-":
            j = sql.find("\n", i + 2)
            i = n if j == -1 else j + 1
            out.append(" ")
            continue
        if ch == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            i = n if end == -1 else end + 2
            out.append(" ")
            continue
        # x'...' / b'...' blob literals carry the same quoting semantics.
        if ch in {"'", '"'} or (ch in "xXbB" and nxt in {"'", '"'}):
            quote = nxt if ch in "xXbB" else ch
            j = i + (2 if ch in "xXbB" else 1)
            while j < n:
                if sql[j] == quote:
                    if j + 1 < n and sql[j + 1] == quote:
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1 if j < n else n
            out.append("?")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def normalize_sql(sql: str) -> str:
    """Structurally normalize SQL, masking every literal as ``?``.

    Both single- and double-quoted literals are masked, and comments are
    removed entirely: SQLite accepts ``"..."`` strings and comment text would
    otherwise leak sensitive values into the plan hash and audit trail.
    """
    masked = _mask_strings_and_comments(sql)
    masked = _NUMBER_RE.sub("?", masked)
    masked = _PLACEHOLDER_RE.sub("?", masked)
    masked = _WS_RE.sub(" ", masked)
    return masked.strip().rstrip(";").strip()


def _unquote_sql_string(token: str) -> str | None:
    if len(token) >= 2 and token[0] == "'" and token[-1] == "'":
        return token[1:-1].replace("''", "'")
    return None


def _unquote_any(token: str) -> str | None:
    """Unquote a single- or double-quoted literal (SQLite accepts both)."""
    if len(token) < 2:
        return None
    quote = token[0]
    if quote not in {"'", '"'} or token[-1] != quote:
        return None
    return token[1:-1].replace(quote * 2, quote)


def _first_string_literal(text: str) -> str | None:
    match = _SINGLE_QUOTED_RE.search(text)
    if not match:
        return None
    return _unquote_sql_string(match.group(0).lstrip("xXbB"))


# -- static SQL analysis -----------------------------------------------------


def _find_functions_with_args(stmt: TokenList) -> list[tuple[str, str | None]]:
    """Return (name, first string literal argument) for every function call."""
    found: list[tuple[str, str | None]] = []

    def first_string_arg(node: Function) -> str | None:
        for token in node.flatten():
            if token.ttype in Literal.String:
                unquoted = _unquote_any(token.value)
                if unquoted is not None:
                    return unquoted
        return None

    def walk(node) -> None:
        if isinstance(node, Function):
            name_token = node.token_first()
            if name_token is not None:
                found.append((name_token.value, first_string_arg(node)))
        if isinstance(node, TokenList):
            for child in node.tokens:
                walk(child)

    walk(stmt)
    return found


def _significant_tokens(stmt: TokenList) -> list:
    result = []
    for token in stmt.tokens:
        if token.is_whitespace or token.ttype in (Whitespace, Comment, Comment.Single, Comment.Multiline):
            continue
        if token.ttype is Punctuation:
            continue
        result.append(token)
    return result


def _identifier_name(token) -> str | None:
    if isinstance(token, Identifier):
        return token.get_real_name()
    if token.ttype in (Name, Name.Placeholder):
        return token.value
    if hasattr(token, "ttype") and token.ttype is not None and token.ttype in Name:
        return token.value
    return None


def analyze_sql(sql: str, network_functions: frozenset[str] = caps._DEFAULT_NETWORK_LOWER) -> tuple[str, dict[str, set[str]], str | None]:
    """Return (verb, {capability: {details}}, ui_target) for one SQL string."""
    parsed = sqlparse.parse(sql)
    capabilities: dict[str, set[str]] = {}
    verb = "OTHER"
    target_parts: list[str] = []

    def add(capability: str, detail: str | None = None) -> None:
        capabilities.setdefault(capability, set())
        if detail:
            capabilities[capability].add(detail)

    if not parsed:
        return verb, capabilities, None
    stmt = parsed[0]
    sig = _significant_tokens(stmt)

    # Leading verb, skipping EXPLAIN/WITH until the real DML/DDL keyword.
    for token in sig:
        if token.ttype in (DML, DDL, Keyword) and token.normalized.upper() in _LEADING_VERBS:
            candidate = token.normalized.upper()
            if candidate in {"EXPLAIN", "WITH"}:
                continue
            verb = candidate
            break
    # sqlparse groups "PRAGMA name" into an unnamed token; catch it from text.
    if verb == "OTHER" and sig:
        first_word = sig[0].normalized.upper().split()
        if first_word and first_word[0] == "PRAGMA":
            verb = "PRAGMA"

    flat_keywords = {t.normalized.upper() for t in stmt.flatten() if t.ttype in (Keyword, DDL, DML, Name)}
    flat_names = [t.value for t in stmt.flatten() if t.ttype in Name]

    # PRAGMA writable_schema=<on> (sqlparse groups this oddly, use regex).
    if verb == "PRAGMA":
        match = _PRAGMA_RE.match(sql.strip())
        if match:
            pragma_name = (match.group("schema") or "") + match.group("name")
            pragma_value = match.group("value")
            normalized_value = pragma_value.strip().strip("'\"").lower() if pragma_value else None
            if pragma_name.lower() == "writable_schema" and normalized_value in _PRAGMA_ENABLE_VALUES:
                add(WRITE_SCHEMA, DETAIL_WRITABLE_SCHEMA)
                target_parts.append(f"PRAGMA writable_schema={normalized_value}")
            else:
                target_parts.append(f"PRAGMA {pragma_name}")
        return verb, capabilities, "; ".join(target_parts) or None

    # ATTACH [DATABASE] ? AS ?  /  VACUUM INTO ?
    if verb == "ATTACH":
        add(FILESYSTEM, DETAIL_ATTACH)
        path = _first_string_literal(sql)
        target_parts.append(f"ATTACH {path or '?'}")
        return verb, capabilities, "; ".join(target_parts) or None

    if verb == "VACUUM":
        if "INTO" in flat_keywords:
            add(FILESYSTEM, DETAIL_VACUUM_INTO)
            path = _first_string_literal(sql)
            target_parts.append(f"VACUUM INTO {path or '?'}")
        return verb, capabilities, "; ".join(target_parts) or None

    # Schema DDL / data DML, watching for direct catalog writes.
    writes_catalog = verb in _WRITE_VERBS and any(name.lower() in _SCHEMA_CATALOGS for name in flat_names)
    object_name: str | None = None

    # Main object name: first identifier following the verb keyword(s).
    for token in sig[1:]:
        name = _identifier_name(token)
        if name and name.upper() not in {"IF", "NOT", "EXISTS", "TEMP", "TEMPORARY", "VIRTUAL", "TABLE", "INDEX", "TRIGGER", "VIEW"}:
            object_name = name
            break
        if isinstance(token, Identifier) and token.get_real_name():
            object_name = token.get_real_name()
            break

    if verb in _SCHEMA_VERBS:
        if verb == "TRUNCATE":
            add(WRITE_SCHEMA, DETAIL_TRUNCATE)
        elif verb == "ALTER":
            add(WRITE_SCHEMA, DETAIL_ALTER)
        elif verb == "DROP":
            add(WRITE_SCHEMA, DETAIL_DROP)
        else:
            detail = DETAIL_VTABLE if "VIRTUAL" in flat_keywords else DETAIL_CREATE
            add(WRITE_SCHEMA, detail)
            # File-backed virtual table modules (sqlean vsv/scanfile/lsdir)
            # read attacker-chosen files when constructed.
            module_match = _USING_MODULE_RE.search(sql) if "VIRTUAL" in flat_keywords else None
            if module_match and module_match.group(1).lower() in caps.FILE_READING_VTABLE_MODULES:
                module_name = module_match.group(1).lower()
                add(FILESYSTEM, DETAIL_READ_FILE)
                target_parts.append(f"VIRTUAL TABLE USING {module_name}")
        if object_name:
            target_parts.append(f"{verb} {object_name}")
    elif verb in _WRITE_VERBS:
        if writes_catalog:
            add(WRITE_SCHEMA, DETAIL_MASTER_WRITE)
            target_parts.append(f"{verb} {object_name or 'sqlite_master'}")
        else:
            detail = {
                "INSERT": DETAIL_INSERT,
                "REPLACE": DETAIL_INSERT,
                "UPDATE": DETAIL_UPDATE,
                "DELETE": DETAIL_DELETE,
            }[verb]
            add(WRITE_DATA, detail)
            if object_name:
                target_parts.append(f"{verb} {object_name}")

    # Dangerous SQL functions (sqlean extensions, network UDFs, ...).
    function_targets: list[str] = []
    for name, first_arg in _find_functions_with_args(stmt):
        found = function_capability(name, network_functions)
        if found:
            capability, detail = found
            add(capability, detail)
            shown = f"{name}({first_arg})" if first_arg is not None else name
            function_targets.append(f"{capability}:{shown}")
    if function_targets:
        target_parts.append("FUNCTION " + ", ".join(sorted(set(function_targets))))

    return verb, capabilities, "; ".join(target_parts) or None


# -- compiler ----------------------------------------------------------------


class PlanCompileError(Exception):
    """Raised on deterministic, non-recoverable compilation problems."""


@dataclass
class _CompiledCommand:
    command: str
    verbosity: Verbosity
    arg: str
    canonical: str | None


class PlanCompiler:
    def __init__(
        self,
        file_reader: FileReader = _default_file_reader,
        favorite_provider: FavoriteProvider = _default_favorite_provider,
        max_nest_depth: int = DEFAULT_MAX_NEST_DEPTH,
        network_functions: frozenset[str] = caps._DEFAULT_NETWORK_LOWER,
    ) -> None:
        self.file_reader = file_reader
        self.favorite_provider = favorite_provider
        self.max_nest_depth = max_nest_depth
        self.network_functions = frozenset(n.lower() for n in network_functions)

    def compile(self, text: str, origin: SourceOrigin) -> ExecutionPlan:
        import time

        entries = self._compile_text(text, origin, depth=0, read_chain=[])
        for index, entry in enumerate(entries, start=1):
            entry.seq = index
        plan_hash = self.compute_hash(entries)
        return ExecutionPlan(
            entries=entries,
            source_signature=origin.signature(),
            plan_hash=plan_hash,
            created_at=time.time(),
        )

    @staticmethod
    def compute_hash(entries: list[PlanEntry]) -> str:
        payload = [
            {
                "kind": entry.kind,
                "verb": entry.verb,
                "template": entry.normalized_template,
                "caps": {cap: sorted(details) for cap, details in sorted(entry.capabilities.items())},
                "origin": entry.origin.type_chain(),
            }
            for entry in entries
        ]
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # -- internals -----------------------------------------------------------

    def _split(self, text: str) -> list[str]:
        stripped = text.strip()
        if stripped.startswith("\\fs"):
            components = [stripped]
        else:
            components = sqlparse.split(stripped)
        result = []
        for component in components:
            sql = component.strip().rstrip(";").strip()
            if sql.endswith("\\G"):
                sql = sql[:-2].strip()
            if sql:
                result.append(sql)
        return result

    def _compile_text(self, text: str, origin: SourceOrigin, depth: int, read_chain: list[str]) -> list[PlanEntry]:
        entries: list[PlanEntry] = []
        is_root = depth == 0
        for sql in self._split(text):
            parsed_command = self._recognize_command(sql)
            if parsed_command is not None:
                entries.extend(self._compile_special(parsed_command, sql, origin, depth, read_chain, is_root))
            else:
                entries.append(self._sql_entry(sql, origin, is_root))
        return entries

    def _recognize_command(self, sql: str) -> _CompiledCommand | None:
        command, verbosity, arg = parse_special_command(sql)
        if not command:
            return None
        spec = lookup_command(command)
        if spec is None:
            return None
        return _CompiledCommand(command=command, verbosity=verbosity, arg=arg, canonical=spec.command)

    def _base_special_entry(self, parsed: _CompiledCommand, sql: str, origin: SourceOrigin, is_root: bool = False) -> PlanEntry:
        declared = command_capabilities(parsed.command)
        canonical = parsed.canonical or parsed.command
        overrides = _COMMAND_DETAIL_OVERRIDES.get(canonical, {})
        entry = PlanEntry(
            seq=0,
            kind=KIND_SPECIAL,
            origin=origin,
            is_root=is_root,
            verb=parsed.command,
            normalized_template=self._normalize_special_template(parsed),
            target=self._special_target(parsed),
            command=parsed.command,
            verbosity=parsed.verbosity.value,
            raw=sql,
        )
        for capability in declared:
            override = overrides.get(capability, DETAIL_SPECIAL)
            details = override if isinstance(override, tuple) else (override,)
            for detail in details:
                entry.add_capability(capability, detail)
        return entry

    @staticmethod
    def _normalize_special_template(parsed: _CompiledCommand) -> str:
        if not parsed.arg:
            return parsed.command
        # Favorite name is a classifier (and part of the origin label); the
        # arguments to the favorite are user values and get masked.
        if parsed.command == "\\f":
            parts = parsed.arg.split(None, 1)
            if len(parts) == 1:
                return f"{parsed.command} {parts[0]}"
            return f"{parsed.command} {parts[0]} ?"
        return f"{parsed.command} ?"

    @staticmethod
    def _special_target(parsed: _CompiledCommand) -> str | None:
        if not parsed.arg:
            return parsed.command
        if parsed.command == "\\f":
            name = parsed.arg.split(None, 1)[0]
            return f"\\f {name}"
        return f"{parsed.command} {parsed.arg}"

    def _compile_special(
        self, parsed: _CompiledCommand, sql: str, origin: SourceOrigin, depth: int, read_chain: list[str], is_root: bool = False
    ) -> list[PlanEntry]:
        canonical = parsed.canonical or parsed.command
        # .read expansion ---------------------------------------------------
        if canonical == ".read":
            return self._expand_read(parsed, sql, origin, depth, read_chain, is_root)
        # favorite expansion ------------------------------------------------
        if canonical == "\\f" and parsed.arg:
            return self._expand_favorite(parsed, sql, origin, depth, is_root)
        # watch: the payload is SQL executed repeatedly ---------------------
        if canonical == "watch":
            return self._expand_watch(parsed, sql, origin, depth, read_chain, is_root)

        return [self._base_special_entry(parsed, sql, origin, is_root)]

    def _expand_read(
        self, parsed: _CompiledCommand, sql: str, origin: SourceOrigin, depth: int, read_chain: list[str], is_root: bool = False
    ) -> list[PlanEntry]:
        entry = self._base_special_entry(parsed, sql, origin, is_root)
        path = parsed.arg
        entry.expansion_key = "read"
        if not path:
            entry.unresolved = True
            entry.error = "missing path"
            return [entry]
        if depth >= self.max_nest_depth:
            entry.unresolved = True
            entry.error = "max nest depth exceeded"
            return [entry]
        expanded_path = os.path.abspath(os.path.expanduser(path))
        if expanded_path in read_chain:
            entry.unresolved = True
            entry.error = "read cycle detected"
            return [entry]
        try:
            contents = self.file_reader(path)
        except OSError as exc:
            entry.unresolved = True
            entry.error = type(exc).__name__
            return [entry]
        child_origin = SourceOrigin(ORIGIN_READ, label=path, parent=origin)
        children = self._compile_text(contents, child_origin, depth + 1, read_chain + [expanded_path])
        if any(child.unresolved for child in children):
            entry.unresolved = True
            entry.error = "nested expansion unresolved"
        return [entry, *children]

    def _expand_favorite(
        self, parsed: _CompiledCommand, sql: str, origin: SourceOrigin, depth: int, is_root: bool = False
    ) -> list[PlanEntry]:
        entry = self._base_special_entry(parsed, sql, origin, is_root)
        name = parsed.arg.split(None, 1)[0]
        entry.expansion_key = f"favorite:{name}"
        template = self.favorite_provider(name)
        if template is None:
            entry.unresolved = True
            entry.error = "favorite not found"
            return [entry]
        child_origin = SourceOrigin(ORIGIN_FAVORITE, label=name, parent=origin)
        children = self._compile_text(template, child_origin, depth + 1, [])
        if any(child.unresolved for child in children):
            entry.unresolved = True
            entry.error = "nested expansion unresolved"
        return [entry, *children]

    def _expand_watch(
        self, parsed: _CompiledCommand, sql: str, origin: SourceOrigin, depth: int, read_chain: list[str], is_root: bool = False
    ) -> list[PlanEntry]:
        entry = self._base_special_entry(parsed, sql, origin, is_root)
        tokens = parsed.arg.split()
        while tokens and (tokens[0].lstrip("-").isdigit() or tokens[0] in {"-c", "--color"}):
            tokens.pop(0)
        payload = " ".join(tokens)
        if not payload:
            entry.unresolved = True
            entry.error = "missing watch query"
            return [entry]
        # The payload is a nested execution even though it shares the origin.
        children = self._compile_text(payload, origin, depth + 1, read_chain)
        return [entry, *children]

    def _sql_entry(self, sql: str, origin: SourceOrigin, is_root: bool = False) -> PlanEntry:
        verb, capabilities, target = analyze_sql(sql, self.network_functions)
        return PlanEntry(
            seq=0,
            kind=KIND_SQL,
            origin=origin,
            is_root=is_root,
            verb=verb,
            normalized_template=normalize_sql(sql),
            capabilities=capabilities,
            target=target,
            raw=sql,
        )


def hash_redacted_entries(redacted: list[dict[str, Any]]) -> str:
    """Recompute the plan hash from a redacted audit-style entry list.

    Accepts both the internal payload shape (``caps``/``origin``) and the
    audit serialization shape (``capabilities``/origin dicts).
    """
    payload = []
    for item in redacted:
        if "caps" in item:
            caps_field = item["caps"]
            origin = item["origin"]
        else:
            caps_field = item.get("capabilities", {})
            origin = [node["kind"] for node in item.get("origin", [])]
        payload.append(
            {
                "kind": item["kind"],
                "verb": item["verb"],
                "template": item["template"],
                "caps": {cap: sorted(details) for cap, details in sorted(caps_field.items())},
                "origin": origin,
            }
        )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
