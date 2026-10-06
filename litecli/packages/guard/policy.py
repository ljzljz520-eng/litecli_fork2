"""Policy engine: capability(+detail) x mode -> verdict.

A decision depends *only* on capabilities, action details and the execution
mode (interactive/batch). Source origins are recorded in the plan and audit
trail but are never consulted here: the same dangerous operation gets the
same verdict whether it came from the prompt, a ``.read`` file, startup
commands, a favorite or the LLM.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from . import capabilities as caps
from .capabilities import DETAIL_CREATE
from .plan import ExecutionPlan

log = logging.getLogger(__name__)

# -- verdicts and modes ------------------------------------------------------

VERDICT_ALLOW = "allow"
VERDICT_CONFIRM = "confirm"
VERDICT_DENY = "deny"

MODE_INTERACTIVE = "interactive"
MODE_BATCH = "batch"
MODES = (MODE_INTERACTIVE, MODE_BATCH)

# Strictest wins.
_VERDICT_ORDER = {VERDICT_ALLOW: 0, VERDICT_CONFIRM: 1, VERDICT_DENY: 2}
_ORDER_VERDICT = {value: key for key, value in _VERDICT_ORDER.items()}
VALID_VERDICTS = frozenset(_VERDICT_ORDER)

# Stable rule identifiers for the default baseline.
RULE_FS = "FS-DEFAULT"
RULE_PROC = "PROC-DEFAULT"
RULE_EXT = "EXT-DEFAULT"
RULE_NET = "NET-DEFAULT"
RULE_WS = "WS-DEFAULT"
RULE_WS_CREATE = "WS-CREATE"
RULE_WD = "WD-DEFAULT"
RULE_UNRESOLVED = "PLAN-UNRESOLVED"

POLICY_VERSION = "1"

# capability -> (interactive, batch, rule id)
_DEFAULT_BASELINE: dict[str, tuple[str, str, str]] = {
    caps.FILESYSTEM: (VERDICT_CONFIRM, VERDICT_DENY, RULE_FS),
    caps.PROCESS: (VERDICT_CONFIRM, VERDICT_DENY, RULE_PROC),
    caps.EXTENSION: (VERDICT_CONFIRM, VERDICT_DENY, RULE_EXT),
    caps.NETWORK: (VERDICT_CONFIRM, VERDICT_DENY, RULE_NET),
    caps.WRITE_SCHEMA: (VERDICT_CONFIRM, VERDICT_DENY, RULE_WS),
    caps.WRITE_DATA: (VERDICT_ALLOW, VERDICT_ALLOW, RULE_WD),
}

_CONFIG_KEY_TO_CAP = {
    "filesystem": caps.FILESYSTEM,
    "process": caps.PROCESS,
    "extension": caps.EXTENSION,
    "network": caps.NETWORK,
    "write_schema": caps.WRITE_SCHEMA,
    "write_data": caps.WRITE_DATA,
}


def strictest(*verdicts: str) -> str:
    return _ORDER_VERDICT[max(_VERDICT_ORDER[v] for v in verdicts)]


@dataclass(frozen=True)
class PolicyRule:
    id: str
    capability: str
    mode: str
    verdict: str
    detail: str | None = None  # None => applies to every detail of the capability

    def snapshot_dict(self) -> dict[str, str | None]:
        return {"id": self.id, "capability": self.capability, "mode": self.mode, "verdict": self.verdict, "detail": self.detail}


@dataclass
class Policy:
    rules: list[PolicyRule]
    version: str = POLICY_VERSION
    enabled: bool = True
    network_functions: frozenset[str] = caps._DEFAULT_NETWORK_LOWER
    max_nest_depth: int = 8
    digest: str = ""

    def __post_init__(self) -> None:
        if not self.digest:
            self.digest = self.compute_digest()

    # -- lookup --------------------------------------------------------------

    def matching_rule(self, capability: str, detail: str | None, mode: str) -> PolicyRule | None:
        generic: PolicyRule | None = None
        exact: PolicyRule | None = None
        for rule in self.rules:
            if rule.capability != capability or rule.mode != mode:
                continue
            if rule.detail == detail and detail is not None:
                exact = rule
            elif rule.detail is None:
                generic = rule
        return exact or generic

    def decide_point(self, capability: str, detail: str | None, mode: str) -> tuple[str, str]:
        rule = self.matching_rule(capability, detail, mode)
        if rule is None:
            # No configured rule: fail closed for unknown capability.
            return VERDICT_DENY, "POLICY-NO-RULE"
        return rule.verdict, rule.id

    # -- snapshots -----------------------------------------------------------

    def rules_snapshot(self) -> list[dict[str, str | None]]:
        return sorted((rule.snapshot_dict() for rule in self.rules), key=lambda item: (item["id"] or "", item["mode"] or ""))

    def compute_digest(self) -> str:
        payload = {
            "version": self.version,
            "rules": self.rules_snapshot(),
            "network_functions": sorted(self.network_functions),
            "max_nest_depth": self.max_nest_depth,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    # -- construction --------------------------------------------------------

    @classmethod
    def default(cls, destructive_warning: bool = True) -> Policy:
        return cls.from_config({}, destructive_warning=destructive_warning)

    @classmethod
    def from_config(cls, section: Mapping[str, Any] | None, destructive_warning: bool = True) -> Policy:
        """Build a policy from a ``[policy]`` config section.

        Invalid values fall back to the documented default with a warning.
        ``destructive_warning=False`` restores legacy behavior: destructive
        write-schema actions are allowed instead of confirmed/denied.
        """
        section = dict(section or {})

        def parse_verdict_pair(key: str, default: tuple[str, str]) -> tuple[str, str]:
            raw = section.get(key)
            if raw in (None, ""):
                return default
            if isinstance(raw, str):
                parts = [part.strip().lower() for part in raw.split(",")]
            else:  # configobj may give a list
                parts = [str(part).strip().lower() for part in raw]
            if len(parts) != 2 or any(part not in VALID_VERDICTS for part in parts):
                log.warning("[policy] invalid %r (%r); using default %s", key, raw, default)
                return default
            return parts[0], parts[1]

        rules: list[PolicyRule] = []
        for config_key, capability in _CONFIG_KEY_TO_CAP.items():
            interactive_default, batch_default, rule_id = _DEFAULT_BASELINE[capability]
            if capability == caps.WRITE_SCHEMA and not destructive_warning:
                interactive_default, batch_default = VERDICT_ALLOW, VERDICT_ALLOW
            interactive, batch = parse_verdict_pair(config_key, (interactive_default, batch_default))
            rules.append(PolicyRule(rule_id, capability, MODE_INTERACTIVE, interactive))
            rules.append(PolicyRule(rule_id, capability, MODE_BATCH, batch))

        # CREATE is a write-schema detail allowed by default on both modes.
        create_i, create_b = parse_verdict_pair(
            "write_schema_create",
            (VERDICT_ALLOW, VERDICT_ALLOW),
        )
        rules.append(PolicyRule(RULE_WS_CREATE, caps.WRITE_SCHEMA, MODE_INTERACTIVE, create_i, detail=DETAIL_CREATE))
        rules.append(PolicyRule(RULE_WS_CREATE, caps.WRITE_SCHEMA, MODE_BATCH, create_b, detail=DETAIL_CREATE))

        network_functions = _parse_network_functions(section.get("network_functions"))
        max_nest_depth = _parse_int(section.get("max_nest_depth"), 8)
        enabled = _parse_bool(section.get("enabled"), True)

        return cls(
            rules=rules,
            version=str(section.get("version") or POLICY_VERSION),
            enabled=enabled,
            network_functions=network_functions,
            max_nest_depth=max_nest_depth,
        )


def _parse_network_functions(raw: Any) -> frozenset[str]:
    if raw in (None, ""):
        return caps._DEFAULT_NETWORK_LOWER
    if isinstance(raw, str):
        names = [part.strip().lower() for part in raw.split(",")]
    else:
        names = [str(part).strip().lower() for part in raw]
    return frozenset(name for name in names if name)


def _parse_int(raw: Any, default: int) -> int:
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        log.warning("[policy] invalid integer %r; using %d", raw, default)
        return default


def _parse_bool(raw: Any, default: bool) -> bool:
    if raw in (None, ""):
        return default
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


# -- decisions ----------------------------------------------------------------


@dataclass
class PointDecision:
    seq: int
    capability: str
    detail: str | None
    verdict: str
    rule_id: str
    reason: str


@dataclass
class EntryDecision:
    seq: int
    verdict: str
    points: list[PointDecision] = field(default_factory=list)

    @property
    def denied_capabilities(self) -> list[str]:
        return sorted({p.capability for p in self.points if p.verdict == VERDICT_DENY})


def rules_snapshot_digest(snapshot: list[dict[str, str | None]]) -> str:
    """Stable digest of a rules snapshot, so replay can detect tampering."""
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass
class Decision:
    plan_hash: str
    mode: str
    verdict: str
    entries: list[EntryDecision]
    policy_version: str
    policy_digest: str
    rules_snapshot: list[dict[str, str | None]]
    rules_digest: str = ""

    def audit_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "mode": self.mode,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "rules_digest": self.rules_digest or rules_snapshot_digest(self.rules_snapshot),
            "rules_snapshot": self.rules_snapshot,
            "entries": [
                {
                    "seq": entry.seq,
                    "verdict": entry.verdict,
                    "points": [
                        {
                            "capability": point.capability,
                            "detail": point.detail,
                            "verdict": point.verdict,
                            "rule_id": point.rule_id,
                            "reason": point.reason,
                        }
                        for point in entry.points
                    ],
                }
                for entry in self.entries
            ],
        }


def decide(plan: ExecutionPlan, mode: str, policy: Policy) -> Decision:
    if mode not in MODES:
        raise ValueError(f"Unknown mode: {mode!r}")
    entry_decisions: list[EntryDecision] = []
    for entry in plan.entries:
        points: list[PointDecision] = []
        if entry.unresolved:
            points.append(
                PointDecision(
                    seq=entry.seq,
                    capability="*",
                    detail=None,
                    verdict=VERDICT_DENY,
                    rule_id=RULE_UNRESOLVED,
                    reason=f"plan entry could not be resolved before execution: {entry.error or 'unknown error'}",
                )
            )
        for capability, details in sorted(entry.capabilities.items()):
            detail_values = sorted(details, key=lambda value: value or "") if details else [None]
            for detail in detail_values:
                verdict, rule_id = policy.decide_point(capability, detail, mode)
                points.append(
                    PointDecision(
                        seq=entry.seq,
                        capability=capability,
                        detail=detail,
                        verdict=verdict,
                        rule_id=rule_id,
                        reason=f"{capability}/{detail or '-'} => {verdict} in {mode} by {rule_id}",
                    )
                )
        entry_verdict = strictest(*(point.verdict for point in points)) if points else VERDICT_ALLOW
        entry_decisions.append(EntryDecision(seq=entry.seq, verdict=entry_verdict, points=points))
    overall = strictest(*(entry.verdict for entry in entry_decisions)) if entry_decisions else VERDICT_ALLOW
    snapshot = policy.rules_snapshot()
    return Decision(
        plan_hash=plan.plan_hash,
        mode=mode,
        verdict=overall,
        entries=entry_decisions,
        policy_version=policy.version,
        policy_digest=policy.digest,
        rules_snapshot=snapshot,
        rules_digest=rules_snapshot_digest(snapshot),
    )


# -- replay -------------------------------------------------------------------


def replay(
    redacted_entries: list[dict[str, Any]],
    mode: str,
    rules_snapshot: list[dict[str, str | None]],
) -> dict[str, Any]:
    """Recompute verdicts from redacted audit data and a rules snapshot.

    Pure function: no raw SQL, no policy object, only capability/detail data.
    """
    rules = [
        PolicyRule(
            id=str(item["id"]),
            capability=str(item["capability"]),
            mode=str(item["mode"]),
            verdict=str(item["verdict"]),
            detail=item.get("detail"),
        )
        for item in rules_snapshot
    ]
    snapshot_policy = Policy(rules=rules)
    replay_entries: list[dict[str, Any]] = []
    for entry in redacted_entries:
        seq = int(entry["seq"])
        points: list[dict[str, str | None]] = []
        verdicts: list[str] = []
        if entry.get("unresolved"):
            points.append({"capability": "*", "detail": None, "verdict": VERDICT_DENY, "rule_id": RULE_UNRESOLVED})
            verdicts.append(VERDICT_DENY)
        for capability, details in sorted((entry.get("capabilities") or {}).items()):
            for detail in sorted(details or [None], key=lambda value: value or ""):
                verdict, rule_id = snapshot_policy.decide_point(capability, detail, mode)
                points.append({"capability": capability, "detail": detail, "verdict": verdict, "rule_id": rule_id})
                verdicts.append(verdict)
        entry_verdict = strictest(*verdicts) if verdicts else VERDICT_ALLOW
        replay_entries.append({"seq": seq, "verdict": entry_verdict, "points": points})
    overall = strictest(*(item["verdict"] for item in replay_entries)) if replay_entries else VERDICT_ALLOW
    return {
        "mode": mode,
        "verdict": overall,
        "entries": replay_entries,
        "rules_digest": rules_snapshot_digest(snapshot_policy.rules_snapshot()),
    }
