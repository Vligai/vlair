#!/usr/bin/env python3
"""
Sigma rule engine for vlair log analysis.

Parses Sigma YAML rules and evaluates them against normalized vlair log events.
Uses PyYAML for rule loading and a custom in-process evaluator for matching —
no query-language backend required.
"""

import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

# Sigma level → vlair risk-score contribution (design.md D5)
SIGMA_LEVEL_SCORES: Dict[str, int] = {
    "informational": 5,
    "low": 15,
    "medium": 35,
    "high": 65,
    "critical": 90,
}

SIGMA_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]

# vlair's normalized event field names (used to validate identity mappings)
_VLAIR_FIELDS: Set[str] = {
    "source_ip",
    "method",
    "path",
    "status",
    "user_agent",
    "referer",
    "size",
    "host",
    "process",
    "pid",
    "message",
    "user",
    "username",
    "timestamp",
    "log_type",
}


class _SigmaRule:
    """Internal representation of a parsed Sigma rule, ready for evaluation."""

    def __init__(self, raw: Dict, path: Path) -> None:
        self.path = path
        self.rule_id: str = str(raw.get("id") or "") or str(path)
        self.title: str = raw.get("title", "Unknown")
        self.level: str = (raw.get("level") or "medium").lower()
        self.tags: List[str] = list(raw.get("tags") or [])
        self.references: List[str] = list(raw.get("references") or [])
        self.mitre_attack: List[str] = self._extract_mitre(self.tags)
        detection = raw.get("detection", {})
        self.condition: str = str(detection.get("condition", "selection"))
        # All keys except 'condition' are selections
        self.selections: Dict[str, Any] = {k: v for k, v in detection.items() if k != "condition"}
        # Filled after field-mapping resolves successfully
        self.mapped_selections: Dict[str, Any] = {}
        # Required event fields for quick short-circuit (populated after mapping)
        self.required_fields: Set[str] = set()

    @staticmethod
    def _extract_mitre(tags: List[str]) -> List[str]:
        results = []
        for tag in tags:
            m = re.match(r"attack\.(t\d+(?:\.\d+)?)", tag, re.IGNORECASE)
            if m:
                results.append(m.group(1).upper())
        return results

    @property
    def rule_link(self) -> str:
        return self.references[0] if self.references else ""


class SigmaEngine:
    """
    Load Sigma rules and evaluate them against vlair normalized log events.

    Usage::

        engine = SigmaEngine(rule_paths=["builtin"], min_level="medium")
        for event in parsed_events:
            engine.evaluate(event)
        matches = engine.get_matches()

    Supported modifiers: contains, startswith, endswith, re, cidr, all, any,
                         lt, lte, gt, gte.
    Supported conditions: selection references, and/or/not, 1-of/all-of patterns.
    """

    BUILTIN_RULES_PATH: Path = Path(__file__).parent.parent / "data" / "sigma_rules"
    BUILTIN_FIELD_MAP_PATH: Path = Path(__file__).parent.parent / "data" / "sigma_field_map.yml"

    def __init__(
        self,
        rule_paths: Union[str, Path, List[Union[str, Path]]],
        field_map_path: Optional[Union[str, Path]] = None,
        min_level: str = "low",
    ) -> None:
        if not _YAML_AVAILABLE:
            raise ImportError(
                "PyYAML is required for Sigma support. Install with: pip install pyyaml"
            )

        self.min_level = min_level.lower()
        self.min_score = SIGMA_LEVEL_SCORES.get(self.min_level, 15)
        self.field_map: Dict[str, str] = self._load_field_map(
            field_map_path or self.BUILTIN_FIELD_MAP_PATH
        )

        self.rules: List[_SigmaRule] = []
        self.skipped_rules: List[Dict[str, str]] = []

        # Dedup table: (rule_id, src_ip) → {count, first_event, last_event, match_obj}
        self._dedup: Dict[Tuple, Dict] = {}

        # Resolve rule paths
        if isinstance(rule_paths, (str, Path)):
            rule_paths = [rule_paths]

        for rp in rule_paths:
            rp_str = str(rp)
            if rp_str == "builtin":
                for p in self._walk_yaml(self.BUILTIN_RULES_PATH):
                    self._load_rule(p)
            else:
                p = Path(rp_str)
                if p.is_file():
                    self._load_rule(p)
                elif p.is_dir():
                    for rp2 in self._walk_yaml(p):
                        self._load_rule(rp2)
                else:
                    sys.stderr.write(f"[sigma] path not found: {rp_str}\n")

    # ------------------------------------------------------------------
    # Loading helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _walk_yaml(directory: Path) -> List[Path]:
        results: List[Path] = []
        for suffix in ("*.yml", "*.yaml"):
            results.extend(directory.rglob(suffix))
        return sorted(results)

    def _load_field_map(self, path: Union[str, Path]) -> Dict[str, str]:
        path = Path(path)
        if not path.exists():
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return {str(k).lower(): str(v) for k, v in data.items() if k and v}
        except Exception as exc:
            sys.stderr.write(f"[sigma] could not load field map {path}: {exc}\n")
            return {}

    def _load_rule(self, path: Path) -> None:
        try:
            with open(path, encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict) or "detection" not in raw:
                self.skipped_rules.append(
                    {"path": str(path), "reason": "missing or invalid detection block"}
                )
                return

            rule = _SigmaRule(raw, path)

            level_score = SIGMA_LEVEL_SCORES.get(rule.level, 15)
            if level_score < self.min_score:
                return  # silently filter below-threshold rules

            mapped, unmapped = self._map_selections(rule.selections)
            if unmapped:
                self.skipped_rules.append(
                    {
                        "path": str(path),
                        "rule_id": rule.rule_id,
                        "reason": f"unmapped fields: {', '.join(sorted(unmapped))}",
                    }
                )
                return

            rule.mapped_selections = mapped
            # Collect field names for short-circuit evaluation (task 8.2)
            req: Set[str] = set()
            for sel_body in mapped.values():
                if isinstance(sel_body, dict):
                    for field_spec in sel_body:
                        req.add(field_spec.split("|")[0])
            rule.required_fields = req
            self.rules.append(rule)

        except Exception as exc:
            self.skipped_rules.append({"path": str(path), "reason": str(exc)})

    def _map_selections(self, selections: Dict) -> Tuple[Dict, Set[str]]:
        """Translate Sigma field names to vlair field names in all selections."""
        mapped: Dict[str, Any] = {}
        unmapped: Set[str] = set()

        for sel_name, sel_body in selections.items():
            if not isinstance(sel_body, dict):
                # Keyword list or scalar — pass through unchanged
                mapped[sel_name] = sel_body
                continue

            mapped_body: Dict[str, Any] = {}
            for raw_field, values in sel_body.items():
                parts = raw_field.split("|")
                sigma_field = parts[0].lower()
                modifiers = [m.lower() for m in parts[1:]]

                vlair_field = self.field_map.get(sigma_field)
                if vlair_field is None:
                    unmapped.add(sigma_field)
                    continue

                key = "|".join([vlair_field] + modifiers) if modifiers else vlair_field
                mapped_body[key] = values

            if unmapped:
                # Stop early — this rule will be skipped
                break
            mapped[sel_name] = mapped_body

        return mapped, unmapped

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, event: Dict) -> None:
        """Evaluate all loaded rules against *event*; accumulates results internally."""
        src_ip: str = str(event.get("source_ip") or event.get("src_ip") or "")

        event_keys = set(event.keys())
        for rule in self.rules:
            # Short-circuit: skip if event has none of the fields this rule needs
            if rule.required_fields and not rule.required_fields.intersection(event_keys):
                continue
            fired = self._eval_condition(rule.condition, rule.mapped_selections, event)
            if not fired:
                continue

            key = (rule.rule_id, src_ip)
            if key in self._dedup:
                entry = self._dedup[key]
                entry["count"] += 1
                entry["last_event"] = event
            else:
                match_obj = {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.title,
                    "level": rule.level,
                    "mitre_attack": rule.mitre_attack,
                    "tags": rule.tags,
                    "matched_event": event,
                    "rule_path": str(rule.path),
                    "rule_link": rule.rule_link,
                    "match_count": 1,
                    "source": "sigma",
                }
                self._dedup[key] = {"count": 1, "first_event": event, "last_event": event, "obj": match_obj}

    def get_matches(self) -> List[Dict]:
        """Return deduplicated match list with final match counts."""
        results = []
        for entry in self._dedup.values():
            obj = dict(entry["obj"])
            obj["match_count"] = entry["count"]
            if entry["count"] > 1:
                obj["first_event"] = entry["first_event"]
                obj["last_event"] = entry["last_event"]
            results.append(obj)
        return results

    def reset(self) -> None:
        """Clear accumulated match state (call between analysis sessions)."""
        self._dedup.clear()

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def _eval_condition(self, condition: str, selections: Dict, event: Dict) -> bool:
        sel_results = {name: self._eval_selection(sel, event) for name, sel in selections.items()}
        try:
            return self._eval_expr(condition.strip(), sel_results)
        except Exception:
            return False

    def _eval_expr(self, expr: str, sel_results: Dict[str, bool]) -> bool:
        """Recursively evaluate a Sigma condition expression."""
        expr = expr.strip()

        # Strip balanced outer parentheses
        if expr.startswith("(") and expr.endswith(")") and self._balanced_parens(expr):
            return self._eval_expr(expr[1:-1].strip(), sel_results)

        # not <expr>
        if re.match(r"^not\s+", expr, re.IGNORECASE):
            return not self._eval_expr(expr[4:].strip(), sel_results)

        # Split on 'or' first (lower precedence)
        or_parts = self._split_on(expr, "or")
        if len(or_parts) > 1:
            return any(self._eval_expr(p, sel_results) for p in or_parts)

        # Split on 'and'
        and_parts = self._split_on(expr, "and")
        if len(and_parts) > 1:
            return all(self._eval_expr(p, sel_results) for p in and_parts)

        # "1 of <pattern>" / "all of <pattern>"
        m = re.match(r"^(1|all)\s+of\s+(\S+)$", expr, re.IGNORECASE)
        if m:
            quantifier = m.group(1).lower()
            pattern = m.group(2)
            candidates = self._glob_selections(pattern, sel_results)
            if not candidates:
                return False
            return any(candidates) if quantifier == "1" else all(candidates)

        # Direct selection reference
        return sel_results.get(expr, False)

    @staticmethod
    def _balanced_parens(expr: str) -> bool:
        """True if the first '(' is closed by the last ')'."""
        depth = 0
        for i, ch in enumerate(expr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth == 0 and i < len(expr) - 1:
                return False
        return depth == 0

    @staticmethod
    def _split_on(expr: str, keyword: str) -> List[str]:
        """Split *expr* on bare *keyword*, respecting parentheses."""
        parts: List[str] = []
        depth = 0
        i = 0
        start = 0
        kw = f" {keyword.lower()} "
        el = expr.lower()

        while i < len(expr):
            if expr[i] == "(":
                depth += 1
                i += 1
            elif expr[i] == ")":
                depth -= 1
                i += 1
            elif depth == 0 and el[i : i + len(kw)] == kw:
                parts.append(expr[start:i].strip())
                start = i + len(kw)
                i += len(kw)
            else:
                i += 1

        parts.append(expr[start:].strip())
        return [p for p in parts if p]

    @staticmethod
    def _glob_selections(pattern: str, sel_results: Dict[str, bool]) -> List[bool]:
        """Return result values for selection names matching *pattern* (supports *)."""
        if pattern.lower() in ("them", "*"):
            return list(sel_results.values())
        regex = re.compile(re.escape(pattern).replace(r"\*", ".*"), re.IGNORECASE)
        return [v for k, v in sel_results.items() if regex.fullmatch(k)]

    # ------------------------------------------------------------------
    # Selection evaluation
    # ------------------------------------------------------------------

    def _eval_selection(self, selection: Any, event: Dict) -> bool:
        """Evaluate a single selection dict or keyword list against *event*."""
        if isinstance(selection, list):
            # Keyword list: match any field's string value against any keyword
            event_str = " ".join(str(v) for v in event.values() if v is not None)
            return any(str(kw).lower() in event_str.lower() for kw in selection)

        if not isinstance(selection, dict):
            return False

        # All field predicates must hold (AND within a selection)
        for field_spec, values in selection.items():
            parts = field_spec.split("|")
            field = parts[0]
            modifiers = [m.lower() for m in parts[1:]]
            event_val = event.get(field)
            if event_val is None:
                return False
            if not self._eval_field(event_val, modifiers, values):
                return False
        return True

    def _eval_field(self, event_val: Any, modifiers: List[str], values: Any) -> bool:
        """Match *event_val* against *values* using *modifiers*."""
        if not isinstance(values, list):
            values = [values]

        require_all = "all" in modifiers
        active_mods = [m for m in modifiers if m not in ("all", "any")]

        results = [self._match_one(event_val, active_mods, v) for v in values]
        return all(results) if require_all else any(results)

    def _match_one(self, event_val: Any, modifiers: List[str], match_val: Any) -> bool:
        """Apply *modifiers* to compare *event_val* against *match_val*."""
        if match_val is None:
            return event_val is None

        ev = str(event_val)
        mv = str(match_val)

        if not modifiers:
            return ev.lower() == mv.lower()

        mod = modifiers[0]

        if mod == "contains":
            return mv.lower() in ev.lower()
        if mod == "startswith":
            return ev.lower().startswith(mv.lower())
        if mod == "endswith":
            return ev.lower().endswith(mv.lower())
        if mod == "re":
            try:
                return bool(re.search(mv, ev, re.IGNORECASE))
            except re.error:
                return False
        if mod == "cidr":
            try:
                return ipaddress.ip_address(ev) in ipaddress.ip_network(mv, strict=False)
            except ValueError:
                return False
        if mod == "lt":
            try:
                return float(ev) < float(mv)
            except ValueError:
                return False
        if mod == "lte":
            try:
                return float(ev) <= float(mv)
            except ValueError:
                return False
        if mod == "gt":
            try:
                return float(ev) > float(mv)
            except ValueError:
                return False
        if mod == "gte":
            try:
                return float(ev) >= float(mv)
            except ValueError:
                return False

        # Unknown modifier: fall back to contains
        return mv.lower() in ev.lower()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def rules_loaded(self) -> int:
        return len(self.rules) + len(self.skipped_rules)

    @property
    def rules_evaluated(self) -> int:
        return len(self.rules)
