#!/usr/bin/env python3
"""
Tests for SigmaEngine — covers tasks 1.4 and 2.7:
  1.4  field-map file loads and contains entries for all bundled-rule fields
  2.7  per-modifier unit tests; condition combinations; rule-loading edge cases
"""

import ipaddress
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _YAML_AVAILABLE, reason="pyyaml not installed")

from vlair.tools.sigma_engine import (
    SIGMA_LEVEL_SCORES,
    SIGMA_LEVEL_ORDER,
    SigmaEngine,
    _SigmaRule,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BUILTIN_RULES_PATH = Path(__file__).parent.parent / "src" / "vlair" / "data" / "sigma_rules"
BUILTIN_FIELD_MAP_PATH = Path(__file__).parent.parent / "src" / "vlair" / "data" / "sigma_field_map.yml"


def _make_rule_file(tmp_path: Path, body: str, name: str = "rule.yml") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def _make_engine(tmp_path: Path, rule_body: str, min_level: str = "low") -> SigmaEngine:
    p = _make_rule_file(tmp_path, rule_body)
    return SigmaEngine(rule_paths=[p], field_map_path=BUILTIN_FIELD_MAP_PATH, min_level=min_level)


def _web_event(**kwargs) -> dict:
    base = {
        "source_ip": "1.2.3.4",
        "method": "GET",
        "path": "/index.html",
        "status": 200,
        "user_agent": "Mozilla/5.0",
        "referer": "-",
        "size": "1234",
        "log_type": "apache",
    }
    base.update(kwargs)
    return base


SIMPLE_RULE = """
    title: Test Rule
    id: aaaabbbb-0000-0000-0000-000000000001
    status: test
    detection:
      selection:
        path|contains: /evil
      condition: selection
    level: medium
"""


# ---------------------------------------------------------------------------
# Task 1.4 — Field-map validation
# ---------------------------------------------------------------------------


class TestFieldMap:
    def test_field_map_file_exists(self):
        assert BUILTIN_FIELD_MAP_PATH.exists(), "sigma_field_map.yml is missing"

    def test_field_map_loads_as_dict(self):
        with open(BUILTIN_FIELD_MAP_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)
        assert len(data) > 0

    def test_field_map_covers_vlair_fields(self):
        with open(BUILTIN_FIELD_MAP_PATH, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        field_map = {str(k).lower(): str(v) for k, v in raw.items()}

        required = {"source_ip", "method", "path", "status", "user_agent", "referer", "host", "process", "message"}
        mapped_targets = set(field_map.values())
        missing = required - mapped_targets
        assert not missing, f"Field map missing vlair targets: {missing}"

    def test_field_map_all_values_are_vlair_fields(self):
        from vlair.tools.sigma_engine import _VLAIR_FIELDS

        with open(BUILTIN_FIELD_MAP_PATH, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        for k, v in raw.items():
            assert str(v) in _VLAIR_FIELDS, f"Field map value '{v}' not in _VLAIR_FIELDS"

    def test_bundled_rule_fields_are_covered(self):
        """Every Sigma field used in bundled rules must appear in the field map."""
        with open(BUILTIN_FIELD_MAP_PATH, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        field_map = {str(k).lower() for k in raw}

        unmapped = set()
        for rule_path in BUILTIN_RULES_PATH.rglob("*.yml"):
            with open(rule_path, encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            detection = rule.get("detection", {})
            for key, _val in detection.items():
                if key == "condition" or not isinstance(_val, dict):
                    continue
                for field_spec in _val:
                    sigma_field = field_spec.split("|")[0].lower()
                    if sigma_field not in field_map:
                        unmapped.add(sigma_field)

        assert not unmapped, f"Bundled rule fields not in field map: {unmapped}"


# ---------------------------------------------------------------------------
# Task 2.7 — Modifier unit tests
# ---------------------------------------------------------------------------


class TestModifierContains:
    def test_contains_match(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        event = _web_event(path="/evil/path")
        engine.evaluate(event)
        assert len(engine.get_matches()) == 1

    def test_contains_no_match(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        event = _web_event(path="/harmless")
        engine.evaluate(event)
        assert engine.get_matches() == []

    def test_contains_case_insensitive(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate(_web_event(path="/EVIL/path"))
        assert len(engine.get_matches()) == 1


class TestModifierStartswith:
    RULE = """
        title: Starts Rule
        id: aaaabbbb-0000-0000-0000-000000000002
        detection:
          selection:
            path|startswith: /admin
          condition: selection
        level: low
    """

    def test_startswith_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/admin/panel"))
        assert len(engine.get_matches()) == 1

    def test_startswith_no_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/public/admin"))
        assert engine.get_matches() == []


class TestModifierEndswith:
    RULE = """
        title: Ends Rule
        id: aaaabbbb-0000-0000-0000-000000000003
        detection:
          selection:
            path|endswith: .php
          condition: selection
        level: low
    """

    def test_endswith_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/shell.php"))
        assert len(engine.get_matches()) == 1

    def test_endswith_no_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/shell.html"))
        assert engine.get_matches() == []


class TestModifierRe:
    RULE = """
        title: Regex Rule
        id: aaaabbbb-0000-0000-0000-000000000004
        detection:
          selection:
            path|re: '^/api/v\\d+/.*$'
          condition: selection
        level: low
    """

    def test_re_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/api/v2/users"))
        assert len(engine.get_matches()) == 1

    def test_re_no_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/api/users"))
        assert engine.get_matches() == []

    def test_re_invalid_pattern_no_crash(self, tmp_path):
        rule = """
            title: Bad Regex
            id: aaaabbbb-0000-0000-0000-000000000005
            detection:
              selection:
                path|re: '[invalid'
              condition: selection
            level: low
        """
        engine = _make_engine(tmp_path, rule)
        engine.evaluate(_web_event(path="/anything"))
        assert engine.get_matches() == []


class TestModifierCidr:
    RULE = """
        title: CIDR Rule
        id: aaaabbbb-0000-0000-0000-000000000006
        detection:
          selection:
            source_ip|cidr: '10.0.0.0/8'
          condition: selection
        level: low
    """

    def test_cidr_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(source_ip="10.1.2.3"))
        assert len(engine.get_matches()) == 1

    def test_cidr_no_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(source_ip="192.168.1.1"))
        assert engine.get_matches() == []

    def test_cidr_invalid_ip_no_crash(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(source_ip="not-an-ip"))
        assert engine.get_matches() == []


class TestModifierComparison:
    def _rule_for_op(self, op: str, val: str) -> str:
        uid = abs(hash(op + val)) % 10**9
        return f"""
            title: Compare Rule
            id: aaaabbbb-0000-0000-0000-{uid:012d}
            detection:
              selection:
                status|{op}: {val}
              condition: selection
            level: low
        """

    def test_lt(self, tmp_path):
        engine = _make_engine(tmp_path, self._rule_for_op("lt", "400"))
        engine.evaluate(_web_event(status=200))
        assert len(engine.get_matches()) == 1
        engine.reset()
        engine.evaluate(_web_event(status=400))
        assert engine.get_matches() == []

    def test_lte(self, tmp_path):
        engine = _make_engine(tmp_path, self._rule_for_op("lte", "200"))
        engine.evaluate(_web_event(status=200))
        assert len(engine.get_matches()) == 1
        engine.reset()
        engine.evaluate(_web_event(status=201))
        assert engine.get_matches() == []

    def test_gt(self, tmp_path):
        engine = _make_engine(tmp_path, self._rule_for_op("gt", "499"))
        engine.evaluate(_web_event(status=500))
        assert len(engine.get_matches()) == 1
        engine.reset()
        engine.evaluate(_web_event(status=200))
        assert engine.get_matches() == []

    def test_gte(self, tmp_path):
        engine = _make_engine(tmp_path, self._rule_for_op("gte", "500"))
        engine.evaluate(_web_event(status=500))
        assert len(engine.get_matches()) == 1
        engine.reset()
        engine.evaluate(_web_event(status=499))
        assert engine.get_matches() == []


class TestModifierAll:
    RULE = """
        title: All Modifier
        id: aaaabbbb-0000-0000-0000-000000000020
        detection:
          selection:
            path|contains|all:
              - admin
              - delete
          condition: selection
        level: low
    """

    def test_all_both_present(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/admin/delete/user"))
        assert len(engine.get_matches()) == 1

    def test_all_only_one_present(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/admin/view/user"))
        assert engine.get_matches() == []


class TestModifierAny:
    RULE = """
        title: Any Modifier
        id: aaaabbbb-0000-0000-0000-000000000021
        detection:
          selection:
            path|contains:
              - /etc/passwd
              - /etc/shadow
          condition: selection
        level: high
    """

    def test_any_first_value(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/../../etc/passwd"))
        assert len(engine.get_matches()) == 1

    def test_any_second_value(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/../../etc/shadow"))
        assert len(engine.get_matches()) == 1

    def test_any_no_match(self, tmp_path):
        engine = _make_engine(tmp_path, self.RULE)
        engine.evaluate(_web_event(path="/etc/hosts"))
        assert engine.get_matches() == []


# ---------------------------------------------------------------------------
# Condition evaluator tests
# ---------------------------------------------------------------------------


class TestConditionLogic:
    def _two_sel_rule(self, condition: str) -> str:
        return f"""
            title: Logic Rule
            id: aaaabbbb-0000-0000-0000-000000000030
            detection:
              sel_a:
                path|contains: /admin
              sel_b:
                method: POST
              condition: {condition}
            level: low
        """

    def test_and_both_true(self, tmp_path):
        engine = _make_engine(tmp_path, self._two_sel_rule("sel_a and sel_b"))
        engine.evaluate(_web_event(path="/admin/panel", method="POST"))
        assert len(engine.get_matches()) == 1

    def test_and_one_false(self, tmp_path):
        engine = _make_engine(tmp_path, self._two_sel_rule("sel_a and sel_b"))
        engine.evaluate(_web_event(path="/admin/panel", method="GET"))
        assert engine.get_matches() == []

    def test_or_one_true(self, tmp_path):
        engine = _make_engine(tmp_path, self._two_sel_rule("sel_a or sel_b"))
        engine.evaluate(_web_event(path="/public", method="POST"))
        assert len(engine.get_matches()) == 1

    def test_or_both_false(self, tmp_path):
        engine = _make_engine(tmp_path, self._two_sel_rule("sel_a or sel_b"))
        engine.evaluate(_web_event(path="/public", method="GET"))
        assert engine.get_matches() == []

    def test_not(self, tmp_path):
        engine = _make_engine(tmp_path, self._two_sel_rule("not sel_b"))
        engine.evaluate(_web_event(method="GET"))
        assert len(engine.get_matches()) == 1
        engine.reset()
        engine.evaluate(_web_event(method="POST"))
        assert engine.get_matches() == []

    def test_parentheses(self, tmp_path):
        engine = _make_engine(tmp_path, self._two_sel_rule("(sel_a or sel_b) and sel_b"))
        engine.evaluate(_web_event(path="/admin/panel", method="POST"))
        assert len(engine.get_matches()) == 1

    def test_1_of_them(self, tmp_path):
        rule = """
            title: 1 Of Them
            id: aaaabbbb-0000-0000-0000-000000000031
            detection:
              sel_a:
                path|contains: /evil
              sel_b:
                path|contains: /bad
              condition: 1 of them
            level: low
        """
        engine = _make_engine(tmp_path, rule)
        engine.evaluate(_web_event(path="/evil/path"))
        assert len(engine.get_matches()) == 1

    def test_all_of_them(self, tmp_path):
        rule = """
            title: All Of Them
            id: aaaabbbb-0000-0000-0000-000000000032
            detection:
              sel_a:
                path|contains: /evil
              sel_b:
                path|contains: /bad
              condition: all of them
            level: low
        """
        engine = _make_engine(tmp_path, rule)
        engine.evaluate(_web_event(path="/evil/bad/path"))
        assert len(engine.get_matches()) == 1
        engine.reset()
        engine.evaluate(_web_event(path="/evil/path"))
        assert engine.get_matches() == []

    def test_1_of_wildcard(self, tmp_path):
        rule = """
            title: Wildcard Of
            id: aaaabbbb-0000-0000-0000-000000000033
            detection:
              filter_a:
                path|contains: /evil
              filter_b:
                path|contains: /bad
              condition: 1 of filter_*
            level: low
        """
        engine = _make_engine(tmp_path, rule)
        engine.evaluate(_web_event(path="/bad/path"))
        assert len(engine.get_matches()) == 1


# ---------------------------------------------------------------------------
# Rule-loading edge cases
# ---------------------------------------------------------------------------


class TestRuleLoading:
    def test_missing_detection_skipped(self, tmp_path):
        p = _make_rule_file(
            tmp_path,
            """
            title: No Detection
            id: aaaabbbb-0000-0000-0000-000000000040
            level: low
        """,
        )
        engine = SigmaEngine(rule_paths=[p], field_map_path=BUILTIN_FIELD_MAP_PATH)
        assert len(engine.rules) == 0
        assert len(engine.skipped_rules) == 1

    def test_unmapped_field_skipped(self, tmp_path):
        p = _make_rule_file(
            tmp_path,
            """
            title: Unmapped Field
            id: aaaabbbb-0000-0000-0000-000000000041
            detection:
              selection:
                nonexistent_sigma_field|contains: value
              condition: selection
            level: low
        """,
        )
        engine = SigmaEngine(rule_paths=[p], field_map_path=BUILTIN_FIELD_MAP_PATH)
        assert len(engine.rules) == 0
        assert any("unmapped" in r["reason"] for r in engine.skipped_rules)

    def test_invalid_yaml_skipped(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("{{not: [valid yaml", encoding="utf-8")
        engine = SigmaEngine(rule_paths=[p], field_map_path=BUILTIN_FIELD_MAP_PATH)
        assert len(engine.skipped_rules) == 1

    def test_min_level_filters_rules(self, tmp_path):
        low = _make_rule_file(
            tmp_path,
            """
            title: Low Rule
            id: aaaabbbb-0000-0000-0000-000000000042
            detection:
              selection:
                path|contains: /low
              condition: selection
            level: low
        """,
            "low.yml",
        )
        engine_high = SigmaEngine(rule_paths=[low], field_map_path=BUILTIN_FIELD_MAP_PATH, min_level="high")
        assert len(engine_high.rules) == 0

        engine_low = SigmaEngine(rule_paths=[low], field_map_path=BUILTIN_FIELD_MAP_PATH, min_level="low")
        assert len(engine_low.rules) == 1

    def test_builtin_keyword_loads_rules(self):
        engine = SigmaEngine(rule_paths=["builtin"], min_level="low")
        assert engine.rules_evaluated > 0

    def test_rules_loaded_includes_skipped(self, tmp_path):
        good = _make_rule_file(tmp_path, SIMPLE_RULE, "good.yml")
        bad = _make_rule_file(
            tmp_path,
            """
            title: Bad
            id: aaaabbbb-0000-0000-0000-000000000043
            detection:
              selection:
                no_such_field: x
              condition: selection
            level: low
        """,
            "bad.yml",
        )
        engine = SigmaEngine(rule_paths=[good, bad], field_map_path=BUILTIN_FIELD_MAP_PATH)
        assert engine.rules_loaded == engine.rules_evaluated + len(engine.skipped_rules)


# ---------------------------------------------------------------------------
# De-duplication tests (task 2.6)
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_same_rule_same_ip_deduped(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        for _ in range(5):
            engine.evaluate(_web_event(path="/evil/path"))
        matches = engine.get_matches()
        assert len(matches) == 1
        assert matches[0]["match_count"] == 5

    def test_same_rule_different_ip_not_deduped(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate(_web_event(path="/evil/path", source_ip="1.1.1.1"))
        engine.evaluate(_web_event(path="/evil/path", source_ip="2.2.2.2"))
        matches = engine.get_matches()
        assert len(matches) == 2

    def test_reset_clears_state(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate(_web_event(path="/evil/path"))
        engine.reset()
        assert engine.get_matches() == []

    def test_match_count_tracked(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate(_web_event(path="/evil/path"))
        engine.evaluate(_web_event(path="/evil/path"))
        assert engine.get_matches()[0]["match_count"] == 2

    def test_first_last_event_populated(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        e1 = _web_event(path="/evil/path", source_ip="3.3.3.3", status=200)
        e2 = _web_event(path="/evil/path", source_ip="3.3.3.3", status=404)
        engine.evaluate(e1)
        engine.evaluate(e2)
        m = engine.get_matches()[0]
        assert m["first_event"]["status"] == 200
        assert m["last_event"]["status"] == 404


# ---------------------------------------------------------------------------
# Match object structure
# ---------------------------------------------------------------------------


class TestMatchStructure:
    def test_match_has_required_keys(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate(_web_event(path="/evil/path"))
        m = engine.get_matches()[0]
        required = {
            "rule_id",
            "rule_name",
            "level",
            "mitre_attack",
            "tags",
            "matched_event",
            "rule_path",
            "match_count",
            "source",
        }
        assert required.issubset(m.keys())

    def test_source_is_sigma(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate(_web_event(path="/evil/path"))
        assert engine.get_matches()[0]["source"] == "sigma"

    def test_mitre_extraction(self, tmp_path):
        rule = """
            title: MITRE Rule
            id: aaaabbbb-0000-0000-0000-000000000050
            tags:
              - attack.initial_access
              - attack.t1190
            detection:
              selection:
                path|contains: /evil
              condition: selection
            level: high
        """
        engine = _make_engine(tmp_path, rule)
        engine.evaluate(_web_event(path="/evil"))
        m = engine.get_matches()[0]
        assert "T1190" in m["mitre_attack"]


# ---------------------------------------------------------------------------
# Benchmark marker (skipped by default in CI — run with pytest -m benchmark)
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
def test_benchmark_not_in_ci(tmp_path):
    """Placeholder: real benchmark lives in task 8.1."""
    pass


# ---------------------------------------------------------------------------
# Task 8.2 — required_fields short-circuit tests
# ---------------------------------------------------------------------------


class TestRequiredFieldsShortCircuit:
    """required_fields is populated and evaluate() skips irrelevant events."""

    def test_required_fields_populated(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        rule = engine.rules[0]
        assert "path" in rule.required_fields

    def test_event_missing_all_fields_skipped(self, tmp_path):
        """Event with no fields this rule cares about should produce no match."""
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate({"host": "myserver", "process": "sshd", "message": "evil"})
        assert engine.get_matches() == []

    def test_event_with_matching_field_still_fires(self, tmp_path):
        engine = _make_engine(tmp_path, SIMPLE_RULE)
        engine.evaluate(_web_event(path="/evil/path"))
        assert len(engine.get_matches()) == 1


# ---------------------------------------------------------------------------
# Task 8.3 — Benchmark (skipped by default; run with pytest -m benchmark)
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
def test_benchmark_100k_events(tmp_path):
    """100k events × builtin rules must complete in under 30s on a laptop."""
    import time

    engine = SigmaEngine(rule_paths=["builtin"], min_level="low")
    events = [_web_event(path=f"/path/{i}", source_ip=f"10.0.{i // 256}.{i % 256}") for i in range(100_000)]

    start = time.time()
    for e in events:
        engine.evaluate(e)
    elapsed = time.time() - start

    assert elapsed < 30, f"Benchmark exceeded 30s: {elapsed:.1f}s"
