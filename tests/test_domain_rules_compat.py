import json
import os
import tempfile
import unittest


class TestDomainRulesSchemaCompat(unittest.TestCase):
    def _write_tmp_json(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path

    def test_strategy_conflict_checker_loads_new_schema(self):
        from core.cli_payload.strategy_conflict_checker import load_domain_rules

        path = self._write_tmp_json(
            {
                "version": "1.0",
                "domain_rules": {
                    "example.com": {"type": "split", "params": {"split_pos": 3}}
                },
            }
        )
        try:
            rules = load_domain_rules(path)
            self.assertIn("example.com", rules)
            self.assertEqual(rules["example.com"]["type"], "split")
        finally:
            os.remove(path)

    def test_strategy_conflict_checker_loads_legacy_schema(self):
        from core.cli_payload.strategy_conflict_checker import load_domain_rules

        path = self._write_tmp_json(
            {
                "example.com": {"type": "split", "params": {"split_pos": 3}},
                "*.example.com": {"type": "disorder", "params": {"split_pos": 2}},
            }
        )
        try:
            rules = load_domain_rules(path)
            self.assertIn("example.com", rules)
            self.assertIn("*.example.com", rules)
        finally:
            os.remove(path)


class TestStrategyDiffToolResolution(unittest.TestCase):
    def _write_tmp_json(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path

    def test_diff_tool_exact_match_new_schema(self):
        from core.cli_payload.strategy_diagnostics import StrategyDiffTool

        path = self._write_tmp_json(
            {
                "version": "1.0",
                "domain_rules": {
                    "example.com": {"type": "split", "params": {"split_pos": 3}}
                },
            }
        )
        try:
            tool = StrategyDiffTool(domain_rules_path=path)
            ok, diffs = tool.compare_strategies(
                "example.com", {"type": "split", "params": {"split_pos": 3}}
            )
            self.assertTrue(ok)
            self.assertEqual(diffs, [])
        finally:
            os.remove(path)

    def test_diff_tool_wildcard_fallback(self):
        from core.cli_payload.strategy_diagnostics import StrategyDiffTool

        path = self._write_tmp_json(
            {
                "domain_rules": {
                    "*.example.com": {"type": "split", "params": {"split_pos": 3}}
                }
            }
        )
        try:
            tool = StrategyDiffTool(domain_rules_path=path)
            ok, diffs = tool.compare_strategies(
                "sub.example.com", {"type": "split", "params": {"split_pos": 3}}
            )
            self.assertTrue(ok)
            self.assertEqual(diffs, [])
        finally:
            os.remove(path)

    def test_diff_tool_parent_fallback(self):
        from core.cli_payload.strategy_diagnostics import StrategyDiffTool

        path = self._write_tmp_json(
            {
                "domain_rules": {
                    "example.com": {"type": "split", "params": {"split_pos": 3}}
                }
            }
        )
        try:
            tool = StrategyDiffTool(domain_rules_path=path)
            ok, diffs = tool.compare_strategies(
                "a.b.example.com", {"type": "split", "params": {"split_pos": 3}}
            )
            self.assertTrue(ok)
            self.assertEqual(diffs, [])
        finally:
            os.remove(path)

    def test_diff_tool_detects_param_mismatch(self):
        from core.cli_payload.strategy_diagnostics import StrategyDiffTool

        path = self._write_tmp_json(
            {
                "domain_rules": {
                    "example.com": {"type": "split", "params": {"split_pos": 3, "ttl": 4}}
                }
            }
        )
        try:
            tool = StrategyDiffTool(domain_rules_path=path)
            ok, diffs = tool.compare_strategies(
                "example.com", {"type": "split", "params": {"split_pos": 2, "ttl": 4}}
            )
            self.assertFalse(ok)
            self.assertTrue(any(d.parameter == "split_pos" for d in diffs))
        finally:
            os.remove(path)
