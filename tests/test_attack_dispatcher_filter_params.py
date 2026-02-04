import unittest
from types import SimpleNamespace


class _FakeRegistry:
    def __init__(self):
        self.attacks = {
            name: SimpleNamespace(priority=SimpleNamespace(name="NORMAL", value=1))
            for name in (
                "fake",
                "seqovl",
                "split",
                "multisplit",
                "disorder",
                "multidisorder",
                "ttl",
                "passthrough",
            )
        }

    def list_attacks(self, category=None, enabled_only=True):
        return list(self.attacks.keys())

    def get_attack_handler(self, name):
        # Only canonical attacks exist, recipe/dynamic names return None
        return (lambda ctx: []) if name in self.attacks else None

    def get_canonical_name(self, name):
        return name


class TestAttackDispatcherFilterParams(unittest.TestCase):
    def test_filter_params_keeps_important_keys_for_fake_recipe(self):
        from core.bypass.engine.attack_dispatcher import AttackDispatcher, DispatcherConfig
        from core.bypass.engine.recipe_resolver import RecipeResolver

        d = AttackDispatcher.__new__(AttackDispatcher)  # bypass __init__
        d.registry = _FakeRegistry()
        d.config = DispatcherConfig()
        d.recipe_resolver = RecipeResolver(registry=d.registry)

        all_params = {
            "ttl": 3,
            "fake_ttl": 3,
            "split_pos": 5,
            "split_count": 8,
            "overlap_size": 20,
            "fooling": ["badsum"],
            "forced": True,
            "no_fallbacks": True,
            "domain": "example.com",
        }

        out = d._filter_params_for_attack("fake_www_example_com_spl5", all_params)
        self.assertIn("ttl", out)
        self.assertIn("split_pos", out)
        self.assertIn("fooling", out)
        self.assertNotIn("overlap_size", out)  # not a fake param

    def test_filter_params_recipe_marker_is_mapped(self):
        from core.bypass.engine.attack_dispatcher import AttackDispatcher, DispatcherConfig
        from core.bypass.engine.recipe_resolver import RecipeResolver

        d = AttackDispatcher.__new__(AttackDispatcher)
        d.registry = _FakeRegistry()
        d.config = DispatcherConfig()
        d.recipe_resolver = RecipeResolver(registry=d.registry)

        # Mock _normalize_attack_type to avoid AttackNotFoundError
        d._normalize_attack_type = lambda name: name.lower()

        all_params = {"ttl": 3, "split_pos": 5, "domain": "example.com"}
        out = d._filter_params_for_attack("__RECIPE__fake_www_example_com_spl5", all_params)
        self.assertIn("ttl", out)
        self.assertIn("split_pos", out)

    def test_filter_params_keeps_seqovl_overlap_for_seqovl_recipe(self):
        from core.bypass.engine.attack_dispatcher import AttackDispatcher, DispatcherConfig
        from core.bypass.engine.recipe_resolver import RecipeResolver

        d = AttackDispatcher.__new__(AttackDispatcher)
        d.registry = _FakeRegistry()
        d.config = DispatcherConfig()
        d.recipe_resolver = RecipeResolver(registry=d.registry)

        all_params = {"split_pos": 5, "overlap_size": 20, "fake_ttl": 3, "domain": "example.com"}
        out = d._filter_params_for_attack("seqovl_www_example_com_spl5", all_params)
        self.assertIn("overlap_size", out)
        self.assertIn("split_pos", out)
        self.assertIn("fake_ttl", out)


if __name__ == "__main__":
    unittest.main()
