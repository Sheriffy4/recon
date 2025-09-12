import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.bypass.techniques.registry import TechniqueRegistry

class TestTechniqueRegistry(unittest.TestCase):

    def setUp(self):
        # The registry is a singleton, but we can create a new instance for testing
        self.registry = TechniqueRegistry()
        # We need to register some techniques for testing
        # This is a bit of a hack, but it's the only way to test the registry
        # without depending on the full application context.
        from core.bypass.techniques.primitives import BypassTechniques

        @self.registry.register("fakeddisorder")
        def apply_fakeddisorder(payload, params):
            return BypassTechniques.apply_fakeddisorder(payload, **params)

        @self.registry.register("multisplit")
        def apply_multisplit(payload, params):
            return BypassTechniques.apply_multisplit(payload, **params)

        @self.registry.register("seqovl")
        def apply_seqovl(payload, params):
            return BypassTechniques.apply_seqovl(payload, **params)


    def test_default_techniques_registered(self):
        self.assertIsNotNone(self.registry.get_technique("fakeddisorder"))
        self.assertIsNotNone(self.registry.get_technique("multisplit"))
        self.assertIsNotNone(self.registry.get_technique("seqovl"))

    def test_apply_technique_found(self):
        payload = b"test payload"
        params = {"split_pos": 4, "overlap_size": 2, "fake_ttl": 1, "fooling_methods": []}
        result = self.registry.apply_technique("fakeddisorder", payload, params)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)

    def test_apply_technique_not_found(self):
        payload = b"test payload"
        params = {}
        with self.assertRaises(Exception):
            self.registry.apply_technique("nonexistent", payload, params)

if __name__ == '__main__':
    unittest.main()
