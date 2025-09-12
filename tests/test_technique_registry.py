import unittest
import sys
import os
from typing import Any, Dict, List, Optional, Tuple

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.bypass.techniques.registry import TechniqueRegistry, TechniqueResult, FakeddisorderTechnique

class TestTechniqueRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = TechniqueRegistry()

    def test_default_techniques_registered(self):
        self.assertIsNotNone(self.registry.get_technique("fakeddisorder"))
        self.assertIsNotNone(self.registry.get_technique("multisplit"))
        self.assertIsNotNone(self.registry.get_technique("seqovl"))

        # Test aliases
        self.assertIsNotNone(self.registry.get_technique("disorder"))
        self.assertEqual(self.registry.get_technique("disorder").name, "fakeddisorder")

    def test_list_techniques(self):
        techniques = self.registry.list_techniques()
        self.assertIn("fakeddisorder", techniques)
        self.assertIn("multisplit", techniques)
        self.assertIn("seqovl", techniques)
        self.assertNotIn("disorder", techniques) # Aliases should not be listed

    def test_apply_technique_found(self):
        payload = b"test payload"
        params = {"split_pos": 4, "overlap_size": 2}
        result = self.registry.apply_technique("fakeddisorder", payload, params)

        self.assertIsInstance(result, TechniqueResult)
        self.assertTrue(result.success)
        self.assertIsInstance(result.segments, list)
        self.assertEqual(len(result.segments), 2)

        # Check metadata
        self.assertEqual(result.metadata["split_pos"], 4)

    def test_apply_technique_not_found(self):
        payload = b"test payload"
        params = {}
        result = self.registry.apply_technique("nonexistent", payload, params)
        self.assertIsNone(result)

    def test_fakeddisorder_technique_apply(self):
        technique = FakeddisorderTechnique()
        payload = b"hello world"
        params = {
            "split_pos": 5,
            "overlap_size": 2,
            "fooling": ["badsum", "badseq"],
            "fake_ttl": 3
        }

        result = technique.apply(payload, params)

        self.assertEqual(len(result.segments), 2)

        # First segment (fake part)
        seg1_payload, seg1_rel_off, seg1_opts = result.segments[0]
        self.assertEqual(seg1_payload, b" world")
        self.assertEqual(seg1_rel_off, 5)
        self.assertTrue(seg1_opts["is_fake"])
        self.assertEqual(seg1_opts["ttl"], 3)
        self.assertTrue(seg1_opts["corrupt_tcp_checksum"])
        self.assertTrue(seg1_opts["corrupt_sequence"])

        # Second segment (real part)
        seg2_payload, seg2_rel_off, seg2_opts = result.segments[1]
        self.assertEqual(seg2_payload, b"hello")
        self.assertEqual(seg2_rel_off, 3) # 5 - 2
        self.assertEqual(seg2_opts["tcp_flags"], 0x18)

if __name__ == '__main__':
    unittest.main()
