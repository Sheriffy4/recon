import unittest

from core.bypass.engine.unified_attack_dispatcher import UnifiedAttackDispatcher


class TestUnifiedAttackDispatcherParamAliases(unittest.TestCase):
    def test_split_position_alias(self):
        d = UnifiedAttackDispatcher(config={"enable_metrics": False, "detailed_logging": False})
        payload = b"abcdefghij"
        packet_info = {"original_ttl": 64}

        segs = d._apply_split(payload, {"split_position": 3}, packet_info)
        self.assertEqual(len(segs), 2)
        self.assertEqual(segs[0].data, b"abc")
        self.assertEqual(segs[1].data, b"defghij")
        self.assertEqual(segs[1].offset, 3)


if __name__ == "__main__":
    unittest.main()
