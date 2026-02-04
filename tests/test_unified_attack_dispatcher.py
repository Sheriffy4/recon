import unittest


class TestUnifiedAttackDispatcher(unittest.TestCase):
    def test_multisplit_clamps_to_payload_len_and_no_empty_segments(self):
        from core.bypass.engine.unified_attack_dispatcher import UnifiedAttackDispatcher

        d = UnifiedAttackDispatcher()
        payload = b"abcdef"
        segs = d._apply_multisplit(payload, split_count=100, packet_info={})

        self.assertLessEqual(len(segs), len(payload))
        self.assertEqual(sum(len(s.data) for s in segs), len(payload))
        self.assertTrue(all(len(s.data) > 0 for s in segs))

    def test_split_count_string_is_handled(self):
        from core.bypass.engine.unified_attack_dispatcher import UnifiedAttackDispatcher

        d = UnifiedAttackDispatcher()
        payload = b"abcdef"
        segs = d._apply_split(payload, params={"split_count": "100"}, packet_info={})
        self.assertLessEqual(len(segs), len(payload))
        self.assertEqual(sum(len(s.data) for s in segs), len(payload))
        self.assertTrue(all(len(s.data) > 0 for s in segs))


if __name__ == "__main__":
    unittest.main()
