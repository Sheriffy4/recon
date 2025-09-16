import unittest
from core.bypass.techniques.primitives import BypassTechniques

class TestPrimitives(unittest.TestCase):
    def test_apply_fakeddisorder_no_overlap(self):
        payload = b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'
        split_pos = 10

        segments = BypassTechniques.apply_fakeddisorder(
            payload,
            split_pos=split_pos,
            overlap_size=None,
            segment_order="disorder_first",
            real_delay_ms=5
        )

        self.assertEqual(len(segments), 2)

        # part2, part1
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]

        # Second segment sent first
        self.assertEqual(segments[0][0], part2)
        self.assertEqual(segments[0][1], split_pos) # offset

        # First segment sent second
        self.assertEqual(segments[1][0], part1)
        self.assertEqual(segments[1][1], 0) # offset
        self.assertIn('delay_ms', segments[1][2])
        self.assertEqual(segments[1][2]['delay_ms'], 5)

    def test_apply_fakeddisorder_no_overlap_fake_first(self):
        payload = b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'
        split_pos = 10

        segments = BypassTechniques.apply_fakeddisorder(
            payload,
            split_pos=split_pos,
            overlap_size=None,
            segment_order="fake_first",
            fake_ttl=2,
            fooling_methods=['badsum']
        )

        self.assertEqual(len(segments), 3)

        part1 = payload[:split_pos]
        part2 = payload[split_pos:]

        # Fake segment
        self.assertTrue(segments[0][2]['is_fake'])
        self.assertEqual(segments[0][2]['ttl'], 2)
        self.assertTrue(segments[0][2]['corrupt_tcp_checksum'])

        # Real segments
        self.assertEqual(segments[1][0], part1)
        self.assertEqual(segments[1][1], 0)

        self.assertEqual(segments[2][0], part2)
        self.assertEqual(segments[2][1], split_pos)

if __name__ == '__main__':
    unittest.main()
