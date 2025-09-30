import unittest
from core.bypass.techniques.primitives import BypassTechniques, _gen_fake_sni

class TestBypassTechniques(unittest.TestCase):

    def test_gen_fake_sni(self):
        """Tests the fake SNI generation."""
        sni = _gen_fake_sni()
        self.assertTrue(sni.endswith(".edu"))
        self.assertGreater(len(sni), 8)

    def test_apply_fakeddisorder_correctly_builds_recipe(self):
        """
        Tests if apply_fakeddisorder creates the correct 3-segment recipe
        in the zapret style (fake, part2, part1).
        """
        payload = b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'
        split_pos = 16
        overlap_size = 4
        fake_ttl = 2
        delay_ms = 10
        fooling_methods = ["badsum", "fakesni"]

        segments = BypassTechniques.apply_fakeddisorder(
            payload,
            split_pos=split_pos,
            overlap_size=overlap_size,
            fake_ttl=fake_ttl,
            fooling_methods=fooling_methods,
            delay_ms=delay_ms
        )

        self.assertEqual(len(segments), 3, "Should create exactly 3 segments")

        part1 = payload[:split_pos]
        part2 = payload[split_pos:]

        # 1. Verify Fake Packet
        fake_segment = segments[0]
        self.assertEqual(fake_segment[0], payload, "Fake segment should contain the full payload")
        self.assertEqual(fake_segment[1], 0, "Fake segment offset should be 0")
        fake_opts = fake_segment[2]
        self.assertTrue(fake_opts['is_fake'])
        self.assertEqual(fake_opts['ttl'], fake_ttl)
        self.assertTrue(fake_opts['corrupt_tcp_checksum'])
        self.assertEqual(fake_opts['delay_ms_after'], delay_ms)
        self.assertIn('fooling_sni', fake_opts)

        # 2. Verify Real Packet Part 2 (sent second)
        real_segment_2 = segments[1]
        self.assertEqual(real_segment_2[0], part2, "Second segment should be part2 of the payload")
        expected_offset = split_pos - overlap_size
        self.assertEqual(real_segment_2[1], expected_offset, "Offset of part2 is incorrect")
        self.assertFalse(real_segment_2[2]['is_fake'])
        self.assertEqual(real_segment_2[2]['tcp_flags'], 0x18) # PSH+ACK

        # 3. Verify Real Packet Part 1 (sent third)
        real_segment_1 = segments[2]
        self.assertEqual(real_segment_1[0], part1, "Third segment should be part1 of the payload")
        self.assertEqual(real_segment_1[1], 0, "Offset of part1 should be 0")
        self.assertFalse(real_segment_1[2]['is_fake'])
        self.assertEqual(real_segment_1[2]['tcp_flags'], 0x10) # ACK

    def test_apply_fakeddisorder_edge_case_large_split_pos(self):
        """
        Tests that apply_fakeddisorder returns a single, normal segment
        if the split_pos is out of bounds.
        """
        payload = b'short payload'
        split_pos = 100 # larger than payload

        segments = BypassTechniques.apply_fakeddisorder(payload, split_pos=split_pos)
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0][0], payload)
        self.assertFalse(segments[0][2]['is_fake'])

    def test_apply_fake_packet_race_with_fakesni(self):
        """
        Tests if apply_fake_packet_race correctly adds fakesni option.
        """
        payload = b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'
        fooling = ["badsum", "fakesni"]

        segments = BypassTechniques.apply_fake_packet_race(payload, fooling=fooling)
        self.assertEqual(len(segments), 2)

        fake_opts = segments[0][2]
        self.assertTrue(fake_opts['is_fake'])
        self.assertTrue(fake_opts['corrupt_tcp_checksum'])
        self.assertIn('fooling_sni', fake_opts)
        self.assertIsNotNone(fake_opts['fooling_sni'])

        real_opts = segments[1][2]
        self.assertFalse(real_opts['is_fake'])

if __name__ == '__main__':
    unittest.main()