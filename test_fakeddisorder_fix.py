import unittest
from core.strategy_interpreter import interpret_strategy
from core.bypass.techniques.primitives import BypassTechniques

class TestFakeddisorderFix(unittest.TestCase):
    def test_fakeddisorder_end_to_end(self):
        """
        Validates that the fixed interpreter and primitive for fakeddisorder work together correctly.
        """
        # 1. Define a complex zapret-style strategy string for fakeddisorder
        strategy_str = (
            "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 "
            "--dpi-desync-fooling=badsum,fakesni --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
        )

        # 2. Use the main interpret_strategy function to parse it
        # This should dispatch to the FixedStrategyInterpreter
        engine_task = interpret_strategy(strategy_str)

        self.assertIsNotNone(engine_task, "Strategy interpretation failed")
        self.assertEqual(engine_task.get('_parser_used'), 'fixed', "The fixed parser was not used")
        self.assertEqual(engine_task['type'], 'fakeddisorder', "Attack type should be fakeddisorder")

        params = engine_task['params']
        self.assertEqual(params['split_pos'], 76)
        self.assertEqual(params['overlap_size'], 336)
        self.assertEqual(params['ttl'], 1)
        self.assertIn('badsum', params['fooling'])
        self.assertIn('fakesni', params['fooling'])

        # 3. Create a sample payload
        # A payload longer than split_pos to ensure splitting happens
        sample_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n" + b"A" * 100

        # 4. Apply the fakeddisorder primitive with the parsed parameters
        recipe = BypassTechniques.apply_fakeddisorder(
            payload=sample_payload,
            split_pos=params['split_pos'],
            overlap_size=params['overlap_size'],
            fake_ttl=params['ttl'],
            fooling_methods=params['fooling']
        )

        # 5. Assert the generated recipe is correct
        self.assertEqual(len(recipe), 3, "Fakeddisorder should generate a 3-packet recipe")

        # Unpack the recipe for easier validation
        (p_fake, offset_fake, opts_fake), (p_real2, offset_real2, opts_real2), (p_real1, offset_real1, opts_real1) = recipe

        # --- Validate Fake Packet (sent first) ---
        self.assertEqual(p_fake, sample_payload, "Fake packet should contain the full payload")
        self.assertTrue(opts_fake['is_fake'])
        self.assertEqual(opts_fake['ttl'], 1, "Fake packet TTL should be 1")
        self.assertTrue(opts_fake['corrupt_tcp_checksum'], "Checksum should be corrupted for badsum")
        self.assertIn('fooling_sni', opts_fake, "fakesni option should be present")

        # --- Validate Real Packet Part 2 (sent second) ---
        expected_part2 = sample_payload[76:]
        self.assertEqual(p_real2, expected_part2, "Second real packet has incorrect payload")
        self.assertFalse(opts_real2['is_fake'])
        expected_offset2 = 76 - 336
        self.assertEqual(offset_real2, expected_offset2, "Second real packet has incorrect offset")

        # --- Validate Real Packet Part 1 (sent third) ---
        expected_part1 = sample_payload[:76]
        self.assertEqual(p_real1, expected_part1, "First real packet has incorrect payload")
        self.assertFalse(opts_real1['is_fake'])
        self.assertEqual(offset_real1, 0, "First real packet should have zero offset")

if __name__ == '__main__':
    unittest.main()