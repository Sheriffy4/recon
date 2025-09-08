import unittest
import sys
import os

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.strategy_interpreter import interpret_strategy

class TestStrategyInterpreter(unittest.TestCase):

    def test_simple_fake_disorder(self):
        strategy_str = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=2"
        parsed = interpret_strategy(strategy_str)
        self.assertEqual(parsed['type'], 'fakedisorder')
        self.assertEqual(parsed['params']['split_pos'], 3)
        self.assertEqual(parsed['params']['ttl'], 2)

    def test_multisplit(self):
        strategy_str = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20"
        parsed = interpret_strategy(strategy_str)
        self.assertEqual(parsed['type'], 'multisplit')
        self.assertEqual(parsed['params']['split_count'], 5)
        self.assertEqual(parsed['params']['split_seqovl'], 20)

    def test_race_attack(self):
        strategy_str = "--dpi-desync=fake --dpi-desync-fooling=badsum"
        parsed = interpret_strategy(strategy_str)
        self.assertEqual(parsed['type'], 'badsum_race')
        self.assertIn('badsum', parsed['params']['fooling'])

    def test_ip_fragmentation(self):
        strategy_str = "--dpi-desync=ipfrag2 --dpi-desync-split-pos=8"
        parsed = interpret_strategy(strategy_str)
        self.assertEqual(parsed['type'], 'ip_fragmentation')
        self.assertEqual(parsed['params']['fragment_size'], 8)

    def test_combined_strategy(self):
        strategy_str = "--filter-udp=443 --dpi-desync=fake,disorder --dpi-desync-ttl=5"
        parsed = interpret_strategy(strategy_str)
        self.assertEqual(parsed['type'], 'fakedisorder')
        self.assertEqual(parsed['params']['ttl'], 5)
        self.assertTrue(parsed['params']['filter_udp_443'])

if __name__ == '__main__':
    unittest.main()
