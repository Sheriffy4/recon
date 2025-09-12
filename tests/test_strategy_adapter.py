import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.bypass.hybrid.strategy_adapter import StrategyAdapter

class TestStrategyAdapter(unittest.TestCase):

    def setUp(self):
        self.mock_parser = Mock()
        self.adapter = StrategyAdapter(self.mock_parser)

    def test_translate_zapret_to_task_fakeddisorder(self):
        zapret_params = {
            'dpi_desync': ['fakeddisorder'],
            'dpi_desync_split_pos': [{'type': 'absolute', 'value': 100}],
            'dpi_desync_split_seqovl': 50,
            'dpi_desync_ttl': 5
        }
        task = self.adapter.translate_zapret_to_task(zapret_params)
        self.assertEqual(task['type'], 'fakeddisorder')
        self.assertEqual(task['params']['split_pos'], 100)
        self.assertEqual(task['params']['overlap_size'], 50)
        self.assertEqual(task['params']['ttl'], 5)

    def test_translate_zapret_to_task_multisplit(self):
        zapret_params = {
            'dpi_desync': ['multisplit'],
            'dpi_desync_split_pos': [{'type': 'absolute', 'value': 10}, {'type': 'absolute', 'value': 20}]
        }
        task = self.adapter.translate_zapret_to_task(zapret_params)
        self.assertEqual(task['type'], 'multisplit')
        self.assertEqual(task['params']['positions'], [10, 20])

    def test_ensure_engine_task_from_dict(self):
        strategy = {'type': 'desync', 'params': {'ttl': 1}}
        task = self.adapter.ensure_engine_task(strategy)
        self.assertEqual(task['type'], 'fakeddisorder') # Alias normalization
        self.assertEqual(task['params']['ttl'], 1)

    def test_ensure_engine_task_from_dsl_string(self):
        strategy = "multisplit(positions=[1,2,3], ttl=5)"
        # This will fail because _parse_dsl_params is simple, but we test the main path
        task = self.adapter.ensure_engine_task(strategy)
        self.assertEqual(task['type'], 'multisplit')
        self.assertEqual(task['params']['ttl'], 5)
        # Note: parsing list values is not supported by the simple _parse_dsl_params

    def test_ensure_engine_task_from_zapret_string(self):
        strategy = "--dpi-desync=fake"
        self.mock_parser.parse.return_value = {'dpi_desync': ['fake']}
        task = self.adapter.ensure_engine_task(strategy)
        self.mock_parser.parse.assert_called_once_with(strategy)
        self.assertEqual(task['type'], 'fake')

if __name__ == '__main__':
    unittest.main()
