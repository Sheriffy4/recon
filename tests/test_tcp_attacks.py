import unittest
import asyncio
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.bypass.attacks.tcp.manipulation import TCPFragmentationAttack, TCPWindowManipulationAttack, TCPSequenceNumberManipulationAttack, TCPOptionsModificationAttack, TCPWindowScalingAttack, UrgentPointerAttack, TCPOptionsPaddingAttack, TCPMultiSplitAttack, TCPTimestampAttack, TCPWindowSizeLimitAttack

class TestTCPManipulationAttacks(unittest.TestCase):

    def setUp(self):
        self.payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=80, payload=self.payload, params={}, engine_type='local')

    def test_tcp_fragmentation_attack(self):
        attack = TCPFragmentationAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('fragments_count', result.metadata)
        self.assertGreater(result.metadata['fragments_count'], 1)

    def test_tcp_window_manipulation_attack(self):
        attack = TCPWindowManipulationAttack()
        self.context.params = {'manipulation_type': 'small'}
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('manipulation_type', result.metadata)
        self.assertEqual(result.metadata['manipulation_type'], 'small')

    def test_tcp_sequence_number_manipulation_attack(self):
        attack = TCPSequenceNumberManipulationAttack()
        self.context.params = {'manipulation_type': 'gap'}
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('manipulation_type', result.metadata)
        self.assertEqual(result.metadata['manipulation_type'], 'gap')

    def test_tcp_options_modification_attack(self):
        attack = TCPOptionsModificationAttack()
        self.context.params = {'modification_type': 'add_sack_perm'}
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('modification_type', result.metadata)
        self.assertEqual(result.metadata['modification_type'], 'add_sack_perm')

    def test_tcp_window_scaling_attack(self):
        attack = TCPWindowScalingAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('window_scale', result.metadata)

    def test_urgent_pointer_attack(self):
        attack = UrgentPointerAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('urgent_data_size', result.metadata)

    def test_tcp_options_padding_attack(self):
        attack = TCPOptionsPaddingAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('padding_size', result.metadata)

    def test_tcp_multisplit_attack(self):
        attack = TCPMultiSplitAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('split_count', result.metadata)

    def test_tcp_timestamp_attack(self):
        attack = TCPTimestampAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('timestamp1', result.metadata)

    def test_tcp_window_size_limit_attack(self):
        attack = TCPWindowSizeLimitAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('window_size', result.metadata)
from core.bypass.attacks.tcp.timing import DripFeedAttack, TimingBasedEvasionAttack, BurstTimingEvasionAttack

class TestTCPTimingAttacks(unittest.TestCase):

    def setUp(self):
        self.payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=80, payload=self.payload, params={}, engine_type='local')

    def test_drip_feed_attack(self):
        attack = DripFeedAttack()
        result = asyncio.run(attack.execute(self.context))
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('drip_chunk_size', result.metadata)

    def test_timing_based_evasion_attack(self):
        attack = TimingBasedEvasionAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('delay_ms', result.metadata)

    def test_burst_timing_evasion_attack(self):
        attack = BurstTimingEvasionAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('burst_size', result.metadata)
if __name__ == '__main__':
    unittest.main()
from core.bypass.attacks.tcp.fooling import BadSumFoolingAttack, MD5SigFoolingAttack, BadSeqFoolingAttack, TTLManipulationAttack

class TestTCPFoolingAttacks(unittest.TestCase):

    def setUp(self):
        self.payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=80, payload=self.payload, params={}, engine_type='local')

    def test_bad_sum_fooling_attack(self):
        attack = BadSumFoolingAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('checksum_corruption', result.metadata)

    def test_md5sig_fooling_attack(self):
        attack = MD5SigFoolingAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('fooling_method', result.metadata)

    def test_bad_seq_fooling_attack(self):
        attack = BadSeqFoolingAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('sequence_corruption', result.metadata)

    def test_ttl_manipulation_attack(self):
        attack = TTLManipulationAttack()
        result = attack.execute(self.context)
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIn('manipulation_type', result.metadata)
        self.assertEqual(result.metadata['manipulation_type'], 'ttl')