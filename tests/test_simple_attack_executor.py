import unittest
from unittest.mock import MagicMock
from core.bypass.attacks.simple_attack_executor import SimpleAttackExecutor
from core.bypass.attacks.base import AttackContext, AttackStatus


class TestSimpleAttackExecutor(unittest.TestCase):
    def setUp(self):
        self.executor = SimpleAttackExecutor()
        self.executor.logger = MagicMock()

    def test_execute_fake_split(self):
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
            params={"split_pos": 10, "overlap_size": 5, "ttl": 123, "fooling": ["badsum"]},
        )
        result = self.executor.execute_attack("fake_split", context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "fake_split")
        self.assertEqual(len(result.segments), 3)
        self.assertEqual(result.packets_sent, 3)

        # Fake packet
        fake_payload, rel_off, opts = result.segments[0]
        self.assertEqual(fake_payload, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(rel_off, 0)
        self.assertTrue(opts["is_fake"])
        self.assertEqual(opts["ttl"], 123)
        self.assertTrue(opts["corrupt_tcp_checksum"])

        # Part 2
        p2_payload, rel_off, opts = result.segments[1]
        self.assertEqual(p2_payload, context.payload[10:])
        self.assertEqual(rel_off, 10)

        # Part 1
        p1_payload, rel_off, opts = result.segments[2]
        self.assertEqual(p1_payload, context.payload[:10])
        self.assertEqual(rel_off, 5)

    def test_execute_disorder(self):
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
            params={"split_pos": 4, "ttl": 64, "fooling": ["md5sig"]},
        )
        result = self.executor.execute_attack("disorder", context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "disorder")
        self.assertEqual(len(result.segments), 2)
        self.assertEqual(result.packets_sent, 2)

        # Part 2
        p2_payload, rel_off, opts = result.segments[0]
        self.assertEqual(p2_payload, context.payload[4:])
        self.assertEqual(rel_off, 4)

        # Part 1
        p1_payload, rel_off, opts = result.segments[1]
        self.assertEqual(p1_payload, context.payload[:4])
        self.assertEqual(rel_off, 0)
        self.assertEqual(opts["ttl"], 64)
        self.assertTrue(opts["add_md5sig_option"])

    def test_execute_fake(self):
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
            params={"ttl": 42, "fooling": ["badseq"]},
        )
        result = self.executor.execute_attack("fake", context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "fake")
        self.assertEqual(len(result.segments), 2)
        self.assertEqual(result.packets_sent, 2)

        # Fake packet
        fake_payload, rel_off, opts = result.segments[0]
        self.assertEqual(fake_payload, b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
        self.assertEqual(rel_off, 0)
        self.assertTrue(opts["is_fake"])
        self.assertEqual(opts["ttl"], 42)
        self.assertTrue(opts["corrupt_sequence"])

        # Original payload
        orig_payload, rel_off, opts = result.segments[1]
        self.assertEqual(orig_payload, context.payload)
        self.assertEqual(rel_off, 0)

    def test_execute_generic(self):
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"some data",
        )
        result = self.executor.execute_attack("some_other_attack", context)

        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertEqual(result.technique_used, "some_other_attack")
        self.assertEqual(len(result.segments), 1)
        self.assertEqual(result.packets_sent, 1)

        payload, rel_off, opts = result.segments[0]
        self.assertEqual(payload, context.payload)
        self.assertEqual(rel_off, 0)


if __name__ == "__main__":
    unittest.main()
