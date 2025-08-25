import unittest
import asyncio

from core.bypass.attacks.base import AttackContext, AttackStatus
from core.bypass.attacks.http.header_attacks import HTTPHeaderAttack
from core.bypass.attacks.dns.demo_dns_attacks import DNSAAttack
from core.bypass.attacks.tcp.fooling import TCPRstAttack

class TestAsyncAttacks(unittest.TestCase):

    def test_http_header_attack_async(self):
        """Tests that the HTTPHeaderAttack runs asynchronously."""
        async def run_test():
            attack = HTTPHeaderAttack()
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=80,
                src_ip="192.168.1.1",
                src_port=12345,
                domain="example.com",
                payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                params={},
            )
            result = await attack.execute(context)
            self.assertIn(result.status, [AttackStatus.SUCCESS, AttackStatus.ERROR])

        asyncio.run(run_test())

    def test_dns_a_attack_async(self):
        """Tests that the DNSAAttack runs asynchronously."""
        async def run_test():
            attack = DNSAAttack()
            context = AttackContext(
                dst_ip="8.8.8.8",
                dst_port=53,
                src_ip="192.168.1.1",
                src_port=12345,
                domain="example.com",
                payload=b"dummy dns query",
                params={},
            )
            result = await attack.execute(context)
            self.assertIn(result.status, [AttackStatus.SUCCESS, AttackStatus.ERROR])

        asyncio.run(run_test())

    def test_tcp_rst_attack_async(self):
        """Tests that the TCPRstAttack runs asynchronously."""
        async def run_test():
            attack = TCPRstAttack()
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=443,
                src_ip="192.168.1.1",
                src_port=12345,
                domain="example.com",
                payload=b"some tcp data",
                params={},
            )
            result = await attack.execute(context)
            self.assertIn(result.status, [AttackStatus.SUCCESS, AttackStatus.ERROR])

        asyncio.run(run_test())

if __name__ == '__main__':
    unittest.main()
