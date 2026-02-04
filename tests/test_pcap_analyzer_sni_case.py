import unittest


class TestPCAPAnalyzerSniCase(unittest.TestCase):
    def test_find_client_hello_domain_case_insensitive(self):
        from core.cli_payload import strategy_diagnostics as sd

        if not getattr(sd, "SCAPY_AVAILABLE", False):
            self.skipTest("scapy not available")

        from scapy.all import IP, TCP, Raw  # type: ignore

        analyzer = sd.PCAPStrategyAnalyzer()

        # Minimal payload that matches analyzer heuristics:
        # payload[0]==0x16 and payload[1]==0x03 plus domain bytes somewhere.
        domain = "example.com"
        mixed_case = "ExAmPlE.CoM"
        payload = b"\x16\x03\x01\x00\x00" + mixed_case.encode("ascii")

        pkt = IP(src="1.1.1.1", dst="2.2.2.2", ttl=64) / TCP(sport=12345, dport=443, seq=1) / Raw(load=payload)
        pkt.time = 1.0  # scapy uses pkt.time in analyzer

        results = analyzer._find_client_hello_packets([pkt], domain)  # pylint: disable=protected-access
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["payload_len"], len(payload))
