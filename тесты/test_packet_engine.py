import unittest
from core.net.packet_engine import PacketEngine
from core.net.byte_packet import IPv4Packet, TCPPacket, UDPPacket


class TestPacketEngine(unittest.TestCase):
    def setUp(self):
        self.packet_engine = PacketEngine()

    def test_ipv4_packet_roundtrip(self):
        # Create sample IPv4 packet
        original_packet = IPv4Packet(
            src_addr="192.168.1.1",
            dst_addr="10.0.0.1",
            ttl=64,
            protocol=6,
            payload=b"Test payload",
        )

        # Serialize and parse back
        raw_data = original_packet.serialize()
        parsed_packet = self.packet_engine.parse_packet(raw_data)

        # Compare fields
        self.assertEqual(parsed_packet.src_addr, original_packet.src_addr)
        self.assertEqual(parsed_packet.dst_addr, original_packet.dst_addr)
        self.assertEqual(parsed_packet.ttl, original_packet.ttl)
        self.assertEqual(parsed_packet.protocol, original_packet.protocol)
        self.assertEqual(parsed_packet.payload, original_packet.payload)

    def test_tcp_packet_processing(self):
        # Create TCP packet
        tcp = TCPPacket(
            src_port=12345,
            dst_port=443,
            seq_num=1000,
            ack_num=2000,
            flags=0x002,  # SYN flag
            payload=b"Test TCP payload",
        )

        # Create IP packet containing TCP
        ip = IPv4Packet(
            src_addr="192.168.1.1",
            dst_addr="10.0.0.1",
            ttl=64,
            protocol=6,
            payload=tcp.serialize(),
        )

        # Update checksums
        tcp.update_checksum(ip)
        ip.update_checksum()

        # Serialize and parse back
        raw_data = ip.serialize()
        parsed_ip = self.packet_engine.parse_packet(raw_data)

        # Verify IP fields
        self.assertEqual(parsed_ip.src_addr, ip.src_addr)
        self.assertEqual(parsed_ip.dst_addr, ip.dst_addr)
        self.assertEqual(parsed_ip.protocol, ip.protocol)

        # Parse TCP payload
        parsed_tcp = TCPPacket.parse(parsed_ip.payload)

        # Verify TCP fields
        self.assertEqual(parsed_tcp.src_port, tcp.src_port)
        self.assertEqual(parsed_tcp.dst_port, tcp.dst_port)
        self.assertEqual(parsed_tcp.seq_num, tcp.seq_num)
        self.assertEqual(parsed_tcp.ack_num, tcp.ack_num)
        self.assertEqual(parsed_tcp.flags, tcp.flags)
        self.assertEqual(parsed_tcp.payload, tcp.payload)

    def test_udp_packet_processing(self):
        # Create UDP packet
        udp = UDPPacket(src_port=53, dst_port=53, payload=b"DNS query")

        # Create IP packet containing UDP
        ip = IPv4Packet(
            src_addr="192.168.1.1",
            dst_addr="8.8.8.8",
            ttl=64,
            protocol=17,  # UDP
            payload=udp.serialize(),
        )

        # Update checksums
        udp.update_checksum(ip)
        ip.update_checksum()

        # Serialize and parse back
        raw_data = ip.serialize()
        parsed_ip = self.packet_engine.parse_packet(raw_data)

        # Parse UDP payload
        parsed_udp = UDPPacket.parse(parsed_ip.payload)

        # Verify fields
        self.assertEqual(parsed_udp.src_port, udp.src_port)
        self.assertEqual(parsed_udp.dst_port, udp.dst_port)
        self.assertEqual(parsed_udp.payload, udp.payload)

    def test_packet_modifications(self):
        # Create IP+TCP packet for testing
        tcp = TCPPacket(src_port=12345, dst_port=443, payload=b"Original payload")

        ip = IPv4Packet(
            src_addr="192.168.1.1",
            dst_addr="10.0.0.1",
            ttl=64,
            protocol=6,
            payload=tcp.serialize(),
        )

        # Test TTL modification
        modified_ip = self.packet_engine.modify_ttl(ip, 32)
        self.assertEqual(modified_ip.ttl, 32)

        # Test padding
        padded_ip = self.packet_engine.add_padding(ip, 10, random=False)
        self.assertEqual(len(padded_ip.payload), len(ip.payload) + 10)

        # Test obfuscation
        obfuscated_ip = self.packet_engine.obfuscate_payload(ip, method="xor")
        self.assertNotEqual(obfuscated_ip.payload, ip.payload)
        # Double XOR should restore original payload
        restored_ip = self.packet_engine.obfuscate_payload(obfuscated_ip, method="xor")
        self.assertEqual(restored_ip.payload, ip.payload)


if __name__ == "__main__":
    unittest.main()
