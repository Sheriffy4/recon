import unittest
from core.net.packet_engine import PacketEngine
from core.net.quic_packet import QUICPacket, QUICPacketType, QUICVersion
from core.net.ech import ECHConfig, ECHClientHello, ECHCipherSuite, ECHVersion

class TestQUICAndECH(unittest.TestCase):
    def setUp(self):
        self.packet_engine = PacketEngine()

    def test_quic_initial_packet(self):
        """Test QUIC Initial packet creation and processing"""
        # Create Initial packet
        initial_packet = self.packet_engine.create_quic_packet(
            packet_type=QUICPacketType.INITIAL,
            version=QUICVersion.VERSION_1,
            dcid=b"destination",
            scid=b"source",
            payload=b"Initial crypto data"
        )
        
        # Verify packet fields
        self.assertEqual(initial_packet.header.packet_type, QUICPacketType.INITIAL)
        self.assertEqual(initial_packet.header.version, QUICVersion.VERSION_1)
        self.assertEqual(initial_packet.header.dcid, b"destination")
        self.assertEqual(initial_packet.header.scid, b"source")
        
        # Test serialization/parsing
        raw_data = initial_packet.serialize()
        parsed_packet = self.packet_engine.parse_quic_packet(raw_data)
        
        self.assertIsNotNone(parsed_packet)
        self.assertEqual(parsed_packet.header.packet_type, initial_packet.header.packet_type)
        self.assertEqual(parsed_packet.header.version, initial_packet.header.version)
        self.assertEqual(parsed_packet.payload, initial_packet.payload)

    def test_quic_version_negotiation(self):
        """Test QUIC version negotiation"""
        # Create packet with unsupported version
        initial_packet = self.packet_engine.create_quic_packet(
            packet_type=QUICPacketType.INITIAL,
            version=0xFFFFFFFF,  # Unsupported version
            dcid=b"destination",
            scid=b"source",
            payload=b"Initial crypto data"
        )
        
        # Process packet - should get Version Negotiation in response
        response = self.packet_engine.process_quic_initial(initial_packet)
        
        self.assertEqual(response.header.packet_type, QUICPacketType.VERSION_NEGOTIATION)
        self.assertEqual(response.header.version, QUICVersion.NEGOTIATION)
        # Check that DCID/SCID are swapped
        self.assertEqual(response.header.dcid, initial_packet.header.scid)
        self.assertEqual(response.header.scid, initial_packet.header.dcid)

    def test_ech_config(self):
        """Test ECH configuration creation and processing"""
        # Create ECH config
        config = self.packet_engine.create_ech_config(
            public_name="example.com",
            config_id=1,
            cipher_suites=[
                ECHCipherSuite.AES_128_GCM_SHA256,
                ECHCipherSuite.CHACHA20_POLY1305_SHA256
            ],
            public_key=b"test_public_key",
            maximum_name_length=128
        )
        
        # Verify config fields
        self.assertEqual(config.public_name, "example.com")
        self.assertEqual(config.config_id, 1)
        self.assertEqual(len(config.cipher_suites), 2)
        self.assertEqual(config.public_key, b"test_public_key")
        
        # Test serialization/parsing
        raw_config = config.serialize()
        parsed_config = ECHConfig.parse(raw_config)
        
        self.assertEqual(parsed_config.public_name, config.public_name)
        self.assertEqual(parsed_config.config_id, config.config_id)
        self.assertEqual(parsed_config.cipher_suites, config.cipher_suites)

    def test_ech_client_hello(self):
        """Test ECH ClientHello creation"""
        # Create ECH config first
        config = self.packet_engine.create_ech_config(
            public_name="example.com",
            config_id=1,
            cipher_suites=[ECHCipherSuite.AES_128_GCM_SHA256]
        )
        
        # Create ClientHello
        inner_ch = b"Inner ClientHello data"
        client_hello = self.packet_engine.create_ech_client_hello(
            config=config,
            inner_ch=inner_ch,
            cipher_suite=ECHCipherSuite.AES_128_GCM_SHA256
        )
        
        # Verify ClientHello fields
        self.assertEqual(client_hello.config_id, config.config_id)
        self.assertEqual(client_hello.cipher_suite, ECHCipherSuite.AES_128_GCM_SHA256)
        
        # Test serialization/parsing
        raw_ch = client_hello.serialize()
        parsed_ch = ECHClientHello.parse(raw_ch)
        
        self.assertEqual(parsed_ch.config_id, client_hello.config_id)
        self.assertEqual(parsed_ch.cipher_suite, client_hello.cipher_suite)

if __name__ == '__main__':
    unittest.main()
