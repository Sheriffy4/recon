import unittest
from unittest.mock import patch, MagicMock

# Add project root to path
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.bypass_engine import BypassEngine

class DummyPacket:
    def __init__(self, payload=b"A"*200):
        self.payload = payload
        self.src_addr = "1.1.1.1"
        self.dst_addr = "2.2.2.2"
        self.src_port = 50000
        self.dst_port = 443
        self.protocol = 6  # TCP
        ip_header = b'\x45\x00\x00\x34\x00\x01\x00\x00\x40\x06\x7c\xb0\x01\x01\x01\x01\x02\x02\x02\x02'
        tcp_header = b'\xc3\x50\x00\x2b\x00\x00\x00\x01\x00\x00\x00\x02\x50\x18\x72\x10\xe5\xd8\x00\x00'
        self.raw = ip_header + tcp_header + self.payload
        self.interface = (0, 0)
        self.direction = 0  # OUTBOUND

class DummyWriter:
    def send(self, pkt):
        pass

class TestEngineRefactoring(unittest.TestCase):
    def test_tlsrec_split_handler_called(self):
        """Verify that the external handler for tlsrec_split is called."""
        be = BypassEngine(debug=False)
        pkt = DummyPacket()
        w = DummyWriter()

        mock_handler = MagicMock(return_value=True)
        # We patch the instance's dictionary directly
        be._exec_handlers['tlsrec_split'] = mock_handler

        task = {"type": "tlsrec_split", "params": {}}
        be.apply_bypass(pkt, w, task)

        mock_handler.assert_called_once_with(be, pkt, w, task['params'], pkt.payload)

    def test_wssize_limit_handler_called(self):
        """Verify that the external handler for wssize_limit is called."""
        be = BypassEngine(debug=False)
        pkt = DummyPacket()
        w = DummyWriter()

        mock_handler = MagicMock(return_value=True)
        # We patch the instance's dictionary directly
        be._exec_handlers['wssize_limit'] = mock_handler

        task = {"type": "wssize_limit", "params": {}}
        be.apply_bypass(pkt, w, task)

        mock_handler.assert_called_once_with(be, pkt, w, task['params'], pkt.payload)
