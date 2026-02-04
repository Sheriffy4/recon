import unittest
import struct


import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import core.bypass.attacks.tls.tls_evasion as tls_evasion


def _minimal_client_hello() -> bytes:
    """
    Minimal single-record TLS 1.2 ClientHello with empty extensions.
    Record:
      type(22) ver(0303) len(47)
    Handshake:
      type(1) len(43)
      body:
        client_version(0303)
        random(32)
        session_id_len(0)
        cipher_suites_len(2) cipher(1301)
        comp_methods_len(1) comp(0)
        extensions_len(0)
    """
    body = b"\x03\x03" + (b"\x11" * 32)
    body += b"\x00"
    body += struct.pack("!H", 2) + b"\x13\x01"
    body += b"\x01\x00"
    body += struct.pack("!H", 0)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    return record


class TestTLSEvasionHelpers(unittest.TestCase):
    def test_find_extensions_offset(self):
        payload = _minimal_client_hello()
        off = tls_evasion._find_extensions_offset_client_hello(payload)
        self.assertNotEqual(off, -1)
        ext_len = struct.unpack("!H", payload[off : off + 2])[0]
        self.assertEqual(ext_len, 0)

    def test_recalculate_lengths_after_extension_insertion(self):
        payload = _minimal_client_hello()
        off = tls_evasion._find_extensions_offset_client_hello(payload)
        self.assertNotEqual(off, -1)

        ext = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"  # supported_groups: [x25519]

        # Insert ext bytes after extensions_len field, but do not fix record/hs lengths yet.
        new_payload = payload[:off] + struct.pack("!H", len(ext)) + ext + payload[off + 2 :]
        # Sanity: lengths should now be inconsistent vs actual
        old_record_len = struct.unpack("!H", new_payload[3:5])[0]
        self.assertNotEqual(old_record_len, len(new_payload) - 5)

        fixed = tls_evasion._recalculate_tls_handshake_lengths(new_payload)
        record_len = struct.unpack("!H", fixed[3:5])[0]
        hs_len = int.from_bytes(fixed[6:9], "big")

        self.assertEqual(record_len, len(fixed) - 5)
        self.assertEqual(hs_len, len(fixed) - 9)


if __name__ == "__main__":
    unittest.main()
