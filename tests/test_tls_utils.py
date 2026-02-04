import struct
import unittest

from core.bypass.attacks.tls.tls_utils import (
    find_client_hello_extensions_offset,
    fix_single_record_client_hello_lengths,
    is_tls_handshake,
    looks_like_tls_record_at,
)


def _build_client_hello_with_extensions(ext_bytes: bytes) -> bytes:
    body = bytearray()
    body += b"\x03\x03"          # client_version TLS1.2
    body += b"\x11" * 32         # random
    body += b"\x00"              # session_id_len
    body += struct.pack("!H", 2) # cipher_suites_len
    body += b"\x00\x3c"          # TLS_RSA_WITH_AES_128_CBC_SHA256 (example)
    body += b"\x01\x00"          # comp_methods_len=1, null
    body += struct.pack("!H", len(ext_bytes))
    body += ext_bytes

    hs = bytearray()
    hs += b"\x01"                                # HandshakeType ClientHello
    hs += len(body).to_bytes(3, "big")           # handshake length
    hs += body

    rec = bytearray()
    rec += b"\x16\x03\x03"                       # record type handshake, version 1.2
    rec += struct.pack("!H", len(hs))            # record length
    rec += hs
    return bytes(rec)


class TestTLSUtils(unittest.TestCase):
    def test_find_extensions_offset(self):
        ext = b"\x00\x00\x00\x00"  # ext_type=0 len=0
        payload = _build_client_hello_with_extensions(ext)
        self.assertTrue(is_tls_handshake(payload))
        off = find_client_hello_extensions_offset(payload)
        self.assertNotEqual(off, -1)
        # At off should be 2-byte extensions length
        ext_len = struct.unpack("!H", payload[off : off + 2])[0]
        self.assertEqual(ext_len, len(ext))

    def test_fix_lengths_after_extension_insertion(self):
        # Build minimal CH with one empty extension
        ext = b"\x00\x00\x00\x00"
        payload = _build_client_hello_with_extensions(ext)

        off = find_client_hello_extensions_offset(payload)
        old_ext_len = struct.unpack("!H", payload[off : off + 2])[0]
        self.assertEqual(old_ext_len, len(ext))

        # Insert another small extension at the beginning (simulate attack mutation).
        new_ext = b"\x12\x34\x00\x01\xff"  # type=0x1234 len=1 data=0xff
        old_ext_data = payload[off + 2 : off + 2 + old_ext_len]
        mutated = (
            payload[:off]
            + struct.pack("!H", len(new_ext) + len(old_ext_data))
            + new_ext
            + old_ext_data
            + payload[off + 2 + old_ext_len :]
        )

        # Now record length/handshake length are stale and must be patched.
        fixed = fix_single_record_client_hello_lengths(mutated)
        rec_len = struct.unpack("!H", fixed[3:5])[0]
        hs_len = int.from_bytes(fixed[6:9], "big")
        self.assertEqual(rec_len, len(fixed) - 5)
        self.assertEqual(hs_len, rec_len - 4)

    def test_fix_lengths_does_not_expand_multirecord(self):
        # Record1: valid ClientHello
        payload1 = _build_client_hello_with_extensions(b"\x00\x00\x00\x00")
        rec1_len = struct.unpack("!H", payload1[3:5])[0]
        self.assertEqual(5 + rec1_len, len(payload1))

        # Record2: dummy application data record
        rec2_body = b"hello"
        payload2 = b"\x17\x03\x03" + struct.pack("!H", len(rec2_body)) + rec2_body
        combined = payload1 + payload2

        # Sanity: record2 header is at old record end
        self.assertTrue(looks_like_tls_record_at(combined, len(payload1)))

        fixed = fix_single_record_client_hello_lengths(combined)
        # Must not change record1 length to cover record2
        self.assertEqual(struct.unpack("!H", fixed[3:5])[0], rec1_len)


if __name__ == "__main__":
    unittest.main()
