import unittest

from core.bypass_engine import BypassTechniques as PublicBT
from core.bypass.techniques.primitives import BypassTechniques as PrimitiveBT

class TestPrimitivesUnified(unittest.TestCase):
    def test_fakeddisorder_equivalence(self):
        payload = b"A" * 200
        res_pub = PublicBT.apply_fakeddisorder(payload, 76, 336)
        res_prim = PrimitiveBT.apply_fakeddisorder(payload, 76, 336)
        self.assertEqual(res_pub, res_prim)

    def test_seqovl_equivalence(self):
        payload = b"HELLO" * 20
        res_pub = PublicBT.apply_seqovl(payload, split_pos=10, overlap_size=20)
        res_prim = PrimitiveBT.apply_seqovl(payload, split_pos=10, overlap_size=20)
        self.assertEqual(res_pub, res_prim)

    def test_fooling_methods_exist_and_equal(self):
        # Синтетичный пакет: IPv4 IHL=5 (20 байт IP заголовок) + 20 байт TCP заголовок
        pkt = bytearray(b"\x45" + b"\x00" * 39)
        pkt_pub_badsum = PublicBT.apply_badsum_fooling(pkt.copy())
        pkt_prim_badsum = PrimitiveBT.apply_badsum_fooling(pkt.copy())
        self.assertEqual(pkt_pub_badsum, pkt_prim_badsum)

        pkt_pub_md5sig = PublicBT.apply_md5sig_fooling(pkt.copy())
        pkt_prim_md5sig = PrimitiveBT.apply_md5sig_fooling(pkt.copy())
        self.assertEqual(pkt_pub_md5sig, pkt_prim_md5sig)

if __name__ == "__main__":
    unittest.main()