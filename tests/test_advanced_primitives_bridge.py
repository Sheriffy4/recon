import unittest

from core.bypass.techniques.primitives import BypassTechniques

_HAS_FINAL = True
try:
    from final_packet_bypass import AdvancedBypassTechniques
except Exception:
    _HAS_FINAL = False


@unittest.skipUnless(_HAS_FINAL, "final_packet_bypass not importable (pydivert or env missing)")
class TestAdvancedPrimitivesBridge(unittest.TestCase):
    def test_tlsrec_split_is_inherited(self):
        payload = b"\x16\x03\x01" + (10).to_bytes(2, "big") + b"0123456789"
        res_adv = AdvancedBypassTechniques.apply_tlsrec_split(payload, 5)
        res_prim = BypassTechniques.apply_tlsrec_split(payload, 5)
        self.assertIsInstance(res_adv, bytes)
        self.assertEqual(res_adv, res_prim)

    def test_wssize_limit_is_inherited(self):
        payload = b"abcdefghij"
        res_adv = AdvancedBypassTechniques.apply_wssize_limit(payload, 3)
        res_prim = BypassTechniques.apply_wssize_limit(payload, 3)
        self.assertEqual(res_adv, res_prim)


if __name__ == "__main__":
    unittest.main()