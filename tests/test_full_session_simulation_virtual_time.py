import asyncio
import unittest

from core.bypass.attacks.combo.full_session_simulation import FullSessionSimulationAttack
from core.bypass.attacks.base import AttackContext, AttackStatus


class TestFullSessionSimulationVirtualTime(unittest.TestCase):
    def test_exec_is_fast_by_default(self):
        attack = FullSessionSimulationAttack()
        ctx = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            domain="example.com",
            payload=b"{}",
            params={"simulate_keep_alive": False, "simulate_teardown": False},
            debug=True,
        )

        async def run():
            return await attack.execute(ctx)

        result = asyncio.run(run())
        self.assertEqual(result.status, AttackStatus.SUCCESS)
        self.assertIsInstance(result.metadata, dict)
        # Should provide engine-friendly segments
        self.assertIn("segments", result.metadata)
        self.assertTrue(isinstance(result.metadata["segments"], list))


if __name__ == "__main__":
    unittest.main()
