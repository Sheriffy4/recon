import asyncio
import unittest


class TestSegmentAttackCLIAsync(unittest.TestCase):
    def test_maybe_await_returns_value_for_non_coroutine(self):
        from core.cli_payload.segment_attack_cli import SegmentAttackCLI

        cli = SegmentAttackCLI.__new__(SegmentAttackCLI)  # avoid heavy __init__
        out = asyncio.run(cli._maybe_await(123))
        self.assertEqual(out, 123)

    def test_maybe_await_awaits_coroutine(self):
        from core.cli_payload.segment_attack_cli import SegmentAttackCLI

        async def coro():
            return "ok"

        cli = SegmentAttackCLI.__new__(SegmentAttackCLI)  # avoid heavy __init__
        out = asyncio.run(cli._maybe_await(coro()))
        self.assertEqual(out, "ok")
