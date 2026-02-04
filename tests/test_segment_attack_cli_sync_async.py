#!/usr/bin/env python3
"""
Test _run_coroutine_sync method in SegmentAttackCLI.

Verifies that coroutines can be safely executed from synchronous contexts,
including when there's already a running event loop.
"""

import unittest
import asyncio
from core.cli_payload.segment_attack_cli import SegmentAttackCLI


class TestSegmentAttackCLISyncAsync(unittest.TestCase):
    """Test synchronous execution of coroutines in CLI."""

    def test_run_coroutine_sync_with_coroutine(self):
        """Test that _run_coroutine_sync executes a coroutine and returns result."""
        cli = SegmentAttackCLI()

        async def sample_coro():
            await asyncio.sleep(0.01)
            return "coroutine_result"

        result = cli._run_coroutine_sync(sample_coro())
        self.assertEqual(result, "coroutine_result")

    def test_run_coroutine_sync_with_non_coroutine(self):
        """Test that _run_coroutine_sync returns non-coroutine values as-is."""
        cli = SegmentAttackCLI()

        result = cli._run_coroutine_sync("plain_value")
        self.assertEqual(result, "plain_value")

        result = cli._run_coroutine_sync(42)
        self.assertEqual(result, 42)

    def test_run_coroutine_sync_with_exception(self):
        """Test that _run_coroutine_sync propagates exceptions from coroutines."""
        cli = SegmentAttackCLI()

        async def failing_coro():
            await asyncio.sleep(0.01)
            raise ValueError("test_error")

        with self.assertRaises(ValueError) as ctx:
            cli._run_coroutine_sync(failing_coro())

        self.assertIn("test_error", str(ctx.exception))

    def test_run_coroutine_sync_from_async_context(self):
        """Test that _run_coroutine_sync works when called from async context."""
        cli = SegmentAttackCLI()

        async def inner_coro():
            await asyncio.sleep(0.01)
            return "inner_result"

        async def outer_async():
            # This simulates calling validate_attack (sync) from an async context
            # where validate_attack internally calls _run_coroutine_sync
            result = cli._run_coroutine_sync(inner_coro())
            return result

        # Run the outer async function
        result = asyncio.run(outer_async())
        self.assertEqual(result, "inner_result")


if __name__ == "__main__":
    unittest.main()
