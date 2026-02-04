"""
Connection Testing Utilities

Provides reusable connection testing functions for DPI fingerprinting.
Extracted from AdvancedFingerprinter to eliminate code duplication.

Requirements: 1.1, 3.1
"""

import asyncio
import logging
from typing import Optional


async def test_payload_size(
    target: str,
    port: int,
    size: int,
    timeout: float = 2.0,
    logger: Optional[logging.Logger] = None,
) -> bool:
    """
    Test if specific payload size works for a connection.

    Args:
        target: Target hostname or IP
        port: Target port
        size: Payload size in bytes to test
        timeout: Connection timeout in seconds
        logger: Optional logger for debugging

    Returns:
        True if connection with payload size succeeds, False otherwise

    Example:
        # Test if 1460 byte payload works
        success = await test_payload_size("example.com", 443, 1460)
    """
    logger = logger or logging.getLogger(__name__)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )

        # Send test payload
        writer.write(b"X" * size)
        await writer.drain()

        writer.close()
        await writer.wait_closed()
        return True

    except asyncio.TimeoutError:
        logger.debug(f"Payload size test timeout for {target}:{port} with size {size}")
        return False
    except ConnectionError as e:
        logger.debug(f"Connection error for {target}:{port} with size {size}: {e}")
        return False
    except Exception as e:
        logger.debug(f"Payload size test failed for {target}:{port}: {e}")
        return False


async def test_connection_with_reordering(
    target: str,
    port: int,
    timeout: float = 2.0,
    logger: Optional[logging.Logger] = None,
) -> bool:
    """
    Test connection with reordered packets.

    Note: This is a simplified implementation. Full implementation would
    reorder TCP segments at different distances to test DPI tolerance.

    Args:
        target: Target hostname or IP
        port: Target port
        timeout: Connection timeout in seconds
        logger: Optional logger for debugging

    Returns:
        True if connection succeeds, False otherwise

    Example:
        success = await test_connection_with_reordering("example.com", 443)
    """
    logger = logger or logging.getLogger(__name__)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True

    except asyncio.TimeoutError:
        logger.debug(f"Reordering test timeout for {target}:{port}")
        return False
    except ConnectionError as e:
        logger.debug(f"Connection error for {target}:{port}: {e}")
        return False
    except Exception as e:
        logger.debug(f"Reordering test failed for {target}:{port}: {e}")
        return False


async def test_fragmented_connection(
    target: str,
    port: int,
    fragment_size: int,
    timeout: float = 2.0,
    logger: Optional[logging.Logger] = None,
) -> bool:
    """
    Test connection with fragmented packets.

    Note: This is a simplified implementation. Full implementation would
    fragment packets at IP layer to test DPI reassembly capabilities.

    Args:
        target: Target hostname or IP
        port: Target port
        fragment_size: Fragment size in bytes
        timeout: Connection timeout in seconds
        logger: Optional logger for debugging

    Returns:
        True if connection with fragmentation succeeds, False otherwise

    Example:
        success = await test_fragmented_connection("example.com", 443, 64)
    """
    logger = logger or logging.getLogger(__name__)

    try:
        # Simplified - actual implementation would fragment packets
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True

    except asyncio.TimeoutError:
        logger.debug(f"Fragmentation test timeout for {target}:{port} with size {fragment_size}")
        return False
    except ConnectionError as e:
        logger.debug(f"Connection error for {target}:{port}: {e}")
        return False
    except Exception as e:
        logger.debug(f"Fragmentation test failed for {target}:{port}: {e}")
        return False


async def test_basic_connectivity(
    target: str,
    port: int,
    timeout: float = 2.0,
    logger: Optional[logging.Logger] = None,
) -> bool:
    """
    Test basic TCP connectivity to target.

    Args:
        target: Target hostname or IP
        port: Target port
        timeout: Connection timeout in seconds
        logger: Optional logger for debugging

    Returns:
        True if connection succeeds, False otherwise

    Example:
        success = await test_basic_connectivity("example.com", 443)
    """
    logger = logger or logging.getLogger(__name__)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True

    except asyncio.TimeoutError:
        logger.debug(f"Connectivity test timeout for {target}:{port}")
        return False
    except ConnectionError as e:
        logger.debug(f"Connection error for {target}:{port}: {e}")
        return False
    except Exception as e:
        logger.debug(f"Connectivity test failed for {target}:{port}: {e}")
        return False


async def test_connection_with_delay(
    target: str,
    port: int,
    delay: float,
    timeout: float = 5.0,
    logger: Optional[logging.Logger] = None,
) -> bool:
    """
    Test connection with artificial delay before sending data.

    Useful for testing timing-sensitive DPI systems.

    Args:
        target: Target hostname or IP
        port: Target port
        delay: Delay in seconds before sending data
        timeout: Connection timeout in seconds
        logger: Optional logger for debugging

    Returns:
        True if connection with delay succeeds, False otherwise

    Example:
        success = await test_connection_with_delay("example.com", 443, 0.5)
    """
    logger = logger or logging.getLogger(__name__)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )

        # Wait before sending data
        await asyncio.sleep(delay)

        # Send minimal data
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        await writer.drain()

        writer.close()
        await writer.wait_closed()
        return True

    except asyncio.TimeoutError:
        logger.debug(f"Delayed connection test timeout for {target}:{port}")
        return False
    except ConnectionError as e:
        logger.debug(f"Connection error for {target}:{port}: {e}")
        return False
    except Exception as e:
        logger.debug(f"Delayed connection test failed for {target}:{port}: {e}")
        return False


async def test_multiple_payload_sizes(
    target: str,
    port: int,
    sizes: list[int],
    timeout: float = 2.0,
    logger: Optional[logging.Logger] = None,
) -> dict[int, bool]:
    """
    Test multiple payload sizes concurrently.

    Args:
        target: Target hostname or IP
        port: Target port
        sizes: List of payload sizes to test
        timeout: Connection timeout in seconds per test
        logger: Optional logger for debugging

    Returns:
        Dictionary mapping payload size to success status

    Example:
        results = await test_multiple_payload_sizes(
            "example.com", 443, [64, 256, 512, 1024, 1460]
        )
        # results = {64: True, 256: True, 512: True, 1024: False, 1460: False}
    """
    logger = logger or logging.getLogger(__name__)

    tasks = [test_payload_size(target, port, size, timeout, logger) for size in sizes]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    return {
        size: result if not isinstance(result, Exception) else False
        for size, result in zip(sizes, results)
    }


async def find_max_payload_size(
    target: str,
    port: int,
    min_size: int = 64,
    max_size: int = 9000,
    step: int = 256,
    timeout: float = 2.0,
    logger: Optional[logging.Logger] = None,
) -> Optional[int]:
    """
    Find maximum working payload size using binary search.

    Args:
        target: Target hostname or IP
        port: Target port
        min_size: Minimum payload size to test
        max_size: Maximum payload size to test
        step: Step size for initial scan
        timeout: Connection timeout in seconds per test
        logger: Optional logger for debugging

    Returns:
        Maximum working payload size, or None if all tests fail

    Example:
        max_size = await find_max_payload_size("example.com", 443)
        # max_size = 1460
    """
    logger = logger or logging.getLogger(__name__)

    # Test sizes from min to max with step
    test_sizes = list(range(min_size, max_size + 1, step))

    # Find the last working size
    last_working = None
    for size in test_sizes:
        if await test_payload_size(target, port, size, timeout, logger):
            last_working = size
        else:
            break

    return last_working
