#!/usr/bin/env python3
"""
pytest configuration for recon tests.
Sets up the environment and common fixtures for all tests.
"""

import sys
import os
import pytest
import asyncio
from pathlib import Path

# Add project root to path
tests_dir = Path(__file__).parent
project_root = tests_dir.parent
sys.path.insert(0, str(project_root))

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def project_root_path():
    """Return the project root path."""
    return project_root

@pytest.fixture
def attack_context():
    """Create a basic AttackContext for testing."""
    from core.bypass.attacks.base import AttackContext
    return AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="192.168.1.1",
        src_port=12345,
        domain="example.com",
        payload=b"test data",
        params={},
    )