"""
Test package for DPI strategy implementation.

This package contains comprehensive unit tests, integration tests, and PCAP validation tests
for the DPI strategy fix implementation.
"""

# Test configuration
TEST_CONFIG = {
    "timeout": 30,  # Test timeout in seconds
    "verbose": True,
    "capture_output": True,
    "fail_fast": False,
}

# Test categories
TEST_CATEGORIES = {
    "unit": [
        "test_position_resolver",
        "test_sni_detector",
        "test_checksum_fooler",
        "test_dpi_strategy_engine",
    ],
    "integration": ["test_strategy_integration"],
    "pcap_validation": ["test_pcap_validation"],
}


# Test fixtures and utilities
def get_test_data_path():
    """Get path to test data directory."""
    import os

    return os.path.join(os.path.dirname(__file__), "data")


def create_test_data_dir():
    """Create test data directory if it doesn't exist."""
    import os

    data_dir = get_test_data_path()
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    return data_dir
