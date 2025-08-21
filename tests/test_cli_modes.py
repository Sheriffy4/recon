# tests/test_cli_modes.py
import pytest
import sys
from unittest.mock import patch, MagicMock

# We need to import main from cli, but avoid running it directly
from recon import cli


@pytest.fixture(autouse=True)
def mock_async_main_runners():
    """Mock all main async runner functions from cli.py."""
    with patch(
        "recon.cli.run_hybrid_mode", new_callable=MagicMock
    ) as mock_hybrid, patch(
        "recon.cli.run_evolutionary_mode", new_callable=MagicMock
    ) as mock_evolve, patch(
        "recon.cli.run_single_strategy_mode", new_callable=MagicMock
    ) as mock_single, patch(
        "recon.cli.run_per_domain_mode", new_callable=MagicMock
    ) as mock_per_domain, patch(
        "recon.cli.run_profiling_mode", new_callable=MagicMock
    ) as mock_profiling:

        # We need to mock asyncio.run to just call the function
        with patch("asyncio.run", side_effect=lambda coro: coro.close()) as mock_run:
            yield {
                "hybrid": mock_hybrid,
                "evolve": mock_evolve,
                "single": mock_single,
                "per_domain": mock_per_domain,
                "profiling": mock_profiling,
            }


def test_default_hybrid_mode(mock_async_main_runners):
    """Test that hybrid mode is called by default."""
    sys.argv = ["cli.py", "test.com"]
    cli.main()
    mock_async_main_runners["hybrid"].assert_called_once()
    mock_async_main_runners["evolve"].assert_not_called()


def test_evolutionary_mode(mock_async_main_runners):
    """Test that --evolve flag calls the correct function."""
    sys.argv = ["cli.py", "test.com", "--evolve"]
    cli.main()
    mock_async_main_runners["evolve"].assert_called_once()
    mock_async_main_runners["hybrid"].assert_not_called()


def test_single_strategy_mode(mock_async_main_runners):
    """Test that --single-strategy flag calls the correct function."""
    sys.argv = ["cli.py", "test.com", "--single-strategy", "--strategy", "test_strat"]
    cli.main()
    mock_async_main_runners["single"].assert_called_once()
    mock_async_main_runners["hybrid"].assert_not_called()


def test_per_domain_mode(mock_async_main_runners):
    """Test that --per-domain flag calls the correct function."""
    sys.argv = ["cli.py", "test.com", "--per-domain"]
    cli.main()
    mock_async_main_runners["per_domain"].assert_called_once()
    mock_async_main_runners["hybrid"].assert_not_called()


def test_profile_pcap_mode(mock_async_main_runners):
    """Test that --profile-pcap flag calls the correct function and exits."""
    sys.argv = ["cli.py", "--profile-pcap", "test.pcap"]
    cli.main()
    mock_async_main_runners["profiling"].assert_called_once()
    mock_async_main_runners[
        "hybrid"
    ].assert_not_called()  # Ensure other modes are not run
