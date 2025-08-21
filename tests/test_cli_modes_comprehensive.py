# tests/test_cli_modes_comprehensive.py
"""
Comprehensive tests for cli.py argument parsing and mode dispatching.
"""
import pytest
import sys
from unittest.mock import patch, MagicMock

# We need to import main from cli, but avoid running it directly
# This structure assumes tests are run from the project root
from recon import cli


@pytest.fixture(autouse=True)
def mock_async_main_runners():
    """Mock all main async runner functions from cli.py to prevent actual execution."""
    # Using MagicMock to allow both sync and async calls if needed
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

        # We need to mock asyncio.run to just call the coroutine's close() method
        # to prevent it from actually running the event loop.
        async def dummy_coro_runner(coro):
            # Coroutines created by async functions need to be closed to avoid warnings
            if hasattr(coro, "close"):
                coro.close()
            return None

        with patch("asyncio.run", side_effect=dummy_coro_runner) as mock_run:
            yield {
                "hybrid": mock_hybrid,
                "evolve": mock_evolve,
                "single": mock_single,
                "per_domain": mock_per_domain,
                "profiling": mock_profiling,
            }


def run_cli_with_args(args: list):
    """Helper function to run the cli.main with specific arguments."""
    with patch.object(sys, "argv", ["cli.py"] + args):
        cli.main()


def test_default_mode_is_hybrid(mock_async_main_runners):
    """Test that hybrid mode is called by default with a single target."""
    run_cli_with_args(["example.com"])
    mock_async_main_runners["hybrid"].assert_called_once()
    # Ensure no other mode was called
    for mode, mock_runner in mock_async_main_runners.items():
        if mode != "hybrid":
            mock_runner.assert_not_called()


def test_evolutionary_mode_flag(mock_async_main_runners):
    """Test that --evolve flag correctly calls the evolutionary mode runner."""
    run_cli_with_args(["example.com", "--evolve"])
    mock_async_main_runners["evolve"].assert_called_once()
    mock_async_main_runners["hybrid"].assert_not_called()


def test_single_strategy_mode_flag(mock_async_main_runners):
    """Test that --single-strategy flag calls the single strategy runner."""
    run_cli_with_args(["example.com", "--single-strategy", "--strategy", "test_strat"])
    mock_async_main_runners["single"].assert_called_once()
    mock_async_main_runners["hybrid"].assert_not_called()


def test_per_domain_mode_flag(mock_async_main_runners):
    """Test that --per-domain flag calls the per-domain runner."""
    run_cli_with_args(["example.com", "--per-domain"])
    mock_async_main_runners["per_domain"].assert_called_once()
    mock_async_main_runners["hybrid"].assert_not_called()


def test_profile_pcap_mode_flag(mock_async_main_runners):
    """Test that --profile-pcap flag calls the profiling runner and exits."""
    run_cli_with_args(["--profile-pcap", "test.pcap"])
    mock_async_main_runners["profiling"].assert_called_once()
    # Ensure no other mode was called, as this mode should be exclusive
    for mode, mock_runner in mock_async_main_runners.items():
        if mode != "profiling":
            mock_runner.assert_not_called()


def test_cache_stats_mode_exits(mock_async_main_runners):
    """Test that --cache-stats flag runs and exits without calling main modes."""
    # Mock the AdaptiveLearningCache to prevent file I/O
    with patch("recon.cli.AdaptiveLearningCache") as mock_cache:
        mock_cache.return_value.get_cache_stats.return_value = {
            "total_strategy_records": 10
        }
        run_cli_with_args(["--cache-stats"])

    # Ensure no main execution mode was called
    for mock_runner in mock_async_main_runners.values():
        mock_runner.assert_not_called()


def test_clear_cache_mode_exits(mock_async_main_runners):
    """Test that --clear-cache flag runs and exits without calling main modes."""
    with patch("pathlib.Path.exists", return_value=True), patch(
        "pathlib.Path.unlink"
    ) as mock_unlink:
        run_cli_with_args(["--clear-cache"])
        mock_unlink.assert_called_once()

    # Ensure no main execution mode was called
    for mock_runner in mock_async_main_runners.values():
        mock_runner.assert_not_called()


def test_argument_passing_to_hybrid_mode(mock_async_main_runners):
    """Test that arguments are correctly passed to the hybrid mode runner."""
    run_cli_with_args(
        ["example.com", "--port", "8443", "--count", "50", "--fingerprint", "--debug"]
    )
    mock_hybrid.assert_called_once()
    call_args, _ = mock_hybrid.call_args
    args = call_args[0]

    assert args.target == "example.com"
    assert args.port == 8443
    assert args.count == 50
    assert args.fingerprint is True
    assert args.debug is True


def test_argument_passing_to_evolutionary_mode(mock_async_main_runners):
    """Test that arguments are correctly passed to the evolutionary mode runner."""
    run_cli_with_args(
        [
            "example.com",
            "--evolve",
            "--population",
            "30",
            "--generations",
            "10",
            "--mutation-rate",
            "0.15",
        ]
    )
    mock_evolve.assert_called_once()
    call_args, _ = mock_evolve.call_args
    args = call_args[0]

    assert args.target == "example.com"
    assert args.evolve is True
    assert args.population == 30
    assert args.generations == 10
    assert args.mutation_rate == 0.15


def test_mode_exclusivity(mock_async_main_runners):
    """Test that only one main execution mode is run at a time."""
    # --evolve should take precedence over default hybrid
    run_cli_with_args(["example.com", "--evolve"])
    mock_async_main_runners["evolve"].assert_called_once()
    mock_async_main_runners["hybrid"].assert_not_called()
    mock_async_main_runners["per_domain"].assert_not_called()

    # --per-domain should take precedence
    run_cli_with_args(["example.com", "--per-domain", "--evolve"])
    mock_async_main_runners["per_domain"].assert_called_once()
    mock_async_main_runners["evolve"].assert_not_called()
    mock_async_main_runners["hybrid"].assert_not_called()
