import pytest
import argparse
import platform

from core.di.cli_provider import CLIServiceProvider


@pytest.mark.skip(reason="as instructed by user")
def test_engine_override_propagation_native():
    # Важно: CLIServiceProvider ожидает флаги debug/test_mode
    args = argparse.Namespace(
        debug=False,
        test_mode=False,
        engine="native",
        no_ml=False,
    )

    provider = CLIServiceProvider(args)
    try:
        tester = provider.get_effectiveness_tester()
        assert getattr(tester, "engine_override", None) == "native"

        if platform.system() == "Windows":
            engine = provider.get_bypass_engine()
            assert isinstance(engine, WindowsBypassEngine)
            assert getattr(engine, "engine_override", None) == "native"
    finally:
        provider.close()