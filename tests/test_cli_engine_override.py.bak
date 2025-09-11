import argparse

from core.di.cli_provider import CLIServiceProvider


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
    finally:
        provider.cleanup()