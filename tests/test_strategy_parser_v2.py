import pytest


def test_strategy_parser_v2_zapret_seqovl_creates_overlap_size_alias():
    """
    Zapret uses --dpi-desync-split-seqovl, but internal logic/validators may rely on overlap_size.
    Parser must provide overlap_size when split_seqovl is present.
    """
    from core.strategy_parser_v2 import StrategyParserV2

    s = (
        "--dpi-desync=fakeddisorder "
        "--dpi-desync-split-seqovl=336 "
        "--dpi-desync-split-pos=76 "
        "--dpi-desync-fooling=md5sig,badsum "
        "--dpi-desync-repeats=1"
    )

    parsed = StrategyParserV2().parse(s)
    assert parsed.attack_type == "fakeddisorder"
    assert parsed.params["split_seqovl"] == 336
    assert parsed.params["overlap_size"] == 336
    assert parsed.params["split_pos"] == 76
    assert parsed.params["fooling"] == ["md5sig", "badsum"]


def test_strategy_parser_v2_rejects_ttl_and_autottl_together():
    """
    ttl and autottl are mutually exclusive and should be rejected early.
    """
    from core.strategy_parser_v2 import StrategyParserV2

    s = (
        "--dpi-desync=fake "
        "--dpi-desync-ttl=4 "
        "--dpi-desync-autottl=2"
    )

    with pytest.raises(ValueError):
        StrategyParserV2().parse(s)


def test_strategy_parser_v2_injects_repeats_default():
    """
    Parser sets repeats default=1 to keep downstream behavior stable.
    """
    from core.strategy_parser_v2 import StrategyParserV2

    s = "--dpi-desync=fake --dpi-desync-ttl=4"
    parsed = StrategyParserV2().parse(s)
    assert parsed.params.get("repeats") == 1
