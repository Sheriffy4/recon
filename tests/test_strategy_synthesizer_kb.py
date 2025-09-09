import pytest

from core.strategy_synthesizer import StrategySynthesizer, AttackContext

class StubKB:
    def get_recommendations(self, ip: str):
        # KB даёт split_pos/overlap + дополнительные fooling методы
        return {
            "split_pos": 42,
            "overlap": 512,
            "fooling_methods": ["badseq", "fragmix"],
        }

class StubFoolingSelector:
    def get_compatible_methods(self, cdn: str):
        # Совместимые по пути (например, по CDN)
        return ["badsum"]

def test_synthesize_robust_prefers_kb_seed_over_kb_recs():
    synth = StrategySynthesizer()
    # Подменяем внешние зависимости
    synth.kb = StubKB()
    synth.fooling_selector = StubFoolingSelector()

    ctx = AttackContext(
        domain="example.com",
        dst_ip="203.0.113.10",
        port=443,
        tls_clienthello=None,  # пусть auto не сработает
        cdn="fastly",  # не cloudflare/akamai → останемся на fakeddisorder
        kb_profile={
            "best_fakeddisorder": {"split_pos": 77, "overlap_size": 300}
        },
    )

    task = synth.synthesize(ctx, profile="robust")
    assert task["type"] == "fakeddisorder"
    params = task["params"]
    # kb_seed имеет приоритет над kb_recs
    assert params["split_pos"] == 77
    assert params["overlap_size"] == 300
    # fooling = совместимые + из KB (объединение без дублей)
    assert set(params["fooling"]) >= {"badsum", "badseq", "fragmix"}
    # ttl для robust = 2
    assert params["ttl"] == 2

def test_synthesize_speedy_uses_kb_recs_when_no_seed():
    synth = StrategySynthesizer()
    synth.kb = StubKB()
    synth.fooling_selector = StubFoolingSelector()

    ctx = AttackContext(
        domain="example.org",
        dst_ip="198.51.100.22",
        port=443,
        tls_clienthello=None,
        cdn="fastly",  # важно: не cloudflare/akamai, чтобы не ушло в multisplit
        kb_profile=None,
    )

    task = synth.synthesize(ctx, profile="speedy")
    assert task["type"] == "fakeddisorder"
    params = task["params"]
    # split_pos взят из kb_recs
    assert params["split_pos"] == 42
    # overlap взят из kb_recs (переопределяет профиль)
    assert params["overlap_size"] == 512
    # fooling включает KB методы
    assert set(params["fooling"]) >= {"badsum", "badseq", "fragmix"}
    # ttl для speedy = 1
    assert params["ttl"] == 1