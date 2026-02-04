import pytest


@pytest.mark.asyncio
async def test_closed_loop_manager_exits_early_when_baseline_success():
    """
    Smoke/regression:
    If baseline access is OK, ClosedLoopManager should return early and MUST NOT
    call fingerprinting / bypass planning pipeline.
    """
    from core.integration.closed_loop_manager import ClosedLoopManager

    class BaselineResult:
        def __init__(self, success: bool, latency_ms: float = 12.0):
            self.success = success
            self.latency_ms = latency_ms

    class DummyEffectivenessTester:
        async def test_baseline(self, domain: str, port: int):
            return BaselineResult(success=True, latency_ms=10.0)

        async def test_with_bypass(self, domain: str, port: int, attack_result):
            raise AssertionError("Should not be called when baseline succeeds")

    class DummyFingerprintEngine:
        async def create_comprehensive_fingerprint_with_extended_metrics(self, *args, **kwargs):
            raise AssertionError("Fingerprinting should not be called when baseline succeeds")

        async def analyze_dpi_behavior(self, *args, **kwargs):
            raise AssertionError("Behavior analysis should not be called when baseline succeeds")

        async def refine_fingerprint(self, *args, **kwargs):
            raise AssertionError("Refinement should not be called when baseline succeeds")

    class DummyStrategyGenerator:
        def generate_strategies(self, *args, **kwargs):
            raise AssertionError("Strategy generation should not be called when baseline succeeds")

        def generate_strategies_with_failure_analysis(self, *args, **kwargs):
            raise AssertionError("Strategy generation should not be called when baseline succeeds")

    class DummyLearningMemory:
        async def load_learning_history(self, *args, **kwargs):
            raise AssertionError("Learning history should not be loaded when baseline succeeds")

        async def save_learning_result(self, *args, **kwargs):
            raise AssertionError("Learning should not be updated when baseline succeeds")

        async def store_behavioral_insights(self, *args, **kwargs):
            raise AssertionError("Behavioral insights should not be stored when baseline succeeds")

        async def store_strategic_insights(self, *args, **kwargs):
            raise AssertionError("Strategic insights should not be stored when baseline succeeds")

        def generate_fingerprint_hash(self, fp_dict):
            return "hash"

    class DummyAttackAdapter:
        async def execute_attack(self, *args, **kwargs):
            raise AssertionError("Attack execution should not be called when baseline succeeds")

    class DummyStrategySaver:
        async def save_strategy(self, *args, **kwargs):
            return None

    mgr = ClosedLoopManager(
        fingerprint_engine=DummyFingerprintEngine(),
        strategy_generator=DummyStrategyGenerator(),
        effectiveness_tester=DummyEffectivenessTester(),
        learning_memory=DummyLearningMemory(),
        attack_adapter=DummyAttackAdapter(),
        strategy_saver=DummyStrategySaver(),
    )

    res = await mgr.run_closed_loop("example.com", 443, max_iterations=3)
    assert res.domain == "example.com"
    assert res.total_iterations == 0
    assert res.convergence_achieved is True
    assert res.final_effectiveness == 1.0
    assert res.best_strategy is None
    assert any("baseline access is OK" in s for s in res.analysis_summary)
