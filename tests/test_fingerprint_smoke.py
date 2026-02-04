import pytest
from datetime import datetime, timedelta


def test_timestamped_cache_find_by_prefix_does_not_crash_on_expired_delete():
    from core.fingerprint.cache_utils import TimestampedCache

    c = TimestampedCache(max_size=10, ttl=timedelta(seconds=1))
    c.set("example.com_1.1.1.1", {"ok": True})
    # force expiration by manipulating internal timestamp (smoke regression test)
    value, ts = c._cache["example.com_1.1.1.1"]
    c._cache["example.com_1.1.1.1"] = (value, datetime.now() - timedelta(seconds=5))

    assert c.find_by_prefix("example.com") is None
    assert "example.com_1.1.1.1" not in c._cache


@pytest.mark.asyncio
async def test_collect_ech_metrics_can_be_called_inside_running_loop(monkeypatch):
    from core.fingerprint.metrics_collector import ExtendedMetricsCollector

    class DummyECHDetector:
        def __init__(self, dns_timeout: float = 1.2):
            self.dns_timeout = dns_timeout

        async def detect_ech_dns(self, domain: str):
            return {"ech_present": True, "alpn": ["h2"], "records": {"dummy": True}}

        async def probe_quic(self, domain: str):
            return {"success": True, "rtt_ms": 12.3}

        async def detect_ech_blockage(self, domain: str):
            return {"ech_blocked": False}

        async def probe_http3(self, domain: str):
            return {"supported": True}

    monkeypatch.setattr("core.fingerprint.metrics_collector.ECHDetector", DummyECHDetector)

    collector = ExtendedMetricsCollector()
    # sync method called from async context must not crash
    metrics = collector.collect_ech_metrics("example.com")
    assert metrics["ech_present"] is True
    assert metrics["quic_support"] is True
    assert metrics["http3_support"] is True


@pytest.mark.asyncio
async def test_ultimate_engine_create_fingerprint_smoke_and_cache(monkeypatch):
    try:
        from core.fingerprint.advanced_fingerprint_engine import UltimateAdvancedFingerprintEngine
        from core.fingerprint.models import EnhancedFingerprint
    except Exception as e:
        pytest.skip(f"Required modules not available: {e}")

    class DummyProber:
        # intentionally does NOT accept force_all to validate kwargs filtering
        async def run_probes(self, domain: str, preliminary_type=None):
            return {"rst_ttl": 42}

    class DummySigClassification:
        dpi_type = "SigDPI"

    class DummyClassification:
        dpi_type = "FinalDPI"
        confidence = 0.75

    class DummyClassifier:
        def _signature_classify(self, fp):
            return DummySigClassification()

        def classify(self, fp):
            return DummyClassification()

    class DummyAttackAdapter:
        def get_available_attacks(self, *args, **kwargs):
            return []

        def get_attack_info(self, *args, **kwargs):
            return {}

    engine = UltimateAdvancedFingerprintEngine(
        prober=DummyProber(),
        classifier=DummyClassifier(),
        attack_adapter=DummyAttackAdapter(),
        debug=True,
        ml_enabled=False,
    )

    # Patch ML predictor to avoid hard dependency on EnhancedFingerprint fields in this smoke test
    class DummyML:
        def extract_ml_features(self, fp):
            return {"dummy": 1.0}

        def is_model_ready(self):
            return False

        def predict_weaknesses(self, fp):
            return ["w"]

        def predict_best_attacks(self, fp):
            return []

    engine.ml_predictor = DummyML()
    engine.ml_enabled = False

    fp1 = await engine.create_comprehensive_fingerprint("example.com", target_ips=["1.1.1.1"])
    assert isinstance(fp1, EnhancedFingerprint)
    assert fp1.domain == "example.com"
    assert fp1.dpi_type == "FinalDPI"
    assert getattr(fp1, "ml_confidence", None) == 0.75

    # second call must hit cache
    fp2 = await engine.create_comprehensive_fingerprint("example.com", target_ips=["1.1.1.1"])
    assert fp2 is fp1
    stats = engine.get_stats()
    assert stats["cache_hits"] >= 1
