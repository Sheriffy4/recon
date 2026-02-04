import inspect
import unittest
from typing import Any, Dict, Optional, List, Tuple


def _maybe_import(path: str):
    parts = path.split(".")
    mod_path = ".".join(parts[:-1])
    sym = parts[-1]
    module = __import__(mod_path, fromlist=[sym])
    return getattr(module, sym)


AttackContext = _maybe_import("core.bypass.attacks.base.AttackContext")
AttackResult = _maybe_import("core.bypass.attacks.base.AttackResult")
AttackStatus = _maybe_import("core.bypass.attacks.base.AttackStatus")
BaseAttack = _maybe_import("core.bypass.attacks.base.BaseAttack")

BackwardCompatibilityManager = _maybe_import(
    "core.bypass.attacks.compatibility.backward_compatibility_manager.BackwardCompatibilityManager"
)
DynamicComboAttack = _maybe_import("core.bypass.attacks.combo.dynamic_combo.DynamicComboAttack")
BaselineAttack = _maybe_import("core.bypass.attacks.combo.baseline.BaselineAttack")


def _make_attack_context(**overrides) -> Any:
    """
    Create AttackContext robustly without assuming exact constructor signature.
    """
    base = dict(
        dst_ip="127.0.0.1",
        dst_port=443,
        payload=b"hello",
        connection_id="test-conn",
        protocol="tcp",
        domain="example.com",
        engine_type="native",
        params={},
    )
    base.update(overrides)
    return AttackContext(**base)


def _make_attack_result(**overrides) -> Any:
    """
    Create AttackResult robustly (only provide args that exist in signature).
    """
    # AttackResult in core.bypass.attacks.base has no constructor param "segments":
    # segments are stored via property -> metadata["segments"].
    kwargs: Dict[str, Any] = dict(
        status=overrides.pop("status", AttackStatus.SUCCESS),
        latency_ms=overrides.pop("latency_ms", 0.0),
        packets_sent=overrides.pop("packets_sent", 0),
        bytes_sent=overrides.pop("bytes_sent", 0),
        connection_established=overrides.pop("connection_established", True),
        data_transmitted=overrides.pop("data_transmitted", True),
        technique_used=overrides.pop("technique_used", "test"),
        metadata=overrides.pop("metadata", {}),
    )
    if "error_message" in overrides:
        kwargs["error_message"] = overrides.pop("error_message")
    return AttackResult(**kwargs)


class _MetaSegmentsAttack(BaseAttack):
    """
    Attack that returns segments ONLY inside metadata["segments"] to test normalization.
    """

    @property
    def name(self) -> str:
        return "meta_segments_attack"

    @property
    def category(self) -> str:
        return "custom"

    @property
    def description(self) -> str:
        return "Test attack"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}

    def execute(self, context: Any) -> Any:
        segs = [(b"X", 0, {"delay_ms": 0})]
        # segments intentionally omitted -> only metadata
        return _make_attack_result(
            status=AttackStatus.SUCCESS,
            metadata={"segments": segs},
            technique_used=self.name,
            packets_sent=len(segs),
            bytes_sent=sum(len(s[0]) for s in segs),
        )


class _DummyAttackAdapter:
    """
    Adapter stub for DynamicComboAttack.
    Produces stage results with different segment schema variants.
    """

    async def execute_attack_by_name(self, attack_name: str, context: Any, strategy_params: Any):
        if attack_name == "stage_a":
            segs = [(b"A", 0, {})]
            res = _make_attack_result(
                status=AttackStatus.SUCCESS,
                metadata={"segments": segs},
                technique_used="stage_a",
                packets_sent=len(segs),
                bytes_sent=1,
            )
            # Also set property (redundant, but tests normalization)
            res.segments = segs
            return res
        if attack_name == "stage_b":
            segs = [(b"B", 0, {})]
            # segments in metadata only
            return _make_attack_result(
                status=AttackStatus.SUCCESS,
                metadata={"segments": segs},
                technique_used="stage_b",
                packets_sent=len(segs),
                bytes_sent=1,
            )
        # default failure
        return _make_attack_result(
            status=AttackStatus.ERROR,
            error_message="unknown stage",
            metadata={},
            technique_used=attack_name,
            packets_sent=0,
            bytes_sent=0,
        )


class TestBaselineAttackSegments(unittest.IsolatedAsyncioTestCase):
    async def test_baseline_attack_exposes_segments(self):
        attack = BaselineAttack()
        ctx = _make_attack_context(payload=b"PAYLOAD", engine_type="native", params={})
        res = await attack.execute(ctx)

        segs = res.segments
        self.assertIsNotNone(segs, "BaselineAttack should expose segments in result.segments")
        self.assertIsInstance(segs, list)
        self.assertEqual(len(segs), 1)
        self.assertEqual(segs[0][0], b"PAYLOAD")

        md = res.metadata or {}
        self.assertIn("segments", md, "BaselineAttack should keep legacy metadata['segments']")
        self.assertEqual(md["segments"], segs)

    async def test_baseline_local_engine_omits_segments(self):
        attack = BaselineAttack()
        ctx = _make_attack_context(payload=b"PAYLOAD", engine_type="local", params={})
        res = await attack.execute(ctx)

        # In local mode segments may be intentionally omitted
        self.assertTrue(
            res.segments in (None, []),
            "Local engine mode should omit segments",
        )
        md = res.metadata or {}
        self.assertTrue(md.get("segments", None) in (None, []))


class TestBackwardCompatibilityManagerSegments(unittest.TestCase):
    def test_manager_normalizes_metadata_segments_into_result_segments(self):
        mgr = BackwardCompatibilityManager()
        attack = _MetaSegmentsAttack()
        ctx = _make_attack_context(payload=b"Z", engine_type="native", params={})

        res = mgr.execute_with_fallback(attack, ctx)
        segs = res.segments
        self.assertIsInstance(segs, list)
        self.assertEqual(len(segs), 1)
        self.assertEqual(segs[0][0], b"X")

        # Also keep compatibility alias if present
        segs2 = getattr(res, "_segments", None)
        if segs2 is not None:
            self.assertEqual(segs2, segs)
        md = res.metadata or {}
        self.assertEqual(md.get("segments"), segs)


class TestDynamicComboSegments(unittest.TestCase):
    def test_dynamic_combo_merges_segments_from_multiple_schema_variants(self):
        attack = DynamicComboAttack(attack_adapter=_DummyAttackAdapter())
        ctx = _make_attack_context(payload=b"IGNORED", engine_type="native", params={})

        res = attack.execute(
            ctx,
            stages=[{"name": "stage_a"}, {"name": "stage_b"}],
            execution_mode="sequential",
            stop_on_failure=False,
            propagate_context=False,
        )
        self.assertEqual(getattr(res, "status", None), AttackStatus.SUCCESS)
        segs = res.segments
        self.assertIsInstance(segs, list)
        self.assertEqual([s[0] for s in segs], [b"A", b"B"])


if __name__ == "__main__":
    unittest.main()
