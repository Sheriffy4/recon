import pytest
from core.bypass.techniques.registry import TechniqueRegistry, FakeddisorderTechnique, TechniqueResult
from core.bypass.exceptions import TechniqueNotFoundError

class TestTechniqueRegistry:

    def setup_method(self):
        self.registry = TechniqueRegistry()

    def test_default_techniques_registered(self):
        assert self.registry.get_technique("fakeddisorder") is not None
        assert self.registry.get_technique("multisplit") is not None
        assert self.registry.get_technique("seqovl") is not None
        # Test aliases
        assert self.registry.get_technique("disorder") is not None
        assert self.registry.get_technique("disorder").__name__ == "apply_fakeddisorder"

    def test_list_techniques(self):
        techniques = self.registry.list_techniques()
        assert "fakeddisorder" in techniques
        assert "multisplit" in techniques
        assert "seqovl" in techniques
        assert "disorder" not in techniques  # Aliases should not be listed

    def test_apply_technique_found(self):
        payload = b"test payload"
        params = {"split_pos": 4, "overlap_size": 2, "fooling_methods": [], "fake_ttl": 1}
        result = self.registry.apply_technique("fakeddisorder", payload, params)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_apply_technique_not_found(self):
        payload = b"test payload"
        params = {}
        with pytest.raises(TechniqueNotFoundError):
            self.registry.apply_technique("nonexistent", payload, params)

    def test_fakeddisorder_technique_apply(self):
        payload = b"hello world"
        params = {
            "split_pos": 5,
            "overlap_size": 2,
            "fooling_methods": ["badsum", "badseq"],
            "fake_ttl": 3
        }
        params["segment_order"] = "real_first"
        result = FakeddisorderTechnique(payload, **params)
        assert len(result) == 2
        # Correct order: real then fake
        real_seg, fake_seg = result
        assert real_seg[0] == b" world"
        assert real_seg[1] == 5
        assert fake_seg[0] == b"hello"
        assert fake_seg[1] == 3
        assert fake_seg[2]["is_fake"] is True
        assert fake_seg[2]["ttl"] == 3
        assert fake_seg[2]["corrupt_tcp_checksum"] is True
        assert fake_seg[2]["corrupt_sequence"] is True
        assert real_seg[2]["is_fake"] is False
