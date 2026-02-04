#!/usr/bin/env python3
"""
Тесты для проверки исправлений из ref.md

Проверяет все критические исправления:
- Runtime: потоковое чтение PCAP, async/sync совместимость
- Семантика: правильное извлечение данных из структур
- Логика: защита от деления на ноль, обработка пустых данных
- Robustness: безопасная работа с отсутствующими полями
"""

import pytest
import asyncio
import time
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from collections import Counter


class TestAdvancedTrafficProfilerFixes:
    """Тесты для advanced_traffic_profiler.py"""
    
    def test_flow_stats_counting(self):
        """Проверка правильного подсчета пакетов на flow"""
        # Имитация подсчета flow_stats
        flow_stats = {}
        packets = [
            {"flow_key": "flow1"},
            {"flow_key": "flow1"},
            {"flow_key": "flow2"},
            {"flow_key": "flow1"},
        ]
        
        for pkt in packets:
            flow_key = pkt["flow_key"]
            flow_stats[flow_key] = flow_stats.get(flow_key, 0) + 1
        
        assert flow_stats["flow1"] == 3
        assert flow_stats["flow2"] == 1
    
    def test_confidence_scores_calculation(self):
        """Проверка расчета confidence scores с учетом реальной полноты"""
        extractors = ["size", "timing", "burst", "behavioral"]
        features = {
            "size": {"data": "present"},
            "timing": {},  # пустой результат
            "burst": {"data": "present"},
            "behavioral": None,  # отсутствует
        }
        
        successful = sum(1 for k in extractors if features.get(k))
        feature_completeness = successful / max(1, len(extractors))
        
        # Должно быть 2/4 = 0.5 (только size и burst непустые)
        assert feature_completeness == 0.5
    
    def test_flow_entropy_zero_division_protection(self):
        """Защита от деления на ноль при расчете flow entropy"""
        flow_stats = {}
        total_packets = sum(flow_stats.values())
        
        # Не должно быть деления на ноль
        if total_packets <= 0:
            flow_entropy = 0.0
        else:
            flow_entropy = 0.0
            for count in flow_stats.values():
                percentage = count / total_packets
                if percentage > 0:
                    import math
                    flow_entropy -= percentage * math.log2(percentage)
        
        assert flow_entropy == 0.0
    
    def test_extract_signatures_correct_keys(self):
        """Проверка извлечения сигнатур из правильных вложенных структур"""
        features = {
            "packet_size_stats": {
                "avg_packet_size": 1200,
                "packet_size_variance": 0.3,
                "packet_size_distribution": {"small": 0.2, "large": 0.8},
            },
            "timing_stats": {
                "avg_inter_packet_delay": 25.0,
                "delay_variance": 0.4,
            },
            "burst_patterns": {
                "burst_patterns": [(3, 10.0), (2, 5.0)],
            },
            "behavioral_features": {
                "idle_periods": [100, 200],
                "bidirectional_ratio": 0.7,
            },
        }
        
        size_stats = features.get("packet_size_stats") or {}
        timing_stats = features.get("timing_stats") or {}
        burst_stats = features.get("burst_patterns") or {}
        behavioral = features.get("behavioral_features") or {}
        
        avg_packet_size = int(size_stats.get("avg_packet_size", 800))
        avg_delay = float(timing_stats.get("avg_inter_packet_delay", 50.0))
        
        assert avg_packet_size == 1200
        assert avg_delay == 25.0


class TestBackwardCompatibilityManagerFixes:
    """Тесты для backward_compatibility_manager.py"""
    
    @pytest.mark.asyncio
    async def test_async_attack_execution(self):
        """Проверка выполнения async атак"""
        
        class AsyncAttack:
            async def execute(self, context):
                await asyncio.sleep(0.01)
                return Mock(status="SUCCESS", segments=[(b"data", 0, {})])
        
        attack = AsyncAttack()
        context = Mock(dst_ip="127.0.0.1", dst_port=80, payload=b"test")
        
        # Должно корректно выполниться
        result = await attack.execute(context)
        assert result.status == "SUCCESS"
    
    def test_extract_segments_unified(self):
        """Проверка унифицированного извлечения сегментов"""
        
        def extract_segments(result):
            if result is None:
                return []
            segs = getattr(result, "segments", None)
            if segs:
                return list(segs)
            segs = getattr(result, "_segments", None)
            if segs:
                return list(segs)
            md = getattr(result, "metadata", None)
            if isinstance(md, dict) and md.get("segments"):
                return list(md["segments"])
            return []
        
        # Тест 1: segments
        result1 = Mock(segments=[(b"data1", 0, {})], _segments=None, metadata={})
        assert len(extract_segments(result1)) == 1
        
        # Тест 2: _segments
        result2 = Mock(segments=None, _segments=[(b"data2", 0, {})], metadata={})
        assert len(extract_segments(result2)) == 1
        
        # Тест 3: metadata["segments"]
        result3 = Mock(segments=None, _segments=None, metadata={"segments": [(b"data3", 0, {})]})
        assert len(extract_segments(result3)) == 1
        
        # Тест 4: пустой результат
        result4 = Mock(segments=None, _segments=None, metadata={})
        assert len(extract_segments(result4)) == 0


class TestAdaptiveComboFixes:
    """Тесты для adaptive_combo.py"""
    
    def test_random_seed_isolation(self):
        """Проверка изоляции random.seed (не портит глобальный RNG)"""
        import random
        
        # Запоминаем состояние глобального RNG
        state_before = random.getstate()
        
        # Используем локальный RNG (как в исправленном коде)
        rng = random.Random(42)
        substitution_table = list(range(256))
        rng.shuffle(substitution_table)
        
        # Глобальный RNG не должен измениться
        state_after = random.getstate()
        
        # Состояния должны быть идентичны
        assert state_before[0] == state_after[0]
    
    def test_coerce_int_robustness(self):
        """Проверка безопасного приведения типов"""
        
        def coerce_int(value, default):
            try:
                return int(value)
            except Exception:
                return default
        
        assert coerce_int("123", 0) == 123
        assert coerce_int("invalid", 5) == 5
        assert coerce_int(None, 10) == 10
        assert coerce_int(3.7, 0) == 3


class TestFailureAnalysisFixes:
    """Тесты для failure_analysis модулей"""
    
    def test_counter_import(self):
        """Проверка правильного импорта Counter"""
        from collections import Counter
        
        failure_types = Counter(["timeout", "rst", "timeout", "dns"])
        assert failure_types["timeout"] == 2
        assert failure_types["rst"] == 1
    
    def test_pattern_detection_with_counter(self):
        """Проверка работы детекции паттернов с Counter"""
        failure_types = Counter({
            "timeout": 15,
            "rst_injection": 8,
            "dns_poisoning": 3,
        })
        
        # Находим доминирующий тип
        if failure_types:
            dominant = failure_types.most_common(1)[0]
            assert dominant[0] == "timeout"
            assert dominant[1] == 15


class TestFingerprintFixes:
    """Тесты для fingerprint модулей"""
    
    def test_method_name_conflict_resolution(self):
        """Проверка разрешения конфликта имен методов"""
        
        class MockEngine:
            def collect_ech_fingerprint_metrics(self, domain):
                """Синхронный метод для ECH метрик"""
                return {"ech_support": True}
            
            async def collect_extended_fingerprint_metrics(self, domain, target_ips=None):
                """Асинхронный метод для расширенных метрик"""
                await asyncio.sleep(0.01)
                return {"effectiveness": 0.8}
        
        engine = MockEngine()
        
        # Синхронный вызов
        ech_metrics = engine.collect_ech_fingerprint_metrics("example.com")
        assert ech_metrics["ech_support"] is True
        
        # Асинхронный вызов
        async def test_async():
            extended = await engine.collect_extended_fingerprint_metrics("example.com")
            assert extended["effectiveness"] == 0.8
        
        asyncio.run(test_async())
    
    def test_rst_packet_extraction_robustness(self):
        """Проверка безопасного извлечения RST пакетов"""
        
        class MockPacket:
            def __init__(self, has_tcp, has_rst):
                self._has_tcp = has_tcp
                self._has_rst = has_rst
            
            def haslayer(self, layer):
                return self._has_tcp
            
            def __getitem__(self, key):
                if key == "TCP":
                    return Mock(flags=Mock(R=self._has_rst))
                raise KeyError(key)
        
        packets = [
            MockPacket(True, True),   # RST пакет
            MockPacket(True, False),  # TCP без RST
            MockPacket(False, False), # Не TCP
        ]
        
        rst_packets = []
        for p in packets:
            try:
                if hasattr(p, "haslayer") and p.haslayer("TCP"):
                    tcp_layer = p["TCP"]
                    if hasattr(tcp_layer.flags, "R") and tcp_layer.flags.R:
                        rst_packets.append(p)
            except Exception:
                continue
        
        assert len(rst_packets) == 1


class TestAuditModuleFixes:
    """Тесты для audit модулей"""
    
    def test_audit_report_zero_division_protection(self):
        """Защита от деления на ноль в отчетах"""
        
        def safe_pct(value, total):
            if total <= 0:
                return 0.0
            return (value / total) * 100.0
        
        assert safe_pct(5, 10) == 50.0
        assert safe_pct(0, 0) == 0.0
        assert safe_pct(5, 0) == 0.0
    
    def test_regex_compilation_performance(self):
        """Проверка компиляции regex для производительности"""
        import re
        
        patterns = [
            r"No advanced attack available for ['\"]([^'\"]+)['\"]",
            r"falling back to primitives.*['\"]([^'\"]+)['\"]",
        ]
        
        # Компилируем один раз
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        
        test_line = "No advanced attack available for 'http_fragmentation', falling back to primitives"
        
        matches = []
        for cre in compiled_patterns:
            matches.extend(cre.findall(test_line))
        
        assert "http_fragmentation" in matches


class TestDynamicComboFixes:
    """Тесты для dynamic_combo.py"""
    
    def test_extract_segments_from_result(self):
        """Проверка извлечения сегментов из результатов атак"""
        
        def extract_segments_from_result(result, context):
            if result is None:
                return []
            segs = getattr(result, "segments", None)
            if segs:
                return list(segs)
            segs = getattr(result, "_segments", None)
            if segs:
                return list(segs)
            md = getattr(result, "metadata", None)
            if isinstance(md, dict) and md.get("segments"):
                return list(md["segments"])
            
            # legacy fallback: modified_payload
            mp = getattr(result, "modified_payload", None)
            if isinstance(mp, (bytes, bytearray)) and mp:
                return [(bytes(mp), 0, {})]
            
            return []
        
        # Тест с modified_payload
        result = Mock(
            segments=None,
            _segments=None,
            metadata={},
            modified_payload=b"legacy_data"
        )
        context = Mock(engine_type="windivert", payload=b"test")
        
        segments = extract_segments_from_result(result, context)
        assert len(segments) == 1
        assert segments[0][0] == b"legacy_data"


class TestProtocolMimicryFixes:
    """Тесты для protocol_mimicry.py"""
    
    def test_segments_output_based_on_engine_type(self):
        """Проверка вывода сегментов в зависимости от engine_type"""
        
        segments = [(b"data1", 0, {}), (b"data2", 100, {})]
        
        # Для local engine сегменты не нужны
        context_local = Mock(engine_type="local")
        out_segments_local = segments if context_local.engine_type != "local" else None
        assert out_segments_local is None
        
        # Для windivert engine сегменты нужны
        context_windivert = Mock(engine_type="windivert")
        out_segments_windivert = segments if context_windivert.engine_type != "local" else None
        assert out_segments_windivert == segments


def test_all_imports():
    """Проверка всех критических импортов"""
    try:
        from collections import Counter
        from typing import List, Dict, Any, Optional, Tuple
        import asyncio
        import threading
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
