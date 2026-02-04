#!/usr/bin/env python3
"""
Adaptive Learning Cache Module

Implements strategy performance tracking and adaptive learning for DPI bypass.
Extracted from cli.py to improve modularity and reduce complexity.
"""

import hashlib
import logging
import pickle
import re
import statistics
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import Rich components for UI
try:
    from rich.console import Console

    console = Console()
except ImportError:

    class Console:
        def print(self, *args, **kwargs):
            print(*args)

    console = Console()

# Get logger
LOG = logging.getLogger("recon.adaptive_cache")


@dataclass
class StrategyPerformanceRecord:
    """Запись о производительности стратегии."""

    strategy: str
    domain: str
    ip: str
    success_rate: float
    avg_latency: float
    timestamp: str
    dpi_fingerprint_hash: str = ""
    test_count: int = 1

    def update_performance(self, success_rate=None, avg_latency=None, latency=None):
        """Обновляет производительность с учетом нового теста."""
        alpha = 0.3  # Коэффициент обучения
        if success_rate is not None:
            self.success_rate = alpha * success_rate + (1 - alpha) * self.success_rate
        if avg_latency is not None:
            self.avg_latency = alpha * avg_latency + (1 - alpha) * self.avg_latency
        if latency is not None:
            self.avg_latency = alpha * latency + (1 - alpha) * self.avg_latency
        self.test_count += 1
        self.timestamp = datetime.now().isoformat()


class AdaptiveLearningCache:
    """Система адаптивного кэширования и обучения."""

    def __init__(self, cache_file: str = "recon_learning_cache.pkl"):
        self.cache_file = Path(cache_file)
        self.strategy_records: Dict[str, StrategyPerformanceRecord] = {}
        self.domain_patterns: Dict[str, Dict[str, float]] = {}
        self.dpi_patterns: Dict[str, Dict[str, float]] = {}
        self.load_cache()

    def _strategy_key(self, strategy: str, domain: str, ip: str) -> str:
        """Создает уникальный ключ для стратегии."""
        strategy_hash = hashlib.md5(strategy.encode()).hexdigest()[:8]
        return f"{domain}_{ip}_{strategy_hash}"

    def _extract_strategy_type(self, strategy: str) -> str:
        """
        Извлекает тип стратегии из полной строки с поддержкой всех атак.

        Args:
            strategy: Строка стратегии zapret для анализа

        Returns:
            str: Имя типа атаки или 'unknown' если не найден

        Raises:
            ValueError: Если strategy не является строкой или пустой
        """
        # Parameter validation
        if not isinstance(strategy, str):
            raise ValueError(f"Strategy must be a string, got {type(strategy)}")

        if not strategy or not strategy.strip():
            raise ValueError("Strategy cannot be empty or whitespace-only")

        from core.bypass.attacks.attack_registry import get_attack_registry
        from core.attack_mapping import get_attack_mapping

        # Use comprehensive attack mapping for extraction
        attack_mapping = get_attack_mapping()
        extracted_type = attack_mapping.extract_strategy_type(strategy)

        if extracted_type != "unknown":
            return extracted_type

        # Also try direct registry lookup for known attack types
        registry = get_attack_registry()
        known_attacks = registry.list_attacks()

        # Normalize strategy for pattern matching
        strategy_lower = strategy.lower().strip()

        # Check if any known attack type is directly mentioned in the strategy
        for attack_type in known_attacks:
            if attack_type in strategy_lower:
                # Ensure it's a word boundary match to avoid false positives
                if re.search(rf"\b{re.escape(attack_type)}\b", strategy_lower):
                    return attack_type

        # Enhanced pattern matching with FIXED priorities
        # Order is CRITICAL - most specific patterns MUST come first
        priority_patterns = [
            # Priority 1: Very specific multi-component patterns (highest priority)
            (
                "fake_fakeddisorder",
                [r"fake,fakeddisorder", r"fakeddisorder.*fake", r"fake.*fakeddisorder"],
            ),
            ("tcp_multisplit", [r"tcp.*multisplit", r"multisplit.*tcp", r"tcp_multisplit"]),
            (
                "tcp_multidisorder",
                [r"tcp.*multidisorder", r"multidisorder.*tcp", r"tcp_multidisorder"],
            ),
            ("tcp_seqovl", [r"tcp.*seqovl", r"seqovl.*tcp", r"tcp_seqovl"]),
            # Priority 2: Specific zapret command patterns (very specific)
            ("ip_fragmentation_advanced", [r"\bipfrag2\b"]),
            ("timing_based_evasion", [r"dpi-desync-delay", r"delay=\d+", r"timing.*evasion"]),
            ("force_tcp", [r"filter-udp=443"]),
            ("badsum_race", [r"dpi-desync-fooling=badsum", r"fooling.*badsum"]),
            ("md5sig_race", [r"dpi-desync-fooling=md5sig", r"fooling.*md5sig"]),
            ("badseq_fooling", [r"dpi-desync-fooling=badseq", r"fooling.*badseq"]),
            # Priority 3: Fake disorder patterns (must come before generic disorder)
            ("fake_disorder", [r"fake.*disorder", r"disorder.*fake", r"fake,disorder"]),
            # Priority 4: Multi-attack patterns (must come before single variants)
            ("multisplit", [r"\bmultisplit\b"]),
            ("multidisorder", [r"\bmultidisorder\b"]),
            ("sequence_overlap", [r"\bseqovl\b", r"sequence_overlap", r"split-seqovl"]),
            # Priority 5: TLS/HTTP specific patterns
            ("tls_record_fragmentation", [r"tls.*record.*split", r"tls-record-split"]),
            ("http_header_case", [r"http.*header.*case", r"http-header-case"]),
            ("h2_frame_splitting", [r"h2.*frame.*split", r"http2.*frame"]),
            ("sni_manipulation", [r"sni.*manip", r"host.*header"]),
            # Priority 6: QUIC patterns
            ("quic_fragmentation", [r"quic.*frag", r"udp.*443.*frag"]),
            ("quic_bypass", [r"quic.*bypass", r"disable.*quic"]),
            # Priority 7: Window and TCP options patterns
            ("window_manipulation", [r"tcp.*window", r"window.*scale"]),
            ("tcp_options_modification", [r"tcp.*options", r"tcp-options-modify"]),
            # Priority 8: Basic fragmentation patterns (lower priority)
            ("simple_fragment", [r"\bsplit\b(?!.*multi)"]),
            ("tcp_fragmentation", [r"tcp.*split(?!.*multi)"]),
            ("ip_fragmentation", [r"ip.*frag(?!2)"]),
            # Priority 9: Timing patterns (generic, lower priority)
            ("timing_based", [r"\bdelay\b", r"timing"]),
            # Priority 10: Generic patterns (lowest priority)
            ("disorder", [r"\bdisorder\b(?!.*multi)(?!.*fake)", r"dpi-desync=disorder"]),
            ("fake", [r"\bfake\b(?!.*disorder)", r"dpi-desync=fake", r"dpi-desync-fake-sni"]),
            ("split", [r"\bsplit\b(?!.*multi)(?!.*seq)"]),
        ]

        # Apply patterns in priority order
        for attack_type, patterns in priority_patterns:
            for pattern in patterns:
                try:
                    if re.search(pattern, strategy_lower):
                        return attack_type
                except re.error as e:
                    LOG.warning(
                        f"Invalid regex pattern '{pattern}' for attack '{attack_type}': {e}"
                    )
                    continue

        # Fallback: Check for any registered attack names in the strategy
        all_attacks = attack_mapping.get_all_attacks()

        # Sort attacks by name length (longest first) to prioritize more specific matches
        sorted_attacks = sorted(all_attacks.items(), key=lambda x: len(x[0]), reverse=True)

        for attack_name, attack_info in sorted_attacks:
            # Check exact attack name match
            attack_name_lower = attack_name.lower()
            if attack_name_lower in strategy_lower:
                # Ensure it's a word boundary match to avoid false positives
                if re.search(rf"\b{re.escape(attack_name_lower)}\b", strategy_lower):
                    return attack_name

            # Check aliases (also sorted by length)
            sorted_aliases = sorted(attack_info.aliases, key=len, reverse=True)
            for alias in sorted_aliases:
                alias_lower = alias.lower()
                if alias_lower in strategy_lower:
                    if re.search(rf"\b{re.escape(alias_lower)}\b", strategy_lower):
                        return attack_name

        # Final fallback: partial matching for compound attack names
        for attack_name, attack_info in sorted_attacks:
            attack_parts = attack_name.lower().split("_")
            if len(attack_parts) > 1:
                # Check if all parts of the attack name are present
                if all(part in strategy_lower for part in attack_parts if len(part) > 2):
                    return attack_name

        return "unknown"

    def record_strategy_performance(
        self,
        strategy: str,
        domain: str,
        ip: str,
        success_rate: float,
        avg_latency: float,
        dpi_fingerprint_hash: str = "",
    ):
        """Записывает производительность стратегии."""
        key = self._strategy_key(strategy, domain, ip)

        if key in self.strategy_records:
            self.strategy_records[key].update_performance(success_rate, avg_latency)
        else:
            self.strategy_records[key] = StrategyPerformanceRecord(
                strategy=strategy,
                domain=domain,
                ip=ip,
                success_rate=success_rate,
                avg_latency=avg_latency,
                timestamp=datetime.now().isoformat(),
                dpi_fingerprint_hash=dpi_fingerprint_hash,
            )

        strategy_type = self._extract_strategy_type(strategy)
        if domain not in self.domain_patterns:
            self.domain_patterns[domain] = {}

        if strategy_type in self.domain_patterns[domain]:
            alpha = 0.2
            old_rate = self.domain_patterns[domain][strategy_type]
            self.domain_patterns[domain][strategy_type] = (
                alpha * success_rate + (1 - alpha) * old_rate
            )
        else:
            self.domain_patterns[domain][strategy_type] = success_rate

        if dpi_fingerprint_hash:
            if dpi_fingerprint_hash not in self.dpi_patterns:
                self.dpi_patterns[dpi_fingerprint_hash] = {}
            if strategy_type in self.dpi_patterns[dpi_fingerprint_hash]:
                alpha = 0.2
                old_rate = self.dpi_patterns[dpi_fingerprint_hash][strategy_type]
                self.dpi_patterns[dpi_fingerprint_hash][strategy_type] = (
                    alpha * success_rate + (1 - alpha) * old_rate
                )
            else:
                self.dpi_patterns[dpi_fingerprint_hash][strategy_type] = success_rate

    def get_strategy_prediction(self, strategy: str, domain: str, ip: str) -> Optional[float]:
        """Предсказывает успешность стратегии на основе истории."""
        key = self._strategy_key(strategy, domain, ip)
        if key in self.strategy_records:
            record = self.strategy_records[key]
            age_hours = (
                datetime.now() - datetime.fromisoformat(record.timestamp)
            ).total_seconds() / 3600
            confidence = max(0.1, 1.0 - age_hours / (24 * 7))
            return record.success_rate * confidence
        return None

    def get_domain_recommendations(self, domain: str, top_n: int = 3) -> List[Tuple[str, float]]:
        """Возвращает рекомендуемые типы стратегий для домена."""
        if domain in self.domain_patterns:
            patterns = self.domain_patterns[domain]
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            return sorted_patterns[:top_n]
        return []

    def get_dpi_recommendations(
        self, dpi_fingerprint_hash: str, top_n: int = 3
    ) -> List[Tuple[str, float]]:
        """Возвращает рекомендуемые типы стратегий для DPI."""
        if dpi_fingerprint_hash in self.dpi_patterns:
            patterns = self.dpi_patterns[dpi_fingerprint_hash]
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            return sorted_patterns[:top_n]
        return []

    def get_smart_strategy_order(
        self,
        strategies: List[str],
        domain: str,
        ip: str,
        dpi_fingerprint_hash: str = "",
    ) -> List[str]:
        """Умно сортирует стратегии по предполагаемой эффективности."""
        strategy_scores = []

        for strategy in strategies:
            score = 0.0
            prediction = self.get_strategy_prediction(strategy, domain, ip)
            if prediction is not None:
                score += prediction * 0.6
            strategy_type = self._extract_strategy_type(strategy)
            domain_recs = dict(self.get_domain_recommendations(domain, 10))
            if strategy_type in domain_recs:
                score += domain_recs[strategy_type] * 0.25
            if dpi_fingerprint_hash:
                dpi_recs = dict(self.get_dpi_recommendations(dpi_fingerprint_hash, 10))
                if strategy_type in dpi_recs:
                    score += dpi_recs[strategy_type] * 0.15
            strategy_scores.append((strategy, score))

        strategy_scores.sort(key=lambda x: x[1], reverse=True)
        return [strategy for strategy, _ in strategy_scores]

    def save_cache(self):
        """Сохраняет кэш в файл."""
        try:
            cache_data = {
                "strategy_records": self.strategy_records,
                "domain_patterns": self.domain_patterns,
                "dpi_patterns": self.dpi_patterns,
                "version": "1.0",
                "saved_at": datetime.now().isoformat(),
            }
            with open(self.cache_file, "wb") as f:
                pickle.dump(cache_data, f)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not save learning cache: {e}[/yellow]")

    def load_cache(self):
        """Загружает кэш из файла."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "rb") as f:
                    cache_data = pickle.load(f)

                self.strategy_records = cache_data.get("strategy_records", {})
                self.domain_patterns = cache_data.get("domain_patterns", {})
                self.dpi_patterns = cache_data.get("dpi_patterns", {})

                console.print(
                    f"[dim]Loaded learning cache: {len(self.strategy_records)} records, "
                    f"{len(self.domain_patterns)} domain patterns[/dim]"
                )
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load learning cache: {e}[/yellow]")
            self.strategy_records = {}
            self.domain_patterns = {}
            self.dpi_patterns = {}

    def get_cache_stats(self) -> dict:
        """Возвращает статистику кэша."""
        total_tests = sum(record.test_count for record in self.strategy_records.values())
        avg_success_rate = (
            statistics.mean([record.success_rate for record in self.strategy_records.values()])
            if self.strategy_records
            else 0
        )

        return {
            "total_records": len(self.strategy_records),
            "total_tests": total_tests,
            "avg_success_rate": avg_success_rate,
            "domain_patterns": len(self.domain_patterns),
            "dpi_patterns": len(self.dpi_patterns),
        }
