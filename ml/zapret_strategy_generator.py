# recon/ml/zapret_strategy_generator.py
import re
import random
import logging
from typing import Optional, List, Any

try:
    from core.fingerprint.advanced_models import (
        DPIFingerprint,
        DPIType,
        ConfidenceLevel,
    )
except ImportError:
    # Fallback for when running from within recon directory
    from core.fingerprint.advanced_models import (
        DPIFingerprint,
        DPIType,
    )

# Import modern attack registry for enhanced strategy generation
try:
    from core.bypass.attacks.attack_registry import AttackRegistry
    from core.bypass.attacks.attack_definition import (
        AttackCategory,
        AttackComplexity,
    )

    MODERN_REGISTRY_AVAILABLE = True
except ImportError:
    MODERN_REGISTRY_AVAILABLE = False


class ZapretStrategyGenerator:
    """Генератор стратегий в формате zapret команд, создающий рабочие комбинации."""

    def __init__(self, use_modern_registry: bool = True):
        """
        Initialize strategy generator.

        Args:
            use_modern_registry: Whether to use modern attack registry for enhanced generation
        """
        # Add logger initialization
        self.logger = logging.getLogger(__name__)

        self.use_modern_registry = use_modern_registry and MODERN_REGISTRY_AVAILABLE
        self.attack_registry = None

        if self.use_modern_registry:
            try:
                self.attack_registry = AttackRegistry()
            except Exception:
                self.use_modern_registry = False

    # --- ИСПРАВЛЕНИЕ: Добавлены более агрессивные и проверенные стратегии ---
    PROVEN_WORKING = [
        # Комбинация фейка, сегментации и fooling
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
        # Атака с сегментацией по маркеру midsld и повторами фейка
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
        # Атака с множественной сегментацией и перекрытием
        "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
        # Атака с перестановкой сегментов и фейком
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3,10 --dpi-desync-fooling=badseq",
        # Новые агрессивные стратегии от эксперта
        "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3",
        "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum",
        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-repeats=3 --dpi-desync-fooling=badsum,badseq",
        "--dpi-desync=fake --dpi-desync-fake-tls=0x1603 --dpi-desync-ttl=2",
    ]

    def _normalize_fingerprint(self, fingerprint: Any) -> Optional[DPIFingerprint]:
        """Преобразует словарь в объект DPIFingerprint или возвращает объект как есть."""
        if isinstance(fingerprint, DPIFingerprint):
            return fingerprint

        if isinstance(fingerprint, dict):
            # Преобразуем словарь в объект DPIFingerprint, безопасно получая значения
            # Это защитит от AttributeError, если какие-то ключи отсутствуют
            try:
                return DPIFingerprint(
                    dpi_type=DPIType(fingerprint.get("dpi_type", "UNKNOWN")),
                    confidence=float(fingerprint.get("confidence", 0.5)),
                    rst_injection_detected=bool(
                        fingerprint.get("rst_injection_detected", False)
                    ),
                    http_header_filtering=bool(
                        fingerprint.get("http_header_filtering", False)
                    ),
                    dns_hijacking_detected=bool(
                        fingerprint.get("dns_hijacking_detected", False)
                    ),
                    # Добавьте сюда другие поля из вашего класса DPIFingerprint по аналогии
                    # Например:
                    # content_inspection_depth=int(fingerprint.get('content_inspection_depth', 0)),
                    # tcp_window_manipulation=bool(fingerprint.get('tcp_window_manipulation', False)),
                )
            except (TypeError, ValueError):
                # В случае ошибки приведения типов, возвращаем None
                # Это может произойти, если в словаре некорректные данные
                return None

        return None

    def generate_strategies(self, fingerprint=None, count=20):
        """
        Generate DPI bypass strategies, enhanced to use fingerprint data.

        Args:
            fingerprint: DPIFingerprint object with detected characteristics (can be None)
            count: Number of strategies to generate

        Returns:
            List of strategy strings
        """
        strategies = []

        # Defensive check: ensure fingerprint is not None before accessing attributes
        if fingerprint is None:
            self.logger.info(
                "No fingerprint provided, generating generic strategies only"
            )
            generic_strategies = self._generate_generic_strategies(count)
            return generic_strategies

        # Use fingerprint data to generate targeted strategies
        if fingerprint:
            # Extract strategy hints from fingerprint (with safety checks)
            raw_metrics = getattr(fingerprint, "raw_metrics", {})
            # Ensure raw_metrics is a dict (not None)
            if raw_metrics is None:
                raw_metrics = {}
            hints = (
                raw_metrics.get("strategy_hints", [])
                if isinstance(raw_metrics, dict)
                else []
            )

            # FIXED: Check fragmentation vulnerability from fingerprint first
            # Try multiple ways to access fragmentation info
            fragmentation_handling = getattr(
                fingerprint, "fragmentation_handling", "unknown"
            )
            if fragmentation_handling == "unknown":
                # Try to get it from raw_metrics.tcp_analysis
                tcp_analysis = raw_metrics.get("tcp_analysis", {})
                fragmentation_handling = tcp_analysis.get(
                    "fragmentation_handling", "unknown"
                )

            self.logger.info(f"Generating strategies using fingerprint hints: {hints}")

            # FIXED: Generate strategies based on detected DPI characteristics
            if "disable_quic" in hints:
                strategies.extend(
                    [
                        "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=4",
                        "--dpi-desync=fake,split --dpi-desync-split-pos=5 --dpi-desync-ttl=3",
                        "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badseq",
                    ]
                )

            if (
                "tcp_segment_reordering" in hints
                and fragmentation_handling != "filtered"
            ):
                strategies.extend(
                    [
                        "--dpi-desync=multidisorder --dpi-desync-split-pos=1,5,10",
                        "--dpi-desync=multidisorder --dpi-desync-split-pos=2,7,15",
                        "--dpi-desync=multisplit --dpi-desync-split-pos=3,8,12",
                    ]
                )

            self.logger.info(
                f"Fragmentation handling detected: {fragmentation_handling}"
            )

            if fragmentation_handling == "vulnerable":
                # DPI is vulnerable to fragmentation - prioritize fragmentation attacks
                self.logger.info(
                    "DPI vulnerable to fragmentation - adding multisplit/multidisorder strategies"
                )
                strategies.extend(
                    [
                        "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
                        "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum",
                        "--dpi-desync=multidisorder --dpi-desync-split-pos=1,3,5,7 --dpi-desync-fooling=badseq",
                        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq",
                        "--dpi-desync=multidisorder --dpi-desync-split-pos=2,6,10,15 --dpi-desync-fooling=badsum",
                        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=64",
                        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq --dpi-desync-ttl=64",
                    ]
                )
            elif fragmentation_handling == "filtered":
                # DPI filters fragmentation - avoid fragmentation attacks
                self.logger.info(
                    "DPI filters fragmentation - avoiding multisplit/multidisorder strategies"
                )
                strategies.extend(
                    [
                        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                        "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq",
                        "--dpi-desync=fake --dpi-desync-split-pos=midsld --dpi-desync-fooling=badsum",
                    ]
                )
            else:
                # Unknown fragmentation handling - add both types but prioritize fragmentation
                self.logger.info(
                    "Fragmentation handling unknown - adding mixed strategies with fragmentation priority"
                )
                strategies.extend(
                    [
                        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=64",
                        "--dpi-desync=multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badseq",
                        "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
                        "--dpi-desync=fake --dpi-desync-ttl=64 --dpi-desync-fooling=badsum",
                    ]
                )

            if "prefer_http11" in hints:
                strategies.extend(
                    [
                        "--dpi-desync=fake,split --dpi-desync-split-pos=10 --dpi-desync-http-protocol=1.1",
                        "--dpi-desync=fake --dpi-desync-ttl=3 --dpi-desync-http-protocol=1.1",
                    ]
                )

            # Add general strategies based on fingerprint confidence
            confidence = getattr(fingerprint, "confidence", 0)
            if confidence > 0.5:
                strategies.extend(
                    [
                        "--dpi-desync=fake,disorder --dpi-desync-split-pos=2",
                        "--dpi-desync=multisplit --dpi-desync-split-pos=1,5,10",
                    ]
                )

        # If no fingerprint or not enough strategies, add generic ones
        if len(strategies) < count:
            generic_strategies = self._generate_generic_strategies(
                count - len(strategies)
            )
            strategies.extend(generic_strategies)

        # Remove duplicates while preserving order
        from core.utils.strategy_utils import deduplicate_with_limit
        unique_strategies = deduplicate_with_limit(strategies, limit=count)

        self.logger.info(f"Generated {len(unique_strategies)} unique strategies")
        return unique_strategies

    def _generate_fingerprint_aware_strategies(
        self, fingerprint: DPIFingerprint, count: int
    ) -> List[str]:
        """Генерирует стратегии с учетом детального фингерпринта DPI."""
        strategies = set()

        if fingerprint.confidence > 0.8:
            # High confidence: use specific and aggressive strategies
            dpi_specific = self._get_dpi_type_strategies(fingerprint.dpi_type)
            strategies.update(dpi_specific)
            characteristic_strategies = self._get_characteristic_based_strategies(
                fingerprint
            )
            strategies.update(characteristic_strategies)
            # Fill up with proven working strategies if needed
            if len(strategies) < count:
                strategies.update(self.PROVEN_WORKING)
        else:
            # Low confidence: use more generic and safe strategies
            strategies.update(self.PROVEN_WORKING)
            # Add some variations to have more options
            if len(strategies) < count:
                base = random.choice(self.PROVEN_WORKING)
                variations = self._generate_variations(base)
                strategies.update(variations)

        # Generate additional variations if we still don't have enough
        while len(strategies) < count:
            base = random.choice(list(strategies) or self.PROVEN_WORKING)
            variations = self._generate_variations(base)
            strategies.update(variations)

        # Rank strategies by confidence and relevance
        strategy_list = list(strategies)
        ranked_strategies = self._rank_strategies_by_confidence(
            strategy_list, fingerprint
        )

        return ranked_strategies[:count]

    def _generate_generic_strategies(self, count: int) -> List[str]:
        """Генерирует общие стратегии когда фингерпринт недоступен."""
        strategies = set(self.PROVEN_WORKING)

        # Генерируем много вариаций для достижения нужного количества
        while len(strategies) < count:
            # Выбираем случайную базовую стратегию
            base = random.choice(self.PROVEN_WORKING)

            # Генерируем различные вариации
            variations = self._generate_variations(base)
            strategies.update(variations)

            # Если все еще мало стратегий, создаем новые комбинации
            if len(strategies) < count:
                new_strategies = self._generate_new_combinations()
                strategies.update(new_strategies)

        strategy_list = list(strategies)
        random.shuffle(strategy_list)
        return strategy_list[:count]

    def _generate_registry_enhanced_strategies(
        self, fingerprint: Optional[Any], count: int
    ) -> List[str]:
        """
        Generate strategies enhanced with modern attack registry.

        Args:
            fingerprint: DPI fingerprint (DPIFingerprint object or dict)
            count: Number of strategies to generate

        Returns:
            List of registry-enhanced strategies
        """
        strategies = set(self.PROVEN_WORKING)

        # --- НАЧАЛО ИЗМЕНЕНИЙ ---
        fp_obj = self._normalize_fingerprint(fingerprint)
        # --- КОНЕЦ ИЗМЕНЕНИЙ ---

        if not self.attack_registry:
            # Если fp_obj не None, можно использовать старую логику
            if fp_obj:
                return self._generate_fingerprint_aware_strategies(fp_obj, count)
            return self._generate_generic_strategies(count)

        available_attacks = self.attack_registry.list_attacks(enabled_only=True)

        # --- ИЗМЕНЕНИЕ: Используем fp_obj вместо fingerprint ---
        if fp_obj:
            category_strategies = self._generate_category_based_strategies(
                fp_obj, available_attacks
            )
            strategies.update(category_strategies)

        registry_strategies = self._generate_from_registry_attacks(available_attacks)
        strategies.update(registry_strategies)

        strategies.update(self.PROVEN_WORKING)

        while len(strategies) < count:
            base = random.choice(list(strategies))
            variations = self._generate_variations(base)
            strategies.update(variations)

            if len(strategies) < count:
                new_strategies = self._generate_new_combinations()
                strategies.update(new_strategies)

        strategy_list = list(strategies)
        # --- ИЗМЕНЕНИЕ: Используем fp_obj вместо fingerprint ---
        if fp_obj:
            ranked_strategies = self._rank_strategies_by_registry(strategy_list, fp_obj)
        else:
            random.shuffle(strategy_list)
            ranked_strategies = strategy_list

        return ranked_strategies[:count]

    def _generate_category_based_strategies(
        self, fingerprint: DPIFingerprint, available_attacks: List[str]
    ) -> List[str]:
        """Generate strategies based on attack categories suitable for the DPI type."""
        strategies = []

        # Map DPI characteristics to attack categories
        if fingerprint.rst_injection_detected:
            # Use TCP fragmentation attacks
            tcp_attacks = [
                aid
                for aid in available_attacks
                if self.attack_registry.get_attack_definition(aid)
                and self.attack_registry.get_attack_definition(aid).category
                == AttackCategory.TCP_FRAGMENTATION
            ]

            for attack_id in tcp_attacks[:3]:  # Use top 3 TCP attacks
                strategies.extend(
                    [
                        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                        "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badseq",
                    ]
                )

        if fingerprint.http_header_filtering:
            # Use HTTP manipulation attacks
            http_attacks = [
                aid
                for aid in available_attacks
                if self.attack_registry.get_attack_definition(aid)
                and self.attack_registry.get_attack_definition(aid).category
                == AttackCategory.HTTP_MANIPULATION
            ]

            for attack_id in http_attacks[:3]:  # Use top 3 HTTP attacks
                strategies.extend(
                    [
                        "--dpi-desync=fake --dpi-desync-split-pos=midsld --dpi-desync-fooling=badsum",
                        "--dpi-desync=multidisorder --dpi-desync-split-pos=midsld,10 --dpi-desync-fooling=badseq",
                    ]
                )

        if fingerprint.dns_hijacking_detected:
            # Use DNS evasion attacks
            dns_attacks = [
                aid
                for aid in available_attacks
                if self.attack_registry.get_attack_definition(aid)
                and self.attack_registry.get_attack_definition(aid).category
                == AttackCategory.DNS_TUNNELING
            ]

            for attack_id in dns_attacks[:2]:  # Use top 2 DNS attacks
                strategies.extend(
                    [
                        "--dpi-desync=fake --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=6",
                        "--dpi-desync=multisplit --dpi-desync-split-count=2 --dpi-desync-fooling=badseq",
                    ]
                )

        return strategies

    def _generate_from_registry_attacks(
        self, available_attacks: List[str]
    ) -> List[str]:
        """Generate strategies from available registry attacks."""
        strategies = []

        # Group attacks by complexity
        simple_attacks = []
        moderate_attacks = []
        advanced_attacks = []

        for attack_id in available_attacks:
            definition = self.attack_registry.get_attack_definition(attack_id)
            if not definition:
                continue

            if definition.complexity == AttackComplexity.SIMPLE:
                simple_attacks.append(attack_id)
            elif definition.complexity == AttackComplexity.MODERATE:
                moderate_attacks.append(attack_id)
            elif definition.complexity in [
                AttackComplexity.ADVANCED,
                AttackComplexity.EXPERT,
            ]:
                advanced_attacks.append(attack_id)

        # Generate strategies for each complexity level
        # Simple attacks - basic strategies
        for attack_id in simple_attacks[:5]:
            strategies.extend(
                [
                    "--dpi-desync=fake --dpi-desync-ttl=3 --dpi-desync-fooling=badsum",
                    "--dpi-desync=disorder --dpi-desync-split-pos=3",
                ]
            )

        # Moderate attacks - intermediate strategies
        for attack_id in moderate_attacks[:3]:
            strategies.extend(
                [
                    "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
                    "--dpi-desync=multisplit --dpi-desync-split-count=2 --dpi-desync-fooling=badseq",
                ]
            )

        # Advanced attacks - complex strategies
        for attack_id in advanced_attacks[:2]:
            strategies.extend(
                [
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1",
                    "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum",
                ]
            )

        return strategies

    def _rank_strategies_by_registry(
        self, strategies: List[str], fingerprint: DPIFingerprint
    ) -> List[str]:
        """Rank strategies using registry information and fingerprint data."""

        def calculate_registry_score(strategy: str) -> float:
            """Calculate strategy score using registry information."""
            score = 0.0

            # Base score from fingerprint matching
            if fingerprint:
                confidence_bonus = fingerprint.confidence * 0.3
                score += confidence_bonus

            # Bonus for proven working strategies
            if strategy in self.PROVEN_WORKING:
                score += 0.4

            # Analyze strategy complexity and match to DPI difficulty
            complexity_penalty = self._calculate_strategy_complexity(strategy) * 0.1
            score -= complexity_penalty

            # Registry-specific bonuses
            if self.attack_registry:
                # Bonus for strategies using enabled attacks
                available_attacks = self.attack_registry.list_attacks(enabled_only=True)
                if available_attacks:  # If we have registry data
                    score += 0.2

            return max(0.0, min(1.0, score))

        # Calculate scores and sort
        strategy_scores = [
            (strategy, calculate_registry_score(strategy)) for strategy in strategies
        ]
        strategy_scores.sort(key=lambda x: x[1], reverse=True)

        return [strategy for strategy, score in strategy_scores]

    def _generate_variations(self, base_strategy: str) -> set:
        """Генерирует вариации базовой стратегии."""
        variations = set()

        # Вариации TTL
        for ttl in [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 15, 20, 64, 127, 128]:
            if "--dpi-desync-ttl=" in base_strategy:
                new_strategy = re.sub(
                    r"--dpi-desync-ttl=\d+", f"--dpi-desync-ttl={ttl}", base_strategy
                )
            else:
                new_strategy = base_strategy + f" --dpi-desync-ttl={ttl}"
            variations.add(new_strategy)

        # Вариации split-pos
        for pos in [1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20, "midsld"]:
            if "--dpi-desync-split-pos=" in base_strategy:
                new_strategy = re.sub(
                    r"--dpi-desync-split-pos=[\w,]+",
                    f"--dpi-desync-split-pos={pos}",
                    base_strategy,
                )
            else:
                new_strategy = base_strategy + f" --dpi-desync-split-pos={pos}"
            variations.add(new_strategy)

        # Вариации repeats
        for repeats in [1, 2, 3, 4, 5]:
            if "--dpi-desync-repeats=" in base_strategy:
                new_strategy = re.sub(
                    r"--dpi-desync-repeats=\d+",
                    f"--dpi-desync-repeats={repeats}",
                    base_strategy,
                )
            else:
                new_strategy = base_strategy + f" --dpi-desync-repeats={repeats}"
            variations.add(new_strategy)

        return variations

    def _generate_new_combinations(self) -> set:
        """Генерирует новые комбинации стратегий."""
        new_strategies = set()

        # Базовые методы
        methods = [
            "fake",
            "fake,fakeddisorder",
            "fake,disorder2",
            "fake,multidisorder",
            "multisplit",
            "multidisorder",
            "disorder",
            "disorder2",
        ]

        # Fooling методы
        fooling_options = ["badsum", "badseq", "badsum,badseq", "md5sig", "datanoack"]

        # Split позиции
        split_positions = [
            "1",
            "2",
            "3",
            "4",
            "5",
            "midsld",
            "1,5",
            "3,10",
            "1,5,10",
            "2,5,10",
        ]

        # TTL значения
        ttl_values = [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 127, 128]

        # Генерируем случайные комбинации
        for _ in range(50):  # Генерируем 50 новых комбинаций
            method = random.choice(methods)
            fooling = random.choice(fooling_options)
            split_pos = random.choice(split_positions)
            ttl = random.choice(ttl_values)

            strategy = f"--dpi-desync={method}"

            if "split" in method or "disorder" in method:
                strategy += f" --dpi-desync-split-pos={split_pos}"

            strategy += f" --dpi-desync-fooling={fooling}"
            strategy += f" --dpi-desync-ttl={ttl}"

            # Иногда добавляем repeats
            if random.random() < 0.3:
                repeats = random.randint(1, 5)
                strategy += f" --dpi-desync-repeats={repeats}"

            # Иногда добавляем fake-tls
            if "fake" in method and random.random() < 0.2:
                strategy += " --dpi-desync-fake-tls=0x1603"

            new_strategies.add(strategy)

        return new_strategies

    def _get_dpi_type_strategies(self, dpi_type: DPIType) -> List[str]:
        """Возвращает стратегии, специфичные для типа DPI."""

        # Шаблоны стратегий для каждого типа DPI
        dpi_strategies = {
            DPIType.ROSKOMNADZOR_TSPU: [
                "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-ttl=3",
                "--dpi-desync=fake --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=4",
                "--dpi-desync=multidisorder --dpi-desync-split-pos=midsld,10 --dpi-desync-fooling=badseq --dpi-desync-ttl=2",
            ],
            DPIType.ROSKOMNADZOR_DPI: [
                "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=2",
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=1",
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-repeats=5 --dpi-desync-fooling=badsum,badseq",
            ],
            DPIType.COMMERCIAL_DPI: [
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20",
                "--dpi-desync=fake,seqovl --dpi-desync-split-pos=3 --dpi-desync-split-seqovl=15",
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=md5sig --dpi-desync-ttl=64",
                "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=datanoack",
            ],
            DPIType.FIREWALL_BASED: [
                "--dpi-desync=fake --dpi-desync-split-pos=2 --dpi-desync-fooling=badseq --dpi-desync-ttl=64",
                "--dpi-desync=multidisorder --dpi-desync-split-pos=1,3,7 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=midsld --dpi-desync-ttl=127",
                "--dpi-desync=fake --dpi-desync-repeats=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=32",
            ],
            DPIType.ISP_TRANSPARENT_PROXY: [
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=8",
                "--dpi-desync=multisplit --dpi-desync-split-count=2 --dpi-desync-split-seqovl=3 --dpi-desync-fooling=badseq",
                "--dpi-desync=disorder --dpi-desync-split-pos=3,8 --dpi-desync-fooling=badsum --dpi-desync-ttl=16",
                "--dpi-desync=fake --dpi-desync-fake-tls=0x1603 --dpi-desync-ttl=4",
            ],
            DPIType.CLOUDFLARE_PROTECTION: [
                "--dpi-desync=fake --dpi-desync-split-pos=5 --dpi-desync-fooling=badsum --dpi-desync-ttl=10",
                "--dpi-desync=multidisorder --dpi-desync-split-pos=2,6,12 --dpi-desync-fooling=badseq",
                "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=midsld --dpi-desync-ttl=15",
                "--dpi-desync=fake --dpi-desync-repeats=2 --dpi-desync-fooling=md5sig --dpi-desync-ttl=20",
            ],
            DPIType.GOVERNMENT_CENSORSHIP: [
                "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,3,5,7 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1",
                "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2 --dpi-desync-repeats=3",
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-repeats=7 --dpi-desync-fooling=badsum,badseq,md5sig",
            ],
        }

        return dpi_strategies.get(dpi_type, [])

    def _get_characteristic_based_strategies(
        self, fingerprint: DPIFingerprint
    ) -> List[str]:
        """Генерирует стратегии на основе конкретных характеристик DPI."""
        strategies = []

        # FIXED: Стратегии для TCP-характеристик с учетом фрагментации

        # FIXED: Fragmentation vulnerability check - this is the key fix!
        fragmentation_handling = getattr(
            fingerprint, "fragmentation_handling", "unknown"
        )

        # Also check raw_metrics for fragmentation info
        if hasattr(fingerprint, "raw_metrics") and fragmentation_handling == "unknown":
            tcp_analysis = fingerprint.raw_metrics.get("tcp_analysis", {})
            fragmentation_handling = tcp_analysis.get(
                "fragmentation_handling", "unknown"
            )

        if fragmentation_handling == "vulnerable":
            # DPI vulnerable to fragmentation - prioritize fragmentation attacks
            strategies.extend(
                [
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
                    "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum",
                    "--dpi-desync=multidisorder --dpi-desync-split-pos=1,3,5,7 --dpi-desync-fooling=badseq",
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq",
                    "--dpi-desync=multidisorder --dpi-desync-split-pos=2,6,10,15 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=64",
                ]
            )
        elif fragmentation_handling == "filtered":
            # DPI filters fragmentation - avoid fragmentation attacks
            strategies.extend(
                [
                    "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq",
                    "--dpi-desync=fake --dpi-desync-split-pos=midsld --dpi-desync-fooling=badsum",
                ]
            )
        else:
            # Unknown or default - assume vulnerable and prioritize fragmentation
            strategies.extend(
                [
                    "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=64",
                    "--dpi-desync=multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badseq",
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
                ]
            )

        if fingerprint.rst_injection_detected:
            # RST инъекция - используем стратегии с низким TTL и повторами
            strategies.extend(
                [
                    "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-repeats=3 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake,disorder --dpi-desync-split-pos=1 --dpi-desync-ttl=2 --dpi-desync-fooling=badseq",
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=15 --dpi-desync-fooling=badsum",
                ]
            )

        if fingerprint.tcp_window_manipulation:
            # Манипуляция с TCP окнами - используем сегментацию
            strategies.extend(
                [
                    "--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-split-seqovl=10",
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum",
                ]
            )

        if fingerprint.sequence_number_anomalies:
            # Аномалии в sequence numbers - используем badseq fooling
            strategies.extend(
                [
                    "--dpi-desync=fake --dpi-desync-fooling=badseq --dpi-desync-ttl=3",
                    "--dpi-desync=disorder2 --dpi-desync-split-pos=2,7 --dpi-desync-fooling=badseq",
                ]
            )

        # Стратегии для HTTP-характеристик
        if fingerprint.http_header_filtering:
            # Фильтрация HTTP заголовков - используем сегментацию по midsld
            strategies.extend(
                [
                    "--dpi-desync=fake --dpi-desync-split-pos=midsld --dpi-desync-fooling=badsum --dpi-desync-ttl=4",
                    "--dpi-desync=multidisorder --dpi-desync-split-pos=midsld,10 --dpi-desync-fooling=badseq",
                ]
            )

        if fingerprint.content_inspection_depth > 1000:
            # Глубокая инспекция контента - агрессивная сегментация
            strategies.extend(
                [
                    "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,3,5,7,10 --dpi-desync-fooling=badsum,badseq",
                ]
            )

        if fingerprint.user_agent_filtering:
            # Фильтрация User-Agent - используем fake TLS
            strategies.extend(
                [
                    "--dpi-desync=fake --dpi-desync-fake-tls=0x1603 --dpi-desync-ttl=5",
                    "--dpi-desync=fake,disorder --dpi-desync-fake-tls=0x1603 --dpi-desync-split-pos=3",
                ]
            )

        # Стратегии для DNS-характеристик
        if fingerprint.dns_hijacking_detected:
            # DNS hijacking - фокус на TCP и TLS обходе
            strategies.extend(
                [
                    "--dpi-desync=fake --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=6",
                    "--dpi-desync=multisplit --dpi-desync-split-count=2 --dpi-desync-fooling=badseq",
                ]
            )

        if fingerprint.doh_blocking and fingerprint.dot_blocking:
            # Блокировка DoH/DoT - агрессивные методы
            strategies.extend(
                [
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=2",
                    "--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-split-seqovl=20",
                ]
            )

        # Стратегии для дополнительных характеристик
        if (
            fingerprint.packet_size_limitations
            and fingerprint.packet_size_limitations < 1000
        ):
            # Ограничения размера пакетов - мелкая сегментация
            strategies.extend(
                [
                    "--dpi-desync=multisplit --dpi-desync-split-count=6 --dpi-desync-split-seqovl=5",
                    "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,2,3,4,5 --dpi-desync-fooling=badsum",
                ]
            )

        if fingerprint.geographic_restrictions:
            # Географические ограничения - сложные стратегии
            strategies.extend(
                [
                    "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=4",
                    "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=35 --dpi-desync-fooling=badsum,badseq",
                ]
            )

        return strategies

    def _rank_strategies_by_confidence(
        self, strategies: List[str], fingerprint: DPIFingerprint
    ) -> List[str]:
        """Ранжирует стратегии по уверенности и релевантности для данного DPI."""

        def calculate_strategy_score(strategy: str) -> float:
            """Вычисляет оценку стратегии для данного фингерпринта."""
            score = 0.0

            # Базовая оценка по уверенности классификации
            confidence_bonus = fingerprint.confidence * 0.3
            score += confidence_bonus

            # Бонус за соответствие типу DPI
            dpi_specific_strategies = self._get_dpi_type_strategies(
                fingerprint.dpi_type
            )
            if strategy in dpi_specific_strategies:
                score += 0.4

            # Бонус за соответствие характеристикам
            characteristic_strategies = self._get_characteristic_based_strategies(
                fingerprint
            )
            if strategy in characteristic_strategies:
                score += 0.3

            # Бонус за проверенные стратегии
            if strategy in self.PROVEN_WORKING:
                score += 0.2

            # Штраф за сложность (слишком сложные стратегии менее надежны)
            complexity_penalty = self._calculate_strategy_complexity(strategy) * 0.1
            score -= complexity_penalty

            # Бонус за релевантность к уровню сложности DPI
            difficulty = fingerprint.calculate_evasion_difficulty()
            strategy_aggressiveness = self._calculate_strategy_aggressiveness(strategy)

            # Оптимальное соответствие агрессивности стратегии сложности DPI
            aggressiveness_match = 1.0 - abs(difficulty - strategy_aggressiveness)
            score += aggressiveness_match * 0.2

            return max(0.0, min(1.0, score))  # Ограничиваем от 0 до 1

        # Вычисляем оценки и сортируем
        strategy_scores = [
            (strategy, calculate_strategy_score(strategy)) for strategy in strategies
        ]
        strategy_scores.sort(key=lambda x: x[1], reverse=True)

        return [strategy for strategy, score in strategy_scores]

    def _calculate_strategy_complexity(self, strategy: str) -> float:
        """Вычисляет сложность стратегии (0.0 = простая, 1.0 = очень сложная)."""
        complexity = 0.0

        # Подсчет количества параметров
        param_count = len(re.findall(r"--dpi-desync-\w+", strategy))
        complexity += min(param_count * 0.1, 0.5)

        # Сложность методов desync
        if "multisplit" in strategy:
            complexity += 0.2
        if "multidisorder" in strategy:
            complexity += 0.2
        if "disorder2" in strategy:
            complexity += 0.15

        # Сложность fooling методов
        fooling_count = len(re.findall(r"badsum|badseq|md5sig|datanoack", strategy))
        complexity += min(fooling_count * 0.05, 0.2)

        # Сложность split позиций
        if "midsld" in strategy:
            complexity += 0.1
        split_positions = re.findall(r"--dpi-desync-split-pos=([^\\s]+)", strategy)
        if split_positions:
            pos_complexity = len(split_positions[0].split(",")) * 0.05
            complexity += min(pos_complexity, 0.15)

        return min(complexity, 1.0)

    def _calculate_strategy_aggressiveness(self, strategy: str) -> float:
        """Вычисляет агрессивность стратегии (0.0 = мягкая, 1.0 = очень агрессивная)."""
        aggressiveness = 0.0

        # TTL значения (меньше = агрессивнее)
        ttl_match = re.search(r"--dpi-desync-ttl=(\d+)", strategy)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 2:
                aggressiveness += 0.3
            elif ttl <= 5:
                aggressiveness += 0.2
            elif ttl <= 10:
                aggressiveness += 0.1

        # Количество повторов
        repeats_match = re.search(r"--dpi-desync-repeats=(\d+)", strategy)
        if repeats_match:
            repeats = int(repeats_match.group(1))
            aggressiveness += min(repeats * 0.05, 0.2)

        # Количество split сегментов
        split_count_match = re.search(r"--dpi-desync-split-count=(\d+)", strategy)
        if split_count_match:
            count = int(split_count_match.group(1))
            aggressiveness += min(count * 0.03, 0.15)

        # Overlap размер
        overlap_match = re.search(r"--dpi-desync-split-seqovl=(\d+)", strategy)
        if overlap_match:
            overlap = int(overlap_match.group(1))
            aggressiveness += min(overlap * 0.01, 0.1)

        # Агрессивные методы
        if "multisplit" in strategy:
            aggressiveness += 0.15
        if "multidisorder" in strategy:
            aggressiveness += 0.15
        if "badsum,badseq" in strategy:
            aggressiveness += 0.1

        return min(aggressiveness, 1.0)

    def _generate_legacy_strategies(self, fingerprint: dict, count: int) -> List[str]:
        """Генерирует стратегии для старого формата фингерпринта (обратная совместимость)."""
        strategies = set(self.PROVEN_WORKING)

        # Добавляем стратегию, учитывающую старый fingerprint
        if fingerprint.get("dpi_type") == "LIKELY_WINDOWS_BASED":
            strategies.add(
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=127"
            )

        # Генерируем дополнительные стратегии
        while len(strategies) < count:
            base = random.choice(self.PROVEN_WORKING)
            variations = self._generate_variations(base)
            strategies.update(variations)

            if len(strategies) < count:
                new_strategies = self._generate_new_combinations()
                strategies.update(new_strategies)

        strategy_list = list(strategies)
        random.shuffle(strategy_list)
        return strategy_list[:count]
