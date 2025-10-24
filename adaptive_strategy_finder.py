#!/usr/bin/env python3
"""
Адаптивная система поиска оптимальных стратегий обхода.
Тестирует все доступные атаки и их комбинации для поиска лучшего решения.
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from itertools import combinations

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("adaptive_strategy_finder")


@dataclass
class AttackConfig:
    """Конфигурация атаки."""

    name: str
    method: str
    params: Dict
    description: str
    complexity: int  # 1-5, где 5 - самая сложная


@dataclass
class TestResult:
    """Результат тестирования стратегии."""

    strategy_name: str
    domain: str
    success: bool
    latency_ms: float
    data_transferred: int
    connection_duration: float
    error: Optional[str] = None
    score: float = 0.0


class AdaptiveStrategyFinder:
    """Адаптивная система поиска оптимальных стратегий."""

    def __init__(self):
        self.available_attacks = self._define_attacks()
        self.test_results: List[TestResult] = []
        self.best_strategies: Dict[str, Dict] = {}

    def _define_attacks(self) -> List[AttackConfig]:
        """Определяет все доступные атаки."""
        return [
            # Проверенные рабочие стратегии из attack_combinator
            AttackConfig(
                name="fakeddisorder_basic",
                method="fakeddisorder",
                params={"split_pos": 3, "fooling": "badsum", "ttl": 3},
                description="Базовая fakeddisorder атака",
                complexity=1,
            ),
            AttackConfig(
                name="fakeddisorder_seqovl",
                method="fakeddisorder",
                params={
                    "split_seqovl": 336,
                    "autottl": 2,
                    "fooling": "md5sig,badsum,badseq",
                    "repeats": 1,
                    "split_pos": 76,
                    "ttl": 1,
                },
                description="Fakeddisorder с seqovl",
                complexity=3,
            ),
            AttackConfig(
                name="multisplit_conservative",
                method="multisplit",
                params={"split_count": 3, "fooling": "badsum", "ttl": 2},
                description="Консервативный multisplit",
                complexity=2,
            ),
            AttackConfig(
                name="multisplit_aggressive",
                method="multisplit",
                params={
                    "split_count": 7,
                    "split_seqovl": 30,
                    "fooling": "badsum",
                    "repeats": 3,
                    "ttl": 4,
                },
                description="Агрессивный multisplit",
                complexity=3,
            ),
            AttackConfig(
                name="multidisorder",
                method="multidisorder",
                params={"split_pos": 3, "fooling": "badsum", "ttl": 2},
                description="Multidisorder атака",
                complexity=2,
            ),
            AttackConfig(
                name="seqovl_standard",
                method="fake,disorder",
                params={
                    "split_pos": 3,
                    "split_seqovl": 20,
                    "fooling": "badsum",
                    "ttl": 2,
                },
                description="Стандартная seqovl атака",
                complexity=2,
            ),
            AttackConfig(
                name="instagram_optimized",
                method="multisplit",
                params={"split_count": 5, "fooling": "badsum", "ttl": 3},
                description="Оптимизированная для Instagram",
                complexity=2,
            ),
            AttackConfig(
                name="conservative_bypass",
                method="fakeddisorder",
                params={"split_pos": 10, "ttl": 3},
                description="Консервативный обход",
                complexity=1,
            ),
            # Дополнительные вариации
            AttackConfig(
                name="split_basic",
                method="split",
                params={"split_pos": 2, "ttl": 2, "fooling": "badsum"},
                description="Базовое разделение пакетов",
                complexity=1,
            ),
            AttackConfig(
                name="disorder_advanced",
                method="disorder",
                params={"split_pos": 3, "ttl": 4, "fooling": "badseq"},
                description="Продвинутое изменение порядка",
                complexity=2,
            ),
            AttackConfig(
                name="fake_simple",
                method="fake",
                params={"ttl": 1, "fooling": "badsum"},
                description="Простые поддельные пакеты",
                complexity=1,
            ),
            AttackConfig(
                name="fake_advanced",
                method="fake",
                params={"ttl": 2, "fooling": "badseq", "repeats": 2},
                description="Продвинутые поддельные пакеты",
                complexity=2,
            ),
            # TTL вариации
            AttackConfig(
                name="low_ttl_multisplit",
                method="multisplit",
                params={"ttl": 1, "split_count": 3, "fooling": "badsum", "repeats": 2},
                description="Низкий TTL с multisplit",
                complexity=2,
            ),
            AttackConfig(
                name="high_ttl_disorder",
                method="disorder",
                params={"ttl": 8, "split_pos": 3, "fooling": "badsum"},
                description="Высокий TTL с disorder",
                complexity=2,
            ),
            # Комбинированные атаки
            AttackConfig(
                name="twitter_optimized",
                method="multisplit",
                params={
                    "split_count": 7,
                    "split_seqovl": 30,
                    "fooling": "badsum",
                    "repeats": 3,
                    "ttl": 4,
                },
                description="Оптимизированная для Twitter",
                complexity=3,
            ),
            AttackConfig(
                name="universal_bypass",
                method="fakeddisorder",
                params={"split_pos": 3, "fooling": "badsum", "ttl": 3, "repeats": 1},
                description="Универсальный обход",
                complexity=2,
            ),
        ]

    def _generate_combinations(self, max_complexity: int = 3) -> List[Dict]:
        """Генерирует комбинации атак."""
        combinations_list = []

        # Одиночные атаки
        for attack in self.available_attacks:
            if attack.complexity <= max_complexity:
                combinations_list.append(
                    {
                        "name": attack.name,
                        "attacks": [attack],
                        "complexity": attack.complexity,
                    }
                )

        # Двойные комбинации
        for attack1, attack2 in combinations(self.available_attacks, 2):
            total_complexity = attack1.complexity + attack2.complexity
            if (
                total_complexity <= max_complexity + 2
            ):  # Позволяем немного больше для комбинаций
                combinations_list.append(
                    {
                        "name": f"{attack1.name}+{attack2.name}",
                        "attacks": [attack1, attack2],
                        "complexity": total_complexity,
                    }
                )

        # Тройные комбинации (только для простых атак)
        simple_attacks = [a for a in self.available_attacks if a.complexity <= 2]
        for attack1, attack2, attack3 in combinations(simple_attacks, 3):
            total_complexity = (
                attack1.complexity + attack2.complexity + attack3.complexity
            )
            if total_complexity <= max_complexity + 1:
                combinations_list.append(
                    {
                        "name": f"{attack1.name}+{attack2.name}+{attack3.name}",
                        "attacks": [attack1, attack2, attack3],
                        "complexity": total_complexity,
                    }
                )

        return sorted(combinations_list, key=lambda x: x["complexity"])

    def _convert_to_zapret_strategy(self, combination: Dict) -> str:
        """Конвертирует комбинацию атак в строку zapret."""
        attacks = combination["attacks"]

        if len(attacks) == 1:
            # Одиночная атака
            attack = attacks[0]
            return self._single_attack_to_zapret(attack)
        else:
            # Комбинация атак
            return self._combination_to_zapret(attacks)

    def _single_attack_to_zapret(self, attack: AttackConfig) -> str:
        """Конвертирует одиночную атаку в zapret формат."""
        # Используем правильные методы для zapret
        method_mapping = {
            "fake": "fake",
            "disorder": "disorder",
            "split": "split",
            "multisplit": "multisplit",
            "multidisorder": "multidisorder",
        }

        method = method_mapping.get(attack.method, attack.method)
        parts = [f"--dpi-desync={method}"]

        for key, value in attack.params.items():
            if key == "ttl":
                parts.append(f"--dpi-desync-ttl={value}")
            elif key == "fooling":
                parts.append(f"--dpi-desync-fooling={value}")
            elif key == "split_pos":
                parts.append(f"--dpi-desync-split-pos={value}")
            elif key == "split_count":
                parts.append(f"--dpi-desync-split-count={value}")
            elif key == "split_seqovl":
                parts.append(f"--dpi-desync-split-seqovl={value}")
            elif key == "repeats":
                parts.append(f"--dpi-desync-repeats={value}")
            elif key == "window_div":
                parts.append(f"--dpi-desync-window-div={value}")
            elif key == "fragment_size":
                parts.append(f"--dpi-desync-fragment-size={value}")
            elif key == "autottl":
                parts.append(f"--dpi-desync-autottl={value}")

        return " ".join(parts)

    def _combination_to_zapret(self, attacks: List[AttackConfig]) -> str:
        """Конвертирует комбинацию атак в zapret формат."""
        methods = []
        all_params = {}

        # Собираем методы и параметры
        for attack in attacks:
            if "," in attack.method:
                methods.extend(attack.method.split(","))
            else:
                methods.append(attack.method)

            # Объединяем параметры (последний побеждает)
            all_params.update(attack.params)

        # Формируем строку
        parts = [f"--dpi-desync={','.join(set(methods))}"]

        for key, value in all_params.items():
            if key == "ttl":
                parts.append(f"--dpi-desync-ttl={value}")
            elif key == "fooling":
                parts.append(f"--dpi-desync-fooling={value}")
            elif key == "split_pos":
                parts.append(f"--dpi-desync-split-pos={value}")
            elif key == "split_count":
                parts.append(f"--dpi-desync-split-count={value}")
            elif key == "split_seqovl":
                parts.append(f"--dpi-desync-split-seqovl={value}")
            elif key == "repeats":
                parts.append(f"--dpi-desync-repeats={value}")

        return " ".join(parts)

    async def test_strategy(
        self, domain: str, strategy_string: str, strategy_name: str
    ) -> TestResult:
        """Тестирует одну стратегию на домене."""
        LOG.info(f"Тестирование {strategy_name} на {domain}")

        start_time = time.time()

        try:
            # Используем attack combinator для тестирования
            from core.attack_combinator import AttackCombinator
            from core.strategy_selector import StrategySelector
            from cli import resolve_all_ips

            # Инициализируем компоненты
            strategy_selector = StrategySelector()
            attack_combinator = AttackCombinator(
                strategy_selector=strategy_selector, debug=False
            )

            # Резолвим IP
            try:
                ips = await resolve_all_ips(domain)
                if not ips:
                    raise Exception(f"Could not resolve {domain}")
                target_ip = list(ips)[0]
            except Exception as e:
                raise Exception(f"DNS resolution failed: {e}")

            # Создаем временную стратегию для тестирования
            temp_strategy_name = f"temp_{strategy_name}"
            attack_combinator.attack_strategies[temp_strategy_name] = strategy_string

            # Тестируем стратегию
            results = await attack_combinator.test_multiple_attacks_parallel(
                domain, target_ip, [temp_strategy_name], 1
            )

            if results and len(results) > 0:
                result = results[0]
                success = result.success
                latency = result.latency_ms

                # Оценка успеха
                score = 0.0
                if success:
                    score = 100.0 - (
                        latency / 10
                    )  # Базовая оценка минус штраф за задержку
                    score = max(score, 10.0)  # Минимум 10 баллов за успех

                return TestResult(
                    strategy_name=strategy_name,
                    domain=domain,
                    success=success,
                    latency_ms=latency,
                    data_transferred=result.data_transferred,
                    connection_duration=latency / 1000,
                    score=score,
                )
            else:
                raise Exception("No test results returned")

        except asyncio.TimeoutError:
            return TestResult(
                strategy_name=strategy_name,
                domain=domain,
                success=False,
                latency_ms=15000,
                data_transferred=0,
                connection_duration=15.0,
                error="Timeout",
                score=0.0,
            )
        except Exception as e:
            return TestResult(
                strategy_name=strategy_name,
                domain=domain,
                success=False,
                latency_ms=time.time() - start_time,
                data_transferred=0,
                connection_duration=time.time() - start_time,
                error=str(e),
                score=0.0,
            )

    async def find_best_strategy_for_domain(
        self, domain: str, max_tests: int = 20
    ) -> Dict:
        """Находит лучшую стратегию для домена с улучшенным алгоритмом."""
        LOG.info(f"Поиск лучшей стратегии для {domain}")

        # Сначала тестируем простые проверенные стратегии
        simple_strategies = [a for a in self.available_attacks if a.complexity <= 2]

        # Приоритизируем стратегии по домену
        domain_priorities = self._get_domain_strategy_priorities(domain)

        # Сортируем стратегии по приоритету для домена
        prioritized_attacks = sorted(
            simple_strategies,
            key=lambda x: domain_priorities.get(x.name, 0),
            reverse=True,
        )

        # Ограничиваем количество тестов
        test_attacks = prioritized_attacks[:max_tests]

        results = []

        print(
            f"\n🔍 Адаптивное тестирование {len(test_attacks)} стратегий для {domain}:"
        )
        print(f"{'Стратегия':<30} {'Результат':<10} {'Задержка':<10} {'Оценка'}")
        print("-" * 70)

        # Тестируем стратегии с адаптивным подходом
        for i, attack in enumerate(test_attacks):
            strategy_string = self._single_attack_to_zapret(attack)
            result = await self.test_strategy(domain, strategy_string, attack.name)
            results.append(result)

            # Выводим прогресс
            status = "✅ Успех" if result.success else "❌ Неудача"
            print(
                f"{attack.name:<30} {status:<10} {result.latency_ms:<10.0f} {result.score:<.1f}"
            )

            # Если нашли успешную стратегию, можем попробовать улучшить её
            if result.success and result.score > 80:
                # Попробуем вариации успешной стратегии
                variations = self._generate_strategy_variations(attack)
                for variation in variations[:3]:  # Максимум 3 вариации
                    var_strategy = self._single_attack_to_zapret(variation)
                    var_result = await self.test_strategy(
                        domain, var_strategy, f"{attack.name}_var"
                    )
                    results.append(var_result)

                    var_status = "✅ Успех" if var_result.success else "❌ Неудача"
                    print(
                        f"{f'{attack.name}_var':<30} {var_status:<10} {var_result.latency_ms:<10.0f} {var_result.score:<.1f}"
                    )

            # Небольшая пауза между тестами
            await asyncio.sleep(0.3)

        # Находим лучший результат
        successful_results = [r for r in results if r.success]

        if successful_results:
            # Сортируем по оценке и выбираем лучший
            best_result = max(successful_results, key=lambda x: x.score)

            return {
                "domain": domain,
                "best_strategy": {"name": best_result.strategy_name},
                "best_result": best_result,
                "all_results": results,
                "success_rate": len(successful_results) / len(results) * 100,
                "zapret_string": self._find_strategy_string_by_name(
                    best_result.strategy_name
                ),
                "adaptive_insights": self._generate_adaptive_insights(results, domain),
            }
        else:
            return {
                "domain": domain,
                "best_strategy": None,
                "best_result": None,
                "all_results": results,
                "success_rate": 0.0,
                "zapret_string": None,
                "adaptive_insights": {
                    "recommendation": "Try different network conditions or DPI detection"
                },
            }

    def _get_domain_strategy_priorities(self, domain: str) -> Dict[str, int]:
        """Возвращает приоритеты стратегий для конкретного домена."""
        priorities = {}

        # Базовые приоритеты для всех доменов
        base_priorities = {
            "fakeddisorder_basic": 10,
            "multisplit_conservative": 9,
            "conservative_bypass": 8,
            "fakeddisorder_seqovl": 7,
            "multisplit_aggressive": 6,
        }

        # Специфичные приоритеты по доменам
        if "x.com" in domain or "twitter" in domain or "twimg.com" in domain:
            twitter_priorities = {
                "twitter_optimized": 15,
                "multisplit_aggressive": 12,
                "fakeddisorder_seqovl": 10,
            }
            priorities.update(twitter_priorities)

        elif "instagram.com" in domain:
            instagram_priorities = {
                "instagram_optimized": 15,
                "multisplit_conservative": 12,
                "fakeddisorder_basic": 10,
            }
            priorities.update(instagram_priorities)

        elif "rutracker" in domain or "torrent" in domain:
            torrent_priorities = {
                "fakeddisorder_seqovl": 15,
                "multisplit_aggressive": 12,
                "seqovl_standard": 10,
            }
            priorities.update(torrent_priorities)

        # Объединяем с базовыми приоритетами
        for name, priority in base_priorities.items():
            if name not in priorities:
                priorities[name] = priority

        return priorities

    def _generate_strategy_variations(
        self, base_attack: AttackConfig
    ) -> List[AttackConfig]:
        """Генерирует вариации успешной стратегии."""
        variations = []

        # Вариация TTL
        if "ttl" in base_attack.params:
            ttl_var = AttackConfig(
                name=f"{base_attack.name}_ttl_var",
                method=base_attack.method,
                params={**base_attack.params, "ttl": base_attack.params["ttl"] + 1},
                description=f"{base_attack.description} (TTL+1)",
                complexity=base_attack.complexity,
            )
            variations.append(ttl_var)

        # Вариация fooling методов
        if (
            "fooling" in base_attack.params
            and base_attack.params["fooling"] == "badsum"
        ):
            fooling_var = AttackConfig(
                name=f"{base_attack.name}_fooling_var",
                method=base_attack.method,
                params={**base_attack.params, "fooling": "badseq"},
                description=f"{base_attack.description} (badseq)",
                complexity=base_attack.complexity,
            )
            variations.append(fooling_var)

        # Вариация repeats
        if base_attack.method in ["multisplit", "fake"]:
            repeats_var = AttackConfig(
                name=f"{base_attack.name}_repeats_var",
                method=base_attack.method,
                params={**base_attack.params, "repeats": 2},
                description=f"{base_attack.description} (repeats=2)",
                complexity=base_attack.complexity,
            )
            variations.append(repeats_var)

        return variations

    def _find_strategy_string_by_name(self, strategy_name: str) -> str:
        """Находит строку стратегии по имени."""
        for attack in self.available_attacks:
            if attack.name == strategy_name or strategy_name.startswith(attack.name):
                return self._single_attack_to_zapret(attack)

        # Fallback стратегия
        return "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3"

    def _generate_adaptive_insights(
        self, results: List[TestResult], domain: str
    ) -> Dict:
        """Генерирует адаптивные инсайты на основе результатов."""
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        insights = {
            "total_tested": len(results),
            "success_count": len(successful),
            "failure_count": len(failed),
            "domain_type": self._classify_domain_type(domain),
        }

        if successful:
            insights["best_methods"] = list(
                set([r.strategy_name.split("_")[0] for r in successful])
            )
            insights["avg_successful_latency"] = sum(
                r.latency_ms for r in successful
            ) / len(successful)
            insights["recommendation"] = (
                "Found working strategies, consider optimizing parameters"
            )
        else:
            insights["recommendation"] = (
                "No strategies worked, may need different approach or network analysis"
            )
            if failed:
                common_errors = [r.error for r in failed if r.error]
                if common_errors:
                    insights["common_errors"] = list(set(common_errors))

        return insights

    def _classify_domain_type(self, domain: str) -> str:
        """Классифицирует тип домена для адаптивных рекомендаций."""
        if any(
            social in domain for social in ["x.com", "twitter", "instagram", "facebook"]
        ):
            return "social_media"
        elif any(torrent in domain for torrent in ["rutracker", "torrent", "tracker"]):
            return "torrent"
        elif any(tech in domain for tech in ["github", "stackoverflow", "google"]):
            return "tech"
        elif any(media in domain for media in ["youtube", "video", "stream"]):
            return "media"
        else:
            return "general"

    async def optimize_multiple_domains(
        self, domains: List[str], max_tests_per_domain: int = 15
    ) -> Dict:
        """Оптимизирует стратегии для множества доменов с адаптивным обучением."""
        LOG.info(f"Адаптивная оптимизация стратегий для {len(domains)} доменов")

        results = {}
        learned_patterns = {}  # Паттерны успешных стратегий

        for i, domain in enumerate(domains):
            print(f"\n🎯 === Оптимизация для {domain} ({i+1}/{len(domains)}) ===")

            # Адаптируем количество тестов на основе предыдущих результатов
            adaptive_max_tests = self._calculate_adaptive_test_count(
                learned_patterns, domain, max_tests_per_domain
            )

            domain_result = await self.find_best_strategy_for_domain(
                domain, adaptive_max_tests
            )
            results[domain] = domain_result

            # Обновляем обученные паттерны
            if domain_result["best_strategy"]:
                self._update_learned_patterns(learned_patterns, domain, domain_result)

                print(
                    f"✅ Найдена лучшая стратегия: {domain_result['best_strategy']['name']}"
                )
                print(f"   Оценка: {domain_result['best_result'].score:.1f}")
                print(f"   Успешность: {domain_result['success_rate']:.1f}%")
                print(f"   Задержка: {domain_result['best_result'].latency_ms:.1f}ms")

                # Показываем адаптивные инсайты
                if "adaptive_insights" in domain_result:
                    insights = domain_result["adaptive_insights"]
                    print(f"   Тип домена: {insights.get('domain_type', 'unknown')}")
                    if "best_methods" in insights:
                        print(
                            f"   Лучшие методы: {', '.join(insights['best_methods'])}"
                        )
            else:
                print("❌ Рабочая стратегия не найдена")
                if "adaptive_insights" in domain_result:
                    insights = domain_result["adaptive_insights"]
                    print(f"   Рекомендация: {insights.get('recommendation', 'N/A')}")

            # Показываем прогресс обучения
            if learned_patterns:
                success_rate = sum(
                    1 for r in results.values() if r["best_strategy"]
                ) / len(results)
                print(f"   📊 Общий прогресс: {success_rate:.1%} успешных доменов")

        # Генерируем общие рекомендации
        general_recommendations = self._generate_general_recommendations(
            results, learned_patterns
        )

        return {
            "domain_results": results,
            "learned_patterns": learned_patterns,
            "general_recommendations": general_recommendations,
            "optimization_summary": self._generate_optimization_summary(results),
        }

    def _calculate_adaptive_test_count(
        self, learned_patterns: Dict, domain: str, base_max: int
    ) -> int:
        """Вычисляет адаптивное количество тестов на основе обученных паттернов."""
        domain_type = self._classify_domain_type(domain)

        # Если у нас есть успешные паттерны для этого типа домена
        if (
            domain_type in learned_patterns
            and learned_patterns[domain_type]["success_count"] > 0
        ):
            # Уменьшаем количество тестов, так как знаем что работает
            return max(5, base_max // 2)
        else:
            # Увеличиваем для неизвестных типов
            return min(base_max + 5, 25)

    def _update_learned_patterns(
        self, learned_patterns: Dict, domain: str, result: Dict
    ):
        """Обновляет обученные паттерны на основе успешного результата."""
        domain_type = self._classify_domain_type(domain)

        if domain_type not in learned_patterns:
            learned_patterns[domain_type] = {
                "success_count": 0,
                "successful_strategies": [],
                "avg_latency": 0,
                "best_methods": set(),
            }

        pattern = learned_patterns[domain_type]
        pattern["success_count"] += 1
        pattern["successful_strategies"].append(result["best_strategy"]["name"])

        # Обновляем среднюю задержку
        current_latency = result["best_result"].latency_ms
        pattern["avg_latency"] = (
            pattern["avg_latency"] * (pattern["success_count"] - 1) + current_latency
        ) / pattern["success_count"]

        # Добавляем успешный метод
        strategy_method = result["best_strategy"]["name"].split("_")[0]
        pattern["best_methods"].add(strategy_method)

    def _generate_general_recommendations(
        self, results: Dict, learned_patterns: Dict
    ) -> Dict:
        """Генерирует общие рекомендации на основе всех результатов."""
        all_results = (
            results
            if isinstance(results, dict) and "domain_results" not in results
            else results.get("domain_results", results)
        )

        successful_domains = [r for r in all_results.values() if r["best_strategy"]]
        total_domains = len(all_results)

        recommendations = {
            "overall_success_rate": (
                len(successful_domains) / total_domains if total_domains > 0 else 0
            ),
            "total_domains_tested": total_domains,
            "successful_domains": len(successful_domains),
        }

        if successful_domains:
            # Анализируем наиболее успешные методы
            method_counts = {}
            for result in successful_domains:
                method = result["best_strategy"]["name"].split("_")[0]
                method_counts[method] = method_counts.get(method, 0) + 1

            recommendations["most_successful_methods"] = sorted(
                method_counts.items(), key=lambda x: x[1], reverse=True
            )[:3]

            # Средняя задержка успешных стратегий
            avg_latency = sum(
                r["best_result"].latency_ms for r in successful_domains
            ) / len(successful_domains)
            recommendations["avg_successful_latency"] = avg_latency

            # Рекомендации по типам доменов
            recommendations["domain_type_insights"] = {}
            for domain_type, pattern in learned_patterns.items():
                if pattern["success_count"] > 0:
                    recommendations["domain_type_insights"][domain_type] = {
                        "success_count": pattern["success_count"],
                        "best_methods": list(pattern["best_methods"]),
                        "avg_latency": pattern["avg_latency"],
                    }

        return recommendations

    def _generate_optimization_summary(self, results: Dict) -> Dict:
        """Генерирует сводку оптимизации."""
        all_results = (
            results
            if isinstance(results, dict) and "domain_results" not in results
            else results.get("domain_results", results)
        )

        successful = [r for r in all_results.values() if r["best_strategy"]]
        failed = [r for r in all_results.values() if not r["best_strategy"]]

        return {
            "total_domains": len(all_results),
            "successful_domains": len(successful),
            "failed_domains": len(failed),
            "success_rate": len(successful) / len(all_results) if all_results else 0,
            "avg_tests_per_domain": (
                sum(len(r["all_results"]) for r in all_results.values())
                / len(all_results)
                if all_results
                else 0
            ),
            "total_strategy_tests": sum(
                len(r["all_results"]) for r in all_results.values()
            ),
        }

    def generate_optimized_config(self, optimization_results: Dict) -> Dict:
        """Генерирует интеллектуальную оптимизированную конфигурацию."""
        # Обрабатываем результаты в зависимости от структуры
        if "domain_results" in optimization_results:
            domain_results = optimization_results["domain_results"]
            learned_patterns = optimization_results.get("learned_patterns", {})
            recommendations = optimization_results.get("general_recommendations", {})
        else:
            domain_results = optimization_results
            learned_patterns = {}
            recommendations = {}

        config = {
            "version": "4.1_adaptive_intelligent",
            "generated_at": time.time(),
            "generator": "AdaptiveStrategyFinder",
            "optimization_summary": {
                "total_domains": len(domain_results),
                "successful_domains": len(
                    [r for r in domain_results.values() if r["best_strategy"]]
                ),
                "average_success_rate": (
                    sum(r["success_rate"] for r in domain_results.values())
                    / len(domain_results)
                    if domain_results
                    else 0
                ),
                "learned_patterns_count": len(learned_patterns),
            },
            "strategies": {},
            "fallback_strategies": {},
            "domain_patterns": {},
            "adaptive_recommendations": recommendations,
        }

        # Генерируем стратегии для каждого домена
        for domain, result in domain_results.items():
            if result["best_strategy"]:
                config["strategies"][domain] = result["zapret_string"]

                # Добавляем метаданные
                config["domain_patterns"][domain] = {
                    "success_rate": result["success_rate"],
                    "best_latency": result["best_result"].latency_ms,
                    "strategy_type": result["best_strategy"]["name"],
                    "domain_type": result.get("adaptive_insights", {}).get(
                        "domain_type", "unknown"
                    ),
                    "confidence": self._calculate_strategy_confidence(result),
                }
            else:
                # Интеллектуальная fallback стратегия на основе типа домена
                domain_type = self._classify_domain_type(domain)
                fallback_strategy = self._get_intelligent_fallback(
                    domain_type, learned_patterns
                )
                config["strategies"][domain] = fallback_strategy

                config["domain_patterns"][domain] = {
                    "success_rate": 0,
                    "strategy_type": "fallback",
                    "domain_type": domain_type,
                    "confidence": 0.1,
                    "note": "No successful strategy found, using intelligent fallback",
                }

        # Генерируем fallback стратегии по типам доменов
        for domain_type, pattern in learned_patterns.items():
            if pattern["success_count"] > 0:
                best_method = max(
                    pattern["best_methods"],
                    key=lambda x: pattern["successful_strategies"].count(x),
                )
                config["fallback_strategies"][domain_type] = (
                    self._generate_fallback_for_method(best_method)
                )

        # Добавляем глобальные рекомендации
        if recommendations:
            config["global_insights"] = {
                "most_successful_methods": recommendations.get(
                    "most_successful_methods", []
                ),
                "avg_successful_latency": recommendations.get(
                    "avg_successful_latency", 0
                ),
                "domain_type_insights": recommendations.get("domain_type_insights", {}),
            }

        return config

    def _calculate_strategy_confidence(self, result: Dict) -> float:
        """Вычисляет уверенность в стратегии на основе результатов."""
        if not result["best_result"]:
            return 0.0

        # Базовая уверенность на основе успешности
        base_confidence = result["success_rate"] / 100.0

        # Бонус за низкую задержку
        latency_bonus = max(0, (500 - result["best_result"].latency_ms) / 500 * 0.2)

        # Бонус за высокую оценку
        score_bonus = result["best_result"].score / 100.0 * 0.3

        # Штраф за малое количество тестов
        test_count = len(result["all_results"])
        test_penalty = 0 if test_count >= 5 else (5 - test_count) * 0.1

        confidence = min(
            1.0, base_confidence + latency_bonus + score_bonus - test_penalty
        )
        return round(confidence, 2)

    def _get_intelligent_fallback(
        self, domain_type: str, learned_patterns: Dict
    ) -> str:
        """Возвращает интеллектуальную fallback стратегию для типа домена."""
        # Если есть обученные паттерны для этого типа
        if (
            domain_type in learned_patterns
            and learned_patterns[domain_type]["success_count"] > 0
        ):
            pattern = learned_patterns[domain_type]
            best_method = max(
                pattern["best_methods"],
                key=lambda x: pattern["successful_strategies"].count(x),
            )
            return self._generate_fallback_for_method(best_method)

        # Стандартные fallback стратегии по типам
        fallback_strategies = {
            "social_media": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "torrent": "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1",
            "tech": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "media": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-ttl=4",
            "general": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
        }

        return fallback_strategies.get(domain_type, fallback_strategies["general"])

    def _generate_fallback_for_method(self, method: str) -> str:
        """Генерирует fallback стратегию для конкретного метода."""
        method_strategies = {
            "fakeddisorder": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "multisplit": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "multidisorder": "--dpi-desync=multidisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "seqovl": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "conservative": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=10 --dpi-desync-ttl=3",
        }

        return method_strategies.get(method, method_strategies["fakeddisorder"])

    def save_results(
        self, results: Dict, filename: str = "adaptive_optimization_results.json"
    ):
        """Сохраняет результаты оптимизации."""
        # Конвертируем TestResult объекты в словари
        serializable_results = {}
        for domain, result in results.items():
            serializable_result = result.copy()
            if serializable_result["best_result"]:
                serializable_result["best_result"] = asdict(
                    serializable_result["best_result"]
                )
            serializable_result["all_results"] = [
                asdict(r) for r in serializable_result["all_results"]
            ]
            serializable_results[domain] = serializable_result

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(serializable_results, f, indent=2, ensure_ascii=False)

        LOG.info(f"Результаты сохранены в {filename}")


async def main():
    """Главная функция для демонстрации адаптивного поиска."""
    finder = AdaptiveStrategyFinder()

    # Тестовые домены
    test_domains = ["x.com", "instagram.com", "rutracker.org"]

    print("🚀 === Адаптивный поиск оптимальных стратегий ===")
    print(f"Доступно атак: {len(finder.available_attacks)}")
    print(f"Тестируемые домены: {', '.join(test_domains)}")

    try:
        # Запускаем оптимизацию
        results = await finder.optimize_multiple_domains(
            test_domains, max_tests_per_domain=10
        )

        # Генерируем конфигурацию
        config = finder.generate_optimized_config(results)

        # Сохраняем результаты
        finder.save_results(results)

        with open("adaptive_strategies.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        print("\n🎉 === Оптимизация завершена ===")
        print(
            f"Успешных доменов: {config['optimization_summary']['successful_domains']}/{config['optimization_summary']['total_domains']}"
        )
        print(
            f"Средняя успешность: {config['optimization_summary']['average_success_rate']:.1f}%"
        )
        print("Конфигурация сохранена в adaptive_strategies.json")

    except KeyboardInterrupt:
        print("\n⏹️ Оптимизация прервана пользователем")
    except Exception as e:
        LOG.error(f"Ошибка оптимизации: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
