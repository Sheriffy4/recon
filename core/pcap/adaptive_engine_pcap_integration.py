"""
Интеграция PCAP анализа в AdaptiveEngine

Задача 7.3: Интегрировать PCAP-анализ в AdaptiveEngine
- Автоматический запуск PCAP анализа после неудачных попыток
- Сохранение и загрузка результатов PCAP анализа
- Корреляция PCAP данных с историческими успехами
- Интеграция с существующим Strategy Failure Analyzer
- Передача результатов PCAP анализа в Strategy Generator
"""

import asyncio
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import asdict
from datetime import datetime, timedelta

# Импорт PCAP компонентов
try:
    from .intelligent_pcap_analyzer import IntelligentPCAPAnalyzer, PCAPAnalysisResult, BlockingType
    from .pcap_strategy_generator import PCAPStrategyGenerator, PCAPGeneratedStrategy

    PCAP_COMPONENTS_AVAILABLE = True
except ImportError:
    PCAP_COMPONENTS_AVAILABLE = False
    IntelligentPCAPAnalyzer = None
    PCAPStrategyGenerator = None

LOG = logging.getLogger("AdaptiveEnginePCAPIntegration")


class AdaptiveEnginePCAPIntegration:
    """
    Интеграция PCAP анализа в AdaptiveEngine

    Обеспечивает:
    - Автоматический анализ PCAP после неудач
    - Генерацию стратегий на основе PCAP
    - Корреляцию с историческими данными
    - Кэширование результатов анализа
    """

    def __init__(self, adaptive_engine):
        self.adaptive_engine = adaptive_engine

        # Инициализация PCAP компонентов
        if PCAP_COMPONENTS_AVAILABLE:
            self.pcap_analyzer = IntelligentPCAPAnalyzer()
            self.strategy_generator = PCAPStrategyGenerator()
            self.pcap_enabled = True
        else:
            self.pcap_analyzer = None
            self.strategy_generator = None
            self.pcap_enabled = False
            LOG.warning("⚠️ PCAP компоненты недоступны")

        # Кэш результатов анализа
        self.analysis_cache_file = "pcap_analysis_cache.json"
        self.analysis_cache = self._load_analysis_cache()

        # Статистика интеграции
        self.integration_stats = {
            "pcap_analyses_performed": 0,
            "strategies_generated_from_pcap": 0,
            "successful_pcap_correlations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }

        LOG.info(f"✅ PCAP интеграция инициализирована (enabled: {self.pcap_enabled})")

    async def analyze_failure_with_pcap(
        self, domain: str, strategy: Any, test_result: Dict[str, Any]
    ) -> Optional[PCAPAnalysisResult]:
        """
        Анализ неудачи с использованием PCAP данных

        Args:
            domain: Доменное имя
            strategy: Стратегия которая не сработала
            test_result: Результат тестирования

        Returns:
            Результат PCAP анализа или None
        """
        if not self.pcap_enabled:
            LOG.debug("PCAP анализ отключен")
            return None

        try:
            # Получаем PCAP файл из результата тестирования
            pcap_file = test_result.get("pcap_file")
            if not pcap_file or not Path(pcap_file).exists():
                LOG.debug(f"PCAP файл недоступен: {pcap_file}")
                return None

            LOG.info(
                f"🔍 Запуск PCAP анализа для {domain} после неудачи стратегии {getattr(strategy, 'name', 'unknown')}"
            )

            # Проверяем кэш
            cache_key = self._get_cache_key(pcap_file, domain)
            if cache_key in self.analysis_cache:
                LOG.debug("📋 Используем кэшированный PCAP анализ")
                self.integration_stats["cache_hits"] += 1
                return self._deserialize_analysis_result(self.analysis_cache[cache_key])

            # Выполняем анализ
            start_time = time.time()
            analysis_result = await self.pcap_analyzer.analyze_pcap_file(
                pcap_file, domain, self._create_strategy_context(strategy)
            )
            analysis_time = time.time() - start_time

            # Кэшируем результат
            self.analysis_cache[cache_key] = self._serialize_analysis_result(analysis_result)
            self._save_analysis_cache()
            self.integration_stats["cache_misses"] += 1

            # Обновляем статистику
            self.integration_stats["pcap_analyses_performed"] += 1

            LOG.info(
                f"✅ PCAP анализ завершен за {analysis_time:.2f}s: "
                f"{analysis_result.blocking_type.value} (confidence: {analysis_result.confidence:.2f})"
            )

            return analysis_result

        except Exception as e:
            LOG.error(f"❌ Ошибка PCAP анализа: {e}")
            return None

    async def generate_strategies_from_pcap(
        self, pcap_analysis: PCAPAnalysisResult, max_strategies: int = 5
    ) -> List[PCAPGeneratedStrategy]:
        """
        Генерация стратегий на основе PCAP анализа

        Args:
            pcap_analysis: Результат PCAP анализа
            max_strategies: Максимальное количество стратегий

        Returns:
            Список сгенерированных стратегий
        """
        if not self.pcap_enabled or not pcap_analysis:
            return []

        try:
            LOG.info(f"🎯 Генерация стратегий на основе PCAP анализа для {pcap_analysis.domain}")

            strategies = await self.strategy_generator.generate_strategies_from_pcap(
                pcap_analysis, max_strategies
            )

            # Обновляем статистику
            self.integration_stats["strategies_generated_from_pcap"] += len(strategies)

            LOG.info(f"✅ Сгенерировано {len(strategies)} стратегий на основе PCAP")

            return strategies

        except Exception as e:
            LOG.error(f"❌ Ошибка генерации стратегий из PCAP: {e}")
            return []

    async def correlate_with_historical_data(
        self, pcap_analysis: PCAPAnalysisResult
    ) -> Dict[str, Any]:
        """
        Корреляция PCAP данных с историческими успехами

        Args:
            pcap_analysis: Результат PCAP анализа

        Returns:
            Данные корреляции
        """
        try:
            correlation_data = {
                "domain": pcap_analysis.domain,
                "blocking_type": pcap_analysis.blocking_type.value,
                "similar_cases": [],
                "successful_strategies": [],
                "recommendations": [],
            }

            # Ищем похожие случаи в кэше
            similar_cases = self._find_similar_cases(pcap_analysis)
            correlation_data["similar_cases"] = similar_cases

            # Ищем успешные стратегии для похожих блокировок
            if hasattr(self.adaptive_engine, "best_strategies"):
                successful_strategies = self._find_successful_strategies_for_blocking_type(
                    pcap_analysis.blocking_type
                )
                correlation_data["successful_strategies"] = successful_strategies

            # Генерируем рекомендации на основе корреляции
            if similar_cases or successful_strategies:
                correlation_data["recommendations"] = self._generate_correlation_recommendations(
                    pcap_analysis, similar_cases, successful_strategies
                )
                self.integration_stats["successful_pcap_correlations"] += 1

            LOG.info(
                f"🔗 Корреляция завершена: {len(similar_cases)} похожих случаев, "
                f"{len(successful_strategies)} успешных стратегий"
            )

            return correlation_data

        except Exception as e:
            LOG.error(f"❌ Ошибка корреляции: {e}")
            return {}

    def _create_strategy_context(self, strategy: Any) -> Dict[str, Any]:
        """Создание контекста стратегии для анализа"""
        context = {
            "strategy_name": getattr(strategy, "name", "unknown"),
            "timestamp": datetime.now().isoformat(),
        }

        if hasattr(strategy, "attack_combination"):
            context["attacks"] = strategy.attack_combination
        elif hasattr(strategy, "attack_name"):
            context["attacks"] = [strategy.attack_name]

        if hasattr(strategy, "parameters"):
            context["parameters"] = strategy.parameters

        return context

    def _find_similar_cases(self, pcap_analysis: PCAPAnalysisResult) -> List[Dict[str, Any]]:
        """Поиск похожих случаев в кэше анализа"""
        similar_cases = []

        try:
            for cache_key, cached_data in self.analysis_cache.items():
                cached_analysis = self._deserialize_analysis_result(cached_data)

                # Проверяем схожесть
                if (
                    cached_analysis.blocking_type == pcap_analysis.blocking_type
                    and cached_analysis.domain != pcap_analysis.domain
                    and abs(cached_analysis.confidence - pcap_analysis.confidence) < 0.3
                ):

                    similar_case = {
                        "domain": cached_analysis.domain,
                        "blocking_type": cached_analysis.blocking_type.value,
                        "confidence": cached_analysis.confidence,
                        "analyzed_at": cached_analysis.analyzed_at.isoformat(),
                        "similarity_score": self._calculate_similarity_score(
                            pcap_analysis, cached_analysis
                        ),
                    }
                    similar_cases.append(similar_case)

            # Сортируем по схожести
            similar_cases.sort(key=lambda x: x["similarity_score"], reverse=True)

        except Exception as e:
            LOG.error(f"❌ Ошибка поиска похожих случаев: {e}")

        return similar_cases[:5]  # Топ 5 похожих случаев

    def _calculate_similarity_score(
        self, analysis1: PCAPAnalysisResult, analysis2: PCAPAnalysisResult
    ) -> float:
        """Вычисление оценки схожести между анализами"""
        score = 0.0

        # Схожесть типа блокировки
        if analysis1.blocking_type == analysis2.blocking_type:
            score += 0.5

        # Схожесть confidence
        confidence_diff = abs(analysis1.confidence - analysis2.confidence)
        score += max(0, 0.3 - confidence_diff)

        # Схожесть количества DPI сигнатур
        sig_count_diff = abs(len(analysis1.dpi_signatures) - len(analysis2.dpi_signatures))
        score += max(0, 0.2 - sig_count_diff * 0.05)

        return min(score, 1.0)

    def _find_successful_strategies_for_blocking_type(
        self, blocking_type: BlockingType
    ) -> List[Dict[str, Any]]:
        """Поиск успешных стратегий для типа блокировки"""
        successful_strategies = []

        try:
            if hasattr(self.adaptive_engine, "best_strategies"):
                for domain, strategy in self.adaptive_engine.best_strategies.items():
                    # Здесь нужна логика сопоставления стратегии с типом блокировки
                    # Пока используем простую эвристику
                    strategy_info = {
                        "domain": domain,
                        "strategy_name": getattr(strategy, "name", "unknown"),
                        "success_rate": 1.0,  # Эти стратегии уже успешны
                    }

                    if hasattr(strategy, "attack_combination"):
                        strategy_info["attacks"] = strategy.attack_combination
                    elif hasattr(strategy, "attack_name"):
                        strategy_info["attacks"] = [strategy.attack_name]

                    if hasattr(strategy, "parameters"):
                        strategy_info["parameters"] = strategy.parameters

                    successful_strategies.append(strategy_info)

        except Exception as e:
            LOG.error(f"❌ Ошибка поиска успешных стратегий: {e}")

        return successful_strategies[:10]  # Топ 10 успешных стратегий

    def _generate_correlation_recommendations(
        self,
        pcap_analysis: PCAPAnalysisResult,
        similar_cases: List[Dict],
        successful_strategies: List[Dict],
    ) -> List[str]:
        """Генерация рекомендаций на основе корреляции"""
        recommendations = []

        # Рекомендации на основе похожих случаев
        if similar_cases:
            recommendations.append(f"Найдено {len(similar_cases)} похожих случаев блокировки")

            # Анализируем общие паттерны
            blocking_types = [case["blocking_type"] for case in similar_cases]
            most_common_type = max(set(blocking_types), key=blocking_types.count)
            recommendations.append(f"Наиболее частый тип блокировки: {most_common_type}")

        # Рекомендации на основе успешных стратегий
        if successful_strategies:
            attack_counts = {}
            for strategy in successful_strategies:
                for attack in strategy.get("attacks", []):
                    attack_counts[attack] = attack_counts.get(attack, 0) + 1

            if attack_counts:
                most_effective_attack = max(attack_counts.keys(), key=lambda k: attack_counts[k])
                recommendations.append(f"Наиболее эффективная атака: {most_effective_attack}")

        # Специфичные рекомендации для типа блокировки
        if pcap_analysis.blocking_type == BlockingType.RST_INJECTION:
            recommendations.append("Для RST инъекций рекомендуется использовать низкий TTL")
        elif pcap_analysis.blocking_type == BlockingType.SNI_FILTERING:
            recommendations.append("Для SNI фильтрации рекомендуется фрагментация TLS")

        return recommendations

    def _load_analysis_cache(self) -> Dict[str, Any]:
        """Загрузка кэша анализа из файла"""
        try:
            if Path(self.analysis_cache_file).exists():
                with open(self.analysis_cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                LOG.info(f"📁 Загружен кэш PCAP анализа: {len(cache_data)} записей")
                return cache_data
        except Exception as e:
            LOG.warning(f"⚠️ Ошибка загрузки кэша анализа: {e}")

        return {}

    def _save_analysis_cache(self):
        """Сохранение кэша анализа в файл"""
        try:
            # Ограничиваем размер кэша
            if len(self.analysis_cache) > 1000:
                # Удаляем старые записи
                sorted_items = sorted(
                    self.analysis_cache.items(),
                    key=lambda x: x[1].get("analyzed_at", ""),
                    reverse=True,
                )
                self.analysis_cache = dict(sorted_items[:800])

            with open(self.analysis_cache_file, "w", encoding="utf-8") as f:
                json.dump(self.analysis_cache, f, indent=2, ensure_ascii=False, default=str)

        except Exception as e:
            LOG.error(f"❌ Ошибка сохранения кэша анализа: {e}")

    def _get_cache_key(self, pcap_file: str, domain: str) -> str:
        """Генерация ключа кэша для PCAP анализа"""
        file_stat = Path(pcap_file).stat() if Path(pcap_file).exists() else None
        key_data = f"{pcap_file}:{domain}:{file_stat.st_mtime if file_stat else 0}"
        import hashlib

        return hashlib.md5(key_data.encode()).hexdigest()

    def _serialize_analysis_result(self, analysis_result: PCAPAnalysisResult) -> Dict[str, Any]:
        """Сериализация результата анализа для кэширования"""
        try:
            return {
                "pcap_file": analysis_result.pcap_file,
                "domain": analysis_result.domain,
                "blocking_detected": analysis_result.blocking_detected,
                "blocking_type": analysis_result.blocking_type.value,
                "confidence": analysis_result.confidence,
                "dpi_signatures": [asdict(sig) for sig in analysis_result.dpi_signatures],
                "analysis_details": analysis_result.analysis_details,
                "recommendations": analysis_result.recommendations,
                "analyzed_at": analysis_result.analyzed_at.isoformat(),
            }
        except Exception as e:
            LOG.error(f"❌ Ошибка сериализации результата анализа: {e}")
            return {}

    def _deserialize_analysis_result(self, cached_data: Dict[str, Any]) -> PCAPAnalysisResult:
        """Десериализация результата анализа из кэша"""
        try:
            # Восстанавливаем BlockingType
            blocking_type = BlockingType(cached_data["blocking_type"])

            # Восстанавливаем DPI сигнатуры
            dpi_signatures = []
            for sig_data in cached_data.get("dpi_signatures", []):
                # Здесь нужно восстановить DPISignature объекты
                # Упрощенная версия без полного восстановления
                pass

            # Восстанавливаем datetime
            analyzed_at = datetime.fromisoformat(cached_data["analyzed_at"])

            return PCAPAnalysisResult(
                pcap_file=cached_data["pcap_file"],
                domain=cached_data["domain"],
                blocking_detected=cached_data["blocking_detected"],
                blocking_type=blocking_type,
                confidence=cached_data["confidence"],
                dpi_signatures=dpi_signatures,
                analysis_details=cached_data.get("analysis_details", {}),
                recommendations=cached_data.get("recommendations", []),
                analyzed_at=analyzed_at,
            )

        except Exception as e:
            LOG.error(f"❌ Ошибка десериализации результата анализа: {e}")
            # Возвращаем пустой результат
            return PCAPAnalysisResult(
                pcap_file="",
                domain="",
                blocking_detected=False,
                blocking_type=BlockingType.UNKNOWN,
                confidence=0.0,
            )

    async def integrate_with_strategy_failure_analyzer(
        self, failure_analyzer, pcap_analysis: PCAPAnalysisResult
    ) -> Dict[str, Any]:
        """
        Интеграция с существующим Strategy Failure Analyzer

        Args:
            failure_analyzer: Экземпляр StrategyFailureAnalyzer
            pcap_analysis: Результат PCAP анализа

        Returns:
            Объединенные результаты анализа
        """
        try:
            integration_result = {
                "pcap_analysis": {
                    "blocking_type": pcap_analysis.blocking_type.value,
                    "confidence": pcap_analysis.confidence,
                    "signatures_count": len(pcap_analysis.dpi_signatures),
                    "recommendations": pcap_analysis.recommendations,
                },
                "sfa_integration": {"enhanced_failure_report": True, "pcap_evidence_added": True},
            }

            # Добавляем PCAP данные в failure report
            if hasattr(failure_analyzer, "_last_failure_report"):
                failure_report = failure_analyzer._last_failure_report
                if failure_report:
                    # Обогащаем failure report данными из PCAP
                    if hasattr(failure_report, "failure_details"):
                        failure_report.failure_details.update(
                            {
                                "pcap_blocking_type": pcap_analysis.blocking_type.value,
                                "pcap_confidence": pcap_analysis.confidence,
                                "pcap_signatures": len(pcap_analysis.dpi_signatures),
                                "pcap_recommendations": pcap_analysis.recommendations[:3],
                            }
                        )

                    integration_result["sfa_integration"]["failure_report_enhanced"] = True

            LOG.info("🔗 Интеграция с SFA завершена успешно")
            return integration_result

        except Exception as e:
            LOG.error(f"❌ Ошибка интеграции с SFA: {e}")
            return {}

    async def cleanup_old_pcap_files(self, max_age_hours: int = 24):
        """Очистка старых PCAP файлов"""
        try:
            cleanup_count = 0
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

            # Ищем PCAP файлы в кэше
            for cache_key, cached_data in list(self.analysis_cache.items()):
                try:
                    analyzed_at = datetime.fromisoformat(cached_data["analyzed_at"])
                    pcap_file = cached_data["pcap_file"]

                    if analyzed_at < cutoff_time and Path(pcap_file).exists():
                        # Удаляем файл
                        Path(pcap_file).unlink()
                        # Удаляем из кэша
                        del self.analysis_cache[cache_key]
                        cleanup_count += 1

                except Exception as e:
                    LOG.debug(f"Ошибка очистки {cache_key}: {e}")

            if cleanup_count > 0:
                self._save_analysis_cache()
                LOG.info(f"🧹 Очищено {cleanup_count} старых PCAP файлов")

        except Exception as e:
            LOG.error(f"❌ Ошибка очистки PCAP файлов: {e}")

    def get_integration_statistics(self) -> Dict[str, Any]:
        """Получение статистики интеграции"""
        stats = self.integration_stats.copy()

        # Добавляем статистику компонентов
        if self.pcap_analyzer:
            stats.update({"pcap_analyzer_stats": self.pcap_analyzer.get_analysis_statistics()})

        if self.strategy_generator:
            stats.update(
                {"strategy_generator_stats": self.strategy_generator.get_generation_statistics()}
            )

        # Статистика кэша
        stats.update(
            {
                "cache_size": len(self.analysis_cache),
                "cache_hit_rate": (
                    stats["cache_hits"] / max(stats["cache_hits"] + stats["cache_misses"], 1)
                )
                * 100,
            }
        )

        return stats

    async def export_pcap_analysis_report(self, output_file: str = "pcap_analysis_report.json"):
        """Экспорт отчета по PCAP анализу"""
        try:
            report = {
                "generated_at": datetime.now().isoformat(),
                "integration_statistics": self.get_integration_statistics(),
                "analysis_cache_summary": {
                    "total_analyses": len(self.analysis_cache),
                    "blocking_types_distribution": {},
                    "domains_analyzed": set(),
                    "average_confidence": 0.0,
                },
            }

            # Анализируем кэш для статистики
            confidences = []
            for cached_data in self.analysis_cache.values():
                blocking_type = cached_data.get("blocking_type", "unknown")
                confidence = cached_data.get("confidence", 0.0)
                domain = cached_data.get("domain", "")

                # Распределение типов блокировок
                if (
                    blocking_type
                    not in report["analysis_cache_summary"]["blocking_types_distribution"]
                ):
                    report["analysis_cache_summary"]["blocking_types_distribution"][
                        blocking_type
                    ] = 0
                report["analysis_cache_summary"]["blocking_types_distribution"][blocking_type] += 1

                # Домены
                report["analysis_cache_summary"]["domains_analyzed"].add(domain)

                # Confidence
                confidences.append(confidence)

            # Финализируем статистику
            report["analysis_cache_summary"]["domains_analyzed"] = len(
                report["analysis_cache_summary"]["domains_analyzed"]
            )
            if confidences:
                report["analysis_cache_summary"]["average_confidence"] = sum(confidences) / len(
                    confidences
                )

            # Сохраняем отчет
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)

            LOG.info(f"📊 Отчет PCAP анализа экспортирован в {output_file}")

        except Exception as e:
            LOG.error(f"❌ Ошибка экспорта отчета: {e}")


# Функция для интеграции в AdaptiveEngine
def integrate_pcap_analysis_into_adaptive_engine(adaptive_engine):
    """
    Интеграция PCAP анализа в существующий AdaptiveEngine

    Args:
        adaptive_engine: Экземпляр AdaptiveEngine

    Returns:
        Экземпляр AdaptiveEnginePCAPIntegration
    """
    try:
        pcap_integration = AdaptiveEnginePCAPIntegration(adaptive_engine)

        # Добавляем методы в AdaptiveEngine
        adaptive_engine.pcap_integration = pcap_integration
        adaptive_engine.analyze_failure_with_pcap = pcap_integration.analyze_failure_with_pcap
        adaptive_engine.generate_strategies_from_pcap = (
            pcap_integration.generate_strategies_from_pcap
        )
        adaptive_engine.correlate_pcap_with_history = (
            pcap_integration.correlate_with_historical_data
        )

        LOG.info("✅ PCAP анализ успешно интегрирован в AdaptiveEngine")
        return pcap_integration

    except Exception as e:
        LOG.error(f"❌ Ошибка интеграции PCAP анализа: {e}")
        return None
