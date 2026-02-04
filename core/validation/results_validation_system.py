"""
Results Validation System - система валидации результатов адаптивного мониторинга.

Этот модуль реализует Task 5.3:
- Автоматическую проверку найденных стратегий
- Валидацию DPI fingerprint'ов на точность
- Систему A/B тестирования старого vs нового подхода
- Метрики качества для continuous improvement

Требования: FR-7
"""

import asyncio
import logging
import random
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ab_tester import ABTester
from .config_loader import ValidationConfigLoader
from .fingerprint_validator import FingerprintValidator
from .history_manager import ValidationHistoryManager
from .metrics_calculator import ValidationMetricsCalculator
from .report_generator import ReportGenerator
from .strategy_tester import StrategyTester

LOG = logging.getLogger("ResultsValidationSystem")


class ValidationTestType(Enum):
    """Типы валидационных тестов."""

    STRATEGY_EFFECTIVENESS = "strategy_effectiveness"
    DPI_FINGERPRINT_ACCURACY = "dpi_fingerprint_accuracy"
    AB_TESTING = "ab_testing"
    QUALITY_METRICS = "quality_metrics"
    REGRESSION_TESTING = "regression_testing"


class ValidationStatus(Enum):
    """Статусы валидации."""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StrategyValidationResult:
    """Результат валидации стратегии."""

    strategy_name: str
    domain: str
    success_rate: float
    avg_response_time: float
    consistency_score: float
    reliability_score: float
    test_count: int
    failures: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FingerprintValidationResult:
    """Результат валидации DPI fingerprint."""

    domain: str
    fingerprint_id: str
    accuracy_score: float
    prediction_accuracy: float
    false_positive_rate: float
    false_negative_rate: float
    confidence_calibration: float
    validation_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ABTestResult:
    """Результат A/B тестирования."""

    test_name: str
    control_group: str
    treatment_group: str
    control_success_rate: float
    treatment_success_rate: float
    statistical_significance: float
    effect_size: float
    confidence_interval: Tuple[float, float]
    recommendation: str
    test_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QualityMetrics:
    """Метрики качества системы."""

    timestamp: datetime
    overall_success_rate: float
    avg_trials_to_success: float
    fingerprint_accuracy: float
    strategy_reuse_rate: float
    false_positive_rate: float
    false_negative_rate: float
    system_reliability: float
    performance_score: float
    improvement_trend: float
    detailed_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationReport:
    """Комплексный отчет валидации."""

    report_id: str
    generated_at: datetime
    test_period: Tuple[datetime, datetime]

    # Результаты валидации
    strategy_validations: List[StrategyValidationResult] = field(default_factory=list)
    fingerprint_validations: List[FingerprintValidationResult] = field(default_factory=list)
    ab_test_results: List[ABTestResult] = field(default_factory=list)
    quality_metrics: Optional[QualityMetrics] = None

    # Сводная информация
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    overall_score: float = 0.0

    # Рекомендации
    recommendations: List[str] = field(default_factory=list)
    action_items: List[str] = field(default_factory=list)


class ResultsValidationSystem:
    """
    Система валидации результатов адаптивного мониторинга.

    Основные функции:
    - Автоматическая проверка найденных стратегий на эффективность
    - Валидация точности DPI fingerprint'ов
    - A/B тестирование старого vs нового подхода
    - Сбор и анализ метрик качества
    - Генерация рекомендаций для улучшения
    """

    def __init__(self, config_file: str = "validation_config.json"):
        """
        Инициализация системы валидации.

        Args:
            config_file: Путь к файлу конфигурации
        """
        self.config_loader = ValidationConfigLoader()
        self.config = self.config_loader.load_config(config_file)
        self.results_dir = Path(self.config.get("results_dir", "validation_results"))
        self.results_dir.mkdir(exist_ok=True, parents=True)

        # Инициализация компонентов
        self._init_components()

        # История валидации
        self.history_manager = ValidationHistoryManager()
        self.validation_history = self.history_manager.load_history(
            self.results_dir, ValidationReport
        )

        # Metrics calculator
        self.metrics_calculator = ValidationMetricsCalculator()

        # Strategy tester
        self.strategy_tester = StrategyTester()

        # Fingerprint validator
        self.fingerprint_validator = FingerprintValidator()

        # A/B tester
        self.ab_tester = ABTester()

        # Report generator
        self.report_generator = ReportGenerator(self.results_dir)

        # Статистика
        self.stats = {
            "total_validations": 0,
            "successful_validations": 0,
            "failed_validations": 0,
            "avg_validation_time": 0.0,
        }

        LOG.info("ResultsValidationSystem initialized")

    def _init_components(self):
        """Инициализация компонентов системы."""
        # Попытка импорта адаптивных компонентов
        try:
            from core.strategy_failure_analyzer import StrategyFailureAnalyzer
            from core.fingerprint.dpi_fingerprint_service import DPIFingerprintService

            self.adaptive_engine = None  # Будет создан при необходимости
            self.failure_analyzer = StrategyFailureAnalyzer()
            self.fingerprint_service = DPIFingerprintService()
            self.adaptive_available = True

        except ImportError as e:
            LOG.warning(f"Adaptive components not available: {e}")
            self.adaptive_engine = None
            self.failure_analyzer = None
            self.fingerprint_service = None
            self.adaptive_available = False

        # Попытка импорта движка
        try:
            from core.unified_bypass_engine import UnifiedBypassEngine

            self.bypass_engine = UnifiedBypassEngine()
            self.engine_available = True

            # Опциональный импорт RealDataValidator
            try:
                from core.validate_real_data_integration import RealDataValidator

                self.real_data_validator = RealDataValidator()
            except ImportError:
                self.real_data_validator = None
                LOG.debug("RealDataValidator not available (optional)")

        except ImportError as e:
            LOG.warning(f"Engine components not available: {e}")
            self.bypass_engine = None
            self.real_data_validator = None
            self.engine_available = False

    async def validate_strategy_effectiveness(
        self, strategy_name: str, domain: str, test_count: Optional[int] = None
    ) -> StrategyValidationResult:
        """
        Валидация эффективности стратегии.

        Проводит множественные тесты стратегии для оценки:
        - Успешности (success rate)
        - Консистентности (consistency)
        - Надежности (reliability)
        - Производительности (response time)

        Args:
            strategy_name: Имя стратегии для валидации
            domain: Доменное имя для тестирования
            test_count: Количество тестов (по умолчанию из конфигурации)

        Returns:
            StrategyValidationResult с результатами валидации
        """
        LOG.info(f"Validating strategy effectiveness: {strategy_name} for {domain}")

        test_count = test_count or self.config["strategy_validation"]["test_count_per_strategy"]
        timeout = self.config["strategy_validation"]["timeout_seconds"]

        results = []
        response_times = []
        failures = []

        for i in range(test_count):
            LOG.debug(f"Strategy validation test {i+1}/{test_count}")

            start_time = time.time()

            try:
                # Тестируем стратегию
                success = await self.strategy_tester.test_strategy_once(
                    strategy_name, domain, timeout, self.bypass_engine
                )
                execution_time = time.time() - start_time

                results.append(success)
                response_times.append(execution_time)

                if not success:
                    failures.append(f"Test {i+1}: Strategy failed")

            except Exception as e:
                execution_time = time.time() - start_time
                results.append(False)
                response_times.append(execution_time)
                failures.append(f"Test {i+1}: Exception - {str(e)}")
                LOG.warning(f"Strategy test {i+1} failed with exception: {e}")

        # Вычисляем метрики
        success_rate = sum(results) / len(results)
        avg_response_time = statistics.mean(response_times)

        # Консистентность - стабильность результатов
        consistency_score = self.strategy_tester.calculate_consistency_score(
            results, response_times
        )

        # Надежность - общая оценка качества
        reliability_score = self.strategy_tester.calculate_reliability_score(
            success_rate, consistency_score, avg_response_time
        )

        validation_result = StrategyValidationResult(
            strategy_name=strategy_name,
            domain=domain,
            success_rate=success_rate,
            avg_response_time=avg_response_time,
            consistency_score=consistency_score,
            reliability_score=reliability_score,
            test_count=test_count,
            failures=failures,
            metadata={
                "response_times": response_times,
                "individual_results": results,
                "timeout_used": timeout,
            },
        )

        LOG.info(
            f"Strategy validation completed: {strategy_name} - "
            f"Success: {success_rate:.2%}, Reliability: {reliability_score:.2f}"
        )

        return validation_result

    async def validate_dpi_fingerprint_accuracy(
        self, domain: str, fingerprint_id: str, test_domains: Optional[List[str]] = None
    ) -> FingerprintValidationResult:
        """
        Валидация точности DPI fingerprint.

        Проверяет:
        - Точность предсказаний fingerprint'а
        - Калибровку уверенности
        - Частоту ложных срабатываний
        - Соответствие реальному поведению DPI

        Args:
            domain: Основной домен fingerprint'а
            fingerprint_id: ID fingerprint'а для валидации
            test_domains: Список доменов для тестирования

        Returns:
            FingerprintValidationResult с результатами валидации
        """
        LOG.info(f"Validating DPI fingerprint accuracy for {domain}")

        if not test_domains:
            # Используем домены по умолчанию для тестирования
            test_domains = [
                domain,
                "google.com",
                "cloudflare.com",
                "github.com",
                "stackoverflow.com",
            ]

        predictions = []
        actual_results = []
        confidence_scores = []

        for test_domain in test_domains[
            : self.config["fingerprint_validation"]["test_domains_count"]
        ]:
            LOG.debug(f"Testing fingerprint prediction for {test_domain}")

            try:
                # Получаем предсказание fingerprint'а
                prediction = self.fingerprint_validator.predict_dpi_behavior(domain, test_domain)
                # Проверяем реальное поведение
                actual_blocked = await self.fingerprint_validator.test_domain_blocking(test_domain)
                # Append atomically to keep arrays aligned
                predictions.append(bool(prediction.get("blocked")))
                confidence_scores.append(float(prediction.get("confidence", 0.0)))
                actual_results.append(bool(actual_blocked))

            except Exception as e:
                LOG.warning(f"Fingerprint validation failed for {test_domain}: {e}")
                continue

        if not predictions:
            return FingerprintValidationResult(
                domain=domain,
                fingerprint_id=fingerprint_id,
                accuracy_score=0.0,
                prediction_accuracy=0.0,
                false_positive_rate=1.0,
                false_negative_rate=1.0,
                confidence_calibration=0.0,
                validation_details={"error": "No valid predictions"},
            )

        # Вычисляем метрики точности
        accuracy_metrics = self.fingerprint_validator.calculate_accuracy_metrics(
            predictions, actual_results
        )
        confidence_calibration = self.fingerprint_validator.calculate_confidence_calibration(
            predictions, actual_results, confidence_scores
        )

        validation_result = FingerprintValidationResult(
            domain=domain,
            fingerprint_id=fingerprint_id,
            accuracy_score=accuracy_metrics["accuracy"],
            prediction_accuracy=accuracy_metrics["precision"],
            false_positive_rate=accuracy_metrics["false_positive_rate"],
            false_negative_rate=accuracy_metrics["false_negative_rate"],
            confidence_calibration=confidence_calibration,
            validation_details={
                "test_domains": test_domains,
                "predictions": predictions,
                "actual_results": actual_results,
                "confidence_scores": confidence_scores,
                "metrics": accuracy_metrics,
            },
        )

        LOG.info(
            f"Fingerprint validation completed: {domain} - "
            f"Accuracy: {accuracy_metrics['accuracy']:.2%}"
        )

        return validation_result

    async def run_ab_testing(
        self,
        test_name: str,
        control_approach: str,
        treatment_approach: str,
        test_domains: List[str],
    ) -> ABTestResult:
        """
        Проведение A/B тестирования старого vs нового подхода.

        Args:
            test_name: Название теста
            control_approach: Контрольный подход (например, "traditional")
            treatment_approach: Тестируемый подход (например, "adaptive")
            test_domains: Список доменов для тестирования

        Returns:
            ABTestResult с результатами A/B теста
        """
        LOG.info(f"Running A/B test: {test_name} - {control_approach} vs {treatment_approach}")

        sample_size = self.config["ab_testing"]["sample_size"]
        significance_level = self.config["ab_testing"]["significance_level"]

        # Разделяем домены на контрольную и тестовую группы
        domains = list(test_domains)  # avoid mutating caller's list
        random.shuffle(domains)
        split_point = len(domains) // 2
        control_domains = domains[:split_point]
        treatment_domains = domains[split_point:]

        # Тестируем контрольную группу
        LOG.info(f"Testing control group ({control_approach}) with {len(control_domains)} domains")

        # Подготовка engines для тестирования
        engines = {
            "adaptive_engine": self.adaptive_engine,
            "adaptive_available": self.adaptive_available,
            "bypass_engine": self.bypass_engine,
        }

        control_results = await self.ab_tester.test_approach(
            control_approach, control_domains[:sample_size], engines
        )

        # Тестируем тестовую группу
        LOG.info(
            f"Testing treatment group ({treatment_approach}) with {len(treatment_domains)} domains"
        )
        treatment_results = await self.ab_tester.test_approach(
            treatment_approach, treatment_domains[:sample_size], engines
        )

        # Вычисляем статистики
        control_success_rate = (
            sum(control_results) / len(control_results) if control_results else 0.0
        )
        treatment_success_rate = (
            sum(treatment_results) / len(treatment_results) if treatment_results else 0.0
        )

        # Статистическая значимость
        statistical_significance = self.ab_tester.calculate_statistical_significance(
            control_results, treatment_results, significance_level
        )

        # Размер эффекта
        effect_size = treatment_success_rate - control_success_rate

        # Доверительный интервал
        confidence_interval = self.ab_tester.calculate_confidence_interval(
            control_results, treatment_results
        )

        # Рекомендация
        min_effect_size = self.config["ab_testing"]["minimum_effect_size"]
        recommendation = self.ab_tester.generate_recommendation(
            effect_size, statistical_significance, significance_level, min_effect_size
        )

        ab_result = ABTestResult(
            test_name=test_name,
            control_group=control_approach,
            treatment_group=treatment_approach,
            control_success_rate=control_success_rate,
            treatment_success_rate=treatment_success_rate,
            statistical_significance=statistical_significance,
            effect_size=effect_size,
            confidence_interval=confidence_interval,
            recommendation=recommendation,
            test_details={
                "control_domains": control_domains,
                "treatment_domains": treatment_domains,
                "control_results": control_results,
                "treatment_results": treatment_results,
                "sample_size": sample_size,
            },
        )

        LOG.info(
            f"A/B test completed: {test_name} - Effect size: {effect_size:.2%}, "
            f"Significance: {statistical_significance:.3f}"
        )

        return ab_result

    async def collect_quality_metrics(self) -> QualityMetrics:
        """
        Сбор метрик качества системы.

        Returns:
            QualityMetrics с текущими показателями качества
        """
        LOG.info("Collecting quality metrics")

        # Анализируем историю валидации для трендов
        recent_reports = [
            report
            for report in self.validation_history
            if (datetime.now() - report.generated_at).days <= 7
        ]

        # Базовые метрики
        overall_success_rate = self.metrics_calculator.calculate_overall_success_rate(
            recent_reports
        )
        avg_trials_to_success = self.metrics_calculator.calculate_avg_trials_to_success()
        fingerprint_accuracy = self.metrics_calculator.calculate_fingerprint_accuracy(
            recent_reports
        )
        strategy_reuse_rate = self.metrics_calculator.calculate_strategy_reuse_rate()

        # Метрики ошибок
        false_positive_rate = self.metrics_calculator.calculate_false_positive_rate(recent_reports)
        false_negative_rate = self.metrics_calculator.calculate_false_negative_rate(recent_reports)

        # Системные метрики
        system_reliability = self.metrics_calculator.calculate_system_reliability(recent_reports)
        performance_score = self.metrics_calculator.calculate_performance_score(recent_reports)
        improvement_trend = self.metrics_calculator.calculate_improvement_trend(recent_reports)

        # Детальные метрики
        detailed_metrics = {
            "validation_reports_analyzed": len(recent_reports),
            "avg_validation_time": self.stats.get("avg_validation_time", 0.0),
            "total_validations": self.stats.get("total_validations", 0),
            "successful_validations": self.stats.get("successful_validations", 0),
            "failed_validations": self.stats.get("failed_validations", 0),
        }

        quality_metrics = QualityMetrics(
            timestamp=datetime.now(),
            overall_success_rate=overall_success_rate,
            avg_trials_to_success=avg_trials_to_success,
            fingerprint_accuracy=fingerprint_accuracy,
            strategy_reuse_rate=strategy_reuse_rate,
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            system_reliability=system_reliability,
            performance_score=performance_score,
            improvement_trend=improvement_trend,
            detailed_metrics=detailed_metrics,
        )

        LOG.info(
            f"Quality metrics collected - Overall success: {overall_success_rate:.2%}, "
            f"System reliability: {system_reliability:.2f}"
        )

        return quality_metrics

    async def generate_validation_report(
        self, test_domains: List[str], include_ab_testing: bool = True
    ) -> ValidationReport:
        """
        Генерация комплексного отчета валидации.

        Args:
            test_domains: Список доменов для тестирования
            include_ab_testing: Включать ли A/B тестирование

        Returns:
            ValidationReport с результатами всех тестов
        """
        LOG.info("Generating comprehensive validation report")

        start_time = datetime.now()
        report_id = f"validation_{start_time.strftime('%Y%m%d_%H%M%S')}"

        # Инициализируем отчет
        report = ValidationReport(
            report_id=report_id,
            generated_at=start_time,
            test_period=(start_time - timedelta(hours=24), start_time),
        )

        # 1. Валидация стратегий
        if self.config["strategy_validation"]["enabled"]:
            LOG.info("Running strategy effectiveness validation")

            # Тестируем несколько стратегий
            test_strategies = ["fake", "disorder", "multisplit", "tls_sni_split"]

            for strategy_name in test_strategies:
                for domain in test_domains[:3]:  # Ограничиваем количество доменов
                    try:
                        strategy_result = await self.validate_strategy_effectiveness(
                            strategy_name, domain
                        )
                        report.strategy_validations.append(strategy_result)

                        # Обновляем счетчики
                        report.total_tests += 1
                        if (
                            strategy_result.success_rate
                            >= self.config["strategy_validation"]["success_threshold"]
                        ):
                            report.passed_tests += 1
                        else:
                            report.failed_tests += 1

                    except Exception as e:
                        LOG.warning(f"Strategy validation failed for {strategy_name}/{domain}: {e}")
                        report.total_tests += 1
                        report.failed_tests += 1

        # 2. Валидация DPI fingerprints
        if self.config["fingerprint_validation"]["enabled"]:
            LOG.info("Running DPI fingerprint validation")

            for domain in test_domains[:5]:  # Ограничиваем количество доменов
                try:
                    fingerprint_result = await self.validate_dpi_fingerprint_accuracy(
                        domain, f"fp_{domain}"
                    )
                    report.fingerprint_validations.append(fingerprint_result)

                    # Обновляем счетчики
                    report.total_tests += 1
                    if (
                        fingerprint_result.accuracy_score
                        >= self.config["fingerprint_validation"]["accuracy_threshold"]
                    ):
                        report.passed_tests += 1
                    else:
                        report.failed_tests += 1

                except Exception as e:
                    LOG.warning(f"Fingerprint validation failed for {domain}: {e}")
                    report.total_tests += 1
                    report.failed_tests += 1

        # 3. A/B тестирование
        if include_ab_testing and self.config["ab_testing"]["enabled"]:
            LOG.info("Running A/B testing")

            try:
                ab_result = await self.run_ab_testing(
                    "adaptive_vs_traditional", "traditional", "adaptive", test_domains
                )
                report.ab_test_results.append(ab_result)

                # Обновляем счетчики
                report.total_tests += 1
                if (
                    ab_result.statistical_significance
                    < self.config["ab_testing"]["significance_level"]
                ):
                    report.passed_tests += 1
                else:
                    report.failed_tests += 1

            except Exception as e:
                LOG.warning(f"A/B testing failed: {e}")
                report.total_tests += 1
                report.failed_tests += 1

        # 4. Сбор метрик качества
        if self.config["quality_metrics"]["enabled"]:
            LOG.info("Collecting quality metrics")

            try:
                quality_metrics = await self.collect_quality_metrics()
                report.quality_metrics = quality_metrics

            except Exception as e:
                LOG.warning(f"Quality metrics collection failed: {e}")

        # Вычисляем общую оценку
        if report.total_tests > 0:
            report.overall_score = report.passed_tests / report.total_tests

        # Генерируем рекомендации
        report.recommendations = self.report_generator.generate_recommendations(report)
        report.action_items = self.report_generator.generate_action_items(report)

        # Сохраняем отчет
        await self.report_generator.save_validation_report(report)

        # Обновляем историю
        self.validation_history.append(report)
        self.history_manager.save_history(self.results_dir, self.validation_history)

        # Обновляем статистику
        self.stats["total_validations"] += 1
        if report.overall_score >= 0.7:
            self.stats["successful_validations"] += 1
        else:
            self.stats["failed_validations"] += 1

        execution_time = (datetime.now() - start_time).total_seconds()
        self.stats["avg_validation_time"] = (
            self.stats.get("avg_validation_time", 0.0) * (self.stats["total_validations"] - 1)
            + execution_time
        ) / self.stats["total_validations"]

        LOG.info(
            f"Validation report generated: {report_id} - "
            f"Score: {report.overall_score:.2%}, Tests: {report.total_tests}"
        )

        return report

    def get_validation_summary(self) -> Dict[str, Any]:
        """Получение сводки по валидации."""
        recent_reports = [
            report
            for report in self.validation_history
            if (datetime.now() - report.generated_at).days <= 7
        ]

        if not recent_reports:
            return {
                "total_reports": 0,
                "avg_score": 0.0,
                "trend": "no_data",
                "last_validation": None,
            }

        avg_score = statistics.mean([r.overall_score for r in recent_reports])

        # Определяем тренд
        if len(recent_reports) >= 2:
            sorted_reports = sorted(recent_reports, key=lambda r: r.generated_at)
            early_scores = [r.overall_score for r in sorted_reports[: len(sorted_reports) // 2]]
            recent_scores = [r.overall_score for r in sorted_reports[len(sorted_reports) // 2 :]]

            early_avg = statistics.mean(early_scores)
            recent_avg = statistics.mean(recent_scores)

            if recent_avg > early_avg + 0.05:
                trend = "improving"
            elif recent_avg < early_avg - 0.05:
                trend = "declining"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"

        return {
            "total_reports": len(recent_reports),
            "avg_score": avg_score,
            "trend": trend,
            "last_validation": (
                recent_reports[-1].generated_at.isoformat() if recent_reports else None
            ),
            "stats": self.stats,
        }


# Вспомогательные функции для интеграции
def create_results_validation_system(
    config_file: str = "validation_config.json",
) -> ResultsValidationSystem:
    """Фабричная функция для создания системы валидации."""
    return ResultsValidationSystem(config_file=config_file)


async def run_validation_suite(
    domains: List[str], config_file: str = "validation_config.json"
) -> ValidationReport:
    """
    Удобная функция для запуска полного набора валидационных тестов.

    Args:
        domains: Список доменов для тестирования
        config_file: Путь к файлу конфигурации

    Returns:
        ValidationReport с результатами всех тестов
    """
    validation_system = ResultsValidationSystem(config_file)
    return await validation_system.generate_validation_report(domains)


async def validate_single_strategy(
    strategy_name: str, domain: str, test_count: int = 5
) -> StrategyValidationResult:
    """
    Удобная функция для валидации одной стратегии.

    Args:
        strategy_name: Имя стратегии
        domain: Домен для тестирования
        test_count: Количество тестов

    Returns:
        StrategyValidationResult с результатами валидации
    """
    validation_system = ResultsValidationSystem()
    return await validation_system.validate_strategy_effectiveness(
        strategy_name, domain, test_count
    )


if __name__ == "__main__":
    # Пример использования
    async def main():
        # Создаем систему валидации
        validation_system = ResultsValidationSystem()

        # Тестовые домены
        test_domains = ["x.com", "instagram.com", "youtube.com"]

        # Запускаем полную валидацию
        report = await validation_system.generate_validation_report(test_domains)

        print(f"Validation completed: {report.report_id}")
        print(f"Overall score: {report.overall_score:.2%}")
        print(f"Tests: {report.passed_tests}/{report.total_tests}")

        # Выводим рекомендации
        if report.recommendations:
            print("\nRecommendations:")
            for rec in report.recommendations:
                print(f"- {rec}")

    # Запускаем пример
    asyncio.run(main())
