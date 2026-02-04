"""
Report Generation Module - генерация отчетов валидации.

Этот модуль отвечает за:
- Генерацию рекомендаций на основе результатов валидации
- Создание списка действий (action items)
- Сохранение отчетов в JSON формат
"""

import json
import logging
import statistics
from pathlib import Path
from typing import List
from dataclasses import asdict

LOG = logging.getLogger("ReportGenerator")


class ReportGenerator:
    """Генератор отчетов валидации."""

    def __init__(self, results_dir: Path):
        """
        Инициализация генератора отчетов.

        Args:
            results_dir: Директория для сохранения отчетов
        """
        self.results_dir = results_dir

    def generate_recommendations(self, report) -> List[str]:
        """
        Генерация рекомендаций на основе результатов валидации.

        Args:
            report: ValidationReport с результатами

        Returns:
            Список рекомендаций
        """
        recommendations = []

        # Рекомендации по стратегиям
        if report.strategy_validations:
            avg_success_rate = statistics.mean(
                [sv.success_rate for sv in report.strategy_validations]
            )

            if avg_success_rate < 0.6:
                recommendations.append(
                    "Низкий уровень успешности стратегий. "
                    "Рекомендуется улучшить алгоритмы генерации стратегий."
                )

            # Найти лучшие стратегии
            best_strategies = sorted(
                report.strategy_validations, key=lambda x: x.reliability_score, reverse=True
            )[:3]
            if best_strategies:
                strategy_names = [s.strategy_name for s in best_strategies]
                recommendations.append(
                    f"Наиболее надежные стратегии: {', '.join(strategy_names)}. "
                    "Рекомендуется приоритизировать их использование."
                )

        # Рекомендации по fingerprints
        if report.fingerprint_validations:
            avg_accuracy = statistics.mean(
                [fv.accuracy_score for fv in report.fingerprint_validations]
            )

            if avg_accuracy < 0.7:
                recommendations.append(
                    "Низкая точность DPI fingerprints. "
                    "Рекомендуется улучшить алгоритмы детекции DPI."
                )

            high_fp_rate = [
                fv for fv in report.fingerprint_validations if fv.false_positive_rate > 0.3
            ]
            if high_fp_rate:
                recommendations.append(
                    f"Высокий уровень ложных срабатываний у {len(high_fp_rate)} fingerprints. "
                    "Рекомендуется пересмотреть критерии классификации."
                )

        # Рекомендации по A/B тестам
        for ab_result in report.ab_test_results:
            if ab_result.effect_size > 0.1 and ab_result.statistical_significance < 0.05:
                recommendations.append(
                    f"A/B тест '{ab_result.test_name}' показал значимое улучшение. "
                    f"{ab_result.recommendation}"
                )

        # Рекомендации по метрикам качества
        if report.quality_metrics:
            qm = report.quality_metrics

            if qm.overall_success_rate < 0.7:
                recommendations.append(
                    "Общий уровень успешности системы ниже целевого. "
                    "Рекомендуется комплексная оптимизация."
                )

            if qm.improvement_trend < -0.05:
                recommendations.append(
                    "Наблюдается негативный тренд в качестве системы. "
                    "Требуется срочное вмешательство."
                )

        return recommendations

    def generate_action_items(self, report) -> List[str]:
        """
        Генерация конкретных действий на основе результатов.

        Args:
            report: ValidationReport с результатами

        Returns:
            Список действий
        """
        action_items = []

        # Действия по стратегиям
        failed_strategies = [sv for sv in report.strategy_validations if sv.success_rate < 0.5]
        if failed_strategies:
            strategy_names = [s.strategy_name for s in failed_strategies]
            action_items.append(
                f"Исследовать причины неудач стратегий: {', '.join(strategy_names)}"
            )

        # Действия по fingerprints
        inaccurate_fingerprints = [
            fv for fv in report.fingerprint_validations if fv.accuracy_score < 0.6
        ]
        if inaccurate_fingerprints:
            domains = [f.domain for f in inaccurate_fingerprints]
            action_items.append(f"Пересобрать DPI fingerprints для доменов: {', '.join(domains)}")

        # Действия по общему качеству
        if report.overall_score < 0.6:
            action_items.append("Провести глубокий анализ системы и определить основные проблемы")

        # Действия по производительности
        slow_strategies = [sv for sv in report.strategy_validations if sv.avg_response_time > 10.0]
        if slow_strategies:
            action_items.append("Оптимизировать производительность медленных стратегий")

        return action_items

    async def save_validation_report(self, report):
        """
        Сохранение отчета валидации в JSON файл.

        Args:
            report: ValidationReport для сохранения
        """
        report_file = self.results_dir / f"{report.report_id}.json"

        try:
            # Конвертируем в JSON-совместимый формат
            report_data = asdict(report)

            # Обрабатываем datetime объекты
            report_data["generated_at"] = report.generated_at.isoformat()
            report_data["test_period"] = [
                report.test_period[0].isoformat(),
                report.test_period[1].isoformat(),
            ]

            if report.quality_metrics:
                report_data["quality_metrics"][
                    "timestamp"
                ] = report.quality_metrics.timestamp.isoformat()

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            LOG.info(f"Validation report saved: {report_file}")

        except (IOError, OSError) as e:
            LOG.error(f"Failed to save validation report: {e}")
        except Exception as e:
            LOG.error(f"Unexpected error saving validation report: {e}")
