"""Rule effectiveness reporting for monitoring system."""

import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)


def generate_rule_effectiveness_report(
    effectiveness_reporter,
    knowledge_accumulator,
    export_json: bool = True,
    export_visualization: bool = True,
) -> Dict[str, Any]:
    """
    Task 8.3: Генерация отчетов об эффективности правил.

    Генерирует статистику по каждому правилу, экспортирует в JSON формате
    и создает визуализацию топ правил по success_rate.

    Args:
        effectiveness_reporter: EffectivenessReporter instance
        knowledge_accumulator: KnowledgeAccumulator instance
        export_json: Экспортировать JSON отчет
        export_visualization: Создать текстовую визуализацию

    Returns:
        Словарь с результатами генерации отчета
    """
    if not effectiveness_reporter:
        logger.warning("Effectiveness reporter not available")
        return {"error": "Effectiveness reporter not available"}

    if not knowledge_accumulator:
        logger.warning("Knowledge accumulator not provided")
        return {"error": "Knowledge accumulator not provided"}

    try:
        # Генерируем комплексный отчет
        created_files = effectiveness_reporter.generate_comprehensive_report(
            knowledge_accumulator,
            export_json=export_json,
            export_visualization=export_visualization,
        )

        # Получаем статистику для возврата
        report = effectiveness_reporter.generate_effectiveness_report(knowledge_accumulator)

        result = {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "created_files": created_files,
            "summary": {
                "total_rules": report.total_rules,
                "active_rules": report.active_rules,
                "high_performance_rules": report.high_performance_rules,
                "top_success_rate": (
                    report.top_rules_by_success_rate[0].success_rate
                    if report.top_rules_by_success_rate
                    else 0.0
                ),
                "recommendations_count": len(report.recommendations),
            },
            "top_rules_preview": [
                {
                    "rule_id": rule.rule_id,
                    "success_rate": rule.success_rate,
                    "total_applications": rule.total_applications,
                    "unique_domains": rule.unique_domains_count,
                }
                for rule in report.top_rules_by_success_rate[:5]
            ],
        }

        logger.info(
            f"📊 Rule effectiveness report generated: "
            f"{report.total_rules} rules analyzed, "
            f"{len(created_files)} files created"
        )

        return result

    except Exception as e:
        logger.error(f"Error generating rule effectiveness report: {e}")
        return {"error": str(e), "success": False}


def get_rule_effectiveness_summary(
    effectiveness_reporter,
    knowledge_accumulator,
) -> Dict[str, Any]:
    """
    Task 8.3: Получение краткой сводки об эффективности правил.

    Args:
        effectiveness_reporter: EffectivenessReporter instance
        knowledge_accumulator: KnowledgeAccumulator instance

    Returns:
        Словарь с краткой статистикой эффективности
    """
    if not effectiveness_reporter or not knowledge_accumulator:
        return {}

    try:
        # Анализируем правила
        rule_stats = effectiveness_reporter.analyze_rule_effectiveness(knowledge_accumulator)

        if not rule_stats:
            return {"total_rules": 0, "message": "No rules found"}

        # Вычисляем основные метрики
        active_rules = [r for r in rule_stats if r.total_applications > 0]
        high_performance_rules = [r for r in active_rules if r.success_rate > 0.8]

        # Топ 3 правила по успешности
        top_rules = sorted(active_rules, key=lambda x: x.success_rate, reverse=True)[:3]

        # Средняя эффективность
        avg_success_rate = 0.0
        if active_rules:
            avg_success_rate = sum(r.success_rate for r in active_rules) / len(active_rules)

        return {
            "total_rules": len(rule_stats),
            "active_rules": len(active_rules),
            "high_performance_rules": len(high_performance_rules),
            "average_success_rate": avg_success_rate,
            "top_rules": [
                {
                    "rule_id": rule.rule_id,
                    "success_rate": rule.success_rate,
                    "applications": rule.total_applications,
                }
                for rule in top_rules
            ],
            "performance_distribution": {
                "excellent": len([r for r in active_rules if r.success_rate > 0.9]),
                "good": len([r for r in active_rules if 0.7 < r.success_rate <= 0.9]),
                "fair": len([r for r in active_rules if 0.5 < r.success_rate <= 0.7]),
                "poor": len([r for r in active_rules if r.success_rate <= 0.5]),
            },
        }

    except Exception as e:
        logger.error(f"Error getting rule effectiveness summary: {e}")
        return {"error": str(e)}
