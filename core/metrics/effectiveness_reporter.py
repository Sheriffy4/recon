"""
Effectiveness Reporter - система генерации отчетов об эффективности правил.

Этот модуль реализует генерацию статистики по каждому правилу,
экспорт в JSON формате и визуализацию топ правил по success_rate
согласно требованиям FR-10.8.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from collections import defaultdict
import statistics

LOG = logging.getLogger("EffectivenessReporter")


@dataclass
class RuleEffectivenessStats:
    """
    Статистика эффективности одного правила.
    
    Содержит детальную информацию о применении правила,
    его успешности и производительности.
    """
    rule_id: str
    description: str
    
    # Основные метрики
    total_applications: int = 0
    successful_applications: int = 0
    failed_applications: int = 0
    success_rate: float = 0.0
    
    # Временные метрики
    first_used: Optional[datetime] = None
    last_used: Optional[datetime] = None
    last_success: Optional[datetime] = None
    
    # Применимость
    domains_applied: List[str] = field(default_factory=list)
    unique_domains_count: int = 0
    
    # Производительность
    average_iterations_to_success: float = 0.0
    confidence_score: float = 0.0
    
    # Категоризация
    root_causes: List[str] = field(default_factory=list)
    recommended_intents: List[str] = field(default_factory=list)
    
    # Метаданные
    auto_generated: bool = False
    created_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь для JSON."""
        data = asdict(self)
        
        # Конвертируем datetime в строки
        for field_name in ["first_used", "last_used", "last_success", "created_at"]:
            if data[field_name]:
                data[field_name] = data[field_name].isoformat()
        
        return data
    
    def calculate_effectiveness_score(self) -> float:
        """
        Вычисление комплексной оценки эффективности правила.
        
        Учитывает success_rate, количество применений, уникальность доменов
        и актуальность (как давно использовалось).
        
        Returns:
            Оценка эффективности от 0.0 до 1.0
        """
        if self.total_applications == 0:
            return 0.0
        
        # Базовая успешность (40% веса)
        success_component = self.success_rate * 0.4
        
        # Частота использования (30% веса)
        # Нормализуем по логарифмической шкале
        usage_score = min(1.0, (self.total_applications / 10.0) ** 0.5)
        usage_component = usage_score * 0.3
        
        # Универсальность (20% веса)
        # Чем больше уникальных доменов, тем лучше
        universality_score = min(1.0, self.unique_domains_count / 5.0)
        universality_component = universality_score * 0.2
        
        # Актуальность (10% веса)
        recency_component = 0.0
        if self.last_used:
            days_since_use = (datetime.now() - self.last_used).days
            recency_score = max(0.0, 1.0 - (days_since_use / 30.0))  # Снижается за 30 дней
            recency_component = recency_score * 0.1
        
        total_score = (
            success_component + 
            usage_component + 
            universality_component + 
            recency_component
        )
        
        return min(1.0, total_score)


@dataclass
class EffectivenessReport:
    """
    Отчет об эффективности правил.
    
    Содержит агрегированную статистику по всем правилам,
    топ правила по различным метрикам и рекомендации.
    """
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Общая статистика
    total_rules: int = 0
    active_rules: int = 0
    high_performance_rules: int = 0
    
    # Топ правила
    top_rules_by_success_rate: List[RuleEffectivenessStats] = field(default_factory=list)
    top_rules_by_usage: List[RuleEffectivenessStats] = field(default_factory=list)
    top_rules_by_effectiveness: List[RuleEffectivenessStats] = field(default_factory=list)
    
    # Анализ по категориям
    effectiveness_by_root_cause: Dict[str, float] = field(default_factory=dict)
    usage_by_root_cause: Dict[str, int] = field(default_factory=dict)
    
    # Рекомендации
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь для JSON."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        
        # Конвертируем списки RuleEffectivenessStats
        for field_name in ["top_rules_by_success_rate", "top_rules_by_usage", "top_rules_by_effectiveness"]:
            data[field_name] = [rule.to_dict() for rule in data[field_name]]
        
        return data


class EffectivenessReporter:
    """
    Генератор отчетов об эффективности правил замкнутого цикла обучения.
    
    Анализирует статистику применения правил из KnowledgeAccumulator,
    генерирует детальные отчеты и предоставляет визуализацию
    топ правил по success_rate.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Инициализация генератора отчетов.
        
        Args:
            output_dir: Директория для сохранения отчетов
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        LOG.info(f"EffectivenessReporter инициализирован, отчеты в {self.output_dir}")
    
    def analyze_rule_effectiveness(self, knowledge_accumulator) -> List[RuleEffectivenessStats]:
        """
        Анализ эффективности всех правил из KnowledgeAccumulator.
        
        Args:
            knowledge_accumulator: Экземпляр KnowledgeAccumulator
            
        Returns:
            Список статистики по каждому правилу
        """
        rule_stats = []
        
        try:
            patterns = knowledge_accumulator.get_all_patterns()
            
            for pattern in patterns:
                stats = RuleEffectivenessStats(
                    rule_id=pattern.id,
                    description=pattern.description
                )
                
                # Извлекаем метрики из метаданных
                metadata = pattern.metadata
                
                stats.total_applications = (
                    metadata.get("success_count", 0) + 
                    metadata.get("failure_count", 0)
                )
                stats.successful_applications = metadata.get("success_count", 0)
                stats.failed_applications = metadata.get("failure_count", 0)
                
                # Вычисляем success_rate
                if stats.total_applications > 0:
                    stats.success_rate = stats.successful_applications / stats.total_applications
                
                # Временные метки
                if "created_at" in metadata:
                    try:
                        stats.created_at = datetime.fromisoformat(metadata["created_at"])
                        stats.first_used = stats.created_at
                    except (ValueError, TypeError):
                        pass
                
                if "last_success" in metadata:
                    try:
                        stats.last_success = datetime.fromisoformat(metadata["last_success"])
                        stats.last_used = stats.last_success
                    except (ValueError, TypeError):
                        pass
                
                # Домены
                stats.domains_applied = metadata.get("domains_applied", [])
                stats.unique_domains_count = len(set(stats.domains_applied))
                
                # Confidence
                stats.confidence_score = metadata.get("confidence", 0.0)
                
                # Категоризация
                if "root_cause" in pattern.conditions:
                    stats.root_causes = [pattern.conditions["root_cause"]]
                
                # Intent'ы
                stats.recommended_intents = [
                    rec.get("intent", "") for rec in pattern.recommend
                ]
                
                # Метаданные
                stats.auto_generated = metadata.get("auto_generated", False)
                
                rule_stats.append(stats)
            
            LOG.info(f"Проанализировано {len(rule_stats)} правил")
            
        except Exception as e:
            LOG.error(f"Ошибка анализа эффективности правил: {e}")
        
        return rule_stats
    
    def generate_effectiveness_report(self, 
                                    knowledge_accumulator,
                                    top_count: int = 10) -> EffectivenessReport:
        """
        Генерация полного отчета об эффективности правил.
        
        Args:
            knowledge_accumulator: Экземпляр KnowledgeAccumulator
            top_count: Количество топ правил в каждой категории
            
        Returns:
            Объект отчета об эффективности
        """
        # Анализируем все правила
        rule_stats = self.analyze_rule_effectiveness(knowledge_accumulator)
        
        report = EffectivenessReport()
        
        # Общая статистика
        report.total_rules = len(rule_stats)
        report.active_rules = len([r for r in rule_stats if r.total_applications > 0])
        report.high_performance_rules = len([r for r in rule_stats if r.success_rate > 0.8])
        
        # Топ правила по success_rate
        rules_by_success = sorted(
            [r for r in rule_stats if r.total_applications > 0],
            key=lambda x: x.success_rate,
            reverse=True
        )
        report.top_rules_by_success_rate = rules_by_success[:top_count]
        
        # Топ правила по использованию
        rules_by_usage = sorted(
            rule_stats,
            key=lambda x: x.total_applications,
            reverse=True
        )
        report.top_rules_by_usage = rules_by_usage[:top_count]
        
        # Топ правила по комплексной эффективности
        for rule in rule_stats:
            rule.effectiveness_score = rule.calculate_effectiveness_score()
        
        rules_by_effectiveness = sorted(
            rule_stats,
            key=lambda x: rule.effectiveness_score,
            reverse=True
        )
        report.top_rules_by_effectiveness = rules_by_effectiveness[:top_count]
        
        # Анализ по root_cause
        root_cause_stats = defaultdict(list)
        for rule in rule_stats:
            for root_cause in rule.root_causes:
                root_cause_stats[root_cause].append(rule)
        
        for root_cause, rules in root_cause_stats.items():
            if rules:
                # Средняя эффективность по root_cause
                success_rates = [r.success_rate for r in rules if r.total_applications > 0]
                if success_rates:
                    report.effectiveness_by_root_cause[root_cause] = statistics.mean(success_rates)
                
                # Общее использование по root_cause
                report.usage_by_root_cause[root_cause] = sum(r.total_applications for r in rules)
        
        # Генерируем рекомендации
        report.recommendations = self._generate_recommendations(rule_stats)
        
        LOG.info(f"Сгенерирован отчет об эффективности: {report.total_rules} правил, "
                f"{report.active_rules} активных, {report.high_performance_rules} высокоэффективных")
        
        return report
    
    def _generate_recommendations(self, rule_stats: List[RuleEffectivenessStats]) -> List[str]:
        """
        Генерация рекомендаций на основе анализа правил.
        
        Args:
            rule_stats: Статистика по правилам
            
        Returns:
            Список рекомендаций
        """
        recommendations = []
        
        # Анализируем неиспользуемые правила
        unused_rules = [r for r in rule_stats if r.total_applications == 0]
        if unused_rules:
            recommendations.append(
                f"Найдено {len(unused_rules)} неиспользуемых правил. "
                "Рассмотрите их удаление или улучшение условий срабатывания."
            )
        
        # Анализируем правила с низкой эффективностью
        low_performance_rules = [
            r for r in rule_stats 
            if r.total_applications > 5 and r.success_rate < 0.3
        ]
        if low_performance_rules:
            recommendations.append(
                f"Найдено {len(low_performance_rules)} правил с низкой эффективностью (<30%). "
                "Рекомендуется пересмотреть их условия или рекомендации."
            )
        
        # Анализируем автогенерированные правила
        auto_rules = [r for r in rule_stats if r.auto_generated]
        successful_auto_rules = [r for r in auto_rules if r.success_rate > 0.7]
        if successful_auto_rules:
            recommendations.append(
                f"Найдено {len(successful_auto_rules)} успешных автогенерированных правил. "
                "Рассмотрите их ручную оптимизацию для улучшения производительности."
            )
        
        # Анализируем покрытие root_cause
        covered_root_causes = set()
        for rule in rule_stats:
            covered_root_causes.update(rule.root_causes)
        
        expected_root_causes = {
            "DPI_SNI_FILTERING",
            "DPI_ACTIVE_RST_INJECTION", 
            "DPI_CONTENT_INSPECTION",
            "DPI_REASSEMBLES_FRAGMENTS",
            "DPI_STATEFUL_TRACKING"
        }
        
        missing_root_causes = expected_root_causes - covered_root_causes
        if missing_root_causes:
            recommendations.append(
                f"Отсутствуют правила для типов блокировок: {', '.join(missing_root_causes)}. "
                "Рекомендуется добавить соответствующие правила."
            )
        
        # Анализируем универсальность правил
        universal_rules = [r for r in rule_stats if r.unique_domains_count > 3]
        if len(universal_rules) < len(rule_stats) * 0.3:
            recommendations.append(
                "Большинство правил применяется к ограниченному числу доменов. "
                "Рассмотрите создание более универсальных правил."
            )
        
        return recommendations
    
    def export_report_json(self, 
                          report: EffectivenessReport,
                          filename: Optional[str] = None) -> str:
        """
        Экспорт отчета в JSON формате.
        
        Args:
            report: Отчет об эффективности
            filename: Имя файла (по умолчанию генерируется автоматически)
            
        Returns:
            Путь к созданному файлу
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"rule_effectiveness_report_{timestamp}.json"
        
        file_path = self.output_dir / filename
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
            
            LOG.info(f"📊 Отчет об эффективности экспортирован в {file_path}")
            return str(file_path)
            
        except Exception as e:
            LOG.error(f"Ошибка экспорта отчета: {e}")
            raise
    
    def generate_top_rules_visualization(self, 
                                       report: EffectivenessReport,
                                       filename: Optional[str] = None) -> str:
        """
        Генерация визуализации топ правил по success_rate.
        
        Создает текстовую визуализацию в виде таблицы с топ правилами.
        
        Args:
            report: Отчет об эффективности
            filename: Имя файла (по умолчанию генерируется автоматически)
            
        Returns:
            Путь к созданному файлу
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"top_rules_visualization_{timestamp}.txt"
        
        file_path = self.output_dir / filename
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ОТЧЕТ ОБ ЭФФЕКТИВНОСТИ ПРАВИЛ ЗАМКНУТОГО ЦИКЛА ОБУЧЕНИЯ\n")
                f.write("=" * 80 + "\n")
                f.write(f"Дата генерации: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Всего правил: {report.total_rules}\n")
                f.write(f"Активных правил: {report.active_rules}\n")
                f.write(f"Высокоэффективных правил (>80%): {report.high_performance_rules}\n\n")
                
                # Топ правила по success_rate
                f.write("ТОП ПРАВИЛА ПО УСПЕШНОСТИ\n")
                f.write("-" * 50 + "\n")
                f.write(f"{'Ранг':<4} {'ID правила':<20} {'Успешность':<12} {'Применений':<12} {'Доменов':<8}\n")
                f.write("-" * 50 + "\n")
                
                for i, rule in enumerate(report.top_rules_by_success_rate, 1):
                    f.write(f"{i:<4} {rule.rule_id[:19]:<20} {rule.success_rate:.1%}{'':>4} "
                           f"{rule.total_applications:<12} {rule.unique_domains_count:<8}\n")
                
                f.write("\n")
                
                # Топ правила по использованию
                f.write("ТОП ПРАВИЛА ПО ИСПОЛЬЗОВАНИЮ\n")
                f.write("-" * 50 + "\n")
                f.write(f"{'Ранг':<4} {'ID правила':<20} {'Применений':<12} {'Успешность':<12} {'Доменов':<8}\n")
                f.write("-" * 50 + "\n")
                
                for i, rule in enumerate(report.top_rules_by_usage, 1):
                    f.write(f"{i:<4} {rule.rule_id[:19]:<20} {rule.total_applications:<12} "
                           f"{rule.success_rate:.1%}{'':>4} {rule.unique_domains_count:<8}\n")
                
                f.write("\n")
                
                # Эффективность по типам блокировок
                if report.effectiveness_by_root_cause:
                    f.write("ЭФФЕКТИВНОСТЬ ПО ТИПАМ БЛОКИРОВОК\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"{'Тип блокировки':<25} {'Эффективность':<15} {'Использований':<12}\n")
                    f.write("-" * 40 + "\n")
                    
                    for root_cause, effectiveness in report.effectiveness_by_root_cause.items():
                        usage = report.usage_by_root_cause.get(root_cause, 0)
                        f.write(f"{root_cause[:24]:<25} {effectiveness:.1%}{'':>6} {usage:<12}\n")
                    
                    f.write("\n")
                
                # Рекомендации
                if report.recommendations:
                    f.write("РЕКОМЕНДАЦИИ\n")
                    f.write("-" * 20 + "\n")
                    for i, recommendation in enumerate(report.recommendations, 1):
                        f.write(f"{i}. {recommendation}\n\n")
            
            LOG.info(f"📊 Визуализация топ правил создана: {file_path}")
            return str(file_path)
            
        except Exception as e:
            LOG.error(f"Ошибка создания визуализации: {e}")
            raise
    
    def generate_comprehensive_report(self, 
                                    knowledge_accumulator,
                                    export_json: bool = True,
                                    export_visualization: bool = True) -> Dict[str, str]:
        """
        Генерация комплексного отчета об эффективности правил.
        
        Args:
            knowledge_accumulator: Экземпляр KnowledgeAccumulator
            export_json: Экспортировать JSON отчет
            export_visualization: Создать текстовую визуализацию
            
        Returns:
            Словарь с путями к созданным файлам
        """
        # Генерируем отчет
        report = self.generate_effectiveness_report(knowledge_accumulator)
        
        created_files = {}
        
        # Экспортируем JSON
        if export_json:
            json_path = self.export_report_json(report)
            created_files["json_report"] = json_path
        
        # Создаем визуализацию
        if export_visualization:
            viz_path = self.generate_top_rules_visualization(report)
            created_files["visualization"] = viz_path
        
        LOG.info(f"📊 Комплексный отчет создан: {len(created_files)} файлов")
        
        return created_files


# Глобальный экземпляр репортера
_global_effectiveness_reporter: Optional[EffectivenessReporter] = None


def get_effectiveness_reporter() -> EffectivenessReporter:
    """
    Получение глобального экземпляра генератора отчетов.
    
    Returns:
        Экземпляр EffectivenessReporter
    """
    global _global_effectiveness_reporter
    
    if _global_effectiveness_reporter is None:
        _global_effectiveness_reporter = EffectivenessReporter()
    
    return _global_effectiveness_reporter