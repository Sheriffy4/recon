#!/usr/bin/env python3
"""
Strategy Diff Tool - Сравнение стратегий между режимами

Этот инструмент сравнивает стратегии между testing mode и service mode,
показывает различия в параметрах и генерирует детальный отчет.

Requirements: 5.1, 5.2, 5.5
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.unified_strategy_loader import UnifiedStrategyLoader, NormalizedStrategy
from core.strategy.validator import StrategyValidator, CompatibilityResult

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)


@dataclass
class StrategyDifference:
    """Различие между стратегиями."""
    
    field_name: str
    testing_value: Any
    service_value: Any
    severity: str  # 'critical', 'warning', 'info'
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'field_name': self.field_name,
            'testing_value': str(self.testing_value),
            'service_value': str(self.service_value),
            'severity': self.severity,
            'description': self.description
        }


@dataclass
class DomainComparison:
    """Сравнение стратегий для домена."""
    
    domain: str
    has_testing_strategy: bool
    has_service_strategy: bool
    testing_strategy: Optional[Dict[str, Any]] = None
    service_strategy: Optional[Dict[str, Any]] = None
    differences: List[StrategyDifference] = field(default_factory=list)
    compatibility_score: float = 0.0
    is_compatible: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'domain': self.domain,
            'has_testing_strategy': self.has_testing_strategy,
            'has_service_strategy': self.has_service_strategy,
            'testing_strategy': self.testing_strategy,
            'service_strategy': self.service_strategy,
            'differences': [d.to_dict() for d in self.differences],
            'compatibility_score': self.compatibility_score,
            'is_compatible': self.is_compatible
        }


class StrategyDiffTool:
    """
    Инструмент для сравнения стратегий между режимами.
    
    Requirements: 5.1, 5.2, 5.5
    """
    
    def __init__(self, debug: bool = False):
        """
        Инициализация инструмента.
        
        Args:
            debug: Включить отладочный вывод
        """
        self.logger = LOG
        if debug:
            self.logger.setLevel(logging.DEBUG)
        
        self.strategy_loader = UnifiedStrategyLoader(debug=debug)
        self.validator = StrategyValidator(
            strategy_loader=self.strategy_loader,
            debug=debug
        )
        
        self.logger.info("✅ Strategy Diff Tool initialized")
    
    def load_strategies_from_file(self, file_path: str) -> Dict[str, Any]:
        """
        Загружает стратегии из JSON файла.
        
        Args:
            file_path: Путь к файлу стратегий
            
        Returns:
            Словарь {domain: strategy}
        """
        try:
            path = Path(file_path)
            if not path.exists():
                self.logger.error(f"❌ Файл не найден: {file_path}")
                return {}
            
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.logger.info(f"📂 Загружено {len(data)} стратегий из {file_path}")
            return data
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка загрузки файла {file_path}: {e}")
            return {}
    
    def compare_strategies(self, 
                          testing_file: str, 
                          service_file: str) -> List[DomainComparison]:
        """
        Сравнивает стратегии из двух файлов.
        
        Args:
            testing_file: Файл стратегий из testing mode
            service_file: Файл стратегий из service mode
            
        Returns:
            Список сравнений для каждого домена
        """
        self.logger.info("🔍 Начало сравнения стратегий")
        
        # Load strategies
        testing_strategies = self.load_strategies_from_file(testing_file)
        service_strategies = self.load_strategies_from_file(service_file)
        
        # Get all unique domains
        all_domains = set(testing_strategies.keys()) | set(service_strategies.keys())
        
        comparisons = []
        
        for domain in sorted(all_domains):
            comparison = self._compare_domain_strategies(
                domain,
                testing_strategies.get(domain),
                service_strategies.get(domain)
            )
            comparisons.append(comparison)
        
        self.logger.info(f"✅ Сравнение завершено: {len(comparisons)} доменов")
        
        return comparisons
    
    def _compare_domain_strategies(self,
                                   domain: str,
                                   testing_strategy: Optional[Dict[str, Any]],
                                   service_strategy: Optional[Dict[str, Any]]) -> DomainComparison:
        """
        Сравнивает стратегии для одного домена.
        
        Args:
            domain: Доменное имя
            testing_strategy: Стратегия из testing mode
            service_strategy: Стратегия из service mode
            
        Returns:
            DomainComparison с результатами сравнения
        """
        comparison = DomainComparison(
            domain=domain,
            has_testing_strategy=testing_strategy is not None,
            has_service_strategy=service_strategy is not None,
            testing_strategy=testing_strategy,
            service_strategy=service_strategy
        )
        
        # If only one strategy exists
        if not testing_strategy or not service_strategy:
            if not testing_strategy:
                comparison.differences.append(StrategyDifference(
                    field_name='existence',
                    testing_value='None',
                    service_value='Present',
                    severity='critical',
                    description='Strategy exists only in service mode'
                ))
            else:
                comparison.differences.append(StrategyDifference(
                    field_name='existence',
                    testing_value='Present',
                    service_value='None',
                    severity='critical',
                    description='Strategy exists only in testing mode'
                ))
            comparison.is_compatible = False
            comparison.compatibility_score = 0.0
            return comparison
        
        # Both strategies exist - compare them
        try:
            # Use validator for compatibility check
            compat_result = self.validator.validate_compatibility(
                testing_strategy,
                service_strategy
            )
            
            comparison.is_compatible = compat_result.is_compatible
            comparison.compatibility_score = compat_result.similarity_score
            
            # Convert compatibility differences to StrategyDifference
            for diff in compat_result.differences:
                severity = diff.get('severity', 'info')
                comparison.differences.append(StrategyDifference(
                    field_name=diff['field'],
                    testing_value=diff['testing_value'],
                    service_value=diff['service_value'],
                    severity=severity,
                    description=f"Parameter mismatch: {diff['field']}"
                ))
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка сравнения стратегий для {domain}: {e}")
            comparison.differences.append(StrategyDifference(
                field_name='comparison_error',
                testing_value='N/A',
                service_value='N/A',
                severity='critical',
                description=f"Comparison failed: {str(e)}"
            ))
            comparison.is_compatible = False
        
        return comparison
    
    def generate_report(self, 
                       comparisons: List[DomainComparison],
                       output_file: Optional[str] = None) -> str:
        """
        Генерирует детальный отчет о сравнении.
        
        Args:
            comparisons: Список сравнений доменов
            output_file: Путь для сохранения отчета (опционально)
            
        Returns:
            Текстовый отчет
        """
        lines = []
        lines.append("=" * 80)
        lines.append("STRATEGY COMPARISON REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Total domains: {len(comparisons)}")
        lines.append("")
        
        # Summary statistics
        compatible_count = sum(1 for c in comparisons if c.is_compatible)
        incompatible_count = len(comparisons) - compatible_count
        only_testing = sum(1 for c in comparisons if c.has_testing_strategy and not c.has_service_strategy)
        only_service = sum(1 for c in comparisons if c.has_service_strategy and not c.has_testing_strategy)
        
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Compatible strategies: {compatible_count}")
        lines.append(f"Incompatible strategies: {incompatible_count}")
        lines.append(f"Only in testing mode: {only_testing}")
        lines.append(f"Only in service mode: {only_service}")
        lines.append("")
        
        # Critical issues
        critical_issues = [c for c in comparisons if any(d.severity == 'critical' for d in c.differences)]
        if critical_issues:
            lines.append("CRITICAL ISSUES")
            lines.append("-" * 80)
            for comp in critical_issues:
                lines.append(f"❌ {comp.domain}")
                for diff in comp.differences:
                    if diff.severity == 'critical':
                        lines.append(f"   - {diff.description}")
                        lines.append(f"     Testing: {diff.testing_value}")
                        lines.append(f"     Service: {diff.service_value}")
            lines.append("")
        
        # Detailed comparison
        lines.append("DETAILED COMPARISON")
        lines.append("-" * 80)
        
        for comp in comparisons:
            status = "✅" if comp.is_compatible else "❌"
            lines.append(f"{status} {comp.domain} (compatibility: {comp.compatibility_score:.2%})")
            
            if comp.differences:
                for diff in comp.differences:
                    severity_icon = {
                        'critical': '🔴',
                        'warning': '🟡',
                        'info': '🔵'
                    }.get(diff.severity, '⚪')
                    
                    lines.append(f"   {severity_icon} {diff.field_name}: {diff.description}")
                    lines.append(f"      Testing: {diff.testing_value}")
                    lines.append(f"      Service: {diff.service_value}")
            else:
                lines.append("   ✅ No differences found")
            
            lines.append("")
        
        lines.append("=" * 80)
        
        report = "\n".join(lines)
        
        # Save to file if requested
        if output_file:
            try:
                Path(output_file).write_text(report, encoding='utf-8')
                self.logger.info(f"📄 Отчет сохранен в {output_file}")
            except Exception as e:
                self.logger.error(f"❌ Ошибка сохранения отчета: {e}")
        
        return report
    
    def generate_json_report(self,
                            comparisons: List[DomainComparison],
                            output_file: str) -> None:
        """
        Генерирует JSON отчет о сравнении.
        
        Args:
            comparisons: Список сравнений доменов
            output_file: Путь для сохранения JSON отчета
        """
        try:
            report_data = {
                'generated_at': datetime.now().isoformat(),
                'total_domains': len(comparisons),
                'compatible_count': sum(1 for c in comparisons if c.is_compatible),
                'incompatible_count': sum(1 for c in comparisons if not c.is_compatible),
                'comparisons': [c.to_dict() for c in comparisons]
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"📄 JSON отчет сохранен в {output_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка сохранения JSON отчета: {e}")


def main():
    """Главная функция CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Strategy Diff Tool - Сравнение стратегий между режимами'
    )
    parser.add_argument(
        '--testing',
        required=True,
        help='Файл стратегий из testing mode (domain_strategies.json)'
    )
    parser.add_argument(
        '--service',
        required=True,
        help='Файл стратегий из service mode'
    )
    parser.add_argument(
        '--output',
        help='Файл для сохранения текстового отчета'
    )
    parser.add_argument(
        '--json-output',
        help='Файл для сохранения JSON отчета'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Включить отладочный вывод'
    )
    
    args = parser.parse_args()
    
    # Create tool
    tool = StrategyDiffTool(debug=args.debug)
    
    # Compare strategies
    comparisons = tool.compare_strategies(args.testing, args.service)
    
    # Generate text report
    report = tool.generate_report(comparisons, args.output)
    
    # Print to console if no output file specified
    if not args.output:
        print(report)
    
    # Generate JSON report if requested
    if args.json_output:
        tool.generate_json_report(comparisons, args.json_output)
    
    # Exit with error code if there are incompatible strategies
    incompatible_count = sum(1 for c in comparisons if not c.is_compatible)
    if incompatible_count > 0:
        LOG.warning(f"⚠️ Found {incompatible_count} incompatible strategies")
        sys.exit(1)
    else:
        LOG.info("✅ All strategies are compatible")
        sys.exit(0)


if __name__ == '__main__':
    main()
