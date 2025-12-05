#!/usr/bin/env python3
"""
PCAP Comparison Tool - Сравнение PCAP файлов из разных режимов

Этот инструмент сравнивает PCAP файлы из testing mode и service mode,
находит различия в применении стратегий и генерирует визуальный отчет.

Requirements: 8.5, 8.6, 8.7
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.pcap.analyzer import PCAPAnalyzer, StrategyAnalysisResult, ComparisonResult

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)


@dataclass
class PCAPComparisonSummary:
    """Сводка сравнения PCAP файлов."""
    
    testing_pcap: str
    service_pcap: str
    testing_packets: int
    service_packets: int
    testing_strategy: Optional[str]
    service_strategy: Optional[str]
    similarity_score: float
    differences_count: int
    critical_differences: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'testing_pcap': self.testing_pcap,
            'service_pcap': self.service_pcap,
            'testing_packets': self.testing_packets,
            'service_packets': self.service_packets,
            'testing_strategy': self.testing_strategy,
            'service_strategy': self.service_strategy,
            'similarity_score': self.similarity_score,
            'differences_count': self.differences_count,
            'critical_differences': self.critical_differences,
            'warnings': self.warnings
        }


class PCAPCompareTool:
    """
    Инструмент для сравнения PCAP файлов между режимами.
    
    Requirements: 8.5, 8.6, 8.7
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
        
        self.analyzer = PCAPAnalyzer()
        
        self.logger.info("✅ PCAP Compare Tool initialized")
    
    def compare_pcaps(self,
                     testing_pcap: str,
                     service_pcap: str,
                     expected_strategy: Optional[Dict[str, Any]] = None) -> Tuple[ComparisonResult, PCAPComparisonSummary]:
        """
        Сравнивает два PCAP файла.
        
        Args:
            testing_pcap: PCAP файл из testing mode
            service_pcap: PCAP файл из service mode
            expected_strategy: Ожидаемая стратегия (опционально)
            
        Returns:
            Кортеж (ComparisonResult, PCAPComparisonSummary)
        """
        self.logger.info(f"🔍 Сравнение PCAP файлов")
        self.logger.info(f"   Testing: {testing_pcap}")
        self.logger.info(f"   Service: {service_pcap}")
        
        # Verify files exist
        if not Path(testing_pcap).exists():
            self.logger.error(f"❌ Testing PCAP не найден: {testing_pcap}")
            raise FileNotFoundError(f"Testing PCAP not found: {testing_pcap}")
        
        if not Path(service_pcap).exists():
            self.logger.error(f"❌ Service PCAP не найден: {service_pcap}")
            raise FileNotFoundError(f"Service PCAP not found: {service_pcap}")
        
        # Compare PCAPs
        comparison = self.analyzer.compare_pcaps(testing_pcap, service_pcap)
        
        # Create summary
        summary = self._create_summary(comparison, expected_strategy)
        
        self.logger.info(f"✅ Сравнение завершено: similarity={summary.similarity_score:.2%}")
        
        return comparison, summary
    
    def _create_summary(self,
                       comparison: ComparisonResult,
                       expected_strategy: Optional[Dict[str, Any]]) -> PCAPComparisonSummary:
        """
        Создает сводку сравнения.
        
        Args:
            comparison: Результат сравнения
            expected_strategy: Ожидаемая стратегия
            
        Returns:
            PCAPComparisonSummary
        """
        testing_analysis = comparison.testing_analysis
        service_analysis = comparison.service_analysis
        
        summary = PCAPComparisonSummary(
            testing_pcap=comparison.testing_pcap,
            service_pcap=comparison.service_pcap,
            testing_packets=testing_analysis.packet_count if testing_analysis else 0,
            service_packets=service_analysis.packet_count if service_analysis else 0,
            testing_strategy=testing_analysis.strategy_type if testing_analysis else None,
            service_strategy=service_analysis.strategy_type if service_analysis else None,
            similarity_score=comparison.similarity_score,
            differences_count=len(comparison.differences)
        )
        
        # Analyze differences
        for diff in comparison.differences:
            diff_type = diff.get('type', 'unknown')
            description = diff.get('description', 'No description')
            
            if diff_type in ['strategy_type', 'split_positions', 'sni_values']:
                summary.critical_differences.append(f"{diff_type}: {description}")
            else:
                summary.warnings.append(f"{diff_type}: {description}")
        
        # Check against expected strategy
        if expected_strategy:
            if testing_analysis and not testing_analysis.matches_expected(expected_strategy):
                summary.warnings.append("Testing PCAP does not match expected strategy")
            
            if service_analysis and not service_analysis.matches_expected(expected_strategy):
                summary.warnings.append("Service PCAP does not match expected strategy")
        
        return summary
    
    def analyze_single_pcap(self,
                           pcap_file: str,
                           expected_strategy: Optional[Dict[str, Any]] = None) -> StrategyAnalysisResult:
        """
        Анализирует один PCAP файл.
        
        Args:
            pcap_file: Путь к PCAP файлу
            expected_strategy: Ожидаемая стратегия (опционально)
            
        Returns:
            StrategyAnalysisResult
        """
        self.logger.info(f"🔍 Анализ PCAP файла: {pcap_file}")
        
        if not Path(pcap_file).exists():
            self.logger.error(f"❌ PCAP файл не найден: {pcap_file}")
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        analysis = self.analyzer.analyze_strategy_application(pcap_file, expected_strategy)
        
        self.logger.info(f"✅ Анализ завершен: strategy={analysis.strategy_type}, packets={analysis.packet_count}")
        
        return analysis
    
    def generate_report(self,
                       comparison: ComparisonResult,
                       summary: PCAPComparisonSummary,
                       output_file: Optional[str] = None) -> str:
        """
        Генерирует визуальный отчет о сравнении.
        
        Args:
            comparison: Результат сравнения
            summary: Сводка сравнения
            output_file: Путь для сохранения отчета (опционально)
            
        Returns:
            Текстовый отчет
        """
        lines = []
        lines.append("=" * 80)
        lines.append("PCAP COMPARISON REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")
        
        # File information
        lines.append("FILES")
        lines.append("-" * 80)
        lines.append(f"Testing PCAP: {summary.testing_pcap}")
        lines.append(f"Service PCAP: {summary.service_pcap}")
        lines.append("")
        
        # Packet statistics
        lines.append("PACKET STATISTICS")
        lines.append("-" * 80)
        lines.append(f"Testing packets: {summary.testing_packets}")
        lines.append(f"Service packets: {summary.service_packets}")
        packet_diff = abs(summary.testing_packets - summary.service_packets)
        if packet_diff > 0:
            lines.append(f"Packet count difference: {packet_diff}")
        lines.append("")
        
        # Strategy detection
        lines.append("STRATEGY DETECTION")
        lines.append("-" * 80)
        lines.append(f"Testing strategy: {summary.testing_strategy or 'Not detected'}")
        lines.append(f"Service strategy: {summary.service_strategy or 'Not detected'}")
        
        if summary.testing_strategy == summary.service_strategy:
            lines.append("✅ Strategies match")
        else:
            lines.append("❌ Strategies differ")
        lines.append("")
        
        # Similarity score
        lines.append("SIMILARITY ANALYSIS")
        lines.append("-" * 80)
        lines.append(f"Similarity score: {summary.similarity_score:.2%}")
        
        if summary.similarity_score >= 0.9:
            lines.append("✅ PCAPs are highly similar")
        elif summary.similarity_score >= 0.7:
            lines.append("🟡 PCAPs have some differences")
        else:
            lines.append("❌ PCAPs are significantly different")
        lines.append("")
        
        # Critical differences
        if summary.critical_differences:
            lines.append("CRITICAL DIFFERENCES")
            lines.append("-" * 80)
            for diff in summary.critical_differences:
                lines.append(f"🔴 {diff}")
            lines.append("")
        
        # Warnings
        if summary.warnings:
            lines.append("WARNINGS")
            lines.append("-" * 80)
            for warning in summary.warnings:
                lines.append(f"🟡 {warning}")
            lines.append("")
        
        # Detailed differences
        if comparison.differences:
            lines.append("DETAILED DIFFERENCES")
            lines.append("-" * 80)
            for i, diff in enumerate(comparison.differences, 1):
                lines.append(f"{i}. {diff.get('type', 'Unknown')}")
                lines.append(f"   Description: {diff.get('description', 'No description')}")
                
                if 'testing' in diff:
                    lines.append(f"   Testing: {diff['testing']}")
                if 'service' in diff:
                    lines.append(f"   Service: {diff['service']}")
                
                lines.append("")
        
        # Testing PCAP analysis
        if comparison.testing_analysis:
            lines.append("TESTING PCAP ANALYSIS")
            lines.append("-" * 80)
            lines.append(self._format_analysis(comparison.testing_analysis))
            lines.append("")
        
        # Service PCAP analysis
        if comparison.service_analysis:
            lines.append("SERVICE PCAP ANALYSIS")
            lines.append("-" * 80)
            lines.append(self._format_analysis(comparison.service_analysis))
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
    
    def _format_analysis(self, analysis: StrategyAnalysisResult) -> str:
        """Форматирует результат анализа для отчета."""
        lines = []
        
        lines.append(f"Strategy detected: {analysis.strategy_detected}")
        lines.append(f"Strategy type: {analysis.strategy_type or 'Unknown'}")
        lines.append(f"Packet count: {analysis.packet_count}")
        
        if analysis.split_positions:
            lines.append(f"Split positions: {analysis.split_positions}")
        
        if analysis.sni_values:
            lines.append(f"SNI values: {analysis.sni_values}")
        
        if analysis.checksums_valid:
            valid_count = sum(1 for v in analysis.checksums_valid.values() if v)
            total_count = len(analysis.checksums_valid)
            lines.append(f"Valid checksums: {valid_count}/{total_count}")
        
        if analysis.anomalies:
            lines.append("Anomalies:")
            for anomaly in analysis.anomalies:
                lines.append(f"  - {anomaly}")
        
        if analysis.parameters:
            lines.append("Parameters:")
            for key, value in analysis.parameters.items():
                lines.append(f"  - {key}: {value}")
        
        return "\n".join(lines)
    
    def generate_json_report(self,
                            comparison: ComparisonResult,
                            summary: PCAPComparisonSummary,
                            output_file: str) -> None:
        """
        Генерирует JSON отчет о сравнении.
        
        Args:
            comparison: Результат сравнения
            summary: Сводка сравнения
            output_file: Путь для сохранения JSON отчета
        """
        try:
            report_data = {
                'generated_at': datetime.now().isoformat(),
                'summary': summary.to_dict(),
                'testing_analysis': {
                    'strategy_detected': comparison.testing_analysis.strategy_detected if comparison.testing_analysis else False,
                    'strategy_type': comparison.testing_analysis.strategy_type if comparison.testing_analysis else None,
                    'packet_count': comparison.testing_analysis.packet_count if comparison.testing_analysis else 0,
                    'split_positions': comparison.testing_analysis.split_positions if comparison.testing_analysis else [],
                    'sni_values': comparison.testing_analysis.sni_values if comparison.testing_analysis else [],
                    'anomalies': comparison.testing_analysis.anomalies if comparison.testing_analysis else [],
                    'parameters': comparison.testing_analysis.parameters if comparison.testing_analysis else {}
                } if comparison.testing_analysis else None,
                'service_analysis': {
                    'strategy_detected': comparison.service_analysis.strategy_detected if comparison.service_analysis else False,
                    'strategy_type': comparison.service_analysis.strategy_type if comparison.service_analysis else None,
                    'packet_count': comparison.service_analysis.packet_count if comparison.service_analysis else 0,
                    'split_positions': comparison.service_analysis.split_positions if comparison.service_analysis else [],
                    'sni_values': comparison.service_analysis.sni_values if comparison.service_analysis else [],
                    'anomalies': comparison.service_analysis.anomalies if comparison.service_analysis else [],
                    'parameters': comparison.service_analysis.parameters if comparison.service_analysis else {}
                } if comparison.service_analysis else None,
                'differences': comparison.differences,
                'similarity_score': comparison.similarity_score
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
        description='PCAP Compare Tool - Сравнение PCAP файлов из разных режимов'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Команда')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Сравнить два PCAP файла')
    compare_parser.add_argument(
        '--testing',
        required=True,
        help='PCAP файл из testing mode'
    )
    compare_parser.add_argument(
        '--service',
        required=True,
        help='PCAP файл из service mode'
    )
    compare_parser.add_argument(
        '--expected-strategy',
        help='JSON файл с ожидаемой стратегией'
    )
    compare_parser.add_argument(
        '--output',
        help='Файл для сохранения текстового отчета'
    )
    compare_parser.add_argument(
        '--json-output',
        help='Файл для сохранения JSON отчета'
    )
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Анализировать один PCAP файл')
    analyze_parser.add_argument(
        '--pcap',
        required=True,
        help='PCAP файл для анализа'
    )
    analyze_parser.add_argument(
        '--expected-strategy',
        help='JSON файл с ожидаемой стратегией'
    )
    analyze_parser.add_argument(
        '--output',
        help='Файл для сохранения отчета'
    )
    
    # Common arguments
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Включить отладочный вывод'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Create tool
    tool = PCAPCompareTool(debug=args.debug)
    
    # Load expected strategy if provided
    expected_strategy = None
    if hasattr(args, 'expected_strategy') and args.expected_strategy:
        try:
            with open(args.expected_strategy, 'r') as f:
                expected_strategy = json.load(f)
        except Exception as e:
            LOG.error(f"❌ Ошибка загрузки ожидаемой стратегии: {e}")
    
    if args.command == 'compare':
        # Compare PCAPs
        comparison, summary = tool.compare_pcaps(
            args.testing,
            args.service,
            expected_strategy
        )
        
        # Generate text report
        report = tool.generate_report(comparison, summary, args.output)
        
        # Print to console if no output file specified
        if not args.output:
            print(report)
        
        # Generate JSON report if requested
        if args.json_output:
            tool.generate_json_report(comparison, summary, args.json_output)
        
        # Exit with error code if similarity is low
        if summary.similarity_score < 0.7:
            LOG.warning(f"⚠️ Low similarity score: {summary.similarity_score:.2%}")
            sys.exit(1)
        else:
            LOG.info(f"✅ PCAPs are similar: {summary.similarity_score:.2%}")
            sys.exit(0)
    
    elif args.command == 'analyze':
        # Analyze single PCAP
        analysis = tool.analyze_single_pcap(args.pcap, expected_strategy)
        
        # Generate report
        lines = []
        lines.append("=" * 80)
        lines.append("PCAP ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append(f"File: {args.pcap}")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")
        lines.append(tool._format_analysis(analysis))
        lines.append("=" * 80)
        
        report = "\n".join(lines)
        
        # Save or print
        if args.output:
            Path(args.output).write_text(report, encoding='utf-8')
            LOG.info(f"📄 Отчет сохранен в {args.output}")
        else:
            print(report)
        
        # Exit with error code if strategy not detected
        if not analysis.strategy_detected:
            LOG.warning("⚠️ Strategy not detected in PCAP")
            sys.exit(1)
        else:
            LOG.info(f"✅ Strategy detected: {analysis.strategy_type}")
            sys.exit(0)


if __name__ == '__main__':
    main()
