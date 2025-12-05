#!/usr/bin/env python3
"""
Mode Validator - Проверка соответствия между режимами

Этот инструмент проверяет соответствие между testing mode и service mode,
тестирует одинаковые стратегии в обоих режимах и генерирует отчет о несоответствиях.

Requirements: 5.1, 5.2, 5.3
"""

import json
import logging
import sys
import asyncio
import socket
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.unified_strategy_loader import UnifiedStrategyLoader, NormalizedStrategy
from core.strategy.validator import StrategyValidator, TestResult, ValidationResult

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)


@dataclass
class ModeTestResult:
    """Результат теста стратегии в одном режиме."""
    
    mode: str  # 'testing' or 'service'
    domain: str
    strategy: Dict[str, Any]
    success: bool
    latency_ms: float = 0.0
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'mode': self.mode,
            'domain': self.domain,
            'strategy': self.strategy,
            'success': self.success,
            'latency_ms': self.latency_ms,
            'error_message': self.error_message,
            'timestamp': self.timestamp
        }


@dataclass
class ModeComparisonResult:
    """Результат сравнения режимов для домена."""
    
    domain: str
    strategy: Dict[str, Any]
    testing_result: ModeTestResult
    service_result: ModeTestResult
    is_consistent: bool
    inconsistency_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'domain': self.domain,
            'strategy': self.strategy,
            'testing_result': self.testing_result.to_dict(),
            'service_result': self.service_result.to_dict(),
            'is_consistent': self.is_consistent,
            'inconsistency_reason': self.inconsistency_reason
        }


class ModeValidator:
    """
    Валидатор соответствия между режимами.
    
    Requirements: 5.1, 5.2, 5.3
    """
    
    def __init__(self, debug: bool = False):
        """
        Инициализация валидатора.
        
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
        
        self.logger.info("✅ Mode Validator initialized")
    
    def load_strategies(self, strategies_file: str) -> Dict[str, Any]:
        """
        Загружает стратегии из файла.
        
        Args:
            strategies_file: Путь к файлу стратегий
            
        Returns:
            Словарь {domain: strategy}
        """
        try:
            path = Path(strategies_file)
            if not path.exists():
                self.logger.error(f"❌ Файл не найден: {strategies_file}")
                return {}
            
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.logger.info(f"📂 Загружено {len(data)} стратегий из {strategies_file}")
            return data
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка загрузки файла {strategies_file}: {e}")
            return {}
    
    async def test_strategy_in_mode(self,
                                   domain: str,
                                   strategy: Dict[str, Any],
                                   mode: str,
                                   timeout: float = 10.0) -> ModeTestResult:
        """
        Тестирует стратегию в одном режиме.
        
        Args:
            domain: Доменное имя
            strategy: Стратегия для теста
            mode: Режим ('testing' или 'service')
            timeout: Таймаут в секундах
            
        Returns:
            ModeTestResult с результатом теста
        """
        self.logger.debug(f"🧪 Тестирование {domain} в режиме {mode}")
        
        start_time = datetime.now()
        
        try:
            # Validate strategy first
            validation_result = self.validator.validate_strategy(strategy)
            
            if not validation_result.is_valid:
                return ModeTestResult(
                    mode=mode,
                    domain=domain,
                    strategy=strategy,
                    success=False,
                    error_message=f"Strategy validation failed: {', '.join(validation_result.errors)}"
                )
            
            # Test connectivity
            success, latency, error = await self._test_connectivity(domain, timeout)
            
            end_time = datetime.now()
            total_latency = (end_time - start_time).total_seconds() * 1000
            
            return ModeTestResult(
                mode=mode,
                domain=domain,
                strategy=strategy,
                success=success,
                latency_ms=latency if success else total_latency,
                error_message=error
            )
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка теста {domain} в режиме {mode}: {e}")
            return ModeTestResult(
                mode=mode,
                domain=domain,
                strategy=strategy,
                success=False,
                error_message=f"Test exception: {str(e)}"
            )
    
    async def _test_connectivity(self,
                                domain: str,
                                timeout: float) -> Tuple[bool, float, Optional[str]]:
        """
        Тестирует подключение к домену.
        
        Args:
            domain: Доменное имя
            timeout: Таймаут в секундах
            
        Returns:
            Кортеж (success, latency_ms, error_message)
        """
        import time
        
        start_time = time.time()
        
        try:
            # Resolve domain
            try:
                ip_addresses = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
                if not ip_addresses:
                    return False, 0.0, f"Could not resolve domain: {domain}"
                
                target_ip = ip_addresses[0][4][0]
                
            except Exception as e:
                return False, 0.0, f"DNS resolution failed: {str(e)}"
            
            # Test TCP connection
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, 443),
                    timeout=timeout
                )
                
                writer.close()
                await writer.wait_closed()
                
                latency = (time.time() - start_time) * 1000
                return True, latency, None
                
            except asyncio.TimeoutError:
                latency = (time.time() - start_time) * 1000
                return False, latency, f"Connection timeout after {timeout}s"
            
            except Exception as e:
                latency = (time.time() - start_time) * 1000
                return False, latency, f"Connection failed: {str(e)}"
        
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return False, latency, f"Test failed: {str(e)}"
    
    async def validate_mode_consistency(self,
                                       strategies: Dict[str, Any],
                                       domains: Optional[List[str]] = None,
                                       timeout: float = 10.0) -> List[ModeComparisonResult]:
        """
        Проверяет соответствие между режимами для стратегий.
        
        Args:
            strategies: Словарь {domain: strategy}
            domains: Список доменов для проверки (None = все)
            timeout: Таймаут для каждого теста
            
        Returns:
            Список ModeComparisonResult
        """
        self.logger.info("🔍 Проверка соответствия между режимами")
        
        # Filter domains if specified
        if domains:
            test_strategies = {d: s for d, s in strategies.items() if d in domains}
        else:
            test_strategies = strategies
        
        self.logger.info(f"📊 Тестирование {len(test_strategies)} доменов")
        
        results = []
        
        for domain, strategy in test_strategies.items():
            self.logger.info(f"🧪 Тестирование {domain}")
            
            # Test in both modes
            testing_result = await self.test_strategy_in_mode(
                domain, strategy, 'testing', timeout
            )
            
            service_result = await self.test_strategy_in_mode(
                domain, strategy, 'service', timeout
            )
            
            # Compare results
            is_consistent = testing_result.success == service_result.success
            inconsistency_reason = None
            
            if not is_consistent:
                if testing_result.success and not service_result.success:
                    inconsistency_reason = f"Works in testing but fails in service: {service_result.error_message}"
                elif not testing_result.success and service_result.success:
                    inconsistency_reason = f"Fails in testing but works in service: {testing_result.error_message}"
            
            comparison = ModeComparisonResult(
                domain=domain,
                strategy=strategy,
                testing_result=testing_result,
                service_result=service_result,
                is_consistent=is_consistent,
                inconsistency_reason=inconsistency_reason
            )
            
            results.append(comparison)
            
            # Log result
            if is_consistent:
                status = "✅" if testing_result.success else "⚠️"
                self.logger.info(f"{status} {domain}: Consistent ({testing_result.success})")
            else:
                self.logger.warning(f"❌ {domain}: Inconsistent - {inconsistency_reason}")
        
        self.logger.info(f"✅ Проверка завершена: {len(results)} доменов")
        
        return results
    
    def generate_report(self,
                       results: List[ModeComparisonResult],
                       output_file: Optional[str] = None) -> str:
        """
        Генерирует отчет о несоответствиях.
        
        Args:
            results: Список результатов сравнения
            output_file: Путь для сохранения отчета (опционально)
            
        Returns:
            Текстовый отчет
        """
        lines = []
        lines.append("=" * 80)
        lines.append("MODE VALIDATION REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Total domains tested: {len(results)}")
        lines.append("")
        
        # Summary statistics
        consistent_count = sum(1 for r in results if r.is_consistent)
        inconsistent_count = len(results) - consistent_count
        
        testing_success = sum(1 for r in results if r.testing_result.success)
        service_success = sum(1 for r in results if r.service_result.success)
        
        both_success = sum(1 for r in results if r.testing_result.success and r.service_result.success)
        both_fail = sum(1 for r in results if not r.testing_result.success and not r.service_result.success)
        
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Consistent results: {consistent_count} ({consistent_count/len(results)*100:.1f}%)")
        lines.append(f"Inconsistent results: {inconsistent_count} ({inconsistent_count/len(results)*100:.1f}%)")
        lines.append("")
        lines.append(f"Testing mode success: {testing_success}/{len(results)}")
        lines.append(f"Service mode success: {service_success}/{len(results)}")
        lines.append(f"Both modes success: {both_success}/{len(results)}")
        lines.append(f"Both modes fail: {both_fail}/{len(results)}")
        lines.append("")
        
        # Inconsistencies
        inconsistent_results = [r for r in results if not r.is_consistent]
        if inconsistent_results:
            lines.append("INCONSISTENCIES")
            lines.append("-" * 80)
            
            for result in inconsistent_results:
                lines.append(f"❌ {result.domain}")
                lines.append(f"   Reason: {result.inconsistency_reason}")
                lines.append(f"   Testing: {'✅ Success' if result.testing_result.success else '❌ Failed'} ({result.testing_result.latency_ms:.1f}ms)")
                if result.testing_result.error_message:
                    lines.append(f"      Error: {result.testing_result.error_message}")
                lines.append(f"   Service: {'✅ Success' if result.service_result.success else '❌ Failed'} ({result.service_result.latency_ms:.1f}ms)")
                if result.service_result.error_message:
                    lines.append(f"      Error: {result.service_result.error_message}")
                lines.append("")
        
        # Consistent successes
        consistent_successes = [r for r in results if r.is_consistent and r.testing_result.success]
        if consistent_successes:
            lines.append("CONSISTENT SUCCESSES")
            lines.append("-" * 80)
            for result in consistent_successes:
                lines.append(f"✅ {result.domain}")
                lines.append(f"   Testing: {result.testing_result.latency_ms:.1f}ms")
                lines.append(f"   Service: {result.service_result.latency_ms:.1f}ms")
            lines.append("")
        
        # Consistent failures
        consistent_failures = [r for r in results if r.is_consistent and not r.testing_result.success]
        if consistent_failures:
            lines.append("CONSISTENT FAILURES")
            lines.append("-" * 80)
            for result in consistent_failures:
                lines.append(f"⚠️ {result.domain}")
                lines.append(f"   Testing error: {result.testing_result.error_message}")
                lines.append(f"   Service error: {result.service_result.error_message}")
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
                            results: List[ModeComparisonResult],
                            output_file: str) -> None:
        """
        Генерирует JSON отчет.
        
        Args:
            results: Список результатов сравнения
            output_file: Путь для сохранения JSON отчета
        """
        try:
            consistent_count = sum(1 for r in results if r.is_consistent)
            
            report_data = {
                'generated_at': datetime.now().isoformat(),
                'total_domains': len(results),
                'consistent_count': consistent_count,
                'inconsistent_count': len(results) - consistent_count,
                'testing_success_count': sum(1 for r in results if r.testing_result.success),
                'service_success_count': sum(1 for r in results if r.service_result.success),
                'results': [r.to_dict() for r in results]
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
        description='Mode Validator - Проверка соответствия между режимами'
    )
    parser.add_argument(
        '--strategies',
        required=True,
        help='Файл стратегий для тестирования (domain_strategies.json)'
    )
    parser.add_argument(
        '--domains',
        nargs='+',
        help='Список доменов для проверки (по умолчанию все)'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=10.0,
        help='Таймаут для каждого теста в секундах (по умолчанию 10)'
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
    
    # Create validator
    validator = ModeValidator(debug=args.debug)
    
    # Load strategies
    strategies = validator.load_strategies(args.strategies)
    
    if not strategies:
        LOG.error("❌ Нет стратегий для тестирования")
        sys.exit(1)
    
    # Run validation
    results = asyncio.run(
        validator.validate_mode_consistency(
            strategies,
            args.domains,
            args.timeout
        )
    )
    
    # Generate text report
    report = validator.generate_report(results, args.output)
    
    # Print to console if no output file specified
    if not args.output:
        print(report)
    
    # Generate JSON report if requested
    if args.json_output:
        validator.generate_json_report(results, args.json_output)
    
    # Exit with error code if there are inconsistencies
    inconsistent_count = sum(1 for r in results if not r.is_consistent)
    if inconsistent_count > 0:
        LOG.warning(f"⚠️ Found {inconsistent_count} inconsistencies")
        sys.exit(1)
    else:
        LOG.info("✅ All modes are consistent")
        sys.exit(0)


if __name__ == '__main__':
    main()
