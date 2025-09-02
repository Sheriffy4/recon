#!/usr/bin/env python3
"""
Diagnostic Adaptive Strategy Finder - Task 18
Tests with accessible domains first to validate the approach.
"""

import asyncio
import json
import time
import logging
import sys
import socket
import ssl
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("adaptive_strategy_finder_diagnostic")


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
    response_preview: str = ""


class AdaptiveStrategyFinderDiagnostic:
    """Диагностическая версия адаптивного поиска стратегий."""
    
    def __init__(self):
        self.test_results: List[TestResult] = []
        
    async def test_basic_connectivity(self, domain: str) -> TestResult:
        """Тестирует базовое подключение без DPI обхода."""
        LOG.info(f"Тестирование базового подключения к {domain}")
        
        start_time = time.time()
        
        try:
            # Резолвим домен
            try:
                ip = socket.gethostbyname(domain)
                LOG.info(f"Resolved {domain} to {ip}")
            except Exception as e:
                return TestResult(
                    strategy_name="baseline",
                    domain=domain,
                    success=False,
                    latency_ms=0,
                    data_transferred=0,
                    connection_duration=0,
                    error=f"DNS resolution failed: {e}",
                    score=0.0
                )
            
            # Тестируем TCP подключение
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)  # Увеличиваем таймаут
            
            try:
                connect_start = time.time()
                sock.connect((ip, 443))
                connect_time = time.time() - connect_start
                LOG.info(f"TCP connection to {domain} successful in {connect_time:.2f}s")
                
                # Тестируем SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                ssl_sock = context.wrap_socket(sock, server_hostname=domain)
                ssl_time = time.time() - connect_start
                LOG.info(f"SSL handshake completed in {ssl_time:.2f}s")
                
                # Отправляем HTTP запрос
                request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                ssl_sock.send(request.encode())
                
                # Читаем ответ
                response_data = b""
                try:
                    while True:
                        chunk = ssl_sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if len(response_data) > 10000:  # Ограничиваем размер
                            break
                except:
                    pass  # Соединение закрыто сервером
                
                total_time = time.time() - start_time
                
                # Анализируем ответ
                response_str = response_data.decode('utf-8', errors='ignore')
                success = "HTTP" in response_str and ("200" in response_str or "html" in response_str.lower())
                
                # Вычисляем оценку
                score = 0.0
                if success:
                    score = 80.0
                    if connect_time < 1.0:
                        score += 15.0
                    elif connect_time < 2.0:
                        score += 10.0
                    if len(response_data) > 1000:
                        score += 5.0
                
                ssl_sock.close()
                sock.close()
                
                return TestResult(
                    strategy_name="baseline",
                    domain=domain,
                    success=success,
                    latency_ms=connect_time * 1000,
                    data_transferred=len(response_data),
                    connection_duration=total_time,
                    score=score,
                    response_preview=response_str[:200] + "..." if len(response_str) > 200 else response_str
                )
                
            except Exception as e:
                sock.close()
                return TestResult(
                    strategy_name="baseline",
                    domain=domain,
                    success=False,
                    latency_ms=(time.time() - start_time) * 1000,
                    data_transferred=0,
                    connection_duration=time.time() - start_time,
                    error=f"Connection failed: {e}",
                    score=0.0
                )
                
        except Exception as e:
            return TestResult(
                strategy_name="baseline",
                domain=domain,
                success=False,
                latency_ms=0,
                data_transferred=0,
                connection_duration=0,
                error=f"General error: {e}",
                score=0.0
            )
    
    async def test_domain_accessibility(self, domains: List[str]) -> Dict[str, TestResult]:
        """Тестирует доступность доменов."""
        results = {}
        
        print("🔍 === Диагностика доступности доменов ===")
        print(f"{'Домен':<20} {'Статус':<12} {'Задержка':<10} {'Данные':<10} {'Ошибка'}")
        print("-" * 80)
        
        for domain in domains:
            result = await self.test_basic_connectivity(domain)
            results[domain] = result
            
            status = "✅ Доступен" if result.success else "❌ Недоступен"
            error_info = result.error[:30] + "..." if result.error and len(result.error) > 30 else (result.error or "")
            
            print(f"{domain:<20} {status:<12} {result.latency_ms:<10.0f} {result.data_transferred:<10} {error_info}")
            
            await asyncio.sleep(0.5)
        
        return results
    
    async def test_with_attack_combinator(self, domain: str) -> Optional[TestResult]:
        """Тестирует домен через attack combinator для сравнения."""
        try:
            from core.attack_combinator import AttackCombinator
            from core.strategy_selector import StrategySelector
            from cli import resolve_all_ips
            
            # Инициализируем компоненты
            strategy_selector = StrategySelector()
            attack_combinator = AttackCombinator(strategy_selector=strategy_selector, debug=False)
            
            # Резолвим IP
            ips = await resolve_all_ips(domain)
            if not ips:
                return None
            target_ip = list(ips)[0]
            
            # Тестируем одну стратегию
            results = await attack_combinator.test_multiple_attacks_parallel(
                domain, target_ip, ["fakeddisorder_basic"], 1
            )
            
            if results and len(results) > 0:
                result = results[0]
                return TestResult(
                    strategy_name="attack_combinator_test",
                    domain=domain,
                    success=result.success,
                    latency_ms=result.latency_ms,
                    data_transferred=result.data_transferred,
                    connection_duration=result.latency_ms / 1000,
                    score=80.0 if result.success else 0.0
                )
            
        except Exception as e:
            LOG.error(f"Attack combinator test failed: {e}")
            return None
        
        return None
    
    def generate_diagnostic_report(self, baseline_results: Dict[str, TestResult], 
                                 combinator_results: Dict[str, Optional[TestResult]]) -> str:
        """Генерирует диагностический отчет."""
        report_lines = []
        
        report_lines.append("=" * 80)
        report_lines.append("ADAPTIVE STRATEGY FINDER DIAGNOSTIC REPORT")
        report_lines.append("Task 18: Debug and Fix Analysis")
        report_lines.append("=" * 80)
        report_lines.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # Анализ базовой доступности
        report_lines.append("BASELINE CONNECTIVITY ANALYSIS")
        report_lines.append("-" * 40)
        
        accessible_domains = [d for d, r in baseline_results.items() if r.success]
        blocked_domains = [d for d, r in baseline_results.items() if not r.success]
        
        report_lines.append(f"Total domains tested: {len(baseline_results)}")
        report_lines.append(f"Accessible domains: {len(accessible_domains)}")
        report_lines.append(f"Blocked/Inaccessible domains: {len(blocked_domains)}")
        report_lines.append("")
        
        if accessible_domains:
            report_lines.append("✅ ACCESSIBLE DOMAINS:")
            for domain in accessible_domains:
                result = baseline_results[domain]
                report_lines.append(f"  • {domain}: {result.latency_ms:.0f}ms, {result.data_transferred}b")
        
        if blocked_domains:
            report_lines.append("")
            report_lines.append("❌ BLOCKED/INACCESSIBLE DOMAINS:")
            for domain in blocked_domains:
                result = baseline_results[domain]
                error = result.error or "Unknown error"
                report_lines.append(f"  • {domain}: {error}")
        
        report_lines.append("")
        
        # Анализ attack combinator
        report_lines.append("ATTACK COMBINATOR COMPARISON")
        report_lines.append("-" * 40)
        
        combinator_working = sum(1 for r in combinator_results.values() if r and r.success)
        combinator_tested = sum(1 for r in combinator_results.values() if r is not None)
        
        report_lines.append(f"Attack combinator tests: {combinator_tested}")
        report_lines.append(f"Attack combinator successes: {combinator_working}")
        
        if combinator_tested > 0:
            for domain, result in combinator_results.items():
                if result:
                    status = "✅ Success" if result.success else "❌ Failed"
                    report_lines.append(f"  • {domain}: {status} ({result.latency_ms:.0f}ms)")
        
        report_lines.append("")
        
        # Проблемы и рекомендации
        report_lines.append("IDENTIFIED ISSUES")
        report_lines.append("-" * 40)
        
        issues = []
        
        if len(blocked_domains) == len(baseline_results):
            issues.append("All domains are inaccessible - network connectivity issue")
        elif len(blocked_domains) > len(accessible_domains):
            issues.append("Most domains are blocked - DPI filtering is active")
        
        if combinator_tested == 0:
            issues.append("Attack combinator integration failed - module import issues")
        elif combinator_working == 0 and combinator_tested > 0:
            issues.append("Attack combinator strategies not working - strategy interpreter issues")
        
        # Анализ ошибок
        timeout_errors = sum(1 for r in baseline_results.values() if r.error and "timeout" in r.error.lower())
        dns_errors = sum(1 for r in baseline_results.values() if r.error and "dns" in r.error.lower())
        connection_errors = sum(1 for r in baseline_results.values() if r.error and "connection" in r.error.lower())
        
        if timeout_errors > 0:
            issues.append(f"Timeout errors detected ({timeout_errors} domains) - network latency issues")
        if dns_errors > 0:
            issues.append(f"DNS resolution errors ({dns_errors} domains) - DNS filtering")
        if connection_errors > 0:
            issues.append(f"Connection errors ({connection_errors} domains) - TCP blocking")
        
        if issues:
            for i, issue in enumerate(issues, 1):
                report_lines.append(f"{i}. {issue}")
        else:
            report_lines.append("No major issues detected")
        
        report_lines.append("")
        
        # Рекомендации
        report_lines.append("RECOMMENDATIONS")
        report_lines.append("-" * 40)
        
        recommendations = []
        
        if len(blocked_domains) > 0:
            recommendations.append("Test with known accessible domains (google.com, cloudflare.com)")
            recommendations.append("Verify network connectivity without DPI bypass")
            recommendations.append("Check if domains are actually blocked in your region")
        
        if combinator_working == 0:
            recommendations.append("Debug strategy interpreter - strategies converting incorrectly")
            recommendations.append("Test individual attack implementations")
            recommendations.append("Verify packet injection is working")
        
        if timeout_errors > 0:
            recommendations.append("Increase connection timeouts")
            recommendations.append("Test with different network interfaces")
        
        if not recommendations:
            recommendations.append("System appears to be working correctly")
            recommendations.append("Try testing with more diverse domain set")
        
        for i, rec in enumerate(recommendations, 1):
            report_lines.append(f"{i}. {rec}")
        
        report_lines.append("")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)


async def main():
    """Главная функция диагностики."""
    finder = AdaptiveStrategyFinderDiagnostic()
    
    # Тестовые домены - смесь заблокированных и доступных
    test_domains = [
        "google.com",      # Должен быть доступен
        "cloudflare.com",  # Должен быть доступен
        "example.com",     # Должен быть доступен
        "x.com",           # Может быть заблокирован
        "instagram.com",   # Может быть заблокирован
        "rutracker.org"    # Вероятно заблокирован
    ]
    
    print("🚀 === Диагностика адаптивного поиска стратегий ===")
    print(f"Тестируемые домены: {', '.join(test_domains)}")
    
    try:
        # Тестируем базовую доступность
        baseline_results = await finder.test_domain_accessibility(test_domains)
        
        print(f"\n🔧 === Тестирование через Attack Combinator ===")
        
        # Тестируем через attack combinator для сравнения
        combinator_results = {}
        for domain in test_domains:
            print(f"Тестирование {domain} через attack combinator...")
            result = await finder.test_with_attack_combinator(domain)
            combinator_results[domain] = result
            
            if result:
                status = "✅ Успех" if result.success else "❌ Неудача"
                print(f"  {domain}: {status} ({result.latency_ms:.0f}ms)")
            else:
                print(f"  {domain}: ❌ Ошибка тестирования")
        
        # Генерируем отчет
        report = finder.generate_diagnostic_report(baseline_results, combinator_results)
        
        # Сохраняем результаты
        results_data = {
            "baseline_results": {d: asdict(r) for d, r in baseline_results.items()},
            "combinator_results": {d: asdict(r) if r else None for d, r in combinator_results.items()},
            "timestamp": time.time()
        }
        
        with open("adaptive_strategy_diagnostic.json", "w", encoding="utf-8") as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)
        
        with open("adaptive_strategy_diagnostic_report.txt", "w", encoding="utf-8") as f:
            f.write(report)
        
        print(f"\n📊 === Диагностический отчет ===")
        print(report)
        
        print(f"\n💾 Результаты сохранены:")
        print(f"  • adaptive_strategy_diagnostic.json")
        print(f"  • adaptive_strategy_diagnostic_report.txt")
        
    except KeyboardInterrupt:
        print(f"\n⏹️ Диагностика прервана пользователем")
    except Exception as e:
        LOG.error(f"Ошибка диагностики: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())