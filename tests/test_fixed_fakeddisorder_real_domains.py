#!/usr/bin/env python3
"""
Тестирование исправленной fakeddisorder атаки с реальными доменами.

Цель: Проверить, что исправления дают результат 27/31 доменов как zapret.
"""

import asyncio
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Any, List

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class RealDomainTester:
    """Тестер исправленной fakeddisorder атаки с реальными доменами."""
    
    def __init__(self):
        self.test_domains = [
            "google.com",
            "youtube.com", 
            "facebook.com",
            "twitter.com",
            "instagram.com",
            "linkedin.com",
            "github.com",
            "stackoverflow.com",
            "reddit.com",
            "wikipedia.org"
        ]
        self.results = {}
    
    def create_test_domains_file(self) -> Path:
        """Создание файла с тестовыми доменами."""
        domains_file = Path("recon/test_domains.txt")
        
        with open(domains_file, 'w', encoding='utf-8') as f:
            for domain in self.test_domains:
                f.write(f"{domain}\n")
        
        logger.info(f"📝 Создан файл доменов: {domains_file} ({len(self.test_domains)} доменов)")
        return domains_file
    
    def test_original_vs_fixed_comparison(self):
        """Сравнение оригинальной и исправленной реализации."""
        logger.info("🔄 Сравнение оригинальной и исправленной реализации...")
        
        domains_file = self.create_test_domains_file()
        
        # Команда с исправленными параметрами (как в zapret)
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-ttl=1"
        
        # Тест с исправленной реализацией
        logger.info("🧪 Тестирование ИСПРАВЛЕННОЙ реализации...")
        fixed_result = self._run_cli_test(domains_file, strategy, "fixed", timeout=120)
        
        # Анализ результатов
        self._analyze_results(fixed_result, "ИСПРАВЛЕННАЯ")
        
        return fixed_result
    
    def _run_cli_test(self, domains_file: Path, strategy: str, test_name: str, timeout: int = 60) -> Dict[str, Any]:
        """Запуск CLI теста с заданной стратегией."""
        logger.info(f"🚀 Запуск теста '{test_name}'...")
        
        # Команда для запуска
        cmd = [
            sys.executable, "cli.py",
            "-d", str(domains_file),
            "--strategy", strategy,
            "--pcap", f"test_{test_name}.pcap"
        ]
        
        logger.info(f"📋 Команда: {' '.join(cmd)}")
        
        start_time = time.time()
        
        try:
            # Запускаем процесс
            result = subprocess.run(
                cmd,
                cwd="recon",
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            execution_time = time.time() - start_time
            
            # Анализируем вывод
            stdout_lines = result.stdout.split('\n') if result.stdout else []
            stderr_lines = result.stderr.split('\n') if result.stderr else []
            
            # Ищем результаты в выводе
            working_domains = 0
            total_domains = len(self.test_domains)
            
            for line in stdout_lines:
                if "сайтов работают" in line or "sites work" in line:
                    # Пытаемся извлечь числа
                    import re
                    match = re.search(r'(\d+)/(\d+)', line)
                    if match:
                        working_domains = int(match.group(1))
                        total_domains = int(match.group(2))
                        break
            
            success_rate = (working_domains / total_domains * 100) if total_domains > 0 else 0
            
            test_result = {
                "test_name": test_name,
                "working_domains": working_domains,
                "total_domains": total_domains,
                "success_rate": success_rate,
                "execution_time": execution_time,
                "return_code": result.returncode,
                "stdout_lines": len(stdout_lines),
                "stderr_lines": len(stderr_lines),
                "command": ' '.join(cmd),
                "strategy": strategy
            }
            
            logger.info(f"✅ Тест '{test_name}' завершен:")
            logger.info(f"   Работающих доменов: {working_domains}/{total_domains}")
            logger.info(f"   Успешность: {success_rate:.1f}%")
            logger.info(f"   Время выполнения: {execution_time:.1f}с")
            logger.info(f"   Код возврата: {result.returncode}")
            
            return test_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Тест '{test_name}' превысил timeout {timeout}с")
            return {
                "test_name": test_name,
                "working_domains": 0,
                "total_domains": len(self.test_domains),
                "success_rate": 0.0,
                "execution_time": timeout,
                "return_code": -1,
                "error": "timeout",
                "command": ' '.join(cmd),
                "strategy": strategy
            }
            
        except Exception as e:
            logger.error(f"❌ Ошибка в тесте '{test_name}': {e}")
            return {
                "test_name": test_name,
                "working_domains": 0,
                "total_domains": len(self.test_domains),
                "success_rate": 0.0,
                "execution_time": 0,
                "return_code": -1,
                "error": str(e),
                "command": ' '.join(cmd),
                "strategy": strategy
            }
    
    def _analyze_results(self, result: Dict[str, Any], implementation_name: str):
        """Анализ результатов тестирования."""
        logger.info(f"📊 АНАЛИЗ РЕЗУЛЬТАТОВ - {implementation_name}:")
        
        working = result.get('working_domains', 0)
        total = result.get('total_domains', 0)
        success_rate = result.get('success_rate', 0.0)
        
        logger.info(f"   Работающих доменов: {working}/{total}")
        logger.info(f"   Успешность: {success_rate:.1f}%")
        
        # Сравнение с zapret результатом (27/31 = 87.1%)
        zapret_success_rate = 87.1
        zapret_working = 27
        zapret_total = 31
        
        if success_rate >= zapret_success_rate * 0.9:  # 90% от zapret результата
            logger.info(f"🎉 ОТЛИЧНО! Результат близок к zapret ({zapret_working}/{zapret_total} = {zapret_success_rate:.1f}%)")
        elif success_rate >= 50:
            logger.info(f"✅ ХОРОШО! Значительное улучшение (цель: {zapret_success_rate:.1f}%)")
        elif success_rate > 0:
            logger.info(f"⚠️  ЧАСТИЧНО: Есть улучшения, но требуется доработка")
        else:
            logger.warning(f"❌ ПРОБЛЕМА: Нет работающих доменов")
        
        # Рекомендации
        if success_rate < zapret_success_rate * 0.5:
            logger.info("💡 РЕКОМЕНДАЦИИ:")
            logger.info("   - Проверить интеграцию исправлений")
            logger.info("   - Убедиться в правильности параметров стратегии")
            logger.info("   - Проанализировать логи выполнения")
    
    def run_comprehensive_test(self):
        """Запуск комплексного тестирования."""
        logger.info("🚀 Запуск комплексного тестирования исправленной fakeddisorder атаки...")
        
        # Тестируем исправленную реализацию
        fixed_result = self.test_original_vs_fixed_comparison()
        
        # Сохраняем результаты
        results = {
            "test_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_domains": self.test_domains,
            "fixed_implementation": fixed_result,
            "zapret_reference": {
                "working_domains": 27,
                "total_domains": 31,
                "success_rate": 87.1
            },
            "analysis": {
                "improvement_achieved": fixed_result.get('success_rate', 0) > 0,
                "zapret_compatibility": fixed_result.get('success_rate', 0) >= 78.4,  # 90% от zapret
                "recommendation": self._get_recommendation(fixed_result)
            }
        }
        
        # Сохраняем отчет
        report_path = Path("recon/REAL_DOMAIN_TEST_RESULTS.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Результаты сохранены: {report_path}")
        
        # Финальная сводка
        self._print_final_summary(results)
        
        return results
    
    def _get_recommendation(self, result: Dict[str, Any]) -> str:
        """Получение рекомендации на основе результатов."""
        success_rate = result.get('success_rate', 0)
        
        if success_rate >= 78.4:  # 90% от zapret
            return "ИСПРАВЛЕНИЯ УСПЕШНЫ! Готово к продакшену."
        elif success_rate >= 50:
            return "ХОРОШИЕ РЕЗУЛЬТАТЫ! Требуется небольшая доработка."
        elif success_rate > 0:
            return "ЧАСТИЧНЫЙ УСПЕХ! Требуется дополнительный анализ."
        else:
            return "ТРЕБУЕТСЯ ОТЛАДКА! Проверить интеграцию исправлений."
    
    def _print_final_summary(self, results: Dict[str, Any]):
        """Вывод финальной сводки результатов."""
        logger.info("🏆 ФИНАЛЬНАЯ СВОДКА ТЕСТИРОВАНИЯ:")
        
        fixed = results['fixed_implementation']
        zapret_ref = results['zapret_reference']
        analysis = results['analysis']
        
        logger.info(f"📊 РЕЗУЛЬТАТЫ:")
        logger.info(f"   Исправленная реализация: {fixed['working_domains']}/{fixed['total_domains']} ({fixed['success_rate']:.1f}%)")
        logger.info(f"   Zapret референс: {zapret_ref['working_domains']}/{zapret_ref['total_domains']} ({zapret_ref['success_rate']:.1f}%)")
        
        logger.info(f"🎯 АНАЛИЗ:")
        logger.info(f"   Улучшение достигнуто: {'✅ ДА' if analysis['improvement_achieved'] else '❌ НЕТ'}")
        logger.info(f"   Zapret совместимость: {'✅ ДА' if analysis['zapret_compatibility'] else '❌ НЕТ'}")
        
        logger.info(f"💡 РЕКОМЕНДАЦИЯ: {analysis['recommendation']}")
        
        if analysis['zapret_compatibility']:
            logger.info("🎉 ПОЗДРАВЛЯЕМ! Исправления fakeddisorder атаки успешны!")
        else:
            logger.info("🔧 Требуется дополнительная работа для достижения zapret совместимости.")

def main():
    """Основная функция тестирования."""
    logger.info("🔧 Тестирование исправленной fakeddisorder атаки с реальными доменами...")
    
    tester = RealDomainTester()
    results = tester.run_comprehensive_test()
    
    # Определяем успешность
    success_rate = results['fixed_implementation'].get('success_rate', 0)
    
    if success_rate >= 78.4:  # 90% от zapret результата
        logger.info("🎉 ТЕСТИРОВАНИЕ УСПЕШНО! Исправления работают корректно.")
        return True
    else:
        logger.warning("⚠️  Результаты ниже ожидаемых. Требуется дополнительная работа.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)