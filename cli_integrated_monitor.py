#!/usr/bin/env python3
"""
Интеграция с cli.py для реального тестирования стратегий
Использует существующую функциональность cli.py для применения обхода
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cli_integrated_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CLIIntegratedMonitor:
    """Монитор, интегрированный с cli.py"""
    
    def __init__(self):
        self.sites_to_test = set()
        self.blocked_sites = {}
        self.working_strategies = {}
        self.test_results = {}
        
        # Стратегии для тестирования (в формате zapret)
        self.test_strategies = [
            {
                "name": "tls_sni_split",
                "description": "Разделение SNI в TLS пакетах",
                "zapret_params": "--dpi-desync=fake,disorder --dpi-desync-split-tls=sni --dpi-desync-fooling=badseq --dpi-desync-ttl=1 --dpi-desync-repeats=3"
            },
            {
                "name": "tls_chello_frag",
                "description": "Фрагментация TLS Client Hello",
                "zapret_params": "--dpi-desync=multisplit --dpi-desync-split-tls=chello --dpi-desync-split-count=8 --dpi-desync-fooling=badsum --dpi-desync-ttl=1"
            },
            {
                "name": "aggressive_multisplit",
                "description": "Агрессивная фрагментация",
                "zapret_params": "--dpi-desync=multisplit --dpi-desync-split-count=20 --dpi-desync-split-seqovl=100 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=5"
            },
            {
                "name": "fake_tls_records",
                "description": "Поддельные TLS записи",
                "zapret_params": "--dpi-desync=fake --dpi-desync-fake-tls=0x160303 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=4"
            },
            {
                "name": "disorder_low_ttl",
                "description": "Нарушение порядка с низким TTL",
                "zapret_params": "--dpi-desync=fake,disorder --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-ttl=1 --dpi-desync-repeats=3"
            }
        ]
        
        self.load_sites()
    
    def load_sites(self):
        """Загружает сайты из sites.txt"""
        
        sites_file = "sites.txt"
        
        try:
            if os.path.exists(sites_file):
                with open(sites_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line.startswith('http'):
                                domain = urlparse(line).netloc
                            else:
                                domain = line
                            
                            self.sites_to_test.add(domain)
                
                logger.info(f"Загружено {len(self.sites_to_test)} сайтов для тестирования")
                
        except Exception as e:
            logger.error(f"Ошибка загрузки сайтов: {e}")
            # Добавляем тестовые сайты
            self.sites_to_test.update([
                "abs-0.twimg.com",
                "instagram.com", 
                "facebook.com",
                "x.com"
            ])
    
    def test_site_with_cli(self, site: str, strategy_params: str = None, timeout: int = 15) -> Tuple[bool, float, str]:
        """Тестирует сайт через cli.py"""
        
        try:
            cmd = [sys.executable, "cli.py", "test", site]
            
            if strategy_params:
                # Добавляем параметры стратегии
                cmd.extend(["--strategy", strategy_params])
            
            cmd.extend(["--timeout", str(timeout)])
            
            start_time = time.time()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
                encoding='utf-8',
                errors='ignore'
            )
            
            elapsed = time.time() - start_time
            
            # Анализируем вывод cli.py
            output = result.stdout + result.stderr
            
            # Ищем индикаторы успеха
            success_indicators = [
                "SUCCESS", "WORKING", "✅", "200", "301", "302", "304"
            ]
            
            failure_indicators = [
                "TIMEOUT", "FAILED", "ERROR", "❌", "BLOCKED", "CONNECTION_ERROR"
            ]
            
            is_success = any(indicator in output.upper() for indicator in success_indicators)
            is_failure = any(indicator in output.upper() for indicator in failure_indicators)
            
            if is_success and not is_failure:
                return True, elapsed * 1000, "CLI_SUCCESS"
            elif is_failure:
                return False, elapsed * 1000, "CLI_FAILED"
            else:
                # Если неясно, считаем неудачей
                return False, elapsed * 1000, f"CLI_UNCLEAR (exit_code: {result.returncode})"
                
        except subprocess.TimeoutExpired:
            return False, timeout * 1000, "CLI_TIMEOUT"
        except FileNotFoundError:
            logger.error("cli.py не найден")
            return False, 0, "CLI_NOT_FOUND"
        except Exception as e:
            logger.error(f"Ошибка запуска cli.py: {e}")
            return False, 0, f"CLI_ERROR: {str(e)[:50]}"
    
    def test_all_sites(self):
        """Тестирует все сайты на доступность"""
        
        logger.info("🔍 Тестирование доступности сайтов через cli.py...")
        
        accessible_sites = []
        blocked_sites = []
        
        # Ограничиваем количество сайтов для демонстрации
        test_sites = list(self.sites_to_test)[:10]
        
        for site in test_sites:
            logger.info(f"Тестирование {site}...")
            
            is_accessible, response_time, status = self.test_site_with_cli(site)
            
            self.test_results[site] = {
                'accessible': is_accessible,
                'response_time': response_time,
                'status': status,
                'timestamp': datetime.now().isoformat()
            }
            
            if is_accessible:
                accessible_sites.append(site)
                logger.info(f"✅ {site} доступен ({response_time:.1f}ms) - {status}")
            else:
                blocked_sites.append(site)
                self.blocked_sites[site] = self.test_results[site]
                logger.warning(f"🚫 {site} заблокирован ({response_time:.1f}ms) - {status}")
        
        logger.info(f"\n📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:")
        logger.info(f"✅ Доступных сайтов: {len(accessible_sites)}")
        logger.info(f"🚫 Заблокированных сайтов: {len(blocked_sites)}")
        
        return accessible_sites, blocked_sites
    
    def calibrate_strategies_for_blocked_sites(self, blocked_sites: List[str]):
        """Калибрует стратегии для заблокированных сайтов через cli.py"""
        
        if not blocked_sites:
            logger.info("Нет заблокированных сайтов для калибровки")
            return
        
        logger.info(f"🎯 Калибровка стратегий через cli.py для заблокированных сайтов")
        
        # Ограничиваем количество сайтов для демонстрации
        test_sites = blocked_sites[:3]
        
        for site in test_sites:
            logger.info(f"\n🔧 Калибровка для {site}...")
            
            working_strategy = None
            
            for strategy in self.test_strategies:
                logger.info(f"   Тестирование стратегии: {strategy['name']}")
                logger.info(f"   Описание: {strategy['description']}")
                logger.info(f"   Параметры: {strategy['zapret_params']}")
                
                # Тестируем стратегию через cli.py
                is_accessible, response_time, status = self.test_site_with_cli(
                    site, strategy['zapret_params']
                )
                
                if is_accessible:
                    working_strategy = strategy
                    logger.info(f"   ✅ Стратегия работает! ({response_time:.1f}ms) - {status}")
                    break
                else:
                    logger.info(f"   ❌ Стратегия не работает ({status})")
                
                time.sleep(3)  # Пауза между тестами
            
            if working_strategy:
                self.working_strategies[site] = working_strategy
                logger.info(f"🎉 Найдена рабочая стратегия для {site}: {working_strategy['name']}")
            else:
                logger.warning(f"❌ Не найдена рабочая стратегия для {site}")
    
    def save_strategies(self):
        """Сохраняет найденные стратегии в файлы конфигурации"""
        
        if not self.working_strategies:
            logger.info("Нет стратегий для сохранения")
            return
        
        logger.info("💾 Сохранение найденных стратегий...")
        
        # Сохраняем в domain_strategies.json
        try:
            domain_strategies_file = "domain_strategies.json"
            
            domain_strategies = {"domain_strategies": {}}
            if os.path.exists(domain_strategies_file):
                with open(domain_strategies_file, 'r', encoding='utf-8') as f:
                    domain_strategies = json.load(f)
            
            if "domain_strategies" not in domain_strategies:
                domain_strategies["domain_strategies"] = {}
            
            for site, strategy in self.working_strategies.items():
                domain_strategies["domain_strategies"][site] = {
                    "domain": site,
                    "strategy": strategy["zapret_params"],
                    "success_rate": 1.0,
                    "avg_latency_ms": 1000.0,
                    "last_tested": datetime.now().isoformat(),
                    "test_count": 1,
                    "split_pos": None,
                    "overlap_size": None,
                    "fake_ttl_source": None,
                    "fooling_modes": None,
                    "calibrated_by": "cli_integrated_monitor",
                    "strategy_name": strategy["name"],
                    "strategy_description": strategy["description"]
                }
            
            with open(domain_strategies_file, 'w', encoding='utf-8') as f:
                json.dump(domain_strategies, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ Сохранено в {domain_strategies_file}")
            
        except Exception as e:
            logger.error(f"Ошибка сохранения domain_strategies.json: {e}")
        
        # Сохраняем в strategies_enhanced.json
        try:
            strategies_enhanced_file = "strategies_enhanced.json"
            
            strategies_enhanced = {}
            if os.path.exists(strategies_enhanced_file):
                with open(strategies_enhanced_file, 'r', encoding='utf-8') as f:
                    strategies_enhanced = json.load(f)
            
            for site, strategy in self.working_strategies.items():
                strategies_enhanced[site] = strategy["zapret_params"]
            
            with open(strategies_enhanced_file, 'w', encoding='utf-8') as f:
                json.dump(strategies_enhanced, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ Сохранено в {strategies_enhanced_file}")
            
        except Exception as e:
            logger.error(f"Ошибка сохранения strategies_enhanced.json: {e}")
    
    def create_cli_config(self):
        """Создает конфигурацию для cli.py"""
        
        if not self.working_strategies:
            return
        
        logger.info("⚙️ Создание конфигурации для cli.py...")
        
        try:
            config = {
                "auto_strategies": {},
                "domain_mapping": {},
                "calibration_results": {
                    "timestamp": datetime.now().isoformat(),
                    "total_calibrated": len(self.working_strategies),
                    "method": "cli_integrated_monitor"
                }
            }
            
            for site, strategy in self.working_strategies.items():
                config["auto_strategies"][site] = strategy["zapret_params"]
                config["domain_mapping"][site] = {
                    "strategy_name": strategy["name"],
                    "description": strategy["description"],
                    "calibrated_at": datetime.now().isoformat()
                }
            
            config_file = "cli_auto_strategies.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ Конфигурация cli.py сохранена: {config_file}")
            
        except Exception as e:
            logger.error(f"Ошибка создания конфигурации cli.py: {e}")
    
    def generate_cli_commands(self):
        """Генерирует команды cli.py для найденных стратегий"""
        
        if not self.working_strategies:
            return
        
        logger.info("📋 Генерация команд cli.py...")
        
        commands = []
        
        for site, strategy in self.working_strategies.items():
            cmd = f'python cli.py test {site} --strategy "{strategy["zapret_params"]}"'
            commands.append({
                "site": site,
                "strategy_name": strategy["name"],
                "command": cmd,
                "description": strategy["description"]
            })
        
        # Сохраняем команды в файл
        try:
            commands_file = "cli_commands.txt"
            
            with open(commands_file, 'w', encoding='utf-8') as f:
                f.write("# Команды cli.py для найденных стратегий\n")
                f.write(f"# Сгенерировано: {datetime.now().isoformat()}\n\n")
                
                for cmd_info in commands:
                    f.write(f"# {cmd_info['site']} - {cmd_info['strategy_name']}\n")
                    f.write(f"# {cmd_info['description']}\n")
                    f.write(f"{cmd_info['command']}\n\n")
            
            logger.info(f"✅ Команды сохранены в {commands_file}")
            
            # Выводим команды в лог
            logger.info("📋 КОМАНДЫ CLI.PY ДЛЯ НАЙДЕННЫХ СТРАТЕГИЙ:")
            for cmd_info in commands:
                logger.info(f"   {cmd_info['site']}: {cmd_info['command']}")
            
        except Exception as e:
            logger.error(f"Ошибка сохранения команд: {e}")
    
    def generate_report(self):
        """Генерирует отчет о калибровке"""
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "method": "cli_integrated_monitor",
            "cli_available": os.path.exists("cli.py"),
            "total_sites_tested": len(self.test_results),
            "accessible_sites": len([s for s in self.test_results.values() if s['accessible']]),
            "blocked_sites": len(self.blocked_sites),
            "strategies_found": len(self.working_strategies),
            "test_results": self.test_results,
            "blocked_sites_details": self.blocked_sites,
            "working_strategies": self.working_strategies
        }
        
        report_file = f"cli_integrated_report_{int(time.time())}.json"
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📄 Отчет сохранен: {report_file}")
            
        except Exception as e:
            logger.error(f"Ошибка сохранения отчета: {e}")
        
        return report
    
    def print_summary(self):
        """Выводит итоговую сводку"""
        
        logger.info("\n" + "="*60)
        logger.info("📊 ИТОГОВАЯ СВОДКА CLI-ИНТЕГРИРОВАННОГО МОНИТОРИНГА")
        logger.info("="*60)
        
        logger.info(f"🔧 CLI.py: {'✅ Доступен' if os.path.exists('cli.py') else '❌ Недоступен'}")
        logger.info(f"🔍 Протестировано сайтов: {len(self.test_results)}")
        logger.info(f"✅ Доступных сайтов: {len([s for s in self.test_results.values() if s['accessible']])}")
        logger.info(f"🚫 Заблокированных сайтов: {len(self.blocked_sites)}")
        logger.info(f"🎯 Найдено рабочих стратегий: {len(self.working_strategies)}")
        
        if self.blocked_sites:
            logger.info(f"\n🚫 ЗАБЛОКИРОВАННЫЕ САЙТЫ:")
            for site, details in self.blocked_sites.items():
                logger.info(f"   • {site}: {details['status']}")
        
        if self.working_strategies:
            logger.info(f"\n🎯 НАЙДЕННЫЕ СТРАТЕГИИ:")
            for site, strategy in self.working_strategies.items():
                logger.info(f"   • {site}: {strategy['name']}")
                logger.info(f"     Команда: python cli.py test {site} --strategy \"{strategy['zapret_params']}\"")
        
        logger.info(f"\n📁 СОЗДАННЫЕ ФАЙЛЫ:")
        logger.info(f"   • domain_strategies.json - основная база стратегий")
        logger.info(f"   • strategies_enhanced.json - расширенная конфигурация")
        logger.info(f"   • cli_auto_strategies.json - конфигурация для cli.py")
        logger.info(f"   • cli_commands.txt - готовые команды")
        
        if self.working_strategies:
            logger.info(f"\n🚀 СЛЕДУЮЩИЕ ШАГИ:")
            logger.info(f"   1. Используйте команды из cli_commands.txt")
            logger.info(f"   2. Запустите recon_service.py с обновленными стратегиями")
            logger.info(f"   3. Проверьте доступность заблокированных сайтов")
        else:
            logger.info(f"\n⚠️ РЕКОМЕНДАЦИИ:")
            logger.info(f"   1. Проверьте работу cli.py")
            logger.info(f"   2. Убедитесь в наличии прав администратора")
            logger.info(f"   3. Попробуйте VPN или прокси")

def main():
    """Главная функция"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description="CLI-интегрированный адаптивный мониторинг")
    parser.add_argument("--debug", action="store_true", help="Режим отладки")
    parser.add_argument("--sites", type=int, default=10, help="Количество сайтов для тестирования")
    parser.add_argument("--calibrate", type=int, default=3, help="Количество сайтов для калибровки")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("🚀 ЗАПУСК CLI-ИНТЕГРИРОВАННОГО АДАПТИВНОГО МОНИТОРИНГА")
    logger.info("="*60)
    
    # Проверяем наличие cli.py
    if not os.path.exists("cli.py"):
        logger.error("❌ cli.py не найден в текущей директории")
        return 1
    
    # Создаем монитор
    monitor = CLIIntegratedMonitor()
    
    try:
        # Этап 1: Тестирование доступности
        accessible_sites, blocked_sites = monitor.test_all_sites()
        
        # Этап 2: Калибровка стратегий
        if blocked_sites:
            monitor.calibrate_strategies_for_blocked_sites(blocked_sites)
        
        # Этап 3: Сохранение результатов
        monitor.save_strategies()
        monitor.create_cli_config()
        monitor.generate_cli_commands()
        
        # Этап 4: Генерация отчета
        report = monitor.generate_report()
        
        # Этап 5: Итоговая сводка
        monitor.print_summary()
        
    except KeyboardInterrupt:
        logger.info("Получен сигнал остановки")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        return 1
    
    logger.info("\n✅ CLI-интегрированная калибровка завершена")
    return 0

if __name__ == "__main__":
    sys.exit(main())