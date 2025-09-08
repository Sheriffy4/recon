#!/usr/bin/env python3
"""
CLI интерфейс для умного движка обхода блокировок.
Поддерживает автоматическое определение заблокированных доменов и DoH обход.
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.smart_bypass_engine import SmartBypassEngine
from core.blocked_domain_detector import BlockedDomainDetector

LOG = logging.getLogger("smart_bypass_cli")


class SmartBypassCLI:
    """CLI интерфейс для умного обхода блокировок."""
    
    def __init__(self):
        self.engine = None
        self.config = {}

    async def init_engine(self, config_file: str = None):
        """Инициализация движка с конфигурацией."""
        if config_file and Path(config_file).exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        else:
            # Конфигурация по умолчанию
            self.config = {
                'doh_providers': ['cloudflare', 'google', 'quad9'],
                'cache_ttl': 300,
                'doh_cache_ttl': 600,
                'hosts_file_path': None  # Использовать системный
            }
        
        self.engine = SmartBypassEngine(self.config)
        LOG.info("Движок обхода инициализирован")

    async def check_domain(self, domain: str, verbose: bool = False):
        """Проверка статуса одного домена."""
        print(f"\n=== Анализ домена: {domain} ===")
        
        status = await self.engine.analyze_domain(domain)
        
        print(f"Домен: {domain}")
        print(f"Заблокирован: {'Да' if status.is_blocked else 'Нет'}")
        print(f"Тип блокировки: {status.block_type}")
        print(f"Требует обхода: {'Да' if status.bypass_required else 'Нет'}")
        
        if verbose:
            print(f"Системный DNS: {list(status.system_ips) if status.system_ips else 'Нет'}")
            print(f"DoH адреса: {list(status.doh_ips) if status.doh_ips else 'Нет'}")
            print(f"Hosts файл: {list(status.hosts_ips) if status.hosts_ips else 'Нет'}")
        
        # Получаем рекомендуемый IP
        ip, method = await self.engine.get_optimal_ip(domain)
        if ip:
            print(f"Рекомендуемый IP: {ip} (метод: {method})")
        else:
            print("Рекомендуемый IP: Не найден")

    async def test_connection(self, domain: str, port: int = 443):
        """Тестирование подключения к домену."""
        print(f"\n=== Тестирование подключения: {domain}:{port} ===")
        
        result = await self.engine.test_connection(domain, port=port)
        
        status_icon = "✓" if result.success else "✗"
        print(f"{status_icon} Результат: {'Успех' if result.success else 'Неудача'}")
        print(f"Метод: {result.method_used}")
        print(f"IP адрес: {result.ip_used}")
        print(f"Задержка: {result.latency_ms:.1f} мс")
        
        if not result.success and result.error:
            print(f"Ошибка: {result.error}")

    async def test_multiple_domains(self, domains: List[str], port: int = 443):
        """Тестирование множества доменов."""
        print(f"\n=== Тестирование {len(domains)} доменов ===")
        
        results = await self.engine.test_multiple_domains(domains, port=port)
        
        print(f"{'Домен':<20} {'Статус':<8} {'Метод':<12} {'IP':<15} {'Задержка':<10}")
        print("-" * 70)
        
        for domain, result in results.items():
            status_icon = "✓" if result.success else "✗"
            ip_display = result.ip_used[:15] if len(result.ip_used) <= 15 else result.ip_used[:12] + "..."
            
            print(f"{domain:<20} {status_icon:<8} {result.method_used:<12} "
                  f"{ip_display:<15} {result.latency_ms:<10.1f}")
            
            if not result.success and result.error:
                print(f"  └─ Ошибка: {result.error}")

    async def find_best_strategies(self, domains: List[str]):
        """Поиск лучших стратегий для доменов."""
        print(f"\n=== Поиск лучших стратегий ===")
        
        for domain in domains:
            print(f"\nАнализ {domain}...")
            best_strategy = await self.engine.find_best_strategy_for_domain(domain)
            
            if best_strategy:
                print(f"  Лучшая стратегия: {best_strategy}")
            else:
                print(f"  Рабочая стратегия не найдена")

    async def show_statistics(self):
        """Показ статистики работы."""
        print(f"\n=== Статистика работы ===")
        
        stats = self.engine.get_statistics()
        
        print(f"Всего запросов: {stats['total_requests']}")
        print(f"Успешных обходов: {stats['successful_bypasses']}")
        print(f"Неудачных попыток: {stats['failed_bypasses']}")
        print(f"Процент успеха: {stats['success_rate_percent']:.1f}%")
        print(f"Уникальных доменов: {stats['unique_domains_processed']}")
        
        if stats['methods_used']:
            print(f"\nИспользованные методы:")
            for method, count in stats['methods_used'].items():
                print(f"  {method}: {count}")

    async def generate_report(self, output_file: str = None):
        """Генерация комплексного отчета."""
        print(f"\n=== Генерация отчета ===")
        
        report = await self.engine.generate_comprehensive_report()
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            print(f"Отчет сохранен в: {output_file}")
        else:
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        
        # Показываем рекомендации
        if report.get('recommendations'):
            print(f"\nРекомендации:")
            for rec in report['recommendations']:
                print(f"  • {rec}")

    async def load_domains_from_file(self, filename: str) -> List[str]:
        """Загрузка доменов из файла."""
        domains = []
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
            LOG.info(f"Загружено {len(domains)} доменов из {filename}")
        except Exception as e:
            LOG.error(f"Ошибка загрузки доменов из {filename}: {e}")
        
        return domains

    async def cleanup(self):
        """Очистка ресурсов."""
        if self.engine:
            await self.engine.cleanup()


async def main():
    """Главная функция CLI."""
    parser = argparse.ArgumentParser(
        description="Умный CLI для обхода блокировок доменов",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:

  # Проверка одного домена
  python smart_bypass_cli.py check x.com

  # Тестирование подключения
  python smart_bypass_cli.py test x.com --port 443

  # Тестирование множества доменов
  python smart_bypass_cli.py test-multiple x.com instagram.com google.com

  # Тестирование доменов из файла
  python smart_bypass_cli.py test-file sites.txt

  # Поиск лучших стратегий
  python smart_bypass_cli.py strategies x.com instagram.com

  # Генерация отчета
  python smart_bypass_cli.py report --output bypass_report.json

  # Подробный режим
  python smart_bypass_cli.py check x.com --verbose
        """
    )
    
    parser.add_argument('--config', '-c', help='Файл конфигурации JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Подробный вывод')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    
    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')
    
    # Команда проверки домена
    check_parser = subparsers.add_parser('check', help='Проверить статус домена')
    check_parser.add_argument('domain', help='Доменное имя для проверки')
    
    # Команда тестирования подключения
    test_parser = subparsers.add_parser('test', help='Тестировать подключение к домену')
    test_parser.add_argument('domain', help='Доменное имя для тестирования')
    test_parser.add_argument('--port', '-p', type=int, default=443, help='Порт для подключения')
    
    # Команда тестирования множества доменов
    multi_parser = subparsers.add_parser('test-multiple', help='Тестировать множество доменов')
    multi_parser.add_argument('domains', nargs='+', help='Список доменов')
    multi_parser.add_argument('--port', '-p', type=int, default=443, help='Порт для подключения')
    
    # Команда тестирования из файла
    file_parser = subparsers.add_parser('test-file', help='Тестировать домены из файла')
    file_parser.add_argument('filename', help='Файл с доменами (по одному на строку)')
    file_parser.add_argument('--port', '-p', type=int, default=443, help='Порт для подключения')
    
    # Команда поиска стратегий
    strategies_parser = subparsers.add_parser('strategies', help='Найти лучшие стратегии')
    strategies_parser.add_argument('domains', nargs='+', help='Список доменов')
    
    # Команда статистики
    subparsers.add_parser('stats', help='Показать статистику')
    
    # Команда отчета
    report_parser = subparsers.add_parser('report', help='Сгенерировать отчет')
    report_parser.add_argument('--output', '-o', help='Файл для сохранения отчета')
    
    args = parser.parse_args()
    
    # Настройка логирования
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if not args.command:
        parser.print_help()
        return
    
    # Создание CLI интерфейса
    cli = SmartBypassCLI()
    
    try:
        # Инициализация движка
        await cli.init_engine(args.config)
        
        # Выполнение команд
        if args.command == 'check':
            await cli.check_domain(args.domain, args.verbose)
        
        elif args.command == 'test':
            await cli.test_connection(args.domain, args.port)
        
        elif args.command == 'test-multiple':
            await cli.test_multiple_domains(args.domains, args.port)
        
        elif args.command == 'test-file':
            domains = await cli.load_domains_from_file(args.filename)
            if domains:
                await cli.test_multiple_domains(domains, args.port)
            else:
                print("Не удалось загрузить домены из файла")
        
        elif args.command == 'strategies':
            await cli.find_best_strategies(args.domains)
        
        elif args.command == 'stats':
            await cli.show_statistics()
        
        elif args.command == 'report':
            await cli.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        LOG.error(f"Ошибка выполнения: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        await cli.cleanup()


if __name__ == '__main__':
    asyncio.run(main())