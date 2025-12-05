#!/usr/bin/env python3
"""
Быстрое тестирование стратегий с оптимизированными таймаутами
"""

import sys
import time
import socket
import ssl
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

# Добавляем путь к модулям
sys.path.insert(0, str(Path(__file__).parent))

from core import UnifiedBypassEngine, EngineConfig


class FastStrategyTester:
    """Быстрое тестирование стратегий на множестве доменов"""
    
    def __init__(self, timeout: float = 5.0, max_workers: int = 15):
        """
        Args:
            timeout: Таймаут для каждого теста (секунды)
            max_workers: Количество параллельных тестов
        """
        self.timeout = timeout
        self.max_workers = max_workers
        
        # Создаем движок
        config = EngineConfig(debug=False)
        self.engine = UnifiedBypassEngine(config)
        
    def test_domain_fast(self, domain: str, strategy: Dict) -> Tuple[bool, float, str]:
        """
        Быстрый тест одного домена
        
        Returns:
            (success, latency_ms, error_msg)
        """
        start = time.time()
        
        try:
            # Резолвим домен
            ip = socket.gethostbyname(domain)
            
            # Тестируем стратегию
            result = self.engine.test_strategy_like_testing_mode(
                target_ip=ip,
                strategy_input=strategy,
                domain=domain,
                timeout=self.timeout
            )
            
            latency = (time.time() - start) * 1000
            
            if result.get('success'):
                return True, latency, ""
            else:
                return False, latency, result.get('error', 'Unknown error')
                
        except socket.gaierror:
            return False, 0, "DNS resolution failed"
        except Exception as e:
            return False, 0, str(e)
    
    def test_strategy_on_domains(
        self, 
        strategy: Dict, 
        domains: List[str],
        show_progress: bool = True
    ) -> Dict:
        """
        Тестирует стратегию на списке доменов параллельно
        
        Returns:
            Словарь с результатами тестирования
        """
        results = []
        successful = []
        failed = []
        latencies = []
        
        total = len(domains)
        completed = 0
        
        print(f"\n🚀 Тестирование стратегии на {total} доменах...")
        print(f"   Параллельность: {self.max_workers} потоков")
        print(f"   Таймаут: {self.timeout}s на домен")
        print()
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Запускаем все тесты
            future_to_domain = {
                executor.submit(self.test_domain_fast, domain, strategy): domain
                for domain in domains
            }
            
            # Собираем результаты по мере выполнения
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                completed += 1
                
                try:
                    success, latency, error = future.result()
                    
                    results.append({
                        'domain': domain,
                        'success': success,
                        'latency_ms': latency,
                        'error': error
                    })
                    
                    if success:
                        successful.append(domain)
                        latencies.append(latency)
                        status = "✅"
                    else:
                        failed.append(domain)
                        status = "❌"
                    
                    if show_progress:
                        print(f"   [{completed}/{total}] {status} {domain} ({latency:.0f}ms)")
                        
                except Exception as e:
                    print(f"   [{completed}/{total}] ❌ {domain} - Exception: {e}")
                    failed.append(domain)
        
        total_time = time.time() - start_time
        success_rate = len(successful) / total if total > 0 else 0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        
        print()
        print("=" * 70)
        print(f"📊 Результаты тестирования:")
        print(f"   Успешно: {len(successful)}/{total} ({success_rate*100:.1f}%)")
        print(f"   Неудачно: {len(failed)}/{total}")
        print(f"   Средняя задержка: {avg_latency:.0f}ms")
        print(f"   Общее время: {total_time:.1f}s")
        print(f"   Скорость: {total/total_time:.1f} доменов/сек")
        print("=" * 70)
        
        return {
            'strategy': strategy,
            'total_domains': total,
            'successful': len(successful),
            'failed': len(failed),
            'success_rate': success_rate,
            'avg_latency_ms': avg_latency,
            'total_time_s': total_time,
            'domains_per_second': total / total_time if total_time > 0 else 0,
            'successful_domains': successful,
            'failed_domains': failed,
            'detailed_results': results
        }


def load_domains_from_file(filename: str = "sites.txt") -> List[str]:
    """Загружает список доменов из файла"""
    domains = []
    
    if Path(filename).exists():
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(('#', '/')):
                    domains.append(line)
    
    return domains


def main():
    """Пример использования"""
    
    # Загружаем домены
    domains = load_domains_from_file("sites.txt")
    
    if not domains:
        print("❌ Файл sites.txt не найден или пуст")
        print("   Используем тестовые домены...")
        domains = [
            "google.com",
            "youtube.com",
            "facebook.com",
            "twitter.com",
            "instagram.com"
        ]
    
    print(f"📋 Загружено {len(domains)} доменов")
    
    # Определяем стратегию для тестирования
    strategy = {
        "type": "disorder",
        "params": {
            "split_pos": 2,
            "window_div": 8,
            "repeats": 1
        }
    }
    
    print(f"🔧 Стратегия: {strategy['type']}")
    print(f"   Параметры: {strategy['params']}")
    
    # Создаем тестер с оптимизированными настройками
    tester = FastStrategyTester(
        timeout=5.0,      # 5 секунд на домен
        max_workers=15    # 15 параллельных тестов
    )
    
    # Запускаем тестирование
    results = tester.test_strategy_on_domains(strategy, domains)
    
    # Показываем топ успешных доменов
    if results['successful_domains']:
        print("\n✅ Успешные домены (первые 10):")
        for domain in results['successful_domains'][:10]:
            print(f"   • {domain}")
    
    # Показываем топ неудачных доменов
    if results['failed_domains']:
        print("\n❌ Неудачные домены (первые 10):")
        for domain in results['failed_domains'][:10]:
            print(f"   • {domain}")


if __name__ == "__main__":
    main()
