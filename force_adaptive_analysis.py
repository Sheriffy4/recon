#!/usr/bin/env python3
"""
Принудительный запуск адаптивного анализа с очисткой кэша
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Добавляем текущую директорию в sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

async def force_adaptive_analysis(domain: str):
    """Принудительный адаптивный анализ с очисткой кэша"""
    
    print(f"🔧 Принудительный адаптивный анализ для {domain}")
    print("=" * 60)
    
    # Импортируем компоненты
    from core.adaptive_engine import AdaptiveEngine, AdaptiveConfig
    
    # Создаем конфигурацию
    config = AdaptiveConfig(
        max_trials=10,
        enable_fingerprinting=True,
        enable_failure_analysis=True,
        mode="comprehensive"
    )
    
    # Инициализируем движок
    engine = AdaptiveEngine(config)
    
    # Принудительно удаляем домен из кэша
    if domain in engine.best_strategies:
        print(f"🗑️ Удаляем сохраненную стратегию для {domain}")
        del engine.best_strategies[domain]
        engine._save_best_strategies()
    
    # Очищаем негативные знания
    if domain in engine.negative_knowledge:
        print(f"🗑️ Очищаем негативные знания для {domain}")
        del engine.negative_knowledge[domain]
        engine._save_negative_knowledge()
    
    # Очищаем кэш fingerprint'ов
    engine._fingerprint_cache.clear()
    
    print(f"✅ Кэш очищен, запускаем полный анализ...")
    
    # Progress callback
    def progress_callback(message: str):
        print(f"📝 {message}")
    
    # Запускаем анализ
    result = await engine.find_best_strategy(domain, progress_callback)
    
    # Показываем результаты
    print("\n" + "=" * 60)
    print("📊 РЕЗУЛЬТАТЫ ПРИНУДИТЕЛЬНОГО АНАЛИЗА")
    print("=" * 60)
    
    print(f"Success: {result.success}")
    print(f"Message: {result.message}")
    print(f"Execution time: {result.execution_time:.2f}s")
    print(f"Trials performed: {result.trials_count}")
    print(f"Fingerprint updated: {result.fingerprint_updated}")
    
    if result.strategy:
        print(f"\nНайденная стратегия:")
        print(f"  Name: {result.strategy.name}")
        if hasattr(result.strategy, 'attack_combination'):
            print(f"  Attacks: {result.strategy.attack_combination}")
        if hasattr(result.strategy, 'parameters'):
            print(f"  Parameters: {result.strategy.parameters}")
    
    # Статистика движка
    stats = engine.get_stats()
    print(f"\n📈 Статистика движка:")
    print(f"  Domains processed: {stats['domains_processed']}")
    print(f"  Fingerprints created: {stats['fingerprints_created']}")
    print(f"  Strategies found: {stats['strategies_found']}")
    print(f"  Total trials: {stats['total_trials']}")
    print(f"  Failures analyzed: {stats['failures_analyzed']}")
    
    return result

async def main():
    """Главная функция"""
    if len(sys.argv) != 2:
        print("Использование: python force_adaptive_analysis.py <domain>")
        print("Пример: python force_adaptive_analysis.py x.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    await force_adaptive_analysis(domain)

if __name__ == "__main__":
    asyncio.run(main())