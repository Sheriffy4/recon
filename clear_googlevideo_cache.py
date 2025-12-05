#!/usr/bin/env python3
"""
Скрипт для очистки кэша стратегий для *.googlevideo.com
Решает проблему конфликта между StrategyManager и domain_rules.json
"""

import sys
from pathlib import Path

def main():
    print("="*80)
    print("🧹 Очистка кэша стратегий для *.googlevideo.com")
    print("="*80)
    print()
    
    try:
        from core.strategy_manager import StrategyManager
        
        sm = StrategyManager()
        print(f"✅ StrategyManager загружен")
        print(f"   Всего стратегий в кэше: {len(sm.domain_strategies)}")
        print()
        
        # Проверяем текущие стратегии для googlevideo.com
        domains_to_clear = ['www.googlevideo.com', '*.googlevideo.com', 'googlevideo.com']
        found_strategies = []
        
        for domain in domains_to_clear:
            if domain in sm.domain_strategies:
                strategy = sm.domain_strategies[domain]
                found_strategies.append(domain)
                print(f"📋 Найдена стратегия для {domain}:")
                print(f"   Тип: {strategy.strategy}")
                print(f"   Параметры:")
                print(f"      split_pos: {strategy.split_pos}")
                print(f"      split_count: {strategy.split_count}")
                print(f"      ttl: {strategy.ttl}")
                print(f"      disorder_method: {strategy.disorder_method}")
                print()
        
        if not found_strategies:
            print("ℹ️  Стратегии для googlevideo.com не найдены в кэше")
            print("   Возможно, они уже были удалены")
            return 0
        
        # Подтверждение удаления
        print(f"⚠️  Будут удалены стратегии для {len(found_strategies)} доменов:")
        for domain in found_strategies:
            print(f"   - {domain}")
        print()
        
        response = input("Продолжить? (y/n): ").strip().lower()
        if response != 'y':
            print("❌ Отменено пользователем")
            return 1
        
        print()
        
        # Удаление стратегий
        for domain in found_strategies:
            del sm.domain_strategies[domain]
            print(f"✅ Удалена стратегия для {domain}")
        
        # Сохранение изменений
        sm.save_strategies()
        print()
        print("✅ Изменения сохранены в domain_strategies.json")
        print()
        
        # Проверка domain_rules.json
        print("="*80)
        print("📋 Проверка domain_rules.json")
        print("="*80)
        print()
        
        import json
        domain_rules_path = Path('domain_rules.json')
        if domain_rules_path.exists():
            with open(domain_rules_path, 'r', encoding='utf-8') as f:
                domain_rules = json.load(f)
            
            for domain in domains_to_clear:
                if domain in domain_rules.get('domain_rules', {}):
                    rule = domain_rules['domain_rules'][domain]
                    print(f"✅ Найдено правило в domain_rules.json для {domain}:")
                    print(f"   Тип: {rule.get('type')}")
                    print(f"   Атаки: {rule.get('attacks', [])}")
                    print(f"   Параметры:")
                    for key, value in rule.get('params', {}).items():
                        print(f"      {key}: {value}")
                    print()
        else:
            print("⚠️  Файл domain_rules.json не найден")
        
        print("="*80)
        print("✅ ГОТОВО!")
        print("="*80)
        print()
        print("Следующие шаги:")
        print("1. Запустите поиск стратегии заново:")
        print("   python cli.py auto *.googlevideo.com --mode deep")
        print()
        print("2. Или протестируйте конкретную стратегию:")
        print("   python cli.py test www.googlevideo.com")
        print()
        print("3. Проверьте применение стратегии в PCAP:")
        print("   python analyze_googlevideo_strategy.py")
        print()
        
        return 0
        
    except ImportError as e:
        print(f"❌ Ошибка импорта: {e}")
        print("   Убедитесь, что вы находитесь в корневой директории проекта")
        return 1
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
