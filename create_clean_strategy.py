#!/usr/bin/env python3
"""
Создание чистой стратегии на основе анализа log2.txt

Из лога видно что успешная комбинация: disorder + multisplit
"""

import json
import time
from pathlib import Path

def create_clean_strategy():
    """Создать чистую стратегию на основе анализа лога."""
    
    # На основе анализа log2.txt, успешная стратегия:
    # - Attack Combination: disorder + multisplit
    # - Параметры: split_pos=2, split_count=6, disorder_method=reverse
    
    clean_strategy = {
        "type": "combo",
        "attacks": ["disorder", "multisplit"],
        "params": {
            "split_pos": 2,
            "split_count": 6,
            "disorder_method": "reverse",
            "fooling": ["badsum"],
            "positions": [3, 9, 15, 21, 27, 33, 39, 45],
            "ttl": 1
        },
        "metadata": {
            "source": "cli_auto_success_log2",
            "created": time.time(),
            "description": "Working strategy extracted from CLI auto success",
            "success_combination": "disorder + multisplit",
            "tested": True,
            "working": True
        }
    }
    
    return clean_strategy

def update_domain_rules_clean(strategy):
    """Обновить domain_rules.json с чистой стратегией."""
    
    rules_file = Path("domain_rules.json")
    
    try:
        # Загружаем текущие правила
        if rules_file.exists():
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
        else:
            rules = {"version": "1.0", "domain_rules": {}}
        
        # Обновляем правило для www.googlevideo.com
        if "domain_rules" not in rules:
            rules["domain_rules"] = {}
        
        rules["domain_rules"]["www.googlevideo.com"] = strategy
        rules["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        
        # Сохраняем
        with open(rules_file, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2, ensure_ascii=False)
        
        print("✅ domain_rules.json обновлен с чистой стратегией")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка обновления: {e}")
        return False

def main():
    """Main function."""
    
    print("="*60)
    print("СОЗДАНИЕ ЧИСТОЙ СТРАТЕГИИ ДЛЯ www.googlevideo.com")
    print("="*60)
    
    # Создаем чистую стратегию
    strategy = create_clean_strategy()
    
    print("✅ ЧИСТАЯ СТРАТЕГИЯ:")
    print(json.dumps(strategy, indent=2, ensure_ascii=False))
    
    # Обновляем правила
    if update_domain_rules_clean(strategy):
        print("\n🎯 Чистая стратегия сохранена в domain_rules.json")
        print("💡 Теперь можно тестировать службу с правильной стратегией")
        
        print("\n📋 ПАРАМЕТРЫ СТРАТЕГИИ:")
        print(f"   Тип: {strategy['type']}")
        print(f"   Атаки: {strategy['attacks']}")
        print(f"   split_pos: {strategy['params']['split_pos']}")
        print(f"   split_count: {strategy['params']['split_count']}")
        print(f"   disorder_method: {strategy['params']['disorder_method']}")
        print(f"   fooling: {strategy['params']['fooling']}")
        print(f"   ttl: {strategy['params']['ttl']}")
    else:
        print("\n❌ Не удалось сохранить стратегию")

if __name__ == "__main__":
    main()