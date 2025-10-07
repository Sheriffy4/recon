#!/usr/bin/env python3
"""
Тестирование различных стратегий для Instagram.
"""

import json
import shutil
from datetime import datetime

strategies_to_test = {
    "strategy_1_original": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4",
    "strategy_2_simple_fake": "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=8",
    "strategy_3_disorder": "--dpi-desync=disorder --dpi-desync-split-pos=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2",
    "strategy_4_fakeddisorder_improved": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=3 --dpi-desync-ttl=8",
    "strategy_5_multidisorder": "--dpi-desync=multidisorder --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2"
}

def apply_strategy(strategy_name):
    """Применяет выбранную стратегию."""
    
    if strategy_name not in strategies_to_test:
        print(f"❌ Стратегия {strategy_name} не найдена!")
        return False
    
    # Резервная копия
    backup_file = f"strategies_before_{strategy_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    shutil.copy('strategies.json', backup_file)
    
    # Читаем и изменяем
    with open('strategies.json', 'r', encoding='utf-8') as f:
        strategies = json.load(f)
    
    new_strategy = strategies_to_test[strategy_name]
    strategies['instagram.com'] = new_strategy
    
    # Связанные домены
    instagram_domains = [
        'static.cdninstagram.com',
        'scontent-arn2-1.cdninstagram.com', 
        'edge-chat.instagram.com'
    ]
    
    for domain in instagram_domains:
        if domain in strategies:
            strategies[domain] = new_strategy
    
    # Сохраняем
    with open('strategies.json', 'w', encoding='utf-8') as f:
        json.dump(strategies, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Применена стратегия: {strategy_name}")
    print(f"📋 {new_strategy}")
    print(f"🔄 Перезапустите службу и проверьте Instagram")
    
    return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Использование: python test_instagram_strategies.py <strategy_name>")
        print("Доступные стратегии:")
        for name in strategies_to_test.keys():
            print(f"  - {name}")
        sys.exit(1)
    
    strategy_name = sys.argv[1]
    apply_strategy(strategy_name)
