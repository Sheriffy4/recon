#!/usr/bin/env python3
"""
Откат изменений Instagram стратегии.
Возвращает к оригинальной multisplit стратегии.
"""

import json
import shutil
from datetime import datetime

def rollback_instagram_strategy():
    """Откатывает стратегию Instagram к оригинальной."""
    
    print("🔄 ОТКАТ СТРАТЕГИИ INSTAGRAM")
    print("=" * 30)
    
    # Создаем резервную копию текущего состояния
    backup_file = f"strategies_after_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    shutil.copy('strategies.json', backup_file)
    print(f"✅ Создана резервная копия: {backup_file}")
    
    # Читаем стратегии
    with open('strategies.json', 'r', encoding='utf-8') as f:
        strategies = json.load(f)
    
    # Возвращаем оригинальную стратегию
    original_strategy = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4"
    
    print(f"📋 Возвращаем оригинальную стратегию:")
    print(f"   {original_strategy}")
    
    # Применяем изменения
    strategies['instagram.com'] = original_strategy
    
    # Также откатываем связанные домены
    instagram_domains = [
        'static.cdninstagram.com',
        'scontent-arn2-1.cdninstagram.com', 
        'edge-chat.instagram.com'
    ]
    
    for domain in instagram_domains:
        if domain in strategies:
            strategies[domain] = original_strategy
            print(f"✅ Откачен {domain}")
    
    # Сохраняем
    with open('strategies.json', 'w', encoding='utf-8') as f:
        json.dump(strategies, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Откат завершен!")
    print(f"🔄 Перезапустите службу для применения изменений")

if __name__ == "__main__":
    rollback_instagram_strategy()
