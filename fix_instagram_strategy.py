#!/usr/bin/env python3
"""
Исправление стратегии для Instagram.
Заменяет проблемную multisplit на стабильную fakeddisorder.
"""

import json
import shutil
from datetime import datetime

def fix_instagram_strategy():
    """Исправляет стратегию для Instagram."""
    
    print("🔧 ИСПРАВЛЕНИЕ СТРАТЕГИИ INSTAGRAM")
    print("=" * 40)
    
    # Создаем резервную копию
    backup_file = f"strategies_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    shutil.copy('strategies.json', backup_file)
    print(f"✅ Создана резервная копия: {backup_file}")
    
    # Читаем текущие стратегии
    try:
        with open('strategies.json', 'r', encoding='utf-8') as f:
            strategies = json.load(f)
    except Exception as e:
        print(f"❌ Ошибка чтения strategies.json: {e}")
        return False
    
    # Текущая проблемная стратегия
    current_strategy = strategies.get('instagram.com', '')
    print(f"📋 Текущая стратегия Instagram:")
    print(f"   {current_strategy}")
    
    # Новая стабильная стратегия (как у Facebook)
    new_strategy = "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4"
    
    print(f"\n🆕 Новая стратегия Instagram:")
    print(f"   {new_strategy}")
    
    # Применяем изменения
    strategies['instagram.com'] = new_strategy
    
    # Также исправим связанные домены Instagram
    instagram_domains = [
        'static.cdninstagram.com',
        'scontent-arn2-1.cdninstagram.com', 
        'edge-chat.instagram.com'
    ]
    
    for domain in instagram_domains:
        if domain in strategies:
            strategies[domain] = new_strategy
            print(f"✅ Обновлен {domain}")
    
    # Сохраняем изменения
    try:
        with open('strategies.json', 'w', encoding='utf-8') as f:
            json.dump(strategies, f, indent=2, ensure_ascii=False)
        print(f"\n✅ Стратегии сохранены в strategies.json")
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")
        return False
    
    print(f"\n💡 ИЗМЕНЕНИЯ:")
    print(f"   ❌ Убрано: multisplit (нестабильная)")
    print(f"   ✅ Добавлено: fakeddisorder (стабильная)")
    print(f"   🎯 TTL: 4 (оптимальное значение)")
    print(f"   📍 Split position: 3 (проверенное значение)")
    
    return True

def create_test_strategy():
    """Создает альтернативную стратегию для тестирования."""
    
    print(f"\n🧪 СОЗДАНИЕ ТЕСТОВОЙ СТРАТЕГИИ:")
    
    test_strategies = {
        'instagram.com': {
            'strategy1_fakeddisorder': "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4",
            'strategy2_fake': "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=8",
            'strategy3_disorder': "--dpi-desync=disorder --dpi-desync-split-pos=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2"
        }
    }
    
    with open('instagram_test_strategies.json', 'w', encoding='utf-8') as f:
        json.dump(test_strategies, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Созданы тестовые стратегии: instagram_test_strategies.json")
    print(f"   Можно протестировать разные варианты")

def restart_service_instruction():
    """Выводит инструкции по перезапуску службы."""
    
    print(f"\n🚀 ИНСТРУКЦИИ ПО ПРИМЕНЕНИЮ:")
    print(f"1. Остановите текущую службу (Ctrl+C)")
    print(f"2. Перезапустите службу:")
    print(f"   python recon_service.py")
    print(f"3. Откройте instagram.com в браузере")
    print(f"4. Проверьте новые записи в логе")
    
    print(f"\n📊 ОЖИДАЕМЫЙ РЕЗУЛЬТАТ:")
    print(f"   ✅ Instagram должен загружаться полностью")
    print(f"   ✅ В логе должны появиться записи 'fakeddisorder'")
    print(f"   ✅ Больше пакетов для Instagram IP")

if __name__ == "__main__":
    success = fix_instagram_strategy()
    
    if success:
        create_test_strategy()
        restart_service_instruction()
        
        print(f"\n" + "=" * 40)
        print(f"🎯 ИСПРАВЛЕНИЕ ЗАВЕРШЕНО!")
        print(f"✅ Instagram стратегия изменена на стабильную")
        print(f"🔄 Перезапустите службу для применения изменений")
    else:
        print(f"\n❌ Исправление не удалось!")