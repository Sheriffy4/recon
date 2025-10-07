#!/usr/bin/env python3
"""
Проверка применения forced override исправления.
"""

import os
import re

def verify_forced_override_applied():
    """Проверяет, что forced override применен."""
    
    print("🔍 ПРОВЕРКА FORCED OVERRIDE ИСПРАВЛЕНИЯ")
    print("=" * 50)
    
    # Ищем файлы с исправлениями
    forced_files = []
    
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Проверяем наличие forced override
                    if ('no_fallbacks' in content and 'forced' in content) or 'FORCED OVERRIDE' in content:
                        forced_files.append(file_path)
                        
                except Exception:
                    continue
    
    print(f"📊 РЕЗУЛЬТАТЫ ПРОВЕРКИ:")
    print(f"   ✅ Файлов с forced override: {len(forced_files)}")
    
    if forced_files:
        print(f"\n📋 ИСПРАВЛЕННЫЕ ФАЙЛЫ:")
        for file_path in forced_files[:10]:  # Показываем первые 10
            print(f"   🔧 {file_path}")
        
        if len(forced_files) > 10:
            print(f"   ... и еще {len(forced_files) - 10} файлов")
    
    # Проверяем резервные копии
    backup_files = []
    for root, dirs, files in os.walk('.'):
        for file in files:
            if '.backup_' in file:
                backup_files.append(os.path.join(root, file))
    
    print(f"\n💾 РЕЗЕРВНЫЕ КОПИИ: {len(backup_files)}")
    
    if len(forced_files) > 0:
        print(f"\n✅ ИСПРАВЛЕНИЕ ПРИМЕНЕНО!")
        print("🚀 Можно перезапускать службу")
        print("🔍 Проверьте лог на записи 'FORCED OVERRIDE'")
        return True
    else:
        print(f"\n❌ ИСПРАВЛЕНИЕ НЕ НАЙДЕНО!")
        print("🔧 Нужно повторить применение исправления")
        return False

if __name__ == "__main__":
    verify_forced_override_applied()
