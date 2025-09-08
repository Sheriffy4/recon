#!/usr/bin/env python3
"""
Исправление критических проблем fakeddisorder атаки.

Проблемы найдены при сравнении с zapret:
1. TTL=64 вместо TTL=1 (Task 3 сломал fakeddisorder)
2. Неправильные параметры стратегии от пользователя

Исправления:
1. Вернуть TTL=1 для fakeddisorder (откат Task 3 частично)
2. Показать пользователю правильную стратегию
"""

import os
import sys

def fix_ttl_for_fakeddisorder():
    """Исправляет TTL для fakeddisorder атаки."""
    
    print("🔧 Исправляем TTL для fakeddisorder атаки...")
    
    # Исправляем FixedStrategyInterpreter
    fixed_interpreter_path = "core/strategy_interpreter_fixed.py"
    
    if not os.path.exists(fixed_interpreter_path):
        print(f"❌ Файл {fixed_interpreter_path} не найден")
        return False
    
    try:
        with open(fixed_interpreter_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Заменяем TTL=64 на TTL=1 для fakeddisorder
        old_line = "                self.ttl = 64  # TASK 3: Changed from 1 to 64 for better compatibility"
        new_line = "                self.ttl = 1  # CRITICAL FIX: TTL=1 required for fakeddisorder DPI bypass"
        
        if old_line in content:
            content = content.replace(old_line, new_line)
            
            with open(fixed_interpreter_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print("✅ TTL исправлен в FixedStrategyInterpreter: 64 -> 1")
            return True
        else:
            print("⚠️  Строка для замены не найдена в FixedStrategyInterpreter")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка при исправлении FixedStrategyInterpreter: {e}")
        return False


def show_correct_strategy():
    """Показывает пользователю правильную стратегию."""
    
    print("\n" + "="*80)
    print("🎯 ПРАВИЛЬНАЯ СТРАТЕГИЯ ДЛЯ ТЕСТИРОВАНИЯ")
    print("="*80)
    
    print("\n❌ НЕПРАВИЛЬНАЯ стратегия (которую вы использовали):")
    print('--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64')
    
    print("\n✅ ПРАВИЛЬНАЯ стратегия (которая работает в zapret):")
    print('--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1')
    
    print("\n🔍 КЛЮЧЕВЫЕ РАЗЛИЧИЯ:")
    print("1. split-seqovl: 1 -> 336 (КРИТИЧНО!)")
    print("2. ttl: 64 -> 1 (КРИТИЧНО!)")
    print("3. fooling: добавлен 'badsum'")
    print("4. убран 'fake,' - только 'fakeddisorder'")
    
    print("\n📋 КОМАНДА ДЛЯ ТЕСТИРОВАНИЯ:")
    print('python cli.py -d sites.txt --strategy "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1" --pcap out_fixed.pcap')
    
    print("\n🎯 ОЖИДАЕМЫЙ РЕЗУЛЬТАТ:")
    print("27/31 доменов должны работать (как в zapret)")


def create_test_script():
    """Создает скрипт для тестирования исправленной стратегии."""
    
    script_content = '''#!/usr/bin/env python3
"""
Тест исправленной fakeddisorder стратегии.
"""

import subprocess
import sys
import os

def test_fixed_strategy():
    """Тестирует исправленную стратегию."""
    
    print("🧪 Тестируем исправленную fakeddisorder стратегию...")
    
    # Правильная стратегия из zapret
    strategy = (
        "--dpi-desync=fakeddisorder "
        "--dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 "
        "--dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 "
        "--dpi-desync-split-pos=76 "
        "--dpi-desync-ttl=1"
    )
    
    cmd = [
        sys.executable, "cli.py",
        "-d", "sites.txt",
        "--strategy", strategy,
        "--pcap", "out_fixed.pcap"
    ]
    
    print(f"Команда: {' '.join(cmd)}")
    print("Запускаем тест...")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        print(f"Код возврата: {result.returncode}")
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("❌ Тест превысил таймаут (5 минут)")
        return False
    except Exception as e:
        print(f"❌ Ошибка при запуске теста: {e}")
        return False

if __name__ == "__main__":
    success = test_fixed_strategy()
    sys.exit(0 if success else 1)
'''
    
    with open("test_fixed_fakeddisorder.py", 'w', encoding='utf-8') as f:
        f.write(script_content)
    
    print("✅ Создан скрипт test_fixed_fakeddisorder.py")


def main():
    """Основная функция исправления."""
    
    print("🚨 ИСПРАВЛЕНИЕ КРИТИЧЕСКИХ ПРОБЛЕМ FAKEDDISORDER")
    print("="*60)
    
    # Исправляем TTL
    ttl_fixed = fix_ttl_for_fakeddisorder()
    
    # Показываем правильную стратегию
    show_correct_strategy()
    
    # Создаем тестовый скрипт
    create_test_script()
    
    print("\n" + "="*80)
    print("📋 ПЛАН ДЕЙСТВИЙ:")
    print("="*80)
    
    if ttl_fixed:
        print("✅ 1. TTL исправлен в коде")
    else:
        print("❌ 1. TTL НЕ исправлен - требуется ручное исправление")
    
    print("✅ 2. Правильная стратегия показана выше")
    print("✅ 3. Тестовый скрипт создан: test_fixed_fakeddisorder.py")
    
    print("\n🎯 СЛЕДУЮЩИЕ ШАГИ:")
    print("1. Запустите: python test_fixed_fakeddisorder.py")
    print("2. Или используйте команду выше вручную")
    print("3. Проверьте, что 27/31 доменов работают")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())