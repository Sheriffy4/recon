#!/usr/bin/env python3
"""
Диагностика: Почему bypass не работает
"""

import sys
import os

print("="*80)
print("🔍 ДИАГНОСТИКА: ПОЧЕМУ BYPASS НЕ РАБОТАЕТ")
print("="*80)

# 1. Проверка исправлений в коде
print("\n1️⃣ ПРОВЕРКА ИСПРАВЛЕНИЙ В КОДЕ:")
print("-"*80)

# Проверка telemetry fix
try:
    with open('core/bypass/engine/base_engine.py', 'r', encoding='utf-8') as f:
        content = f.read()
        
    if "Update aggregate telemetry" in content:
        print("✅ Telemetry fix найден в base_engine.py")
    else:
        print("❌ Telemetry fix НЕ НАЙДЕН в base_engine.py")
        print("   Файл не содержит строку 'Update aggregate telemetry'")
    
    if "self._telemetry['aggregate']['segments_sent'] += len(specs)" in content:
        print("✅ Код обновления segments_sent найден")
    else:
        print("❌ Код обновления segments_sent НЕ НАЙДЕН")
        
except Exception as e:
    print(f"❌ Ошибка чтения base_engine.py: {e}")

# Проверка checksum fix
try:
    with open('core/bypass/packet/sender.py', 'r', encoding='utf-8') as f:
        content = f.read()
        
    if "WINDIVERT_FLAG_NO_CHECKSUM" in content:
        print("✅ Checksum fix найден в sender.py")
    else:
        print("❌ Checksum fix НЕ НАЙДЕН в sender.py")
        
    if "flags=0x0001" in content:
        print("✅ Код флага NO_CHECKSUM найден")
    else:
        print("❌ Код флага NO_CHECKSUM НЕ НАЙДЕН")
        
except Exception as e:
    print(f"❌ Ошибка чтения sender.py: {e}")

# 2. Проверка файлов результатов
print("\n2️⃣ ПРОВЕРКА ФАЙЛОВ РЕЗУЛЬТАТОВ:")
print("-"*80)

files_to_check = [
    'recon_summary.json',
    'log.txt',
]

for fname in files_to_check:
    if os.path.exists(fname):
        size = os.path.getsize(fname)
        print(f"✅ {fname} существует ({size} байт)")
    else:
        print(f"❌ {fname} НЕ СУЩЕСТВУЕТ")

# Проверка PCAP файлов
import glob
pcap_files = glob.glob('recon*.pcap')
if pcap_files:
    print(f"✅ Найдено {len(pcap_files)} PCAP файлов:")
    for pf in pcap_files:
        size = os.path.getsize(pf)
        print(f"   - {pf} ({size} байт)")
else:
    print("❌ PCAP файлы не найдены")

# 3. Анализ CLI запуска
print("\n3️⃣ АНАЛИЗ CLI:")
print("-"*80)

try:
    with open('cli.py', 'r', encoding='utf-8') as f:
        cli_content = f.read()
    
    # Проверка импортов
    if "from core.bypass.engine.base_engine import" in cli_content:
        print("✅ CLI импортирует base_engine")
    else:
        print("⚠️ CLI не импортирует base_engine напрямую")
    
    # Проверка создания engine
    if "WindowsBypassEngine" in cli_content or "BypassEngine" in cli_content:
        print("✅ CLI создает bypass engine")
    else:
        print("❌ CLI НЕ создает bypass engine")
        
except Exception as e:
    print(f"❌ Ошибка чтения cli.py: {e}")

# 4. Проверка зависимостей
print("\n4️⃣ ПРОВЕРКА ЗАВИСИМОСТЕЙ:")
print("-"*80)

try:
    import pydivert
    print(f"✅ pydivert установлен (версия: {pydivert.__version__})")
except ImportError:
    print("❌ pydivert НЕ УСТАНОВЛЕН")

try:
    from scapy.all import rdpcap
    print("✅ scapy установлен")
except ImportError:
    print("❌ scapy НЕ УСТАНОВЛЕН")

# 5. Проверка прав администратора
print("\n5️⃣ ПРОВЕРКА ПРАВ:")
print("-"*80)

import ctypes
try:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if is_admin:
        print("✅ Скрипт запущен с правами администратора")
    else:
        print("❌ Скрипт НЕ запущен с правами администратора")
        print("   WinDivert требует прав администратора!")
except Exception as e:
    print(f"⚠️ Не удалось проверить права: {e}")

# 6. Рекомендации
print("\n" + "="*80)
print("📋 РЕКОМЕНДАЦИИ:")
print("="*80)

recommendations = []

# Проверяем основные проблемы
if not os.path.exists('recon_summary.json'):
    recommendations.append("❌ recon_summary.json не создан - CLI не завершился нормально")
    recommendations.append("   Проверьте ошибки в выводе CLI")

if not pcap_files:
    recommendations.append("❌ PCAP файлы не созданы - bypass не активировался")
    recommendations.append("   Проверьте, что WinDivert работает")

try:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if not is_admin:
        recommendations.append("❌ КРИТИЧНО: Запустите скрипт с правами администратора!")
        recommendations.append("   Правый клик -> Запуск от имени администратора")
except:
    pass

if recommendations:
    for rec in recommendations:
        print(rec)
else:
    print("✅ Основные проверки пройдены")
    print("   Проблема может быть в логике bypass")

print("\n" + "="*80)
print("🎯 СЛЕДУЮЩИЕ ШАГИ:")
print("="*80)

print("""
1. Если НЕ запущено от администратора:
   - Закройте терминал
   - Откройте PowerShell/CMD от имени администратора
   - Перейдите в папку recon
   - Запустите: python test_critical_fixes.py

2. Если запущено от администратора, но bypass не работает:
   - Проверьте вывод CLI на ошибки
   - Запустите: python cli.py x.com --debug --strategy "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
   - Ищите строки с [ERROR] или [CRITICAL]

3. Если исправления не применены:
   - Убедитесь, что вы в правильной папке
   - Проверьте, что файлы base_engine.py и sender.py содержат исправления
   - Возможно нужно перезапустить Python (закрыть все окна)
""")

print("="*80)
