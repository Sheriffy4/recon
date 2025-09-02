#!/usr/bin/env python3
"""
Анализатор расхождений между стратегиями recon и zapret

Этот скрипт анализирует почему recon показывает 0% успешности,
а zapret с той же стратегией показывает 87% (27/31 доменов).
"""

import json
import sys
from pathlib import Path
from core.strategy_interpreter import interpret_strategy

def analyze_strategy_discrepancy():
    """Анализ расхождений в стратегиях."""
    
    print("=" * 80)
    print("АНАЛИЗ РАСХОЖДЕНИЙ МЕЖДУ RECON И ZAPRET")
    print("=" * 80)
    
    # Стратегия, которую использует пользователь
    user_strategy = (
        "--dpi-desync=fake,fakeddisorder "
        "--dpi-desync-split-seqovl=1 "
        "--dpi-desync-autottl=2 "
        "--dpi-desync-fake-http=PAYLOADTLS "
        "--dpi-desync-fake-tls=PAYLOADTLS "
        "--dpi-desync-fooling=badseq,md5sig "
        "--dpi-desync-ttl=64"
    )
    
    # Успешная стратегия zapret (27/31 доменов работают)
    zapret_successful_strategy = (
        "--dpi-desync=fakeddisorder "
        "--dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 "
        "--dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 "
        "--dpi-desync-split-pos=76 "
        "--dpi-desync-ttl=1"
    )
    
    print("1. АНАЛИЗ СТРАТЕГИИ ПОЛЬЗОВАТЕЛЯ")
    print("-" * 40)
    print(f"Команда: {user_strategy}")
    
    user_parsed = interpret_strategy(user_strategy)
    print(f"Парсинг: {user_parsed}")
    
    print("\n2. АНАЛИЗ УСПЕШНОЙ СТРАТЕГИИ ZAPRET")
    print("-" * 40)
    print(f"Команда: {zapret_successful_strategy}")
    
    zapret_parsed = interpret_strategy(zapret_successful_strategy)
    print(f"Парсинг: {zapret_parsed}")
    
    print("\n3. КРИТИЧЕСКИЕ РАЗЛИЧИЯ")
    print("-" * 40)
    
    user_params = user_parsed['params']
    zapret_params = zapret_parsed['params']
    
    differences = []
    
    # Проверяем overlap_size (split-seqovl)
    if user_params.get('overlap_size') != zapret_params.get('overlap_size'):
        differences.append({
            'parameter': 'overlap_size (split-seqovl)',
            'user_value': user_params.get('overlap_size'),
            'zapret_value': zapret_params.get('overlap_size'),
            'impact': 'КРИТИЧЕСКИЙ - определяет размер перекрытия пакетов'
        })
    
    # Проверяем TTL
    if user_params.get('ttl') != zapret_params.get('ttl'):
        differences.append({
            'parameter': 'ttl',
            'user_value': user_params.get('ttl'),
            'zapret_value': zapret_params.get('ttl'),
            'impact': 'КРИТИЧЕСКИЙ - определяет время жизни поддельных пакетов'
        })
    
    # Проверяем fooling methods
    user_fooling = set(user_params.get('fooling', []))
    zapret_fooling = set(zapret_params.get('fooling', []))
    if user_fooling != zapret_fooling:
        differences.append({
            'parameter': 'fooling',
            'user_value': list(user_fooling),
            'zapret_value': list(zapret_fooling),
            'impact': 'ВАЖНЫЙ - методы обмана DPI системы'
        })
    
    # Проверяем repeats
    if user_params.get('repeats') != zapret_params.get('repeats'):
        differences.append({
            'parameter': 'repeats',
            'user_value': user_params.get('repeats'),
            'zapret_value': zapret_params.get('repeats'),
            'impact': 'СРЕДНИЙ - количество повторений атаки'
        })
    
    for i, diff in enumerate(differences, 1):
        print(f"{i}. {diff['parameter']}:")
        print(f"   Пользователь: {diff['user_value']}")
        print(f"   Zapret:       {diff['zapret_value']}")
        print(f"   Влияние:      {diff['impact']}")
        print()
    
    print("4. АНАЛИЗ РЕЗУЛЬТАТОВ")
    print("-" * 40)
    
    # Читаем отчет recon
    try:
        with open('recon_report_20250902_101841.json', 'r', encoding='utf-8') as f:
            recon_report = json.load(f)
        
        print(f"Recon результаты:")
        print(f"  - Успешность: {recon_report['success_rate']}%")
        print(f"  - Рабочих стратегий: {recon_report['working_strategies_found']}")
        print(f"  - Время выполнения: {recon_report['execution_time_seconds']:.1f} сек")
        
    except FileNotFoundError:
        print("Файл recon_report_20250902_101841.json не найден")
    
    # Анализируем лог zapret
    try:
        with open('test_log_zapret_iter_4_20250901_105104.txt', 'r', encoding='utf-8') as f:
            zapret_log = f.read()
        
        # Ищем успешную стратегию
        if "Successes: 27/31" in zapret_log:
            print(f"\nZapret результаты:")
            print(f"  - Успешность: 87.1% (27/31)")
            print(f"  - Стратегия: fakeddisorder с правильными параметрами")
            
    except FileNotFoundError:
        print("Файл test_log_zapret_iter_4_20250901_105104.txt не найден")
    
    print("\n5. РЕКОМЕНДАЦИИ")
    print("-" * 40)
    
    print("🔧 ИСПРАВИТЬ СТРАТЕГИЮ:")
    print("   Замените вашу команду на успешную стратегию zapret:")
    print()
    print("   ВМЕСТО:")
    print(f"   {user_strategy}")
    print()
    print("   ИСПОЛЬЗУЙТЕ:")
    print(f"   {zapret_successful_strategy}")
    print()
    
    print("🎯 КЛЮЧЕВЫЕ ИЗМЕНЕНИЯ:")
    print("   1. split-seqovl: 1 → 336 (размер перекрытия)")
    print("   2. ttl: 64 → 1 (время жизни поддельных пакетов)")
    print("   3. fooling: добавить 'badsum' к существующим методам")
    print("   4. добавить --dpi-desync-repeats=1")
    print()
    
    print("📊 ОЖИДАЕМЫЙ РЕЗУЛЬТАТ:")
    print("   - Успешность должна вырасти с 0% до ~87%")
    print("   - Должно работать 27 из 31 домена")
    print("   - Включая x.com, instagram.com, youtube.com")
    
    print("\n6. ТЕХНИЧЕСКОЕ ОБЪЯСНЕНИЕ")
    print("-" * 40)
    
    print("Почему не работает текущая стратегия:")
    print("• overlap_size=1 слишком мал для эффективного обмана DPI")
    print("• ttl=64 позволяет поддельным пакетам достигать цели")
    print("• отсутствие badsum снижает эффективность обмана")
    print()
    
    print("Почему работает стратегия zapret:")
    print("• overlap_size=336 создает достаточное перекрытие")
    print("• ttl=1 гарантирует, что поддельные пакеты не достигнут цели")
    print("• badsum портит контрольные суммы поддельных пакетов")
    print("• комбинация методов fooling максимизирует обман DPI")
    
    return differences

def generate_corrected_command():
    """Генерирует исправленную команду для пользователя."""
    
    corrected_command = (
        "python cli.py -d sites.txt "
        '--strategy "'
        "--dpi-desync=fakeddisorder "
        "--dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 "
        "--dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 "
        "--dpi-desync-split-pos=76 "
        "--dpi-desync-ttl=1"
        '" --pcap out_fixed.pcap'
    )
    
    print("\n" + "=" * 80)
    print("ИСПРАВЛЕННАЯ КОМАНДА ДЛЯ ТЕСТИРОВАНИЯ")
    print("=" * 80)
    print()
    print(corrected_command)
    print()
    print("Сохраните эту команду в файл test_fixed.bat:")
    
    with open('test_fixed.bat', 'w', encoding='utf-8') as f:
        f.write(corrected_command + '\n')
    
    print("✅ Файл test_fixed.bat создан")
    
    return corrected_command

if __name__ == "__main__":
    differences = analyze_strategy_discrepancy()
    generate_corrected_command()
    
    print(f"\n🎉 Анализ завершен. Найдено {len(differences)} критических различий.")
    print("   Используйте исправленную команду для получения 87% успешности!")