#!/usr/bin/env python3
"""
Анализ различий между PCAP файлами recon и zapret для понимания
почему recon открывает 0 доменов, а zapret 27 доменов.
"""

import sys
import json
from pathlib import Path

def analyze_strategy_differences():
    """Анализирует различия в стратегиях."""
    
    print("🔍 АНАЛИЗ РАЗЛИЧИЙ МЕЖДУ RECON И ZAPRET")
    print("=" * 60)
    
    # Успешная стратегия zapret
    zapret_strategy = {
        "dpi_desync": "fakeddisorder",
        "split_seqovl": 336,
        "autottl": 2,
        "fooling": ["md5sig", "badsum", "badseq"],
        "repeats": 1,
        "split_pos": 76,
        "ttl": 1
    }
    
    # Тестируемая стратегия recon
    recon_strategy = {
        "dpi_desync": "fake,fakeddisorder",
        "split_seqovl": 1,
        "autottl": 2,
        "fake_http": "PAYLOADTLS",
        "fake_tls": "PAYLOADTLS",
        "fooling": ["badseq", "md5sig"],
        "ttl": 64
    }
    
    print("📊 СРАВНЕНИЕ СТРАТЕГИЙ:")
    print()
    print("ZAPRET (27 доменов работают):")
    for key, value in zapret_strategy.items():
        print(f"  {key}: {value}")
    
    print()
    print("RECON (0 доменов работают):")
    for key, value in recon_strategy.items():
        print(f"  {key}: {value}")
    
    print()
    print("🔍 КРИТИЧЕСКИЕ РАЗЛИЧИЯ:")
    
    differences = []
    
    # 1. Метод desync
    if zapret_strategy["dpi_desync"] != recon_strategy["dpi_desync"]:
        differences.append({
            "parameter": "dpi_desync",
            "zapret": zapret_strategy["dpi_desync"],
            "recon": recon_strategy["dpi_desync"],
            "impact": "КРИТИЧЕСКИЙ - разные методы обхода"
        })
    
    # 2. split_seqovl
    if zapret_strategy["split_seqovl"] != recon_strategy["split_seqovl"]:
        differences.append({
            "parameter": "split_seqovl",
            "zapret": zapret_strategy["split_seqovl"],
            "recon": recon_strategy["split_seqovl"],
            "impact": "КРИТИЧЕСКИЙ - размер перекрытия последовательности"
        })
    
    # 3. TTL
    if zapret_strategy["ttl"] != recon_strategy["ttl"]:
        differences.append({
            "parameter": "ttl",
            "zapret": zapret_strategy["ttl"],
            "recon": recon_strategy["ttl"],
            "impact": "КРИТИЧЕСКИЙ - время жизни пакета"
        })
    
    # 4. fooling порядок
    zapret_fooling = set(zapret_strategy["fooling"])
    recon_fooling = set(recon_strategy["fooling"])
    if zapret_fooling != recon_fooling:
        differences.append({
            "parameter": "fooling",
            "zapret": zapret_strategy["fooling"],
            "recon": recon_strategy["fooling"],
            "impact": "СРЕДНИЙ - разные методы обмана"
        })
    
    # 5. split_pos
    if "split_pos" in zapret_strategy and "split_pos" not in recon_strategy:
        differences.append({
            "parameter": "split_pos",
            "zapret": zapret_strategy["split_pos"],
            "recon": "НЕ УКАЗАН",
            "impact": "КРИТИЧЕСКИЙ - позиция разделения не указана"
        })
    
    for i, diff in enumerate(differences, 1):
        print(f"{i}. {diff['parameter']}:")
        print(f"   Zapret: {diff['zapret']}")
        print(f"   Recon:  {diff['recon']}")
        print(f"   Влияние: {diff['impact']}")
        print()
    
    return differences

def analyze_recon_report():
    """Анализирует отчет recon для понимания проблем."""
    
    report_path = Path("recon_report_20250902_111606.json")
    if not report_path.exists():
        print(f"❌ Файл отчета {report_path} не найден")
        return None
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        print("📋 АНАЛИЗ ОТЧЕТА RECON:")
        print(f"  Всего стратегий протестировано: {report['total_strategies_tested']}")
        print(f"  Рабочих стратегий найдено: {report['working_strategies_found']}")
        print(f"  Процент успеха: {report['success_rate']}%")
        print(f"  Время выполнения: {report['execution_time_seconds']:.1f} сек")
        print()
        
        # Анализ результатов по доменам
        blocked_count = sum(1 for status in report['domain_status'].values() if status == "BLOCKED")
        total_domains = len(report['domain_status'])
        
        print(f"📊 СТАТУС ДОМЕНОВ:")
        print(f"  Заблокировано: {blocked_count}/{total_domains}")
        print(f"  Работает: {total_domains - blocked_count}/{total_domains}")
        print()
        
        # Анализ использованной стратегии
        if report['all_results']:
            strategy_info = report['all_results'][0]
            print("🎯 ИСПОЛЬЗОВАННАЯ СТРАТЕГИЯ:")
            print(f"  Название: {strategy_info['strategy_dict']['name']}")
            print(f"  Параметры:")
            for key, value in strategy_info['strategy_dict']['params'].items():
                print(f"    {key}: {value}")
            print()
        
        return report
        
    except Exception as e:
        print(f"❌ Ошибка чтения отчета: {e}")
        return None

def generate_corrected_strategy():
    """Генерирует исправленную стратегию на основе успешной zapret стратегии."""
    
    print("🔧 РЕКОМЕНДУЕМЫЕ ИСПРАВЛЕНИЯ:")
    print()
    
    # Успешная zapret стратегия
    corrected_strategy = "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
    
    print("1. ИСПОЛЬЗОВАТЬ УСПЕШНУЮ ZAPRET СТРАТЕГИЮ:")
    print(f"   {corrected_strategy}")
    print()
    
    print("2. КЛЮЧЕВЫЕ ИЗМЕНЕНИЯ:")
    print("   ❌ Убрать: fake,fakeddisorder -> ✅ Использовать: fakeddisorder")
    print("   ❌ Убрать: split-seqovl=1 -> ✅ Использовать: split-seqovl=336")
    print("   ❌ Убрать: ttl=64 -> ✅ Использовать: ttl=1")
    print("   ✅ Добавить: split-pos=76")
    print("   ✅ Добавить: repeats=1")
    print("   ❌ Убрать: fake-http и fake-tls параметры")
    print()
    
    print("3. КОМАНДА ДЛЯ ТЕСТИРОВАНИЯ:")
    test_command = f'python cli.py -d sites.txt --strategy "{corrected_strategy}" --pcap out_corrected.pcap'
    print(f"   {test_command}")
    print()
    
    return corrected_strategy

def main():
    """Главная функция анализа."""
    
    print("🚀 АНАЛИЗ ПРОБЛЕМЫ: RECON 0 доменов vs ZAPRET 27 доменов")
    print("=" * 70)
    print()
    
    # 1. Анализ различий в стратегиях
    differences = analyze_strategy_differences()
    
    print()
    print("=" * 70)
    
    # 2. Анализ отчета recon
    report = analyze_recon_report()
    
    print("=" * 70)
    
    # 3. Генерация исправленной стратегии
    corrected_strategy = generate_corrected_strategy()
    
    print("=" * 70)
    print("🎯 ЗАКЛЮЧЕНИЕ:")
    print()
    print("ОСНОВНЫЕ ПРОБЛЕМЫ:")
    print("1. ❌ Неправильный метод desync: 'fake,fakeddisorder' вместо 'fakeddisorder'")
    print("2. ❌ Неправильный split-seqovl: 1 вместо 336")
    print("3. ❌ Неправильный TTL: 64 вместо 1")
    print("4. ❌ Отсутствует split-pos: должно быть 76")
    print("5. ❌ Лишние параметры fake-http и fake-tls")
    print()
    print("РЕШЕНИЕ:")
    print("Использовать точную стратегию zapret, которая показала 27/31 успешных доменов.")
    print()
    
    return corrected_strategy

if __name__ == "__main__":
    corrected_strategy = main()