#!/usr/bin/env python3
"""
Анализ корневой причины различий в применении стратегий
"""

import json
from pathlib import Path

def analyze_strategy_mismatch():
    """Анализ различий в применении стратегий"""
    
    print("АНАЛИЗ КОРНЕВОЙ ПРИЧИНЫ РАЗЛИЧИЙ В СТРАТЕГИЯХ")
    print("=" * 60)
    
    # Загружаем отчёт сравнения
    try:
        with open('strategy_comparison_report.json', 'r', encoding='utf-8') as f:
            report = json.load(f)
    except FileNotFoundError:
        print("❌ Файл strategy_comparison_report.json не найден")
        return
    
    # Анализ ключевых различий
    differences = report.get('parameters', {}).get('differences', {})
    
    print("\n🔍 КЛЮЧЕВЫЕ РАЗЛИЧИЯ:")
    
    # 1. Split позиции
    split_pos_diff = differences.get('split_pos', {})
    if split_pos_diff:
        search_pos = split_pos_diff.get('search', 'N/A')
        service_pos = split_pos_diff.get('service', 'N/A')
        print(f"📍 Split позиция: поиск={search_pos}, служба={service_pos}")
        print(f"   Разница: {abs(int(service_pos) - int(search_pos)) if isinstance(search_pos, int) and isinstance(service_pos, int) else 'N/A'} байт")
    
    # 2. TTL различия
    ttl_diff = differences.get('ttl', {})
    if ttl_diff:
        search_ttl = ttl_diff.get('search', 'N/A')
        service_ttl = ttl_diff.get('service', 'N/A')
        print(f"🕒 TTL значения: поиск={search_ttl}, служба={service_ttl}")
    
    # 3. Количество split операций
    split_count_diff = differences.get('split_count', {})
    if split_count_diff:
        search_count = split_count_diff.get('search', 'N/A')
        service_count = split_count_diff.get('service', 'N/A')
        print(f"🔢 Количество split: поиск={search_count}, служба={service_count}")
    
    # Анализ возможных причин
    print("\n🎯 ВОЗМОЖНЫЕ ПРИЧИНЫ РАЗЛИЧИЙ:")
    
    causes = []
    
    # Причина 1: Различные конфигурации
    if split_pos_diff:
        causes.append("1. Различные конфигурации split_pos в режимах поиска и службы")
    
    if ttl_diff:
        causes.append("2. Различные TTL настройки для fake пакетов")
    
    # Причина 2: Различные алгоритмы применения
    packet_count = report.get('packets', {}).get('count_difference', 0)
    if abs(packet_count) > 100:
        causes.append("3. Кардинально различные алгоритмы применения стратегий")
    
    # Причина 3: Различные источники параметров
    causes.append("4. Параметры берутся из разных источников (конфиг vs база знаний)")
    
    for cause in causes:
        print(f"   {cause}")
    
    # Рекомендации по исправлению
    print("\n💡 РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ:")
    
    recommendations = [
        "1. Проверить источники параметров стратегий в обоих режимах",
        "2. Убедиться, что domain_rules.json используется одинаково",
        "3. Проверить логику применения параметров в bypass engine",
        "4. Добавить логирование параметров перед применением стратегии",
        "5. Создать единый источник конфигурации для обоих режимов"
    ]
    
    for rec in recommendations:
        print(f"   {rec}")
    
    # Анализ конкретных файлов
    print("\n📁 ФАЙЛЫ ДЛЯ ПРОВЕРКИ:")
    
    files_to_check = [
        "domain_rules.json - проверить параметры для *.googlevideo.com",
        "core/bypass/engine/ - логика применения стратегий",
        "core/adaptive_engine.py - параметры в режиме поиска",
        "simple_service.py - параметры в режиме службы",
        "Логи обоих режимов - сравнить применяемые параметры"
    ]
    
    for file_info in files_to_check:
        print(f"   📄 {file_info}")

def check_domain_rules():
    """Проверка правил домена"""
    
    print("\n" + "=" * 60)
    print("ПРОВЕРКА DOMAIN RULES")
    print("=" * 60)
    
    try:
        with open('domain_rules.json', 'r', encoding='utf-8') as f:
            rules = json.load(f)
    except FileNotFoundError:
        print("❌ Файл domain_rules.json не найден")
        return
    
    # Поиск правил для googlevideo
    googlevideo_rules = {}
    for domain, rule in rules.items():
        if 'googlevideo' in domain.lower():
            googlevideo_rules[domain] = rule
    
    print(f"🔍 Найдено {len(googlevideo_rules)} правил для googlevideo:")
    
    for domain, rule in googlevideo_rules.items():
        print(f"\n📋 Домен: {domain}")
        print(f"   Тип: {rule.get('type', 'не указан')}")
        print(f"   Атаки: {rule.get('attacks', [])}")
        
        params = rule.get('params', {})
        if params:
            print(f"   Параметры:")
            for key, value in params.items():
                print(f"     {key}: {value}")
        
        metadata = rule.get('metadata', {})
        if metadata:
            print(f"   Метаданные:")
            print(f"     Неудачи: {metadata.get('failure_count', 0)}")
            print(f"     Последняя неудача: {metadata.get('last_failure_time', 'нет')}")

def analyze_parameter_sources():
    """Анализ источников параметров"""
    
    print("\n" + "=" * 60)
    print("АНАЛИЗ ИСТОЧНИКОВ ПАРАМЕТРОВ")
    print("=" * 60)
    
    # Проверяем adaptive_knowledge.json
    adaptive_file = Path("adaptive_knowledge.json")
    if adaptive_file.exists():
        try:
            with open(adaptive_file, 'r', encoding='utf-8') as f:
                adaptive_data = json.load(f)
            
            print("📚 ADAPTIVE_KNOWLEDGE.JSON:")
            
            googlevideo_data = {}
            for domain, data in adaptive_data.items():
                if 'googlevideo' in domain.lower():
                    googlevideo_data[domain] = data
            
            if googlevideo_data:
                for domain, data in googlevideo_data.items():
                    print(f"\n   Домен: {domain}")
                    strategies = data.get('strategies', [])
                    print(f"   Стратегий: {len(strategies)}")
                    
                    for strategy in strategies[:3]:  # Показать первые 3
                        print(f"     - {strategy.get('strategy_name', 'unknown')}")
                        params = strategy.get('strategy_params', {})
                        if params:
                            print(f"       Параметры: {params}")
            else:
                print("   ❌ Нет данных для googlevideo")
        
        except Exception as e:
            print(f"   ❌ Ошибка чтения adaptive_knowledge.json: {e}")
    else:
        print("📚 ADAPTIVE_KNOWLEDGE.JSON: файл не найден")

def generate_fix_script():
    """Генерация скрипта для исправления"""
    
    print("\n" + "=" * 60)
    print("ГЕНЕРАЦИЯ СКРИПТА ИСПРАВЛЕНИЯ")
    print("=" * 60)
    
    fix_script = """#!/usr/bin/env python3
'''
Скрипт для исправления различий в применении стратегий
'''

import json
from pathlib import Path

def fix_strategy_parameters():
    '''Исправление параметров стратегий'''
    
    print("Исправление параметров стратегий...")
    
    # 1. Проверить domain_rules.json
    try:
        with open('domain_rules.json', 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        # Найти правило для *.googlevideo.com
        googlevideo_rule = None
        for domain, rule in rules.items():
            if 'googlevideo' in domain and '*' in domain:
                googlevideo_rule = rule
                break
        
        if googlevideo_rule:
            params = googlevideo_rule.get('params', {})
            print(f"Текущие параметры: {params}")
            
            # Установить параметры из режима поиска
            params['split_pos'] = 3  # Из режима поиска
            params['ttl'] = 3        # Из режима поиска
            
            print(f"Новые параметры: {params}")
            
            # Сохранить изменения
            with open('domain_rules.json', 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
            
            print("✅ Параметры обновлены в domain_rules.json")
        else:
            print("❌ Правило для *.googlevideo.com не найдено")
    
    except Exception as e:
        print(f"❌ Ошибка: {e}")

if __name__ == "__main__":
    fix_strategy_parameters()
"""
    
    with open('fix_strategy_parameters.py', 'w', encoding='utf-8') as f:
        f.write(fix_script)
    
    print("📄 Создан скрипт fix_strategy_parameters.py")
    print("   Запустите: python fix_strategy_parameters.py")

def main():
    """Основная функция"""
    
    analyze_strategy_mismatch()
    check_domain_rules()
    analyze_parameter_sources()
    generate_fix_script()
    
    print("\n" + "=" * 60)
    print("ЗАКЛЮЧЕНИЕ")
    print("=" * 60)
    
    print("""
🎯 КОРНЕВАЯ ПРИЧИНА:
   Режим поиска и режим службы используют РАЗНЫЕ параметры стратегий:
   - split_pos: 3 (поиск) vs 39 (служба)
   - ttl: 3 (поиск) vs 1 (служба)

🔧 РЕШЕНИЕ:
   1. Унифицировать источник параметров
   2. Использовать одинаковые значения в обоих режимах
   3. Проверить логику чтения параметров из domain_rules.json

⚡ СЛЕДУЮЩИЕ ШАГИ:
   1. Запустить fix_strategy_parameters.py
   2. Перезапустить службу обхода
   3. Проверить, что параметры применяются одинаково
   4. Повторить тест с новыми PCAP файлами
""")

if __name__ == "__main__":
    main()