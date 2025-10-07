#!/usr/bin/env python3
"""
Анализ лога службы с forced override для оценки эффективности.
"""

import re
from datetime import datetime
from collections import defaultdict, Counter

def analyze_service_log():
    """Анализирует лог службы с forced override."""
    
    print("🔍 АНАЛИЗ ЛОГА СЛУЖБЫ С FORCED OVERRIDE")
    print("=" * 50)
    
    try:
        with open('log.txt', 'r', encoding='utf-8') as f:
            log_content = f.read()
    except FileNotFoundError:
        print("❌ Файл log.txt не найден!")
        return
    
    # Статистика
    stats = {
        'forced_override_calls': 0,
        'bypass_applications': 0,
        'strategy_mappings': 0,
        'domains_resolved': 0,
        'unique_ips': set(),
        'strategies_used': Counter(),
        'domains_with_strategies': defaultdict(list),
        'errors': [],
        'warnings': []
    }
    
    # Паттерны для поиска
    patterns = {
        'forced_override': r'🔥 FORCED OVERRIDE',
        'bypass_application': r'🎯 Applying bypass for (\d+\.\d+\.\d+\.\d+)',
        'strategy_mapping': r'✅ Mapped IP (\d+\.\d+\.\d+\.\d+) \(([^)]+)\) -> (\w+)',
        'domain_resolution': r'🔍 Resolved ([^\s]+) -> (\d+\.\d+\.\d+\.\d+)',
        'strategy_interpretation': r'✅ Strategy interpreted: (\w+)',
        'error': r'\[ERROR\s*\]',
        'warning': r'\[WARNING\]'
    }
    
    print("📊 ОБРАБОТКА ЛОГА...")
    
    # Анализ forced override вызовов
    forced_override_matches = re.findall(patterns['forced_override'], log_content)
    stats['forced_override_calls'] = len(forced_override_matches)
    
    # Анализ применения bypass
    bypass_matches = re.findall(patterns['bypass_application'], log_content)
    stats['bypass_applications'] = len(bypass_matches)
    for ip in bypass_matches:
        stats['unique_ips'].add(ip)
    
    # Анализ маппинга стратегий
    mapping_matches = re.findall(patterns['strategy_mapping'], log_content)
    stats['strategy_mappings'] = len(mapping_matches)
    
    for ip, domain, strategy in mapping_matches:
        stats['unique_ips'].add(ip)
        stats['strategies_used'][strategy] += 1
        stats['domains_with_strategies'][domain].append(strategy)
    
    # Анализ разрешения доменов
    resolution_matches = re.findall(patterns['domain_resolution'], log_content)
    stats['domains_resolved'] = len(resolution_matches)
    
    # Анализ интерпретации стратегий
    interpretation_matches = re.findall(patterns['strategy_interpretation'], log_content)
    for strategy in interpretation_matches:
        stats['strategies_used'][strategy] += 1
    
    # Поиск ошибок и предупреждений
    error_lines = [line for line in log_content.split('\n') if re.search(patterns['error'], line)]
    warning_lines = [line for line in log_content.split('\n') if re.search(patterns['warning'], line)]
    
    stats['errors'] = error_lines
    stats['warnings'] = warning_lines
    
    # Вывод результатов
    print("\n📈 СТАТИСТИКА FORCED OVERRIDE:")
    print(f"   🔥 Вызовы forced override: {stats['forced_override_calls']}")
    print(f"   🎯 Применения bypass: {stats['bypass_applications']}")
    print(f"   🗺️ Маппинги стратегий: {stats['strategy_mappings']}")
    print(f"   🌐 Разрешенные домены: {stats['domains_resolved']}")
    print(f"   📍 Уникальные IP: {len(stats['unique_ips'])}")
    
    print(f"\n🎲 ИСПОЛЬЗУЕМЫЕ СТРАТЕГИИ:")
    for strategy, count in stats['strategies_used'].most_common():
        print(f"   ✅ {strategy}: {count} раз")
    
    print(f"\n🌍 ДОМЕНЫ С СТРАТЕГИЯМИ:")
    for domain, strategies in list(stats['domains_with_strategies'].items())[:10]:  # Показываем первые 10
        unique_strategies = list(set(strategies))
        print(f"   🔗 {domain}: {', '.join(unique_strategies)}")
    
    if len(stats['domains_with_strategies']) > 10:
        print(f"   ... и еще {len(stats['domains_with_strategies']) - 10} доменов")
    
    # YouTube анализ
    youtube_domains = [domain for domain in stats['domains_with_strategies'].keys() 
                      if 'youtube' in domain.lower() or 'ytimg' in domain.lower()]
    
    if youtube_domains:
        print(f"\n🎥 YOUTUBE ДОМЕНЫ ({len(youtube_domains)}):")
        for domain in youtube_domains[:5]:  # Показываем первые 5
            strategies = list(set(stats['domains_with_strategies'][domain]))
            print(f"   📺 {domain}: {', '.join(strategies)}")
    
    # Анализ ошибок и предупреждений
    if stats['errors']:
        print(f"\n❌ ОШИБКИ ({len(stats['errors'])}):")
        for error in stats['errors'][:3]:  # Показываем первые 3
            print(f"   🚨 {error.strip()}")
    
    if stats['warnings']:
        print(f"\n⚠️ ПРЕДУПРЕЖДЕНИЯ ({len(stats['warnings'])}):")
        for warning in stats['warnings'][:3]:  # Показываем первые 3
            print(f"   ⚠️ {warning.strip()}")
    
    # Оценка эффективности
    print(f"\n🎯 ОЦЕНКА ЭФФЕКТИВНОСТИ:")
    
    if stats['forced_override_calls'] > 0:
        print(f"   ✅ Forced override активен!")
        print(f"   📊 Вызовов: {stats['forced_override_calls']}")
    else:
        print(f"   ❌ Forced override НЕ обнаружен в логе!")
    
    if stats['bypass_applications'] > 0:
        print(f"   ✅ Bypass применяется активно!")
        print(f"   📊 Применений: {stats['bypass_applications']}")
    else:
        print(f"   ❌ Bypass НЕ применяется!")
    
    if len(stats['unique_ips']) > 20:
        print(f"   ✅ Хорошее покрытие IP адресов: {len(stats['unique_ips'])}")
    elif len(stats['unique_ips']) > 10:
        print(f"   ⚠️ Среднее покрытие IP адресов: {len(stats['unique_ips'])}")
    else:
        print(f"   ❌ Низкое покрытие IP адресов: {len(stats['unique_ips'])}")
    
    # Рекомендации
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    
    if stats['forced_override_calls'] == 0:
        print("   🔧 Forced override не работает - проверьте исправление")
    elif stats['bypass_applications'] == 0:
        print("   🔧 Bypass не применяется - проверьте сетевой трафик")
    elif len(stats['errors']) > 0:
        print("   🔧 Есть ошибки - проверьте детали в логе")
    elif 'fakeddisorder' in stats['strategies_used'] and 'multidisorder' in stats['strategies_used']:
        print("   ✅ Используются разные стратегии - хорошо!")
        print("   🎯 YouTube должен частично работать")
        print("   🚀 Попробуйте открыть другие сайты для полной проверки")
    else:
        print("   ⚠️ Ограниченное разнообразие стратегий")
    
    return stats

def check_youtube_specific():
    """Проверяет специфичную информацию о YouTube."""
    
    print(f"\n🎥 ДЕТАЛЬНЫЙ АНАЛИЗ YOUTUBE:")
    print("=" * 30)
    
    try:
        with open('log.txt', 'r', encoding='utf-8') as f:
            log_content = f.read()
    except FileNotFoundError:
        return
    
    # YouTube связанные домены
    youtube_patterns = [
        r'youtube\.com',
        r'ytimg\.com',
        r'googleapis\.com',
        r'ggpht\.com'
    ]
    
    youtube_info = {}
    
    for pattern in youtube_patterns:
        matches = re.findall(f'({pattern})', log_content, re.IGNORECASE)
        if matches:
            youtube_info[pattern] = len(matches)
    
    if youtube_info:
        print("📊 YouTube домены в логе:")
        for domain_pattern, count in youtube_info.items():
            print(f"   📺 {domain_pattern}: {count} упоминаний")
    
    # Поиск конкретных IP для YouTube
    youtube_ips = re.findall(r'youtube\.com.*?(\d+\.\d+\.\d+\.\d+)', log_content)
    if youtube_ips:
        print(f"\n📍 IP адреса YouTube:")
        for ip in set(youtube_ips):
            print(f"   🌐 {ip}")
    
    # Поиск применения bypass для YouTube IP
    youtube_bypass = re.findall(r'🎯 Applying bypass for (\d+\.\d+\.\d+\.\d+)', log_content)
    youtube_bypass_ips = set(youtube_bypass) & set(youtube_ips)
    
    if youtube_bypass_ips:
        print(f"\n✅ Bypass применен для YouTube IP:")
        for ip in youtube_bypass_ips:
            print(f"   🎯 {ip}")
    else:
        print(f"\n⚠️ Bypass для YouTube IP не найден в логе")

if __name__ == "__main__":
    try:
        stats = analyze_service_log()
        check_youtube_specific()
        
        print(f"\n" + "=" * 50)
        print("🎉 АНАЛИЗ ЗАВЕРШЕН!")
        
        if stats and stats['forced_override_calls'] > 0:
            print("✅ Forced override работает!")
            print("🎯 Исправление применено успешно!")
            
            if stats['bypass_applications'] > 0:
                print("🚀 Bypass активно применяется!")
                print("\n📋 СЛЕДУЮЩИЕ ШАГИ:")
                print("1. Откройте YouTube в браузере")
                print("2. Проверьте другие сайты (Instagram, X.com)")
                print("3. Если есть проблемы - сообщите детали")
            else:
                print("⚠️ Bypass настроен, но не применяется")
                print("💡 Возможно, нет активного трафика к целевым сайтам")
        else:
            print("❌ Forced override НЕ работает!")
            print("🔧 Нужно проверить исправление")
        
    except Exception as e:
        print(f"❌ Ошибка анализа: {e}")
        print("🔧 Проверьте наличие файла log.txt")