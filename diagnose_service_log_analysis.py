#!/usr/bin/env python3
"""
Анализ лога службы обхода для выявления проблем.
Создает детальный отчет о работе службы.
"""

import re
import json
from datetime import datetime
from collections import defaultdict, Counter

def analyze_service_log():
    """Анализирует лог службы и создает отчет."""
    
    print("🔍 АНАЛИЗ ЛОГА СЛУЖБЫ ОБХОДА")
    print("=" * 50)
    
    try:
        with open('log.txt', 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read()
    except FileNotFoundError:
        print("❌ Файл log.txt не найден!")
        return
    
    lines = log_content.split('\n')
    
    # Статистика
    stats = {
        'total_lines': len(lines),
        'domains_loaded': 0,
        'strategies_loaded': 0,
        'ip_mappings': 0,
        'bypass_applications': [],
        'packet_sends': [],
        'errors': [],
        'warnings': [],
        'domains_with_bypass': set(),
        'ips_with_bypass': set()
    }
    
    # Анализ строк
    for line in lines:
        if not line.strip():
            continue
            
        # Загрузка доменов и стратегий
        if "Loaded" in line and "domain-specific strategies" in line:
            match = re.search(r'(\d+) domain-specific strategies', line)
            if match:
                stats['strategies_loaded'] = int(match.group(1))
        
        if "Loaded" in line and "domains from sites.txt" in line:
            match = re.search(r'(\d+) domains from sites.txt', line)
            if match:
                stats['domains_loaded'] = int(match.group(1))
        
        # IP маппинги
        if "Mapped IP" in line:
            stats['ip_mappings'] += 1
        
        # Применение bypass
        if "🎯 Applying bypass for" in line:
            match = re.search(r'for ([0-9.]+)', line)
            if match:
                ip = match.group(1)
                stats['bypass_applications'].append(ip)
                stats['ips_with_bypass'].add(ip)
        
        # Отправка пакетов
        if "📤 FAKE" in line or "📤 REAL" in line:
            match = re.search(r'dst=([0-9.]+):(\d+)', line)
            if match:
                ip, port = match.groups()
                stats['packet_sends'].append(f"{ip}:{port}")
        
        # Ошибки и предупреждения
        if "[ERROR" in line:
            stats['errors'].append(line.strip())
        
        if "[WARNING" in line:
            stats['warnings'].append(line.strip())
    
    # Создание отчета
    print(f"📊 СТАТИСТИКА:")
    print(f"   Всего строк в логе: {stats['total_lines']}")
    print(f"   Загружено стратегий: {stats['strategies_loaded']}")
    print(f"   Загружено доменов: {stats['domains_loaded']}")
    print(f"   Создано IP-маппингов: {stats['ip_mappings']}")
    print(f"   Применений bypass: {len(stats['bypass_applications'])}")
    print(f"   Отправок пакетов: {len(stats['packet_sends'])}")
    print(f"   Ошибок: {len(stats['errors'])}")
    print(f"   Предупреждений: {len(stats['warnings'])}")
    
    print(f"\n🎯 ДОМЕНЫ С АКТИВНЫМ BYPASS:")
    if stats['ips_with_bypass']:
        # Попытка сопоставить IP с доменами из лога
        ip_to_domain = {}
        for line in lines:
            if "Resolved" in line:
                match = re.search(r'Resolved ([^\s]+) -> ([0-9.]+)', line)
                if match:
                    domain, ip = match.groups()
                    ip_to_domain[ip] = domain
        
        for ip in stats['ips_with_bypass']:
            domain = ip_to_domain.get(ip, "неизвестный домен")
            print(f"   ✅ {ip} ({domain})")
    else:
        print("   ❌ НЕТ активных bypass!")
    
    print(f"\n📤 ОТПРАВКА ПАКЕТОВ:")
    if stats['packet_sends']:
        packet_counter = Counter(stats['packet_sends'])
        for target, count in packet_counter.most_common(10):
            print(f"   {target}: {count} пакетов")
    else:
        print("   ❌ Пакеты НЕ отправлялись!")
    
    print(f"\n⚠️ ПРЕДУПРЕЖДЕНИЯ:")
    for warning in stats['warnings'][-5:]:  # Последние 5
        print(f"   {warning}")
    
    print(f"\n❌ ОШИБКИ:")
    for error in stats['errors'][-5:]:  # Последние 5
        print(f"   {error}")
    
    # Анализ проблем
    print(f"\n🔍 АНАЛИЗ ПРОБЛЕМ:")
    
    problems = []
    
    if len(stats['bypass_applications']) == 0:
        problems.append("❌ КРИТИЧНО: Bypass НЕ применяется ни к одному домену!")
    elif len(stats['bypass_applications']) < 5:
        problems.append(f"⚠️ Bypass применяется только к {len(stats['bypass_applications'])} доменам из {stats['domains_loaded']}")
    
    if len(stats['packet_sends']) == 0:
        problems.append("❌ КРИТИЧНО: Пакеты НЕ отправляются!")
    
    if stats['errors']:
        problems.append(f"❌ Обнаружено {len(stats['errors'])} ошибок")
    
    # Проверка Instagram
    instagram_ips = []
    for line in lines:
        if "instagram.com" in line and "Resolved" in line:
            match = re.search(r'-> ([0-9.]+)', line)
            if match:
                instagram_ips.append(match.group(1))
    
    instagram_bypass = any(ip in stats['ips_with_bypass'] for ip in instagram_ips)
    if instagram_ips and not instagram_bypass:
        problems.append(f"⚠️ Instagram ({', '.join(instagram_ips)}) НЕ получает bypass!")
    
    if not problems:
        print("   ✅ Серьезных проблем не обнаружено")
    else:
        for problem in problems:
            print(f"   {problem}")
    
    # Рекомендации
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    
    if len(stats['bypass_applications']) == 0:
        print("   1. Проверить, что служба запущена от имени администратора")
        print("   2. Убедиться, что WinDivert установлен корректно")
        print("   3. Проверить, что трафик действительно идет к целевым доменам")
        print("   4. Запустить тест: откройте instagram.com в браузере")
    
    if instagram_ips and not instagram_bypass:
        print("   5. Instagram показывает 'заставку' из-за отсутствия bypass")
        print("   6. Проверить стратегию multisplit для Instagram")
        print("   7. Возможно, нужно изменить стратегию на fakeddisorder")
    
    if len(stats['packet_sends']) < len(stats['bypass_applications']) * 3:
        print("   8. Мало отправленных пакетов - возможны проблемы с сетью")
    
    print("\n🚀 СЛЕДУЮЩИЕ ШАГИ:")
    print("   1. Откройте instagram.com в браузере для генерации трафика")
    print("   2. Проверьте, появятся ли новые записи в логе")
    print("   3. Если bypass не применяется, перезапустите службу от администратора")
    
    return stats

def check_instagram_strategy():
    """Проверяет стратегию для Instagram."""
    
    print("\n🔍 ПРОВЕРКА СТРАТЕГИИ INSTAGRAM:")
    
    try:
        with open('strategies.json', 'r', encoding='utf-8') as f:
            strategies = json.load(f)
        
        instagram_strategy = strategies.get('instagram.com')
        if instagram_strategy:
            print(f"   ✅ Стратегия найдена: {instagram_strategy}")
            
            if instagram_strategy.get('desync_method') == 'multisplit':
                print("   ⚠️ Используется multisplit - может работать нестабильно")
                print("   💡 Рекомендация: попробовать fakeddisorder")
        else:
            print("   ❌ Стратегия для instagram.com НЕ найдена!")
            
    except FileNotFoundError:
        print("   ❌ Файл strategies.json не найден!")

if __name__ == "__main__":
    stats = analyze_service_log()
    check_instagram_strategy()
    
    print("\n" + "=" * 50)
    print("🎯 ИТОГОВЫЙ ДИАГНОЗ:")
    
    if stats and len(stats['bypass_applications']) == 0:
        print("❌ Служба НЕ работает - bypass не применяется!")
        print("🔧 Решение: перезапустить службу от администратора")
    elif stats and len(stats['bypass_applications']) < 3:
        print("⚠️ Служба работает частично - мало активности")
        print("🔧 Решение: открыть больше заблокированных сайтов")
    else:
        print("✅ Служба работает, но возможны улучшения")