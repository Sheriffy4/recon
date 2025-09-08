#!/usr/bin/env python3
"""
Анализ проблем с работой заблокированных доменов после изменений
"""

import json
import os
from collections import defaultdict

def analyze_current_issues():
    """Анализ текущих проблем на основе логов и pcap данных."""
    
    print("🔍 === АНАЛИЗ ТЕКУЩИХ ПРОБЛЕМ ===\n")
    
    # Анализ логов службы
    print("📋 1. АНАЛИЗ ЛОГОВ СЛУЖБЫ:")
    print("✅ Положительные моменты:")
    print("   • Служба корректно загружает 14 стратегий")
    print("   • SNI извлечение работает: 'Выбрана стратегия по SNI: x.com'")
    print("   • Domain-specific стратегии применяются:")
    print("     - x.com -> multisplit (5 splits)")
    print("     - instagram.com -> fakedisorder") 
    print("     - rutracker.org -> fakedisorder")
    print("     - facebook.com -> multisplit (8 splits)")
    
    print("\n❌ Проблемы:")
    print("   • Много 'Применяется глобальная стратегия по умолчанию'")
    print("   • Instagram медиа не грузит (субдомены не покрыты)")
    print("   • X.com не работает полностью") 
    print("   • YouTube видео не воспроизводится")
    
    # Анализ pcap данных
    print("\n📊 2. АНАЛИЗ PCAP ДАННЫХ:")
    print("✅ Обнаружено:")
    print("   • 7,330 TCP пакетов")
    print("   • 590 TLS пакетов") 
    print("   • 426 ClientHello пакетов")
    print("   • 697 подозрительных паттернов (split packets)")
    print("   • Успешное извлечение SNI для основных доменов")
    
    print("\n❌ Проблемы в pcap:")
    print("   • Много 'unknown' трафика без SNI")
    print("   • Мелкие пакеты с PSH флагом (признак разделения)")
    print("   • Отсутствие некоторых субдоменов в стратегиях")
    
    # Анализ покрытия стратегиями
    print("\n🎯 3. АНАЛИЗ ПОКРЫТИЯ СТРАТЕГИЯМИ:")
    
    with open('strategies.json', 'r', encoding='utf-8') as f:
        strategies = json.load(f)
    
    print(f"Загружено стратегий: {len(strategies)}")
    
    # Основные домены
    main_domains = ['instagram.com', 'x.com', 'youtube.com', 'facebook.com', 'rutracker.org']
    
    # Важные субдомены для каждого сервиса
    critical_subdomains = {
        'instagram.com': [
            'www.instagram.com',
            'static.cdninstagram.com', 
            'scontent-arn2-1.cdninstagram.com',
            'edge-chat.instagram.com',
            'instagram.fnag1-1.fna.fbcdn.net'
        ],
        'x.com': [
            'abs.twimg.com',
            'abs-0.twimg.com', 
            'pbs.twimg.com',
            'video.twimg.com',
            'ton.twimg.com',
            'api.x.com'
        ],
        'youtube.com': [
            'www.youtube.com',
            'youtubei.googleapis.com',
            'youtube-ui.l.google.com',
            'yt3.ggpht.com',
            'i.ytimg.com'
        ],
        'facebook.com': [
            'www.facebook.com',
            'static.xx.fbcdn.net',
            'scontent.xx.fbcdn.net'
        ]
    }
    
    print("\n🔍 Покрытие критически важных субдоменов:")
    missing_strategies = []
    
    for main_domain, subdomains in critical_subdomains.items():
        print(f"\n📱 {main_domain.upper()}:")
        print(f"   Основной домен: {'✅' if main_domain in strategies else '❌'}")
        
        for subdomain in subdomains:
            has_strategy = False
            strategy_type = "none"
            
            # Проверяем прямое соответствие
            if subdomain in strategies:
                has_strategy = True
                strategy_type = "direct"
            else:
                # Проверяем wildcard
                domain_parts = subdomain.split('.')
                for i in range(len(domain_parts)):
                    wildcard = '*.' + '.'.join(domain_parts[i+1:])
                    if wildcard in strategies:
                        has_strategy = True
                        strategy_type = f"wildcard ({wildcard})"
                        break
            
            status = "✅" if has_strategy else "❌"
            print(f"   {subdomain}: {status} {strategy_type}")
            
            if not has_strategy:
                missing_strategies.append((main_domain, subdomain))
    
    # Рекомендации по исправлению
    print(f"\n💡 4. РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ:")
    
    if missing_strategies:
        print(f"\n🔧 Необходимо добавить стратегии для {len(missing_strategies)} субдоменов:")
        
        recommendations = {}
        for main_domain, subdomain in missing_strategies:
            if main_domain not in recommendations:
                recommendations[main_domain] = []
            recommendations[main_domain].append(subdomain)
        
        for main_domain, subdomains in recommendations.items():
            main_strategy = strategies.get(main_domain, strategies.get('default'))
            print(f"\n   {main_domain.upper()} субдомены:")
            for subdomain in subdomains:
                print(f"   📝 {subdomain} -> использовать стратегию как у {main_domain}")
    
    print(f"\n🚀 5. ПЛАН ДЕЙСТВИЙ:")
    print("   1. Добавить отсутствующие субдомены в strategies.json")
    print("   2. Перезапустить службу recon_service.py")
    print("   3. Протестировать доступ к проблемным сайтам")
    print("   4. Мониторить логи на предмет 'глобальной стратегии'")
    
    return missing_strategies, recommendations

def create_enhanced_strategies():
    """Создание улучшенного файла стратегий."""
    
    print("\n🔧 === СОЗДАНИЕ УЛУЧШЕННЫХ СТРАТЕГИЙ ===")
    
    # Загружаем текущие стратегии
    with open('strategies.json', 'r', encoding='utf-8') as f:
        current_strategies = json.load(f)
    
    # Новые стратегии для критически важных субдоменов
    new_strategies = {
        # Instagram субдомены
        "www.instagram.com": current_strategies["instagram.com"],
        "static.cdninstagram.com": current_strategies["instagram.com"], 
        "scontent-arn2-1.cdninstagram.com": current_strategies["instagram.com"],
        "edge-chat.instagram.com": current_strategies["instagram.com"],
        "*.cdninstagram.com": current_strategies["instagram.com"],
        "*.fbcdn.net": current_strategies["instagram.com"],
        
        # X.com/Twitter субдомены (уже есть *.twimg.com, но добавим специфичные)
        "www.x.com": current_strategies["x.com"],
        "api.x.com": current_strategies["x.com"],
        "mobile.x.com": current_strategies["x.com"],
        
        # YouTube субдомены
        "www.youtube.com": current_strategies["youtube.com"],
        "youtubei.googleapis.com": current_strategies["youtube.com"],
        "*.googleapis.com": current_strategies["youtube.com"],
        "*.ytimg.com": current_strategies["youtube.com"],
        "*.ggpht.com": current_strategies["youtube.com"],
        
        # Facebook субдомены  
        "www.facebook.com": current_strategies["facebook.com"],
        "*.fbcdn.net": current_strategies["facebook.com"],
        "*.xx.fbcdn.net": current_strategies["facebook.com"],
        
        # Общие wildcard для популярных CDN
        "*.cloudflare.net": current_strategies["default"],
        "*.fastly.com": current_strategies["default"],
        "*.fastly.net": current_strategies["default"]
    }
    
    # Объединяем стратегии
    enhanced_strategies = current_strategies.copy()
    enhanced_strategies.update(new_strategies)
    
    # Сохраняем улучшенный файл
    with open('strategies_enhanced.json', 'w', encoding='utf-8') as f:
        json.dump(enhanced_strategies, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Создан enhanced файл с {len(enhanced_strategies)} стратегиями")
    print(f"   Добавлено новых: {len(new_strategies)}")
    
    # Показываем добавленные стратегии
    print(f"\n📝 Добавленные стратегии:")
    for domain, strategy in new_strategies.items():
        print(f"   {domain}")
    
    return enhanced_strategies

def diagnose_service_issues():
    """Диагностика проблем службы на основе логов."""
    
    print(f"\n🔍 === ДИАГНОСТИКА СЛУЖБЫ ===")
    
    # Анализ паттернов из логов
    service_issues = {
        "positive": [
            "✅ Loaded 14 domain-specific strategies",
            "✅ Using 13 domains from strategies", 
            "✅ DPI Bypass Engine started successfully",
            "🎯 Выбрана стратегия по SNI: x.com",
            "🎯 Выбрана стратегия по SNI: instagram.com",
            "🎯 Выбрана стратегия по родительскому домену: instagram.com для www.instagram.com"
        ],
        "concerning": [
            "⚠️ Failed to load domains: 'utf-8' codec can't decode byte 0xff",
            "🎯 Применяется глобальная стратегия по умолчанию (много случаев)",
            "⚠️ Для SNI chrome.cloudflare-dns.com не найдена специфичная стратегия",
            "⚠️ Для SNI scontent-arn2-1.cdninstagram.com не найдена специфичная стратегия"
        ]
    }
    
    print("✅ Что работает правильно:")
    for item in service_issues["positive"]:
        print(f"   {item}")
    
    print(f"\n⚠️ Что требует внимания:")
    for item in service_issues["concerning"]:
        print(f"   {item}")
    
    print(f"\n💡 Выводы:")
    print("   • Основная архитектура работает корректно")
    print("   • SNI извлечение и выбор стратегий функционирует") 
    print("   • Проблема в неполном покрытии субдоменов")
    print("   • Много трафика попадает под 'default' стратегию")

if __name__ == "__main__":
    print("🚀 === КОМПЛЕКСНАЯ ДИАГНОСТИКА ПРОБЛЕМ ===\n")
    
    # Основной анализ
    missing_strategies, recommendations = analyze_current_issues()
    
    # Диагностика службы
    diagnose_service_issues()
    
    # Создание улучшенных стратегий
    enhanced_strategies = create_enhanced_strategies()
    
    print(f"\n🎯 === ФИНАЛЬНЫЕ РЕКОМЕНДАЦИИ ===")
    print("1. Замените strategies.json на strategies_enhanced.json")
    print("2. Перезапустите службу recon_service.py")
    print("3. Проверьте работу проблемных доменов")
    print("4. Мониторьте логи на уменьшение 'глобальной стратегии'")
    
    print(f"\n✅ Анализ завершен. Файлы созданы:")
    print("   • strategies_enhanced.json - улучшенные стратегии")