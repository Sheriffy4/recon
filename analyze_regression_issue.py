#!/usr/bin/env python3
"""
Анализ регрессии после исправления Instagram стратегии.
Выясняем, почему Instagram перестал работать совсем.
"""

import re
import json
from datetime import datetime
from collections import defaultdict, Counter

def analyze_regression():
    """Анализирует регрессию после изменения стратегии."""
    
    print("🚨 АНАЛИЗ РЕГРЕССИИ ПОСЛЕ ИСПРАВЛЕНИЯ")
    print("=" * 50)
    
    # Читаем лог
    try:
        with open('log.txt', 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read()
    except FileNotFoundError:
        print("❌ Файл log.txt не найден!")
        return
    
    lines = log_content.split('\n')
    
    # Анализ активности Instagram
    instagram_activity = {
        'ip_addresses': [],
        'bypass_applications': 0,
        'packet_sends': 0,
        'strategy_used': None,
        'errors': [],
        'warnings': []
    }
    
    # Поиск IP адресов Instagram
    for line in lines:
        if 'instagram.com' in line and 'Resolved' in line:
            match = re.search(r'-> ([0-9.]+)', line)
            if match:
                ip = match.group(1)
                instagram_activity['ip_addresses'].append(ip)
        
        # Проверка стратегии для Instagram IP
        if 'Mapped IP' in line and any(ip in line for ip in instagram_activity['ip_addresses']):
            match = re.search(r'-> (\w+)', line)
            if match:
                instagram_activity['strategy_used'] = match.group(1)
        
        # Применение bypass для Instagram
        if 'Applying bypass for' in line:
            for ip in instagram_activity['ip_addresses']:
                if ip in line:
                    instagram_activity['bypass_applications'] += 1
                    # Извлекаем тип стратегии
                    match = re.search(r'Type: (\w+)', line)
                    if match:
                        instagram_activity['strategy_used'] = match.group(1)
        
        # Отправка пакетов для Instagram
        if ('📤 FAKE' in line or '📤 REAL' in line):
            for ip in instagram_activity['ip_addresses']:
                if ip in line:
                    instagram_activity['packet_sends'] += 1
    
    print(f"📊 АКТИВНОСТЬ INSTAGRAM:")
    print(f"   IP адреса: {instagram_activity['ip_addresses']}")
    print(f"   Стратегия: {instagram_activity['strategy_used']}")
    print(f"   Применений bypass: {instagram_activity['bypass_applications']}")
    print(f"   Отправлено пакетов: {instagram_activity['packet_sends']}")
    
    # Анализ предупреждений
    warnings_analysis = defaultdict(int)
    for line in lines:
        if '[WARNING]' in line:
            if 'Negative offset' in line:
                warnings_analysis['negative_offset'] += 1
            elif 'WinDivert send()' in line:
                warnings_analysis['windivert_flags'] += 1
            elif 'checksum' in line:
                warnings_analysis['checksum_issues'] += 1
    
    print(f"\n⚠️ АНАЛИЗ ПРЕДУПРЕЖДЕНИЙ:")
    for warning_type, count in warnings_analysis.items():
        print(f"   {warning_type}: {count} раз")
    
    # Сравнение с предыдущим состоянием
    print(f"\n🔍 ДИАГНОЗ ПРОБЛЕМЫ:")
    
    problems = []
    
    if instagram_activity['strategy_used'] == 'fakeddisorder':
        if instagram_activity['bypass_applications'] > 0:
            if instagram_activity['packet_sends'] > 0:
                problems.append("✅ Instagram получает bypass с новой стратегией fakeddisorder")
                problems.append("⚠️ Но сайт все равно не загружается - возможно проблема в параметрах")
            else:
                problems.append("❌ Bypass применяется, но пакеты не отправляются")
        else:
            problems.append("❌ Bypass вообще не применяется к Instagram")
    
    if warnings_analysis['negative_offset'] > 0:
        problems.append(f"⚠️ {warnings_analysis['negative_offset']} предупреждений 'Negative offset' - проблема с расчетом пакетов")
    
    if warnings_analysis['windivert_flags'] > 0:
        problems.append(f"⚠️ {warnings_analysis['windivert_flags']} предупреждений WinDivert - проблемы с отправкой")
    
    for problem in problems:
        print(f"   {problem}")
    
    return instagram_activity, warnings_analysis

def check_strategy_effectiveness():
    """Проверяет эффективность текущей стратегии."""
    
    print(f"\n🧪 ПРОВЕРКА ЭФФЕКТИВНОСТИ СТРАТЕГИИ:")
    
    # Читаем текущую стратегию
    try:
        with open('strategies.json', 'r', encoding='utf-8') as f:
            strategies = json.load(f)
        
        instagram_strategy = strategies.get('instagram.com', '')
        print(f"📋 Текущая стратегия Instagram: {instagram_strategy}")
        
        # Анализ параметров
        if 'fakeddisorder' in instagram_strategy:
            print("✅ Использует fakeddisorder")
            
            if '--dpi-desync-ttl=4' in instagram_strategy:
                print("⚠️ TTL=4 может быть слишком низким")
            
            if '--dpi-desync-split-pos=3' in instagram_strategy:
                print("⚠️ Split position=3 может быть неоптимальным")
            
            if '--dpi-desync-fooling=badsum' in instagram_strategy:
                print("✅ Использует badsum fooling")
        
    except Exception as e:
        print(f"❌ Ошибка чтения стратегий: {e}")

def suggest_alternative_strategies():
    """Предлагает альтернативные стратегии."""
    
    print(f"\n💡 АЛЬТЕРНАТИВНЫЕ СТРАТЕГИИ ДЛЯ INSTAGRAM:")
    
    alternatives = {
        'strategy_1_original': "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4",
        'strategy_2_simple_fake': "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=8",
        'strategy_3_disorder': "--dpi-desync=disorder --dpi-desync-split-pos=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2",
        'strategy_4_fakeddisorder_improved': "--dpi-desync=fakeddisorder --dpi-desync-split-pos=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=3 --dpi-desync-ttl=8",
        'strategy_5_multidisorder': "--dpi-desync=multidisorder --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2"
    }
    
    print("1. Вернуться к оригинальной (multisplit)")
    print("2. Простая fake стратегия")  
    print("3. Disorder стратегия")
    print("4. Улучшенная fakeddisorder")
    print("5. Multidisorder (как у X.com)")
    
    return alternatives

def create_rollback_script():
    """Создает скрипт для отката изменений."""
    
    print(f"\n🔄 СОЗДАНИЕ СКРИПТА ОТКАТА:")
    
    rollback_script = '''#!/usr/bin/env python3
"""
Откат изменений Instagram стратегии.
Возвращает к оригинальной multisplit стратегии.
"""

import json
import shutil
from datetime import datetime

def rollback_instagram_strategy():
    """Откатывает стратегию Instagram к оригинальной."""
    
    print("🔄 ОТКАТ СТРАТЕГИИ INSTAGRAM")
    print("=" * 30)
    
    # Создаем резервную копию текущего состояния
    backup_file = f"strategies_after_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    shutil.copy('strategies.json', backup_file)
    print(f"✅ Создана резервная копия: {backup_file}")
    
    # Читаем стратегии
    with open('strategies.json', 'r', encoding='utf-8') as f:
        strategies = json.load(f)
    
    # Возвращаем оригинальную стратегию
    original_strategy = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4"
    
    print(f"📋 Возвращаем оригинальную стратегию:")
    print(f"   {original_strategy}")
    
    # Применяем изменения
    strategies['instagram.com'] = original_strategy
    
    # Также откатываем связанные домены
    instagram_domains = [
        'static.cdninstagram.com',
        'scontent-arn2-1.cdninstagram.com', 
        'edge-chat.instagram.com'
    ]
    
    for domain in instagram_domains:
        if domain in strategies:
            strategies[domain] = original_strategy
            print(f"✅ Откачен {domain}")
    
    # Сохраняем
    with open('strategies.json', 'w', encoding='utf-8') as f:
        json.dump(strategies, f, indent=2, ensure_ascii=False)
    
    print(f"\\n✅ Откат завершен!")
    print(f"🔄 Перезапустите службу для применения изменений")

if __name__ == "__main__":
    rollback_instagram_strategy()
'''
    
    with open('rollback_instagram_fix.py', 'w', encoding='utf-8') as f:
        f.write(rollback_script)
    
    print("✅ Создан скрипт отката: rollback_instagram_fix.py")

def create_test_strategies():
    """Создает набор тестовых стратегий."""
    
    alternatives = suggest_alternative_strategies()
    
    test_script = f'''#!/usr/bin/env python3
"""
Тестирование различных стратегий для Instagram.
"""

import json
import shutil
from datetime import datetime

strategies_to_test = {json.dumps(alternatives, indent=4, ensure_ascii=False)}

def apply_strategy(strategy_name):
    """Применяет выбранную стратегию."""
    
    if strategy_name not in strategies_to_test:
        print(f"❌ Стратегия {{strategy_name}} не найдена!")
        return False
    
    # Резервная копия
    backup_file = f"strategies_before_{{strategy_name}}_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.json"
    shutil.copy('strategies.json', backup_file)
    
    # Читаем и изменяем
    with open('strategies.json', 'r', encoding='utf-8') as f:
        strategies = json.load(f)
    
    new_strategy = strategies_to_test[strategy_name]
    strategies['instagram.com'] = new_strategy
    
    # Связанные домены
    instagram_domains = [
        'static.cdninstagram.com',
        'scontent-arn2-1.cdninstagram.com', 
        'edge-chat.instagram.com'
    ]
    
    for domain in instagram_domains:
        if domain in strategies:
            strategies[domain] = new_strategy
    
    # Сохраняем
    with open('strategies.json', 'w', encoding='utf-8') as f:
        json.dump(strategies, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Применена стратегия: {{strategy_name}}")
    print(f"📋 {{new_strategy}}")
    print(f"🔄 Перезапустите службу и проверьте Instagram")
    
    return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Использование: python test_instagram_strategies.py <strategy_name>")
        print("Доступные стратегии:")
        for name in strategies_to_test.keys():
            print(f"  - {{name}}")
        sys.exit(1)
    
    strategy_name = sys.argv[1]
    apply_strategy(strategy_name)
'''
    
    with open('test_instagram_strategies.py', 'w', encoding='utf-8') as f:
        f.write(test_script)
    
    print("✅ Создан скрипт тестирования: test_instagram_strategies.py")

if __name__ == "__main__":
    # Анализ регрессии
    instagram_activity, warnings = analyze_regression()
    
    # Проверка стратегии
    check_strategy_effectiveness()
    
    # Предложения
    alternatives = suggest_alternative_strategies()
    
    # Создание скриптов
    create_rollback_script()
    create_test_strategies()
    
    print(f"\n" + "=" * 50)
    print(f"🎯 ИТОГОВЫЙ ДИАГНОЗ РЕГРЕССИИ:")
    
    if instagram_activity['bypass_applications'] > 0:
        print(f"✅ Instagram получает bypass ({instagram_activity['bypass_applications']} применений)")
        print(f"✅ Отправлено {instagram_activity['packet_sends']} пакетов")
        print(f"❌ НО сайт не загружается - проблема в параметрах стратегии")
        
        print(f"\n🚀 РЕКОМЕНДУЕМЫЕ ДЕЙСТВИЯ:")
        print(f"1. Попробовать улучшенную fakeddisorder:")
        print(f"   python test_instagram_strategies.py strategy_4_fakeddisorder_improved")
        print(f"2. Или вернуться к оригинальной:")
        print(f"   python rollback_instagram_fix.py")
        print(f"3. Или попробовать multidisorder (как у X.com):")
        print(f"   python test_instagram_strategies.py strategy_5_multidisorder")
    else:
        print(f"❌ Instagram НЕ получает bypass!")
        print(f"🔧 Проблема в конфигурации или службе")
    
    if warnings['negative_offset'] > 0:
        print(f"\n⚠️ ВНИМАНИЕ: {warnings['negative_offset']} предупреждений 'Negative offset'")
        print(f"   Это указывает на проблемы с расчетом пакетов в текущей стратегии")