#!/usr/bin/env python3
"""
Извлечение рабочей стратегии из log2.txt

Цель: Найти точные параметры рабочей стратегии из CLI auto лога
"""

import re
import json
from pathlib import Path

def extract_strategy_from_log():
    """Извлечь стратегию из log2.txt."""
    
    log_file = Path("log2.txt")
    if not log_file.exists():
        print("❌ log2.txt не найден!")
        return None
    
    print("📄 Анализ log2.txt...")
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"❌ Ошибка чтения файла: {e}")
        return None
    
    # Ищем SUCCESS результат
    success_patterns = [
        r'\[OK\]\s*SUCCESS',
        r'SUCCESS.*Strategy',
        r'Strategy.*SUCCESS',
        r'Found working.*strategy',
        r'ADAPTIVE ANALYSIS RESULTS.*SUCCESS'
    ]
    
    success_found = False
    for pattern in success_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            success_found = True
            print(f"✅ Найден SUCCESS по паттерну: {pattern}")
            break
    
    if not success_found:
        print("❌ SUCCESS не найден в логе")
        return None
    
    # Ищем информацию о стратегии
    strategy_info = {}
    
    # Паттерны для поиска стратегии
    strategy_patterns = [
        r'Strategy:\s*([^\n\r]+)',
        r'Attack Combination:\s*([^\n\r]+)',
        r'smart_combo_([a-zA-Z_]+)',
        r'disorder.*multisplit',
        r'fake.*split'
    ]
    
    for pattern in strategy_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            print(f"🔍 Найдено по паттерну '{pattern}': {matches}")
            strategy_info[pattern] = matches
    
    # Ищем параметры
    param_patterns = [
        r'split_pos["\']?\s*:\s*(\d+)',
        r'split_count["\']?\s*:\s*(\d+)',
        r'ttl["\']?\s*:\s*(\d+)',
        r'disorder_method["\']?\s*:\s*["\']?([^"\'}\s,]+)',
        r'fooling["\']?\s*:\s*\[?["\']?([^"\'}\]]+)',
        r'positions["\']?\s*:\s*\[([^\]]+)\]'
    ]
    
    params = {}
    for pattern in param_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            param_name = pattern.split('[')[0]
            print(f"🔧 Параметр {param_name}: {matches}")
            params[param_name] = matches[-1]  # Берем последнее значение
    
    # Формируем стратегию
    if strategy_info or params:
        print("\n📋 ИЗВЛЕЧЕННАЯ ИНФОРМАЦИЯ:")
        print(f"   Стратегии: {strategy_info}")
        print(f"   Параметры: {params}")
        
        # Пытаемся определить тип стратегии
        strategy_type = "unknown"
        attacks = []
        
        # Анализируем найденные стратегии
        for pattern, matches in strategy_info.items():
            for match in matches:
                if "smart_combo" in match.lower():
                    strategy_type = match
                elif "disorder" in match.lower() and "multisplit" in match.lower():
                    attacks = ["disorder", "multisplit"]
                elif "fake" in match.lower() and "split" in match.lower():
                    attacks = ["fake", "split"]
        
        # Формируем финальную стратегию
        working_strategy = {
            "type": strategy_type,
            "attacks": attacks,
            "params": {},
            "metadata": {
                "source": "extracted_from_log2",
                "extracted_info": strategy_info,
                "extracted_params": params
            }
        }
        
        # Добавляем параметры
        if "split_pos" in params:
            working_strategy["params"]["split_pos"] = int(params["split_pos"])
        if "split_count" in params:
            working_strategy["params"]["split_count"] = int(params["split_count"])
        if "ttl" in params:
            working_strategy["params"]["ttl"] = int(params["ttl"])
        if "disorder_method" in params:
            working_strategy["params"]["disorder_method"] = params["disorder_method"]
        if "fooling" in params:
            working_strategy["params"]["fooling"] = [params["fooling"]]
        
        return working_strategy
    
    else:
        print("❌ Не удалось извлечь информацию о стратегии")
        return None

def update_domain_rules(strategy):
    """Обновить domain_rules.json с извлеченной стратегией."""
    
    if not strategy:
        print("❌ Нет стратегии для обновления")
        return False
    
    rules_file = Path("domain_rules.json")
    
    try:
        # Загружаем текущие правила
        if rules_file.exists():
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
        else:
            rules = {"version": "1.0", "domain_rules": {}}
        
        # Обновляем правило для www.googlevideo.com
        if "domain_rules" not in rules:
            rules["domain_rules"] = {}
        
        rules["domain_rules"]["www.googlevideo.com"] = strategy
        
        # Сохраняем
        with open(rules_file, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2, ensure_ascii=False)
        
        print("✅ domain_rules.json обновлен")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка обновления domain_rules.json: {e}")
        return False

def main():
    """Main function."""
    
    print("="*60)
    print("ИЗВЛЕЧЕНИЕ РАБОЧЕЙ СТРАТЕГИИ ИЗ LOG2.TXT")
    print("="*60)
    
    # Извлекаем стратегию
    strategy = extract_strategy_from_log()
    
    if strategy:
        print("\n✅ ИЗВЛЕЧЕННАЯ СТРАТЕГИЯ:")
        print(json.dumps(strategy, indent=2, ensure_ascii=False))
        
        # Обновляем правила
        if update_domain_rules(strategy):
            print("\n🎯 Стратегия сохранена в domain_rules.json")
            print("💡 Теперь можно тестировать службу с этой стратегией")
        else:
            print("\n❌ Не удалось сохранить стратегию")
    else:
        print("\n❌ Не удалось извлечь стратегию из лога")
        print("💡 Проверьте содержимое log2.txt вручную")

if __name__ == "__main__":
    main()