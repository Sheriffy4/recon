#!/usr/bin/env python3
"""
Миграция domain_rules.json - добавление поля attacks ко всем стратегиям
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List

def extract_attacks_from_rule(rule_type: str, params: Dict) -> List[str]:
    """
    Извлекает список атак из существующего правила.
    
    Args:
        rule_type: Тип стратегии (disorder, fake, multisplit, etc.)
        params: Параметры стратегии
        
    Returns:
        Список атак
    """
    attacks = []
    
    # Определяем по типу
    rule_type_lower = rule_type.lower()
    
    if "fake" in rule_type_lower:
        attacks.append("fake")
    
    if "disorder" in rule_type_lower:
        attacks.append("disorder")
    
    if "multisplit" in rule_type_lower:
        attacks.append("multisplit")
    elif "split" in rule_type_lower:
        attacks.append("split")
    
    # Определяем по параметрам
    if params.get("disorder_method") and "disorder" not in attacks:
        attacks.append("disorder")
    
    if params.get("split_count"):
        split_count = params.get("split_count", 0)
        if split_count > 2 and "multisplit" not in attacks:
            attacks.append("multisplit")
        elif split_count > 0 and "split" not in attacks and "multisplit" not in attacks:
            attacks.append("split")
    
    if (params.get("fake_tls") or params.get("fake_http") or params.get("fooling")) and "fake" not in attacks:
        attacks.append("fake")
    
    if params.get("split_seqovl") and "seqovl" not in attacks:
        attacks.append("seqovl")
    
    if params.get("oob_data") or params.get("oob"):
        attacks.append("oob")
    
    # Если ничего не определили, используем тип как единственную атаку
    if not attacks:
        clean_type = rule_type_lower.replace("_", "").replace("attack", "").strip()
        if clean_type:
            attacks.append(clean_type)
    
    return attacks

def create_metadata_for_existing_rule(domain: str, rule_type: str, attacks: List[str]) -> Dict:
    """
    Создает метаданные для существующего правила.
    
    Args:
        domain: Домен
        rule_type: Тип стратегии
        attacks: Список атак
        
    Returns:
        Словарь с метаданными
    """
    return {
        "discovered_at": "unknown",  # Неизвестно когда была создана
        "last_tested": "unknown",
        "source": "manual_configuration",  # Предполагаем ручную настройку
        "strategy_name": f"{rule_type}_strategy",
        "strategy_id": f"{domain}_{rule_type}_migrated",
        "success_rate": 1.0,  # Предполагаем, что работает
        "avg_latency_ms": 0.0,
        "test_count": 0,
        "attack_type": rule_type,
        "attacks": attacks,
        "attack_count": len(attacks),
        "validation_status": "migrated",
        "validated_at": datetime.now().isoformat(),
        "rationale": f"Migrated from legacy format. Strategy uses {len(attacks)} attack(s): {', '.join(attacks)}.",
        "domain": domain,
        "calibration_method": "manual",
        "confidence_score": 0.8,
        "migration_note": "Automatically migrated to new format with attacks field"
    }

def migrate_domain_rules(input_file: str = "domain_rules.json", 
                         backup: bool = True) -> bool:
    """
    Мигрирует domain_rules.json, добавляя поле attacks.
    
    Args:
        input_file: Путь к файлу domain_rules.json
        backup: Создавать ли резервную копию
        
    Returns:
        True если миграция успешна
    """
    input_path = Path(input_file)
    
    if not input_path.exists():
        print(f"❌ Файл {input_file} не найден")
        return False
    
    # Создаем резервную копию
    if backup:
        backup_file = input_path.with_suffix('.json.backup')
        print(f"📦 Создание резервной копии: {backup_file}")
        
        with open(input_path, 'r', encoding='utf-8') as f:
            backup_data = f.read()
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write(backup_data)
        
        print(f"✅ Резервная копия создана")
    
    # Загружаем данные
    print(f"\n📖 Загрузка {input_file}...")
    
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if "domain_rules" not in data:
        print("❌ Неверный формат файла: отсутствует ключ 'domain_rules'")
        return False
    
    domain_rules = data["domain_rules"]
    
    print(f"Найдено {len(domain_rules)} правил для миграции")
    print()
    
    # Мигрируем каждое правило
    migrated_count = 0
    skipped_count = 0
    
    for domain, rule in domain_rules.items():
        # Проверяем, есть ли уже поле attacks
        if "attacks" in rule:
            print(f"⏭️  {domain}: уже имеет поле 'attacks', пропускаем")
            skipped_count += 1
            continue
        
        # Извлекаем тип и параметры
        rule_type = rule.get("type", "unknown")
        params = rule.get("params", {})
        
        # Извлекаем атаки
        attacks = extract_attacks_from_rule(rule_type, params)
        
        # Добавляем поле attacks
        rule["attacks"] = attacks
        
        # Добавляем или обновляем метаданные
        if "metadata" not in rule:
            rule["metadata"] = create_metadata_for_existing_rule(domain, rule_type, attacks)
        else:
            # Обновляем существующие метаданные
            rule["metadata"]["attacks"] = attacks
            rule["metadata"]["attack_count"] = len(attacks)
            if "migration_note" not in rule["metadata"]:
                rule["metadata"]["migration_note"] = "Added attacks field during migration"
        
        print(f"✅ {domain}: добавлено поле 'attacks' = {attacks}")
        migrated_count += 1
    
    # Обновляем default_strategy если есть
    if "default_strategy" in data and data["default_strategy"]:
        default_rule = data["default_strategy"]
        
        if "attacks" not in default_rule:
            rule_type = default_rule.get("type", "unknown")
            params = default_rule.get("params", {})
            attacks = extract_attacks_from_rule(rule_type, params)
            
            default_rule["attacks"] = attacks
            
            if "metadata" not in default_rule:
                default_rule["metadata"] = create_metadata_for_existing_rule(
                    "default", rule_type, attacks
                )
            else:
                default_rule["metadata"]["attacks"] = attacks
                default_rule["metadata"]["attack_count"] = len(attacks)
            
            print(f"✅ default_strategy: добавлено поле 'attacks' = {attacks}")
            migrated_count += 1
    
    # Обновляем timestamp
    data["last_updated"] = datetime.now().isoformat()
    
    # Сохраняем
    print(f"\n💾 Сохранение обновленного файла...")
    
    with open(input_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Файл сохранен")
    print()
    print("=" * 70)
    print("📊 РЕЗУЛЬТАТЫ МИГРАЦИИ")
    print("=" * 70)
    print(f"Мигрировано правил: {migrated_count}")
    print(f"Пропущено (уже имеют attacks): {skipped_count}")
    print(f"Всего правил: {len(domain_rules)}")
    print()
    
    return True

def main():
    """Главная функция"""
    
    print()
    print("=" * 70)
    print("🔄 Миграция domain_rules.json - добавление поля attacks")
    print("=" * 70)
    print()
    
    success = migrate_domain_rules(
        input_file="domain_rules.json",
        backup=True
    )
    
    if success:
        print("✅ Миграция завершена успешно!")
        print()
        print("Теперь все стратегии имеют поле 'attacks' с информацией о комбинациях атак.")
        print("Резервная копия сохранена в domain_rules.json.backup")
        return 0
    else:
        print("❌ Миграция не удалась")
        return 1

if __name__ == "__main__":
    sys.exit(main())
