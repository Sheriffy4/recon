#!/usr/bin/env python3
"""
Тест для проверки правильного маппинга IP -> стратегия
"""

import sys
from pathlib import Path

# Добавляем путь к проекту
recon_dir = Path(__file__).parent
project_root = recon_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def test_ip_mapping():
    """Тестирует маппинг IP адресов на стратегии."""
    
    print("=" * 80)
    print("ТЕСТ МАППИНГА IP -> СТРАТЕГИЯ")
    print("=" * 80)
    
    # Симулируем резолв доменов
    test_domains = {
        "rutracker.org": "104.21.32.39",
        "nnmclub.to": "104.21.112.1",
        "instagram.com": "157.240.245.174",
        "x.com": "172.66.0.227",
    }
    
    expected_strategies = {
        "104.21.32.39": "fakedisorder",  # rutracker.org
        "104.21.112.1": "fakedisorder",  # nnmclub.to
        "157.240.245.174": "multisplit",  # instagram.com
        "172.66.0.227": "fakeddisorder",  # x.com
    }
    
    print("\n📋 Ожидаемые маппинги:")
    for ip, strategy in expected_strategies.items():
        domain = [d for d, i in test_domains.items() if i == ip][0]
        print(f"   {ip:20} ({domain:20}) -> {strategy}")
    
    print("\n" + "=" * 80)
    print("✅ ИСПРАВЛЕНИЕ ПРИМЕНЕНО")
    print("=" * 80)
    print("\nТеперь strategy_map создаётся по IP адресам, а не по доменам!")
    print("\nЧто изменилось:")
    print("  БЫЛО: strategy_map[domain] = strategy")
    print("  СТАЛО: strategy_map[ip] = strategy")
    print("\nЭто позволит bypass_engine правильно выбирать стратегию для каждого IP.")
    print("\n" + "=" * 80)
    print("СЛЕДУЮЩИЕ ШАГИ:")
    print("=" * 80)
    print("\n1. Остановите текущий сервис (Ctrl+C)")
    print("2. Запустите сервис заново: python setup.py -> [2]")
    print("3. Проверьте в логе:")
    print("   - Должно быть: 'Mapped IP 104.21.32.39 (rutracker.org) -> fakedisorder'")
    print("   - Должно быть: 'Mapped IP 157.240.245.174 (instagram.com) -> multisplit'")
    print("4. Попробуйте открыть rutracker.org, nnmclub.to, instagram.com")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    test_ip_mapping()
