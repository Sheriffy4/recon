#!/usr/bin/env python3
"""
Анализ свежего out2.pcap для диагностики проблем.
"""

import sys
import os
import json

def analyze_fresh_pcap():
    """Анализирует свежий PCAP и JSON отчет."""
    print("🔍 АНАЛИЗ СВЕЖЕГО OUT2.PCAP")
    print("=" * 40)
    
    # Анализируем JSON отчет
    json_data = {
        "flow": "192.168.18.188:60937 -> 172.66.0.227:443",
        "dst": "172.66.0.227",
        "sni": None,
        "metrics": {
            "fake_first": True,
            "ttl_order_ok": True,
            "csum_fake_bad": False,
            "flags_real_psh": True,
            "flags_fake_no_psh": True,
            "seq_order_ok": True,
            "fake": {
                "ttl": 3,
                "flags": 16,
                "csum_ok": True,
                "seq": 183139756,
                "len": 76
            },
            "real": {
                "ttl": 128,
                "flags": 24,
                "csum_ok": True,
                "seq": 183139832,
                "len": 441
            },
            "pair_dt_ms": 0.18286705017089844,
            "sni": None
        }
    }
    
    print("📊 АНАЛИЗ JSON ОТЧЕТА:")
    fake = json_data["metrics"]["fake"]
    real = json_data["metrics"]["real"]
    
    print(f"🎭 FAKE пакет:")
    print(f"  TTL: {fake['ttl']} {'❌ (должен быть 1)' if fake['ttl'] != 1 else '✅'}")
    print(f"  Flags: {fake['flags']} {'❌ (должны быть 24 PSH|ACK)' if fake['flags'] != 24 else '✅'}")
    print(f"  Checksum: {'OK' if fake['csum_ok'] else 'BAD'} {'❌ (должна быть BAD)' if fake['csum_ok'] else '✅'}")
    print(f"  Длина: {fake['len']} {'❌ (должна быть ~500)' if fake['len'] < 400 else '✅'}")
    
    print(f"\n🎯 REAL пакет:")
    print(f"  TTL: {real['ttl']} {'❌ (должен быть 3)' if real['ttl'] != 3 else '✅'}")
    print(f"  Flags: {real['flags']} {'✅' if real['flags'] == 24 else '❌'}")
    print(f"  Checksum: {'OK' if real['csum_ok'] else 'BAD'} {'✅' if real['csum_ok'] else '❌'}")
    print(f"  Длина: {real['len']}")
    
    print(f"\n🎯 ДИАГНОСТИКА:")
    
    # Проверяем признаки zapret-style
    is_zapret_style = (
        fake['len'] >= 400 and  # Большой fake пакет
        fake['ttl'] == 1 and    # TTL=1 для fake
        not fake['csum_ok'] and # Испорченная checksum
        real['ttl'] == 3        # TTL=3 для real
    )
    
    if is_zapret_style:
        print("✅ ZAPRET-STYLE логика АКТИВНА")
    else:
        print("❌ ZAPRET-STYLE логика НЕ АКТИВНА")
        print("   Используется стандартный fakeddisorder")
    
    # Анализируем конкретные проблемы
    problems = []
    
    if fake['len'] < 400:
        problems.append("Fake пакет слишком маленький (76 vs ~500 байт)")
    
    if fake['ttl'] != 1:
        problems.append(f"Неправильный TTL для fake ({fake['ttl']} vs 1)")
    
    if fake['csum_ok']:
        problems.append("Checksum fake пакета не испорчена")
    
    if fake['flags'] != 24:
        problems.append(f"Неправильные флаги fake ({fake['flags']} vs 24)")
    
    if real['ttl'] != 3:
        problems.append(f"Неправильный TTL для real ({real['ttl']} vs 3)")
    
    if problems:
        print(f"\n🚨 НАЙДЕННЫЕ ПРОБЛЕМЫ:")
        for i, problem in enumerate(problems, 1):
            print(f"  {i}. {problem}")
    
    # Возможные причины
    print(f"\n🔧 ВОЗМОЖНЫЕ ПРИЧИНЫ:")
    print("1. Zapret-style условия не выполняются:")
    print("   - split_pos != 3")
    print("   - 'badsum' не в fooling")
    print("   - zapret_compatible = False")
    
    print("\n2. Используется другая ветка кода:")
    print("   - Стандартный fakeddisorder")
    print("   - Калибратор активен")
    print("   - Принудительная стратегия не работает")
    
    print("\n3. Код не применился:")
    print("   - Файл не сохранился")
    print("   - Кэш модулей")
    print("   - Другая версия движка")
    
    return not problems

def main():
    """Главная функция."""
    success = analyze_fresh_pcap()
    
    print(f"\n🎯 РЕКОМЕНДАЦИИ:")
    print("1. Проверьте активацию zapret-style в логах")
    print("2. Убедитесь что split_pos=3 и fooling=['badsum']")
    print("3. Добавьте отладочные принты в код")
    print("4. Проверьте что используется правильная версия движка")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)