#!/usr/bin/env python3
"""
Диагностика проблем с zapret совместимостью
Анализирует логи и PCAP для выявления проблем.
"""
import sys
import os
import json
from pathlib import Path

# Add recon directory to path
recon_dir = os.path.dirname(os.path.abspath(__file__))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

def analyze_pcap_data(pcap_data):
    """Анализирует данные PCAP."""
    print("🔍 Анализ PCAP данных:")
    issues = []
    
    # Проверяем SNI
    sni = pcap_data.get("sni", "")
    if sni in ["api.x.com", "twitter.com", "x.com"]:
        issues.append(f"❌ Реальный SNI: {sni}")
    else:
        print(f"  ✅ Поддельный SNI: {sni}")
    
    # Проверяем metrics
    metrics = pcap_data.get("metrics", {})
    
    # Checksum
    if not metrics.get("csum_fake_bad", False):
        issues.append("❌ Checksum не испорчен (csum_fake_bad: false)")
    else:
        print("  ✅ Checksum испорчен")
    
    # PSH флаг
    if not metrics.get("flags_real_psh", False):
        issues.append("❌ Нет PSH флага в реальных пакетах")
    else:
        print("  ✅ PSH флаг присутствует")
    
    # Timing
    timing = metrics.get("pair_dt_ms", 0)
    if timing > 0.5:
        issues.append(f"❌ Медленный timing: {timing}ms (должно быть <0.1ms)")
    else:
        print(f"  ✅ Быстрый timing: {timing}ms")
    
    # Размер fake пакета
    fake_len = metrics.get("fake", {}).get("len", 0)
    if fake_len < 200:
        issues.append(f"❌ Маленький fake пакет: {fake_len} байт (должно быть >500)")
    else:
        print(f"  ✅ Полный fake пакет: {fake_len} байт")
    
    # TTL
    fake_ttl = metrics.get("fake", {}).get("ttl", 0)
    real_ttl = metrics.get("real", {}).get("ttl", 0)
    if fake_ttl != 3 or real_ttl != 3:
        issues.append(f"❌ Неправильный TTL: fake={fake_ttl}, real={real_ttl} (должно быть 3)")
    else:
        print(f"  ✅ Правильный TTL: {fake_ttl}")
    
    return issues

def check_strategy_parsing():
    """Проверяет парсинг стратегии."""
    print("\n🔧 Проверка парсинга стратегии:")
    try:
        from core.strategy_interpreter import interpret_strategy
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
        result = interpret_strategy(strategy)
        params = result.get('params', {})
        
        print(f"  Тип: {result.get('type')}")
        print(f"  TTL: {params.get('ttl')}")
        print(f"  split_pos: {params.get('split_pos')}")
        print(f"  fooling: {params.get('fooling')}")
        
        # Проверяем условия zapret совместимости
        split_pos = params.get('split_pos')
        fooling = params.get('fooling', [])
        zapret_compatible = (split_pos == 3 and "badsum" in fooling)
        
        if zapret_compatible:
            print("  ✅ Zapret-совместимые условия выполнены")
        else:
            print("  ❌ Zapret-совместимые условия НЕ выполнены")
            
        return zapret_compatible
    except Exception as e:
        print(f"  ❌ Ошибка парсинга: {e}")
        return False

def generate_recommendations(issues):
    """Генерирует рекомендации по исправлению."""
    print(f"\n🛠️  Найдено проблем: {len(issues)}")
    
    if not issues:
        print("🎉 Все проверки пройдены!")
        return
    
    print("\n📋 Рекомендации по исправлению:")
    for i, issue in enumerate(issues, 1):
        print(f"{i}. {issue}")
    
    print("\n🔧 Возможные причины:")
    if any("Checksum не испорчен" in issue for issue in issues):
        print("• Checksum: Код не попадает в zapret-style ветку или pipeline пересчитывает checksum")
    if any("Нет PSH флага" in issue for issue in issues):
        print("• PSH флаг: Используется неправильный метод отправки реальных пакетов")
    if any("Медленный timing" in issue for issue in issues):
        print("• Timing: Задержки не уменьшены или используется медленный путь")
    if any("Маленький fake пакет" in issue for issue in issues):
        print("• Размер пакета: Не используется _send_full_fake_zapret_style")

def main():
    """Основная функция диагностики."""
    print("🩺 Диагностика проблем zapret совместимости")
    print("=" * 50)
    
    # Проверяем парсинг стратегии
    strategy_ok = check_strategy_parsing()
    
    # Анализируем PCAP данные из сообщения пользователя
    pcap_data = {
        "flow": "192.168.18.188:51613 -> 172.66.0.227:443",
        "dst": "172.66.0.227",
        "sni": "microsoft.com",
        "metrics": {
            "fake_first": True,
            "ttl_order_ok": False,
            "csum_fake_bad": False,
            "flags_real_psh": False,
            "flags_fake_no_psh": False,
            "seq_order_ok": True,
            "fake": {"ttl": 3, "flags": 24, "csum_ok": True, "seq": 1703074754, "len": 74},
            "real": {"ttl": 3, "flags": 16, "csum_ok": True, "seq": 1703074754, "len": 76},
            "pair_dt_ms": 1.9359588623046875,
            "sni": "microsoft.com"
        }
    }
    
    issues = analyze_pcap_data(pcap_data)
    
    # Генерируем рекомендации
    generate_recommendations(issues)
    
    # Итоговая оценка
    print("\n" + "=" * 50)
    if not issues and strategy_ok:
        print("✅ Система готова к работе!")
    else:
        print("❌ Требуются дополнительные исправления")
        print("\n💡 Следующие шаги:")
        print("1. Проверьте логи на наличие сообщений:")
        print("   - 'Zapret-compatible strategy detected'")
        print("   - 'ZAPRET-STYLE ACTIVATED'")
        print("   - 'Sending FULL fake with corrupted checksum'")
        print("2. Если логов нет - код не попадает в zapret-style ветку")
        print("3. Если логи есть, но checksum не портится - проблема в pipeline")

if __name__ == "__main__":
    main()