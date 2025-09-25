#!/usr/bin/env python3
"""
Сравнение последовательностей пакетов между recon и zapret
"""
import sys
import os

def analyze_sequence_pattern(pcap_file, name):
    """Анализирует паттерн последовательности пакетов."""
    print(f"\n📊 Анализ паттерна последовательности ({name}):")
    
    if not os.path.exists(pcap_file):
        print(f"❌ Файл не найден: {pcap_file}")
        return None
    
    # Запускаем простой анализатор
    import subprocess
    
    try:
        result = subprocess.run([
            sys.executable, "simple_pcap_compare.py"
        ], capture_output=True, text=True, timeout=30)
        
        output = result.stdout
        
        # Извлекаем информацию о ClientHello пакетах
        client_hello_patterns = []
        lines = output.split('\n')
        
        current_ch = None
        for line in lines:
            if "ClientHello #" in line:
                if current_ch:
                    client_hello_patterns.append(current_ch)
                current_ch = {"info": line.strip(), "nearby": []}
            elif "🔍 Соседние пакеты:" in line:
                continue
            elif current_ch and ("TTL=" in line and "Flags=" in line):
                current_ch["nearby"].append(line.strip())
        
        if current_ch:
            client_hello_patterns.append(current_ch)
        
        return client_hello_patterns
        
    except Exception as e:
        print(f"❌ Ошибка анализа: {e}")
        return None

def extract_pattern_from_recon():
    """Извлекает паттерн из вывода recon анализа."""
    print("\n🔍 Извлечение паттерна из RECON:")
    
    # Из анализа видим четкий паттерн:
    recon_pattern = {
        "sequence": [
            {"position": -2, "ttl": 3, "flags": "PSH+ACK", "length": 3, "type": "fake_segment_1"},
            {"position": -1, "ttl": 3, "flags": "PSH+ACK", "length": 514, "type": "fake_segment_2"},
            {"position": 0, "ttl": 3, "flags": "PSH+ACK", "length": 77, "type": "client_hello"},
            {"position": 1, "ttl": 3, "flags": "PSH+ACK", "length": 3, "type": "real_segment_1"},
            {"position": 2, "ttl": 3, "flags": "PSH+ACK", "length": 514, "type": "real_segment_2"}
        ],
        "exceptions": [
            {"ttl": 128, "flags": "PSH+ACK", "length": 517, "type": "real_no_bypass"}
        ]
    }
    
    print("  📦 Стандартный паттерн:")
    for pkt in recon_pattern["sequence"]:
        marker = ">>> " if pkt["position"] == 0 else "    "
        print(f"  {marker}Pos {pkt['position']:+2d}: TTL={pkt['ttl']}, Flags={pkt['flags']}, Len={pkt['length']} ({pkt['type']})")
    
    print("\n  🔄 Исключения:")
    for pkt in recon_pattern["exceptions"]:
        print(f"      TTL={pkt['ttl']}, Flags={pkt['flags']}, Len={pkt['length']} ({pkt['type']})")
    
    return recon_pattern

def analyze_zapret_pattern():
    """Анализирует паттерн zapret (нужен zapret.pcap)."""
    print("\n🔍 Анализ паттерна ZAPRET:")
    
    if not os.path.exists("zapret.pcap"):
        print("❌ Файл zapret.pcap не найден")
        print("💡 Для сравнения нужен PCAP файл от zapret с теми же параметрами")
        return None
    
    # Здесь будет анализ zapret.pcap когда файл будет доступен
    print("📋 Ожидаемый паттерн zapret (на основе документации):")
    
    zapret_expected = {
        "sequence": [
            {"position": 0, "ttl": 3, "flags": "PSH+ACK", "length": "~500", "type": "fake_client_hello", "checksum": "bad"},
            {"position": 1, "ttl": 3, "flags": "PSH+ACK", "length": 3, "type": "real_segment_1", "checksum": "good"},
            {"position": 2, "ttl": 3, "flags": "PSH+ACK", "length": "~514", "type": "real_segment_2", "checksum": "good"}
        ]
    }
    
    print("  📦 Ожидаемый паттерн zapret:")
    for pkt in zapret_expected["sequence"]:
        marker = ">>> " if "fake" in pkt["type"] else "    "
        checksum_info = f", Checksum={pkt.get('checksum', 'unknown')}" if 'checksum' in pkt else ""
        print(f"  {marker}Pos {pkt['position']:+2d}: TTL={pkt['ttl']}, Flags={pkt['flags']}, Len={pkt['length']} ({pkt['type']}{checksum_info})")
    
    return zapret_expected

def compare_patterns(recon_pattern, zapret_pattern):
    """Сравнивает паттерны recon и zapret."""
    print(f"\n🔄 СРАВНЕНИЕ ПАТТЕРНОВ:")
    print("=" * 60)
    
    if not zapret_pattern:
        print("❌ Нет данных zapret для сравнения")
        return
    
    print("📊 Ключевые различия:")
    
    # Recon отправляет 5 пакетов, zapret - 3
    print(f"   Количество пакетов: Recon=5, Zapret=3")
    
    # Recon отправляет fake сегменты ДО ClientHello
    print(f"   Порядок: Recon=[fake1, fake2, CH, real1, real2], Zapret=[fake_CH, real1, real2]")
    
    # Размеры пакетов
    print(f"   Fake ClientHello: Recon=77 байт, Zapret=~500 байт")
    
    # Checksum
    print(f"   Checksum: Recon=good (0xffff), Zapret=bad")
    
    print(f"\n💡 Основные проблемы:")
    print(f"   1. Recon отправляет дополнительные fake сегменты")
    print(f"   2. Recon не портит checksum в fake ClientHello")
    print(f"   3. Recon использует маленький fake ClientHello")

def generate_fix_recommendations():
    """Генерирует рекомендации по исправлению."""
    print(f"\n🛠️  РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ:")
    print("=" * 60)
    
    print("1. 📦 Исправить последовательность пакетов:")
    print("   - Убрать дополнительные fake сегменты перед ClientHello")
    print("   - Отправлять только: [fake_ClientHello, real_segment1, real_segment2]")
    
    print("\n2. 🔧 Исправить checksum:")
    print("   - Убедиться что fake ClientHello имеет испорченную checksum")
    print("   - Проверить что real сегменты имеют правильную checksum")
    
    print("\n3. 📏 Исправить размер fake ClientHello:")
    print("   - Использовать полный ClientHello (~500 байт) вместо 77 байт")
    print("   - Убедиться что fake SNI включен в полный пакет")
    
    print("\n4. ⚡ Исправить timing:")
    print("   - Минимизировать задержки между пакетами")
    print("   - Стремиться к <0.1ms как в zapret")
    
    print("\n🎯 Приоритет исправлений:")
    print("   1. ВЫСОКИЙ: Последовательность пакетов")
    print("   2. ВЫСОКИЙ: Checksum в fake пакетах")
    print("   3. СРЕДНИЙ: Размер fake ClientHello")
    print("   4. НИЗКИЙ: Timing оптимизация")

def main():
    """Основная функция."""
    print("🔍 СРАВНЕНИЕ ПОСЛЕДОВАТЕЛЬНОСТЕЙ ПАКЕТОВ")
    print("=" * 60)
    
    # Извлекаем паттерн из recon
    recon_pattern = extract_pattern_from_recon()
    
    # Анализируем ожидаемый паттерн zapret
    zapret_pattern = analyze_zapret_pattern()
    
    # Сравниваем паттерны
    compare_patterns(recon_pattern, zapret_pattern)
    
    # Генерируем рекомендации
    generate_fix_recommendations()
    
    print("\n" + "=" * 60)
    print("✅ Анализ завершен")

if __name__ == "__main__":
    main()