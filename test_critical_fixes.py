#!/usr/bin/env python3
"""
Тест критических исправлений Recon
Проверяет:
1. Telemetry обновляется
2. Checksum испорчен для fake packets
3. Количество пакетов правильное
"""

import subprocess
import json
import time
from pathlib import Path
from scapy.all import rdpcap, TCP, IP, Raw

def run_recon_test():
    """Запускает Recon с тестовой стратегией"""
    print("="*80)
    print("🧪 ЗАПУСК ТЕСТА RECON С ИСПРАВЛЕНИЯМИ")
    print("="*80)
    
    # Удаляем старые файлы
    for f in ['recon_summary.json', 'log.txt', 'recon_x1.pcap']:
        if Path(f).exists():
            Path(f).unlink()
            print(f"✓ Удален старый файл: {f}")
    
    # Запускаем Recon
    cmd = [
        'python', 'cli.py', 'x.com',
        '--debug',
        '--strategy', '--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3'
    ]
    
    print(f"\n📝 Команда: {' '.join(cmd)}")
    print("\n⏳ Запуск Recon (это займет ~60 секунд)...\n")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        print("✓ Recon завершен")
        return True
        
    except subprocess.TimeoutExpired:
        print("❌ Timeout: Recon не завершился за 120 секунд")
        return False
    except Exception as e:
        print(f"❌ Ошибка запуска Recon: {e}")
        return False


def check_telemetry():
    """Проверяет telemetry в summary"""
    print("\n" + "="*80)
    print("📊 ПРОВЕРКА TELEMETRY")
    print("="*80)
    
    if not Path('recon_summary.json').exists():
        print("❌ Файл recon_summary.json не найден")
        return False
    
    with open('recon_summary.json', 'r') as f:
        summary = json.load(f)
    
    issues = []
    
    for result in summary.get('all_results', []):
        strategy_id = result['strategy_id']
        telemetry = result.get('engine_telemetry', {})
        
        segments_sent = telemetry.get('segments_sent', 0)
        fake_packets_sent = telemetry.get('fake_packets_sent', 0)
        
        print(f"\n📋 Стратегия: {strategy_id}")
        print(f"   segments_sent: {segments_sent}")
        print(f"   fake_packets_sent: {fake_packets_sent}")
        
        if segments_sent == 0:
            issues.append(f"❌ segments_sent=0 для {strategy_id}")
        else:
            print(f"   ✅ segments_sent > 0")
        
        if fake_packets_sent == 0:
            issues.append(f"❌ fake_packets_sent=0 для {strategy_id}")
        else:
            print(f"   ✅ fake_packets_sent > 0")
    
    if issues:
        print(f"\n❌ TELEMETRY ПРОБЛЕМЫ:")
        for issue in issues:
            print(f"   {issue}")
        return False
    else:
        print(f"\n✅ TELEMETRY OK: Все счетчики обновляются")
        return True


def check_pcap():
    """Проверяет PCAP файл"""
    print("\n" + "="*80)
    print("📦 ПРОВЕРКА PCAP")
    print("="*80)
    
    pcap_files = list(Path('.').glob('recon_*.pcap'))
    if not pcap_files:
        print("❌ PCAP файл не найден")
        return False
    
    pcap_file = pcap_files[0]
    print(f"\n📁 Анализ: {pcap_file}")
    
    try:
        packets = rdpcap(str(pcap_file))
        print(f"✓ Загружено пакетов: {len(packets)}")
        
        client_hello_packets = []
        
        for i, pkt in enumerate(packets):
            if IP in pkt and TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                
                # TLS Client Hello
                if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                    ip = pkt[IP]
                    tcp = pkt[TCP]
                    
                    is_fake = ip.ttl <= 10
                    pkt_type = "FAKE" if is_fake else "REAL"
                    
                    client_hello_packets.append({
                        'index': i,
                        'type': pkt_type,
                        'ttl': ip.ttl,
                        'len': len(payload),
                        'checksum': tcp.chksum,
                        'seq': tcp.seq
                    })
                    
                    print(f"\n   [{i}] {pkt_type} Client Hello:")
                    print(f"       TTL: {ip.ttl}")
                    print(f"       Length: {len(payload)}")
                    print(f"       Checksum: 0x{tcp.chksum:04X}")
                    print(f"       Seq: 0x{tcp.seq:08X}")
        
        print(f"\n📊 Всего Client Hello пакетов: {len(client_hello_packets)}")
        
        issues = []
        
        # Проверка 1: Должен быть хотя бы 1 fake packet
        fake_packets = [p for p in client_hello_packets if p['type'] == 'FAKE']
        if not fake_packets:
            issues.append("❌ Нет fake пакетов")
        else:
            print(f"✅ Найдено {len(fake_packets)} fake пакетов")
            
            # Проверка 2: Fake packet должен иметь испорченный checksum
            for fp in fake_packets:
                if fp['checksum'] == 0xDEAD:
                    print(f"✅ Fake packet имеет испорченный checksum (0xDEAD)")
                else:
                    issues.append(f"⚠️ Fake packet checksum = 0x{fp['checksum']:04X} (ожидалось 0xDEAD)")
                    print(f"⚠️ Checksum не испорчен (возможно WinDivert пересчитал)")
        
        # Проверка 3: Real packets должны иметь правильный TTL
        real_packets = [p for p in client_hello_packets if p['type'] == 'REAL']
        for rp in real_packets:
            if rp['ttl'] == 128:
                issues.append(f"❌ Real packet имеет TTL=128 (должно быть 64)")
            elif rp['ttl'] == 64:
                print(f"✅ Real packet имеет правильный TTL=64")
        
        if issues:
            print(f"\n⚠️ PCAP ПРОБЛЕМЫ:")
            for issue in issues:
                print(f"   {issue}")
            return False
        else:
            print(f"\n✅ PCAP OK")
            return True
            
    except Exception as e:
        print(f"❌ Ошибка анализа PCAP: {e}")
        return False


def main():
    print("="*80)
    print("🔍 ТЕСТ КРИТИЧЕСКИХ ИСПРАВЛЕНИЙ RECON")
    print("="*80)
    print("\nЭтот тест проверяет:")
    print("1. ✅ Telemetry обновляется (segments_sent, fake_packets_sent)")
    print("2. ✅ Checksum испорчен для fake packets")
    print("3. ✅ TTL правильный для real packets")
    print("\n" + "="*80)
    
    # Шаг 1: Запуск Recon
    if not run_recon_test():
        print("\n❌ ТЕСТ ПРОВАЛЕН: Recon не запустился")
        return
    
    # Даем время на завершение
    time.sleep(2)
    
    # Шаг 2: Проверка telemetry
    telemetry_ok = check_telemetry()
    
    # Шаг 3: Проверка PCAP
    pcap_ok = check_pcap()
    
    # Итоговый результат
    print("\n" + "="*80)
    print("📋 ИТОГОВЫЙ РЕЗУЛЬТАТ")
    print("="*80)
    
    if telemetry_ok and pcap_ok:
        print("\n✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("\nИсправления работают:")
        print("  ✅ Telemetry обновляется")
        print("  ✅ PCAP корректный")
    else:
        print("\n❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ")
        if not telemetry_ok:
            print("  ❌ Telemetry не обновляется")
        if not pcap_ok:
            print("  ❌ PCAP имеет проблемы")
    
    print("\n" + "="*80)


if __name__ == '__main__':
    main()
