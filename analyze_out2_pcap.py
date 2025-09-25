#!/usr/bin/env python3
"""
Анализ out2.pcap для выяснения причин неработающих стратегий.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def analyze_out2_pcap():
    """Анализирует out2.pcap для поиска проблем."""
    print("🔍 АНАЛИЗ OUT2.PCAP - ПОИСК ПРИЧИН НЕРАБОТАЮЩИХ СТРАТЕГИЙ")
    print("=" * 70)
    
    try:
        import subprocess
        import json
        from collections import defaultdict
        
        # Проверяем наличие файла
        pcap_file = "out2.pcap"
        if not os.path.exists(pcap_file):
            print(f"❌ Файл {pcap_file} не найден!")
            return False
        
        print(f"✅ Файл {pcap_file} найден")
        
        # Анализируем PCAP с помощью tshark
        print("\n🔍 Анализ пакетов с помощью tshark...")
        
        try:
            # Базовая статистика
            result = subprocess.run([
                "tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("📊 TCP соединения:")
                print(result.stdout)
            else:
                print("⚠️ Не удалось получить статистику TCP соединений")
        except Exception as e:
            print(f"⚠️ Ошибка tshark: {e}")
        
        # Анализируем TLS пакеты
        print("\n🔍 Анализ TLS пакетов...")
        try:
            result = subprocess.run([
                "tshark", "-r", pcap_file, "-Y", "tls", "-T", "fields",
                "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", 
                "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tls.handshake.type",
                "-e", "frame.len", "-e", "ip.ttl"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines and lines[0]:
                    print(f"📊 Найдено TLS пакетов: {len(lines)}")
                    print("🔍 Первые 10 TLS пакетов:")
                    print("Frame | Src IP | Dst IP | SrcPort | DstPort | TLS Type | Len | TTL")
                    print("-" * 80)
                    
                    for i, line in enumerate(lines[:10]):
                        if line.strip():
                            fields = line.split('\t')
                            if len(fields) >= 7:
                                frame, src, dst, sport, dport, tls_type, length, ttl = fields[:8]
                                print(f"{frame:5} | {src:15} | {dst:15} | {sport:7} | {dport:7} | {tls_type:8} | {length:4} | {ttl}")
                else:
                    print("❌ TLS пакеты не найдены!")
            else:
                print("⚠️ Не удалось проанализировать TLS пакеты")
        except Exception as e:
            print(f"⚠️ Ошибка анализа TLS: {e}")
        
        # Анализируем TCP флаги и последовательности
        print("\n🔍 Анализ TCP флагов и последовательностей...")
        try:
            result = subprocess.run([
                "tshark", "-r", pcap_file, "-Y", "tcp.port == 443", "-T", "fields",
                "-e", "frame.number", "-e", "ip.src", "-e", "tcp.flags", 
                "-e", "tcp.seq", "-e", "tcp.len", "-e", "ip.ttl", "-e", "tcp.checksum_status"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines and lines[0]:
                    print(f"📊 Найдено TCP пакетов на порт 443: {len(lines)}")
                    
                    # Группируем по TTL
                    ttl_stats = defaultdict(int)
                    checksum_stats = defaultdict(int)
                    flag_stats = defaultdict(int)
                    
                    print("🔍 Первые 15 TCP пакетов:")
                    print("Frame | Src IP | Flags | Seq | Len | TTL | Checksum")
                    print("-" * 70)
                    
                    for i, line in enumerate(lines[:15]):
                        if line.strip():
                            fields = line.split('\t')
                            if len(fields) >= 6:
                                frame, src, flags, seq, length, ttl = fields[:6]
                                checksum = fields[6] if len(fields) > 6 else "unknown"
                                
                                print(f"{frame:5} | {src:15} | {flags:5} | {seq:10} | {length:3} | {ttl:3} | {checksum}")
                                
                                if ttl:
                                    ttl_stats[ttl] += 1
                                if checksum:
                                    checksum_stats[checksum] += 1
                                if flags:
                                    flag_stats[flags] += 1
                    
                    print(f"\n📊 Статистика TTL:")
                    for ttl, count in sorted(ttl_stats.items()):
                        print(f"  TTL {ttl}: {count} пакетов")
                    
                    print(f"\n📊 Статистика Checksum:")
                    for status, count in checksum_stats.items():
                        print(f"  {status}: {count} пакетов")
                    
                    print(f"\n📊 Статистика TCP флагов:")
                    for flags, count in sorted(flag_stats.items()):
                        print(f"  Flags {flags}: {count} пакетов")
                        
                else:
                    print("❌ TCP пакеты на порт 443 не найдены!")
            else:
                print("⚠️ Не удалось проанализировать TCP пакеты")
        except Exception as e:
            print(f"⚠️ Ошибка анализа TCP: {e}")
        
        # Поиск признаков zapret-style пакетов
        print("\n🎯 ПОИСК ZAPRET-STYLE ПРИЗНАКОВ...")
        
        # Ищем пакеты с TTL=1-3 (fake пакеты)
        try:
            result = subprocess.run([
                "tshark", "-r", pcap_file, "-Y", "tcp.port == 443 and (ip.ttl == 1 or ip.ttl == 2 or ip.ttl == 3)", 
                "-T", "fields", "-e", "frame.number", "-e", "ip.ttl", "-e", "tcp.len", "-e", "tcp.checksum_status"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines and lines[0]:
                    print(f"✅ Найдено пакетов с низким TTL (1-3): {len(lines)}")
                    for line in lines[:10]:
                        if line.strip():
                            fields = line.split('\t')
                            if len(fields) >= 3:
                                frame, ttl, length, checksum = fields[:4]
                                print(f"  Frame {frame}: TTL={ttl}, Len={length}, Checksum={checksum}")
                else:
                    print("❌ Пакеты с низким TTL (1-3) НЕ НАЙДЕНЫ!")
                    print("   Это может означать, что zapret-style логика не активируется")
            else:
                print("⚠️ Не удалось найти пакеты с низким TTL")
        except Exception as e:
            print(f"⚠️ Ошибка поиска TTL: {e}")
        
        # Ищем пакеты с испорченной checksum
        try:
            result = subprocess.run([
                "tshark", "-r", pcap_file, "-Y", "tcp.port == 443 and tcp.checksum_status == \"Bad\"", 
                "-T", "fields", "-e", "frame.number", "-e", "ip.ttl", "-e", "tcp.len"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines and lines[0]:
                    print(f"✅ Найдено пакетов с плохой checksum: {len(lines)}")
                    for line in lines[:5]:
                        if line.strip():
                            fields = line.split('\t')
                            if len(fields) >= 3:
                                frame, ttl, length = fields[:3]
                                print(f"  Frame {frame}: TTL={ttl}, Len={length}")
                else:
                    print("❌ Пакеты с плохой checksum НЕ НАЙДЕНЫ!")
                    print("   Это может означать, что badsum не работает")
            else:
                print("⚠️ Не удалось найти пакеты с плохой checksum")
        except Exception as e:
            print(f"⚠️ Ошибка поиска badsum: {e}")
        
        print("\n🎯 ДИАГНОСТИКА ПРОБЛЕМ:")
        print("1. Проверьте, активируется ли zapret-style логика")
        print("2. Проверьте, отправляются ли пакеты с TTL=1-3")
        print("3. Проверьте, портится ли checksum в fake пакетах")
        print("4. Проверьте последовательность пакетов")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = analyze_out2_pcap()
    sys.exit(0 if success else 1)