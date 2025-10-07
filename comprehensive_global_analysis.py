#!/usr/bin/env python3
"""
ГЛОБАЛЬНЫЙ АНАЛИЗ RECON - Поиск ВСЕХ проблем
Анализирует PCAP, логи, код и находит ВСЕ причины неработоспособности bypass
"""

import sys
import os
import json
from scapy.all import *

def analyze_pcap_differences(recon_pcap, zapret_pcap):
    """Детальное сравнение PCAP файлов"""
    print("=" * 80)
    print("АНАЛИЗ PCAP ФАЙЛОВ")
    print("=" * 80)
    print()
    
    try:
        print(f"Читаем {recon_pcap}...")
        recon_packets = rdpcap(recon_pcap)
        print(f"  Пакетов: {len(recon_packets)}")
        
        print(f"Читаем {zapret_pcap}...")
        zapret_packets = rdpcap(zapret_pcap)
        print(f"  Пакетов: {len(zapret_packets)}")
        print()
        
        differences = []
        
        # Анализ TCP пакетов к x.com
        print("Анализ TCP пакетов к x.com (104.244.42.*)...")
        print()
        
        recon_tcp = [p for p in recon_packets if TCP in p and IP in p and p[IP].dst.startswith('104.244.42')]
        zapret_tcp = [p for p in zapret_packets if TCP in p and IP in p and p[IP].dst.startswith('104.244.42')]
        
        print(f"Recon TCP пакетов: {len(recon_tcp)}")
        print(f"Zapret TCP пакетов: {len(zapret_tcp)}")
        print()
        
        # Сравнение первых 10 пакетов
        print("Сравнение первых пакетов:")
        print()
        
        for i in range(min(10, len(recon_tcp), len(zapret_tcp))):
            r = recon_tcp[i]
            z = zapret_tcp[i]
            
            print(f"Пакет #{i+1}:")
            
            # TTL
            if r[IP].ttl != z[IP].ttl:
                diff = f"  ❌ TTL: Recon={r[IP].ttl}, Zapret={z[IP].ttl}"
                print(diff)
                differences.append(diff)
            else:
                print(f"  ✅ TTL: {r[IP].ttl}")
            
            # TCP Flags
            if r[TCP].flags != z[TCP].flags:
                diff = f"  ❌ Flags: Recon={r[TCP].flags}, Zapret={z[TCP].flags}"
                print(diff)
                differences.append(diff)
            else:
                print(f"  ✅ Flags: {r[TCP].flags}")
            
            # Payload length
            r_len = len(r[TCP].payload) if Raw in r else 0
            z_len = len(z[TCP].payload) if Raw in z else 0
            if r_len != z_len:
                diff = f"  ⚠️  Payload: Recon={r_len}, Zapret={z_len}"
                print(diff)
                differences.append(diff)
            else:
                print(f"  ✅ Payload: {r_len} bytes")
            
            # TCP Options
            r_opts = len(r[TCP].options) if hasattr(r[TCP], 'options') else 0
            z_opts = len(z[TCP].options) if hasattr(z[TCP], 'options') else 0
            if r_opts != z_opts:
                diff = f"  ❌ TCP Options: Recon={r_opts}, Zapret={z_opts}"
                print(diff)
                differences.append(diff)
            else:
                print(f"  ✅ TCP Options: {r_opts}")
            
            # Window Size
            if r[TCP].window != z[TCP].window:
                diff = f"  ⚠️  Window: Recon={r[TCP].window}, Zapret={z[TCP].window}"
                print(diff)
            else:
                print(f"  ✅ Window: {r[TCP].window}")
            
            print()
        
        return differences
        
    except Exception as e:
        print(f"❌ Ошибка анализа PCAP: {e}")
        import traceback
        traceback.print_exc()
        return []

def analyze_log_file(log_file):
    """Анализ лог файла на ошибки"""
    print("=" * 80)
    print("АНАЛИЗ LOG.TXT")
    print("=" * 80)
    print()
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()
        
        issues = []
        
        # Поиск ошибок
        if 'ERROR' in log_content:
            errors = [line for line in log_content.split('\n') if 'ERROR' in line]
            print(f"❌ Найдено {len(errors)} ERROR строк:")
            for err in errors[:10]:  # Первые 10
                print(f"  {err[:100]}")
            issues.append(f"ERROR count: {len(errors)}")
            print()
        
        # Поиск WARNING
        if 'WARNING' in log_content:
            warnings = [line for line in log_content.split('\n') if 'WARNING' in line]
            print(f"⚠️  Найдено {len(warnings)} WARNING строк")
            issues.append(f"WARNING count: {len(warnings)}")
            print()
        
        # Поиск bypass активации
        if 'Bypass activated' in log_content or 'bypass activated' in log_content:
            print("✅ Bypass активирован")
        else:
            print("❌ Bypass НЕ активирован!")
            issues.append("Bypass not activated")
        print()
        
        # Поиск отправки пакетов
        if 'FAKE' in log_content or 'REAL' in log_content:
            fake_count = log_content.count('FAKE')
            real_count = log_content.count('REAL')
            print(f"📤 Отправлено пакетов:")
            print(f"  FAKE: {fake_count}")
            print(f"  REAL: {real_count}")
        else:
            print("❌ Пакеты НЕ отправляются!")
            issues.append("No packets sent")
        print()
        
        # Поиск TTL
        if 'using TTL=64' in log_content:
            print("✅ TTL=64 используется (исправление применено)")
        elif 'using TTL=128' in log_content or 'base_ttl=128' in log_content:
            print("❌ TTL=128 используется (исправление НЕ применено!)")
            issues.append("TTL=128 still used")
        print()
        
        return issues
        
    except Exception as e:
        print(f"❌ Ошибка чтения лога: {e}")
        return []

def analyze_summary_json(summary_file):
    """Анализ recon_summary.json"""
    print("=" * 80)
    print("АНАЛИЗ RECON_SUMMARY.JSON")
    print("=" * 80)
    print()
    
    try:
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        print(f"Стратегий протестировано: {summary.get('total_strategies_tested', 0)}")
        print(f"Рабочих стратегий: {summary.get('working_strategies_found', 0)}")
        print(f"Success rate: {summary.get('success_rate', 0)*100:.1f}%")
        print()
        
        best = summary.get('best_strategy', {})
        if best:
            print("Лучшая стратегия:")
            print(f"  {best.get('strategy', 'N/A')}")
            print(f"  Success: {best.get('success_rate', 0)*100:.1f}% ({best.get('successful_sites', 0)}/{best.get('total_sites', 0)})")
            print(f"  Latency: {best.get('avg_latency_ms', 0):.1f}ms")
            print()
            
            telemetry = best.get('engine_telemetry', {})
            print("Telemetry:")
            print(f"  ClientHello: {telemetry.get('CH', 0)}")
            print(f"  ServerHello: {telemetry.get('SH', 0)}")
            print(f"  RST: {telemetry.get('RST', 0)}")
            print()
        
        # Анализ всех стратегий
        all_results = summary.get('all_results', [])
        print(f"Детали всех {len(all_results)} стратегий:")
        for i, result in enumerate(all_results, 1):
            print(f"\n{i}. {result.get('strategy', 'N/A')}")
            print(f"   Success: {result.get('success_rate', 0)*100:.1f}% ({result.get('successful_sites', 0)}/{result.get('total_sites', 0)})")
            tel = result.get('engine_telemetry', {})
            print(f"   CH={tel.get('CH', 0)}, SH={tel.get('SH', 0)}, RST={tel.get('RST', 0)}")
        
        print()
        return summary
        
    except Exception as e:
        print(f"❌ Ошибка чтения summary: {e}")
        return {}

def main():
    print()
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "ГЛОБАЛЬНЫЙ АНАЛИЗ RECON" + " " * 35 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    # 1. Анализ PCAP
    pcap_diffs = analyze_pcap_differences('recon_x1.pcap', 'zapret_x.pcap')
    
    # 2. Анализ логов
    log_issues = analyze_log_file('log.txt')
    
    # 3. Анализ summary
    summary = analyze_summary_json('recon_summary.json')
    
    # Итоговый отчет
    print("=" * 80)
    print("ИТОГОВЫЙ ОТЧЕТ")
    print("=" * 80)
    print()
    
    print("НАЙДЕННЫЕ ПРОБЛЕМЫ:")
    print()
    
    if pcap_diffs:
        print(f"1. PCAP различия: {len(pcap_diffs)}")
        for diff in pcap_diffs[:5]:
            print(f"   {diff}")
        print()
    
    if log_issues:
        print(f"2. Проблемы в логах: {len(log_issues)}")
        for issue in log_issues:
            print(f"   {issue}")
        print()
    
    print("3. Success rate:")
    print(f"   Текущий: {summary.get('success_rate', 0)*100:.1f}%")
    print(f"   Цель: 90%+")
    print(f"   Разница: {90 - summary.get('success_rate', 0)*100:.1f}%")
    print()
    
    print("РЕКОМЕНДАЦИИ:")
    print("1. Проверить что TTL=64 применяется")
    print("2. Проверить что bypass активируется")
    print("3. Проверить что пакеты отправляются")
    print("4. Сравнить PCAP детально в Wireshark")
    print()

if __name__ == "__main__":
    # Fix encoding for Windows console
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    main()
