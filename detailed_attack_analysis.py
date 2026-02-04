#!/usr/bin/env python3
"""
Детальный анализ проблемы: почему атаки не применяются к пакетам
"""

import re
from typing import List, Dict, Any
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def analyze_log_issues(log_file: str) -> Dict[str, Any]:
    """Анализирует проблемы в логе."""
    issues = {
        'test_failures': [],
        'discovery_mode_issues': [],
        'service_mode_issues': [],
        'pcap_issues': [],
        'attack_application_issues': []
    }
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Ищем причины неудач тестов
    fail_patterns = [
        r'❌ Test FAIL: ([^\n]+)',
        r'WARNING.*([^\n]+)',
        r'ERROR.*([^\n]+)'
    ]
    
    for pattern in fail_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if 'No HTTP response' in match:
                issues['test_failures'].append(f"Нет HTTP ответа: {match}")
            elif 'PCAP' in match:
                issues['pcap_issues'].append(f"Проблема PCAP: {match}")
            elif 'service' in match.lower():
                issues['service_mode_issues'].append(f"Проблема сервиса: {match}")
    
    # Ищем проблемы с Discovery mode
    discovery_patterns = [
        r'🔍 Discovery mode: ([^\n]+)',
        r'Discovery.*disabled ([^\n]+)',
        r'override disabled ([^\n]+)'
    ]
    
    for pattern in discovery_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            issues['discovery_mode_issues'].append(match)
    
    # Ищем проблемы с применением атак
    attack_patterns = [
        r'PCAP capture not available ([^\n]+)',
        r'Testing without capture ([^\n]+)',
        r'Service.*without.*capture ([^\n]+)'
    ]
    
    for pattern in attack_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            issues['attack_application_issues'].append(match)
    
    return issues

def analyze_pcap_timing(pcap_file: str) -> Dict[str, Any]:
    """Анализирует временные характеристики PCAP."""
    if not SCAPY_AVAILABLE:
        return {'error': 'Scapy недоступен'}
    
    try:
        packets = rdpcap(pcap_file)
        googlevideo_packets = []
        
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                if pkt[IP].dst == "142.250.74.100":  # googlevideo.com
                    googlevideo_packets.append(pkt)
        
        if not googlevideo_packets:
            return {'error': 'Нет пакетов к googlevideo.com'}
        
        # Анализируем временные интервалы
        timestamps = [float(pkt.time) for pkt in googlevideo_packets]
        timestamps.sort()
        
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        # Группируем пакеты по временным окнам (предполагаемые тесты)
        test_windows = []
        current_window = [googlevideo_packets[0]]
        
        for i in range(1, len(googlevideo_packets)):
            time_diff = timestamps[i] - timestamps[i-1]
            if time_diff > 5.0:  # Новый тест, если пауза больше 5 секунд
                test_windows.append(current_window)
                current_window = [googlevideo_packets[i]]
            else:
                current_window.append(googlevideo_packets[i])
        
        if current_window:
            test_windows.append(current_window)
        
        return {
            'total_packets': len(googlevideo_packets),
            'time_span': timestamps[-1] - timestamps[0],
            'test_windows': len(test_windows),
            'packets_per_window': [len(window) for window in test_windows],
            'avg_interval': sum(intervals) / len(intervals) if intervals else 0,
            'max_interval': max(intervals) if intervals else 0
        }
        
    except Exception as e:
        return {'error': str(e)}

def analyze_attack_effectiveness(log_file: str, pcap_file: str) -> str:
    """Анализирует эффективность применения атак."""
    report = []
    report.append("# Детальный анализ проблем с применением атак")
    report.append("")
    
    # Анализируем проблемы в логе
    log_issues = analyze_log_issues(log_file)
    
    report.append("## Проблемы в логе")
    
    if log_issues['test_failures']:
        report.append("### Причины неудач тестов:")
        for issue in log_issues['test_failures'][:5]:
            report.append(f"- {issue}")
        report.append("")
    
    if log_issues['attack_application_issues']:
        report.append("### Проблемы с применением атак:")
        for issue in log_issues['attack_application_issues']:
            report.append(f"- {issue}")
        report.append("")
    
    if log_issues['discovery_mode_issues']:
        report.append("### Проблемы Discovery mode:")
        for issue in log_issues['discovery_mode_issues'][:3]:
            report.append(f"- {issue}")
        report.append("")
    
    # Анализируем PCAP
    pcap_analysis = analyze_pcap_timing(pcap_file)
    
    report.append("## Анализ PCAP")
    if 'error' in pcap_analysis:
        report.append(f"❌ Ошибка анализа PCAP: {pcap_analysis['error']}")
    else:
        report.append(f"- Всего пакетов к googlevideo.com: {pcap_analysis['total_packets']}")
        report.append(f"- Временной диапазон: {pcap_analysis['time_span']:.1f} секунд")
        report.append(f"- Предполагаемых тестовых окон: {pcap_analysis['test_windows']}")
        report.append(f"- Пакетов на окно: {pcap_analysis['packets_per_window']}")
        report.append(f"- Средний интервал между пакетами: {pcap_analysis['avg_interval']:.3f}с")
        report.append("")
    
    # Основные выводы
    report.append("## Основные проблемы")
    
    # Проверяем основные проблемы
    main_issues = []
    
    if any('PCAP capture not available' in issue for issue in log_issues['attack_application_issues']):
        main_issues.append("❌ **КРИТИЧНО**: PCAP захват недоступен во время тестирования")
        main_issues.append("   - Атаки не могут быть применены без PCAP захвата")
        main_issues.append("   - Система работает в режиме 'testing without capture'")
    
    if any('No HTTP response' in issue for issue in log_issues['test_failures']):
        main_issues.append("❌ **ПРОБЛЕМА**: Нет HTTP ответов от целевого домена")
        main_issues.append("   - Возможно, домен недоступен или блокируется")
        main_issues.append("   - Тесты завершаются неудачей из-за отсутствия ответа")
    
    if log_issues['discovery_mode_issues']:
        main_issues.append("⚠️ **ВНИМАНИЕ**: Discovery mode активен")
        main_issues.append("   - Стратегии могут быть переопределены для разнообразия")
        main_issues.append("   - CLI/service parity override отключен")
    
    if 'error' not in pcap_analysis and pcap_analysis['total_packets'] > 0:
        if pcap_analysis['test_windows'] < 25:
            main_issues.append("⚠️ **НЕСООТВЕТСТВИЕ**: Меньше тестовых окон, чем стратегий")
            main_issues.append(f"   - Ожидалось 25 тестов, найдено {pcap_analysis['test_windows']} окон")
        
        avg_packets = sum(pcap_analysis['packets_per_window']) / len(pcap_analysis['packets_per_window'])
        if avg_packets < 5:
            main_issues.append("⚠️ **ПРОБЛЕМА**: Мало пакетов на тест")
            main_issues.append(f"   - Среднее количество пакетов на тест: {avg_packets:.1f}")
            main_issues.append("   - Возможно, соединения не устанавливаются")
    
    for issue in main_issues:
        report.append(issue)
    
    report.append("")
    
    # Рекомендации по исправлению
    report.append("## Рекомендации по исправлению")
    report.append("")
    
    if any('PCAP capture not available' in issue for issue in log_issues['attack_application_issues']):
        report.append("### 1. Исправление проблем с PCAP захватом")
        report.append("```bash")
        report.append("# Проверьте права администратора")
        report.append("# Убедитесь, что WinDivert работает корректно")
        report.append("# Перезапустите с правами администратора")
        report.append("```")
        report.append("")
    
    if any('No HTTP response' in issue for issue in log_issues['test_failures']):
        report.append("### 2. Проверка доступности домена")
        report.append("```bash")
        report.append("# Проверьте доступность")
        report.append("curl -I https://www.googlevideo.com")
        report.append("nslookup www.googlevideo.com")
        report.append("")
        report.append("# Попробуйте другой домен для тестирования")
        report.append("python cli.py auto youtube.com --pcap test_youtube.pcap")
        report.append("```")
        report.append("")
    
    report.append("### 3. Альтернативные подходы")
    report.append("- Используйте режим service вместо auto для более стабильного тестирования")
    report.append("- Тестируйте на локально доступных доменах")
    report.append("- Проверьте сетевые настройки и firewall")
    report.append("")
    
    return "\n".join(report)

def main():
    """Основная функция."""
    report = analyze_attack_effectiveness("test_new.txt", "test_new.pcap")
    
    # Сохраняем отчет
    report_file = "detailed_attack_analysis_report.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print("📄 Детальный анализ сохранен в", report_file)
    print("\n" + "="*70)
    print("ДЕТАЛЬНЫЙ АНАЛИЗ ПРОБЛЕМ")
    print("="*70)
    print(report)

if __name__ == "__main__":
    main()