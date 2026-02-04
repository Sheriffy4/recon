#!/usr/bin/env python3
"""
Анализ корневой причины ретрансмиссий в службе обхода
"""

import re
from pathlib import Path
from typing import Dict, List, Any

def analyze_retransmission_patterns():
    """Анализ паттернов ретрансмиссий"""
    
    print("АНАЛИЗ КОРНЕВОЙ ПРИЧИНЫ РЕТРАНСМИССИЙ")
    print("=" * 50)
    
    # Читаем логи
    search_log = read_log_safe("log2.txt")
    service_log = read_log_safe("log.txt")
    
    if not search_log or not service_log:
        return
    
    print("\n🔍 АНАЛИЗ РЕТРАНСМИССИЙ:")
    
    # Анализ режима поиска
    search_retrans = extract_retransmissions(search_log, "поиск")
    service_retrans = extract_retransmissions(service_log, "служба")
    
    print(f"\n📊 СРАВНЕНИЕ:")
    print(f"Режим поиска: {search_retrans['count']} ретрансмиссий")
    print(f"Режим службы: {service_retrans['count']} ретрансмиссий")
    print(f"Разница: {service_retrans['count'] - search_retrans['count']} (+{((service_retrans['count'] / max(search_retrans['count'], 1)) - 1) * 100:.0f}%)")
    
    # Анализ причин
    print(f"\n🎯 ВОЗМОЖНЫЕ ПРИЧИНЫ РЕТРАНСМИССИЙ:")
    
    causes = analyze_retransmission_causes(search_log, service_log)
    for i, cause in enumerate(causes, 1):
        print(f"{i}. {cause}")
    
    # Анализ таймингов
    print(f"\n⏱️ АНАЛИЗ ТАЙМИНГОВ:")
    analyze_timing_differences(search_log, service_log)
    
    # Анализ сегментации
    print(f"\n📦 АНАЛИЗ СЕГМЕНТАЦИИ:")
    analyze_segmentation_differences(search_log, service_log)

def read_log_safe(filename: str) -> str:
    """Безопасное чтение лог файла"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except FileNotFoundError:
        print(f"❌ Файл {filename} не найден")
        return ""

def extract_retransmissions(log_content: str, mode_name: str) -> Dict[str, Any]:
    """Извлечение информации о ретрансмиссиях"""
    
    # Поиск общего количества ретрансмиссий
    retrans_patterns = [
        r'retransmissions detected: (\d+)',
        r'total_retrans=(\d+)',
        r'RETRANSMISSION DETECTED.*total_retrans=(\d+)'
    ]
    
    max_retrans = 0
    for pattern in retrans_patterns:
        matches = re.findall(pattern, log_content, re.IGNORECASE)
        if matches:
            max_retrans = max(max_retrans, max(int(m) for m in matches))
    
    # Поиск отдельных событий ретрансмиссий
    retrans_events = re.findall(r'RETRANSMISSION DETECTED.*seq=0x([A-F0-9]+)', log_content)
    
    return {
        'count': max_retrans,
        'events': len(retrans_events),
        'sequences': retrans_events
    }

def analyze_retransmission_causes(search_log: str, service_log: str) -> List[str]:
    """Анализ причин ретрансмиссий"""
    
    causes = []
    
    # 1. Проверка различий в таймингах отправки
    search_delays = extract_packet_delays(search_log)
    service_delays = extract_packet_delays(service_log)
    
    if service_delays and search_delays:
        service_avg = sum(service_delays) / len(service_delays)
        search_avg = sum(search_delays) / len(search_delays)
        
        if service_avg > search_avg * 2:
            causes.append(f"Служба отправляет пакеты медленнее (средняя задержка: {service_avg:.1f}мс vs {search_avg:.1f}мс)")
    
    # 2. Проверка различий в размерах сегментов
    search_segments = extract_segment_sizes(search_log)
    service_segments = extract_segment_sizes(service_log)
    
    if len(service_segments) != len(search_segments):
        causes.append(f"Различное количество сегментов: служба={len(service_segments)}, поиск={len(search_segments)}")
    
    # 3. Проверка ошибок отправки
    service_errors = extract_send_errors(service_log)
    search_errors = extract_send_errors(search_log)
    
    if service_errors > search_errors:
        causes.append(f"Больше ошибок отправки в службе: {service_errors} vs {search_errors}")
    
    # 4. Проверка различий в последовательности пакетов
    search_sequences = extract_packet_sequences(search_log)
    service_sequences = extract_packet_sequences(service_log)
    
    if search_sequences and service_sequences:
        if search_sequences != service_sequences:
            causes.append("Различная последовательность отправки пакетов")
    
    # 5. Проверка проблем с WinDivert
    windivert_issues = check_windivert_issues(service_log)
    if windivert_issues:
        causes.extend(windivert_issues)
    
    # 6. Проверка проблем с производительностью
    perf_issues = check_performance_issues(service_log)
    if perf_issues:
        causes.extend(perf_issues)
    
    return causes

def extract_packet_delays(log_content: str) -> List[float]:
    """Извлечение задержек между пакетами"""
    delays = []
    
    # Поиск задержек
    delay_patterns = [
        r'Delaying (\d+)ms after packet',
        r'delay[=:]\s*(\d+)',
        r'sleep\(([0-9.]+)\)'
    ]
    
    for pattern in delay_patterns:
        matches = re.findall(pattern, log_content)
        delays.extend([float(m) for m in matches])
    
    return delays

def extract_segment_sizes(log_content: str) -> List[int]:
    """Извлечение размеров сегментов"""
    sizes = []
    
    # Поиск размеров сегментов
    size_patterns = [
        r'len=(\d+)',
        r'payload_len=(\d+)',
        r'segment.*?(\d+) bytes'
    ]
    
    for pattern in size_patterns:
        matches = re.findall(pattern, log_content)
        sizes.extend([int(m) for m in matches])
    
    return sizes

def extract_send_errors(log_content: str) -> int:
    """Извлечение количества ошибок отправки"""
    error_patterns = [
        r'ERROR.*send',
        r'Failed to send',
        r'Send error',
        r'WinDivert.*error'
    ]
    
    error_count = 0
    for pattern in error_patterns:
        matches = re.findall(pattern, log_content, re.IGNORECASE)
        error_count += len(matches)
    
    return error_count

def extract_packet_sequences(log_content: str) -> List[str]:
    """Извлечение последовательности пакетов"""
    sequences = []
    
    # Поиск последовательностей пакетов
    seq_pattern = r'seq=0x([A-F0-9]+)'
    matches = re.findall(seq_pattern, log_content)
    
    return matches

def check_windivert_issues(log_content: str) -> List[str]:
    """Проверка проблем с WinDivert"""
    issues = []
    
    # Поиск проблем с WinDivert
    windivert_patterns = [
        (r'WinDivert.*failed', "Ошибки WinDivert при отправке"),
        (r'mark.*mismatch', "Проблемы с маркировкой пакетов"),
        (r'filter.*error', "Ошибки фильтрации WinDivert"),
        (r'capture.*failed', "Ошибки захвата пакетов")
    ]
    
    for pattern, description in windivert_patterns:
        if re.search(pattern, log_content, re.IGNORECASE):
            issues.append(description)
    
    return issues

def check_performance_issues(log_content: str) -> List[str]:
    """Проверка проблем с производительностью"""
    issues = []
    
    # Поиск медленных операций
    timing_pattern = r'(\d+\.\d+)ms'
    timings = [float(m) for m in re.findall(timing_pattern, log_content)]
    
    if timings:
        avg_timing = sum(timings) / len(timings)
        max_timing = max(timings)
        
        if avg_timing > 50:  # Более 50мс в среднем
            issues.append(f"Медленная обработка пакетов (среднее: {avg_timing:.1f}мс)")
        
        if max_timing > 200:  # Более 200мс максимум
            issues.append(f"Очень медленные операции (максимум: {max_timing:.1f}мс)")
    
    return issues

def analyze_timing_differences(search_log: str, service_log: str):
    """Анализ различий в таймингах"""
    
    # Извлечение таймингов
    search_timings = extract_timing_metrics(search_log)
    service_timings = extract_timing_metrics(service_log)
    
    print(f"Режим поиска:")
    print(f"  Intercept to send: {search_timings.get('intercept_to_send', 'N/A')}мс")
    print(f"  Total time: {search_timings.get('total_time', 'N/A')}мс")
    
    print(f"Режим службы:")
    print(f"  Intercept to send: {service_timings.get('intercept_to_send', 'N/A')}мс")
    print(f"  Total time: {service_timings.get('total_time', 'N/A')}мс")
    
    # Сравнение
    if search_timings.get('total_time') and service_timings.get('total_time'):
        ratio = service_timings['total_time'] / search_timings['total_time']
        if ratio > 2:
            print(f"⚠️ Служба работает в {ratio:.1f}x раз медленнее")

def extract_timing_metrics(log_content: str) -> Dict[str, float]:
    """Извлечение метрик таймингов"""
    timings = {}
    
    # Поиск таймингов bypass
    timing_pattern = r'intercept_to_send=([0-9.]+)ms.*total_time=([0-9.]+)ms'
    matches = re.findall(timing_pattern, log_content)
    
    if matches:
        timings['intercept_to_send'] = float(matches[-1][0])
        timings['total_time'] = float(matches[-1][1])
    
    return timings

def analyze_segmentation_differences(search_log: str, service_log: str):
    """Анализ различий в сегментации"""
    
    # Извлечение информации о сегментах
    search_segments = extract_segment_info(search_log)
    service_segments = extract_segment_info(service_log)
    
    print(f"Режим поиска: {len(search_segments)} сегментов")
    print(f"Режим службы: {len(service_segments)} сегментов")
    
    if search_segments and service_segments:
        # Сравнение размеров
        search_sizes = [s['size'] for s in search_segments if 'size' in s]
        service_sizes = [s['size'] for s in service_segments if 'size' in s]
        
        if search_sizes and service_sizes:
            search_total = sum(search_sizes)
            service_total = sum(service_sizes)
            
            print(f"Общий размер данных: поиск={search_total}б, служба={service_total}б")
            
            if abs(search_total - service_total) > 100:
                print(f"⚠️ Значительная разница в объёме данных: {abs(search_total - service_total)}б")

def extract_segment_info(log_content: str) -> List[Dict[str, Any]]:
    """Извлечение информации о сегментах"""
    segments = []
    
    # Поиск сегментов
    segment_pattern = r'Segment (\d+)/(\d+): len=(\d+)'
    matches = re.findall(segment_pattern, log_content)
    
    for match in matches:
        segments.append({
            'number': int(match[0]),
            'total': int(match[1]),
            'size': int(match[2])
        })
    
    return segments

def generate_fix_recommendations():
    """Генерация рекомендаций по исправлению"""
    
    print(f"\n💡 РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ:")
    
    recommendations = [
        "1. Увеличить задержки между пакетами в службе (добавить sleep)",
        "2. Проверить настройки WinDivert в службе vs режиме поиска",
        "3. Добавить retry логику при ошибках отправки",
        "4. Оптимизировать производительность обработки пакетов",
        "5. Проверить права доступа и приоритет процесса службы",
        "6. Добавить мониторинг сетевых ошибок",
        "7. Рассмотреть использование другого метода отправки пакетов"
    ]
    
    for rec in recommendations:
        print(f"  {rec}")
    
    print(f"\n🔧 КОНКРЕТНЫЕ ДЕЙСТВИЯ:")
    print(f"  1. Добавить в службу: time.sleep(0.005) между отправкой пакетов")
    print(f"  2. Проверить, что WinDivert filter одинаковый в обоих режимах")
    print(f"  3. Добавить логирование всех WinDivert операций")
    print(f"  4. Сравнить приоритеты процессов (режим поиска vs служба)")

def main():
    """Основная функция"""
    
    analyze_retransmission_patterns()
    generate_fix_recommendations()
    
    print(f"\n" + "=" * 60)
    print("ЗАКЛЮЧЕНИЕ")
    print("=" * 60)
    
    print("""
🎯 КОРНЕВАЯ ПРИЧИНА РЕТРАНСМИССИЙ:
   Служба обхода отправляет пакеты с проблемами, которые приводят к 
   массовым ретрансмиссиям (316 vs 34 в режиме поиска).

🔧 ОСНОВНАЯ ГИПОТЕЗА:
   Различия в сетевом стеке или таймингах между режимами работы.
   Режим поиска работает в контексте CLI, служба - как системный сервис.

⚡ ПЕРВООЧЕРЕДНЫЕ ДЕЙСТВИЯ:
   1. Добавить задержки между пакетами в службе
   2. Проверить настройки WinDivert
   3. Сравнить права доступа и приоритеты процессов
""")

if __name__ == "__main__":
    main()