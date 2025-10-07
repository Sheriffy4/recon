#!/usr/bin/env python3
"""
Диагностический скрипт для анализа проблемы с bypass сервисом.
Анализирует лог и выявляет проблемы.
"""
def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    # Добавляем forced параметры
    if len(args) > 1 and isinstance(args[1], dict):
        # Второй аргумент - стратегия
        strategy = args[1].copy()
        strategy['no_fallbacks'] = True
        strategy['forced'] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")
    
    return original_func(*args, **kwargs)



import re
from collections import defaultdict

def analyze_log(log_file="log.txt"):
    """Анализирует лог файл и выявляет проблемы."""
    
    print("=" * 80)
    print("ДИАГНОСТИКА BYPASS СЕРВИСА")
    print("=" * 80)
    
    with open(log_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Статистика
    stats = {
        'resolved_ips': set(),
        'resolved_domains': set(),
        'bypass_applications': 0,
        'fake_packets': 0,
        'real_packets': 0,
        'retransmissions': defaultdict(int),
        'unique_sequences': set(),
        'sequence_repeats': defaultdict(int)
    }
    
    # Паттерны для поиска
    resolved_pattern = re.compile(r'Resolved (.+?) -> ([\d.]+)')
    bypass_pattern = re.compile(r'Applying bypass for ([\d.]+)')
    fake_pattern = re.compile(r'FAKE.*seq=(0x[0-9A-F]+)')
    real_pattern = re.compile(r'REAL.*seq=(0x[0-9A-F]+)')
    
    for line in lines:
        # Резолвинг доменов
        match = resolved_pattern.search(line)
        if match:
            domain, ip = match.groups()
            stats['resolved_domains'].add(domain)
            stats['resolved_ips'].add(ip)
        
        # Применение bypass
        if 'Applying bypass' in line:
            stats['bypass_applications'] += 1
            match = bypass_pattern.search(line)
            if match:
                ip = match.group(1)
        
        # FAKE пакеты
        match = fake_pattern.search(line)
        if match:
            stats['fake_packets'] += 1
            seq = match.group(1)
            stats['unique_sequences'].add(seq)
            stats['sequence_repeats'][seq] += 1
        
        # REAL пакеты
        match = real_pattern.search(line)
        if match:
            stats['real_packets'] += 1
            seq = match.group(1)
            stats['unique_sequences'].add(seq)
            stats['sequence_repeats'][seq] += 1
    
    # Анализ ретрансмиссий
    for seq, count in stats['sequence_repeats'].items():
        if count > 2:  # Больше 1 пары (fake+real)
            stats['retransmissions'][seq] = count
    
    # Вывод результатов
    print(f"\n📊 СТАТИСТИКА:")
    print(f"  • Резолвнуто доменов: {len(stats['resolved_domains'])}")
    print(f"  • Резолвнуто IP адресов: {len(stats['resolved_ips'])}")
    print(f"  • Применений bypass: {stats['bypass_applications']}")
    print(f"  • Отправлено FAKE пакетов: {stats['fake_packets']}")
    print(f"  • Отправлено REAL пакетов: {stats['real_packets']}")
    print(f"  • Уникальных sequence numbers: {len(stats['unique_sequences'])}")
    
    # Проблемы
    print(f"\n⚠️  ОБНАРУЖЕННЫЕ ПРОБЛЕМЫ:")
    
    if stats['retransmissions']:
        print(f"\n  ❌ РЕТРАНСМИССИИ ОБНАРУЖЕНЫ!")
        print(f"     Найдено {len(stats['retransmissions'])} sequence numbers с повторами:")
        for seq, count in sorted(stats['retransmissions'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"       • {seq}: {count} раз (ожидалось 2)")
        print(f"\n     ПРИЧИНА: Bypass engine перехватывает TCP ретрансмиссии")
        print(f"     РЕШЕНИЕ: Нужно перехватывать только ПЕРВЫЙ пакет с данными")
    else:
        print(f"  ✅ Ретрансмиссий не обнаружено")
    
    # Проверка соотношения fake/real
    if stats['fake_packets'] != stats['real_packets']:
        print(f"\n  ⚠️  Несоответствие количества FAKE и REAL пакетов!")
        print(f"     FAKE: {stats['fake_packets']}, REAL: {stats['real_packets']}")
    else:
        print(f"\n  ✅ Количество FAKE и REAL пакетов совпадает")
    
    # Проверка применения bypass
    expected_applications = len(stats['unique_sequences'])
    if stats['bypass_applications'] > expected_applications * 1.5:
        print(f"\n  ⚠️  Слишком много применений bypass!")
        print(f"     Применений: {stats['bypass_applications']}")
        print(f"     Уникальных пакетов: {expected_applications}")
        print(f"     ПРИЧИНА: Bypass применяется к ретрансмиссиям")
    
    print(f"\n" + "=" * 80)
    print(f"РЕКОМЕНДАЦИИ:")
    print(f"=" * 80)
    
    if stats['retransmissions']:
        print(f"""
1. ПРОБЛЕМА: Bypass engine перехватывает TCP ретрансмиссии вместо первого пакета

2. ПРИЧИНА: WinDivert фильтр перехватывает ВСЕ пакеты к целевым IP, включая:
   - Первый ClientHello (нужно перехватить)
   - Ретрансмиссии ClientHello (НЕ нужно перехватывать)
   - Обычные данные после handshake (НЕ нужно перехватывать)

3. РЕШЕНИЕ: Добавить отслеживание уже обработанных TCP потоков:
   - Создать словарь обработанных потоков: (src_ip, src_port, dst_ip, dst_port)
   - При перехвате ClientHello проверять, не обработан ли уже этот поток
   - Если поток уже обработан → пропустить пакет без bypass
   - Если поток новый → применить bypass и добавить в словарь

4. КОД ДЛЯ ИСПРАВЛЕНИЯ в base_engine.py:

   В методе _run_bypass_loop, перед применением bypass:
   
   ```python
   # Добавить в __init__:
   self._processed_flows = {{}}  # {{flow_key: timestamp}}
   self._flow_timeout = 60.0  # Таймаут для очистки старых потоков
   
   # В _run_bypass_loop, перед apply_bypass:
   if self._is_tls_clienthello(packet.payload):
       flow_key = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
       
       # Проверяем, не обработан ли уже этот поток
       if flow_key in self._processed_flows:
           # Это ретрансмиссия, пропускаем
           w.send(packet)
           continue
       
       # Новый поток, применяем bypass
       self._processed_flows[flow_key] = time.time()
       self.apply_bypass(packet, w, strategy_task, forced=True)
       
       # Очистка старых потоков (опционально)
       current_time = time.time()
       self._processed_flows = {{
           k: v for k, v in self._processed_flows.items()
           if current_time - v < self._flow_timeout
       }}
   ```
""")
    else:
        print(f"\n  ✅ Ретрансмиссий не обнаружено, проблема может быть в другом")
        print(f"\n  Возможные причины:")
        print(f"    1. DPI блокирует пакеты несмотря на bypass")
        print(f"    2. Неправильные параметры bypass стратегий")
        print(f"    3. Проблемы с сетевым стеком Windows")
    
    print(f"\n" + "=" * 80)

if __name__ == "__main__":
    analyze_log()
