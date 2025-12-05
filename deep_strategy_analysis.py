#!/usr/bin/env python3
"""
Глубокий анализ стратегий - детальное изучение того, как стратегии применяются и почему не работают
"""

import json
from collections import defaultdict

def analyze_packet_details(packets):
    """Детальный анализ каждого пакета"""
    analysis = {
        'total_packets': len(packets),
        'tcp_packets': 0,
        'tls_packets': 0,
        'small_packets': 0,
        'fake_candidates': 0,
        'split_evidence': 0,
        'timing_anomalies': 0,
        'ttl_variations': set(),
        'packet_sizes': [],
        'sequence_analysis': {},
        'detailed_packets': []
    }
    
    timestamps = []
    sequences = []
    
    for i, packet in enumerate(packets):
        packet_detail = {
            'index': i,
            'num': packet.get('num'),
            'timestamp': packet.get('timestamp'),
            'src_ip': packet.get('src_ip'),
            'dst_ip': packet.get('dst_ip'),
            'src_port': packet.get('src_port'),
            'dst_port': packet.get('dst_port'),
            'ttl': packet.get('ttl'),
            'payload_len': packet.get('payload_len', 0),
            'flags': packet.get('flags', ''),
            'seq': packet.get('seq'),
            'ack': packet.get('ack'),
            'analysis': {}
        }
        
        # TCP анализ
        if packet.get('src_port') or packet.get('dst_port'):
            analysis['tcp_packets'] += 1
            
            # TTL анализ
            ttl = packet.get('ttl')
            if ttl:
                analysis['ttl_variations'].add(ttl)
                
                # Низкий TTL = возможный fake пакет
                if ttl <= 5:
                    analysis['fake_candidates'] += 1
                    packet_detail['analysis']['likely_fake'] = True
                    packet_detail['analysis']['fake_reason'] = f"Low TTL: {ttl}"
            
            # Размер payload
            payload_len = packet.get('payload_len', 0)
            analysis['packet_sizes'].append(payload_len)
            
            # Маленькие пакеты = возможный split
            if payload_len > 0 and payload_len <= 10:
                analysis['small_packets'] += 1
                analysis['split_evidence'] += 1
                packet_detail['analysis']['likely_split'] = True
                packet_detail['analysis']['split_reason'] = f"Small payload: {payload_len} bytes"
            
            # TLS анализ
            payload_hex = packet.get('payload_hex', '')
            if payload_hex and payload_hex.startswith('16'):
                analysis['tls_packets'] += 1
                packet_detail['analysis']['tls_packet'] = True
                
                # Анализ TLS record
                if len(payload_hex) >= 10:
                    try:
                        tls_version = payload_hex[2:6]
                        tls_length = int(payload_hex[6:10], 16)
                        packet_detail['analysis']['tls_version'] = tls_version
                        packet_detail['analysis']['tls_length'] = tls_length
                        
                        # Фрагментированный TLS handshake
                        if payload_len < 100 and tls_length > payload_len:
                            packet_detail['analysis']['fragmented_tls'] = True
                    except:
                        pass
            
            # Sequence анализ
            seq = packet.get('seq')
            if seq is not None:
                sequences.append((i, seq))
        
        # Timing анализ
        timestamp = packet.get('timestamp')
        if timestamp:
            timestamps.append((i, timestamp))
        
        analysis['detailed_packets'].append(packet_detail)
    
    # Анализ последовательности
    if len(sequences) > 1:
        disorder_count = 0
        for i in range(1, len(sequences)):
            if sequences[i][1] < sequences[i-1][1]:
                disorder_count += 1
                # Отмечаем пакеты с нарушением порядка
                analysis['detailed_packets'][sequences[i][0]]['analysis']['out_of_order'] = True
        
        analysis['sequence_analysis']['disorder_count'] = disorder_count
        analysis['sequence_analysis']['total_sequences'] = len(sequences)
    
    # Анализ тайминга
    if len(timestamps) > 1:
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i][1] - timestamps[i-1][1]
            intervals.append(interval)
            
            # Очень быстрые интервалы (возможно fake пакеты)
            if interval < 0.001:
                analysis['timing_anomalies'] += 1
                analysis['detailed_packets'][timestamps[i][0]]['analysis']['fast_timing'] = True
        
        if intervals:
            analysis['sequence_analysis']['avg_interval'] = sum(intervals) / len(intervals)
            analysis['sequence_analysis']['min_interval'] = min(intervals)
            analysis['sequence_analysis']['max_interval'] = max(intervals)
    
    # Преобразуем set в list для JSON
    analysis['ttl_variations'] = list(analysis['ttl_variations'])
    
    return analysis

def identify_strategy_type(analysis):
    """Определение типа примененной стратегии на основе анализа"""
    strategies = []
    
    # Split стратегия
    if analysis['split_evidence'] > 0:
        strategies.append({
            'type': 'split',
            'confidence': min(analysis['split_evidence'] / analysis['total_packets'], 1.0),
            'evidence': f"{analysis['split_evidence']} small packets detected"
        })
    
    # Fake стратегия
    if analysis['fake_candidates'] > 0:
        strategies.append({
            'type': 'fake',
            'confidence': min(analysis['fake_candidates'] / analysis['total_packets'], 1.0),
            'evidence': f"{analysis['fake_candidates']} low-TTL packets detected"
        })
    
    # Disorder стратегия
    disorder_count = analysis['sequence_analysis'].get('disorder_count', 0)
    if disorder_count > 0:
        strategies.append({
            'type': 'disorder',
            'confidence': min(disorder_count / analysis['tcp_packets'], 1.0) if analysis['tcp_packets'] > 0 else 0,
            'evidence': f"{disorder_count} out-of-order packets detected"
        })
    
    # Multisplit стратегия
    if analysis['split_evidence'] > 2:
        strategies.append({
            'type': 'multisplit',
            'confidence': min(analysis['split_evidence'] / 5, 1.0),
            'evidence': f"Multiple small packets: {analysis['split_evidence']}"
        })
    
    # Timing-based стратегия
    if analysis['timing_anomalies'] > 0:
        strategies.append({
            'type': 'timing',
            'confidence': min(analysis['timing_anomalies'] / analysis['total_packets'], 1.0),
            'evidence': f"{analysis['timing_anomalies']} timing anomalies detected"
        })
    
    return strategies

def analyze_failure_reasons(analysis):
    """Анализ возможных причин неудачи стратегий"""
    reasons = []
    
    # Проверка на DPI обнаружение
    if analysis['tls_packets'] > 0 and analysis['split_evidence'] > 0:
        reasons.append({
            'category': 'DPI_DETECTION',
            'reason': 'DPI может обнаруживать фрагментированный TLS handshake',
            'severity': 'HIGH',
            'recommendation': 'Попробовать более агрессивную фрагментацию или обфускацию'
        })
    
    # Проверка TTL эффективности
    ttl_variations = len(analysis['ttl_variations'])
    if ttl_variations > 1 and analysis['fake_candidates'] == 0:
        reasons.append({
            'category': 'TTL_INEFFECTIVE',
            'reason': 'TTL вариации есть, но нет низких TTL для fake пакетов',
            'severity': 'MEDIUM',
            'recommendation': 'Использовать более низкие TTL значения (1-3)'
        })
    
    # Проверка размеров пакетов
    if analysis['packet_sizes']:
        avg_size = sum(analysis['packet_sizes']) / len(analysis['packet_sizes'])
        if avg_size > 100 and analysis['split_evidence'] == 0:
            reasons.append({
                'category': 'INSUFFICIENT_FRAGMENTATION',
                'reason': f'Средний размер пакета {avg_size:.1f} байт - недостаточная фрагментация',
                'severity': 'HIGH',
                'recommendation': 'Увеличить агрессивность split стратегий'
            })
    
    # Проверка timing атак
    timing_info = analysis['sequence_analysis']
    if timing_info.get('min_interval', 1) > 0.01:
        reasons.append({
            'category': 'TIMING_INEFFECTIVE',
            'reason': f'Минимальный интервал {timing_info.get("min_interval", 0):.3f}s - недостаточно быстро',
            'severity': 'LOW',
            'recommendation': 'Использовать более агрессивные timing атаки'
        })
    
    return reasons

def main():
    print("🔬 Глубокий анализ применения стратегий")
    print("=" * 60)
    
    # Загружаем adapt.json
    try:
        with open("adapt.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("❌ Файл adapt.json не найден")
        return
    
    flows = data.get("flows", {})
    
    print(f"📊 Глубокий анализ {len(flows)} потоков")
    
    all_results = {}
    
    for flow_name, packets in flows.items():
        print(f"\n🔗 Поток: {flow_name}")
        print(f"   Пакетов: {len(packets)}")
        
        # Детальный анализ
        analysis = analyze_packet_details(packets)
        
        # Определение стратегий
        strategies = identify_strategy_type(analysis)
        
        # Анализ причин неудач
        failure_reasons = analyze_failure_reasons(analysis)
        
        print(f"   📋 Статистика:")
        print(f"     TCP пакеты: {analysis['tcp_packets']}")
        print(f"     TLS пакеты: {analysis['tls_packets']}")
        print(f"     Маленькие пакеты: {analysis['small_packets']}")
        print(f"     Кандидаты в fake: {analysis['fake_candidates']}")
        print(f"     TTL вариации: {analysis['ttl_variations']}")
        
        if analysis['packet_sizes']:
            avg_size = sum(analysis['packet_sizes']) / len(analysis['packet_sizes'])
            print(f"     Средний размер: {avg_size:.1f} байт")
        
        print(f"   🎯 Обнаруженные стратегии:")
        if strategies:
            for strategy in strategies:
                confidence_pct = strategy['confidence'] * 100
                print(f"     ✅ {strategy['type']}: {confidence_pct:.1f}% ({strategy['evidence']})")
        else:
            print(f"     ❌ Стратегии не обнаружены")
        
        print(f"   ⚠️  Причины неудач:")
        if failure_reasons:
            for reason in failure_reasons:
                severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}[reason['severity']]
                print(f"     {severity_icon} {reason['category']}: {reason['reason']}")
                print(f"        💡 {reason['recommendation']}")
        else:
            print(f"     ✅ Очевидных проблем не обнаружено")
        
        # Детальный анализ пакетов
        print(f"   📦 Детали пакетов:")
        for packet in analysis['detailed_packets'][:5]:  # Показываем первые 5
            packet_analysis = packet.get('analysis', {})
            flags_str = f" flags={packet['flags']}" if packet['flags'] else ""
            ttl_str = f" TTL={packet['ttl']}" if packet['ttl'] else ""
            payload_str = f" payload={packet['payload_len']}" if packet['payload_len'] else ""
            
            analysis_tags = []
            if packet_analysis.get('likely_fake'):
                analysis_tags.append("FAKE")
            if packet_analysis.get('likely_split'):
                analysis_tags.append("SPLIT")
            if packet_analysis.get('tls_packet'):
                analysis_tags.append("TLS")
            if packet_analysis.get('out_of_order'):
                analysis_tags.append("DISORDER")
            if packet_analysis.get('fast_timing'):
                analysis_tags.append("FAST")
            
            tags_str = f" [{','.join(analysis_tags)}]" if analysis_tags else ""
            
            print(f"     #{packet['num']}: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']}{ttl_str}{payload_str}{flags_str}{tags_str}")
        
        if len(analysis['detailed_packets']) > 5:
            print(f"     ... и еще {len(analysis['detailed_packets']) - 5} пакетов")
        
        all_results[flow_name] = {
            'analysis': analysis,
            'strategies': strategies,
            'failure_reasons': failure_reasons
        }
    
    # Общие выводы
    print(f"\n📊 ОБЩИЕ ВЫВОДЫ:")
    
    total_strategies = sum(len(result['strategies']) for result in all_results.values())
    total_flows_with_strategies = sum(1 for result in all_results.values() if result['strategies'])
    
    print(f"   Потоков со стратегиями: {total_flows_with_strategies}/{len(flows)}")
    print(f"   Всего обнаружено стратегий: {total_strategies}")
    
    # Статистика по типам стратегий
    strategy_stats = defaultdict(int)
    for result in all_results.values():
        for strategy in result['strategies']:
            strategy_stats[strategy['type']] += 1
    
    print(f"   Статистика стратегий:")
    for strategy_type, count in strategy_stats.items():
        print(f"     {strategy_type}: {count} потоков")
    
    # Основные проблемы
    problem_stats = defaultdict(int)
    for result in all_results.values():
        for reason in result['failure_reasons']:
            problem_stats[reason['category']] += 1
    
    print(f"   Основные проблемы:")
    for problem_type, count in problem_stats.items():
        print(f"     {problem_type}: {count} потоков")
    
    # Рекомендации
    print(f"\n💡 ИТОГОВЫЕ РЕКОМЕНДАЦИИ:")
    
    if total_flows_with_strategies == 0:
        print("   ❌ КРИТИЧНО: Стратегии не применяются!")
        print("     1. Проверить активацию bypass engine")
        print("     2. Убедиться в корректности параметров")
        print("     3. Проверить WinDivert функциональность")
    elif total_flows_with_strategies < len(flows):
        print("   ⚠️  ЧАСТИЧНО: Стратегии применяются не ко всем потокам")
        print("     1. Проверить фильтрацию трафика")
        print("     2. Убедиться в корректности доменных правил")
    else:
        print("   ✅ Стратегии применяются, но DPI адаптировался")
        
        if 'DPI_DETECTION' in problem_stats:
            print("     1. DPI обнаруживает модификации - нужны более скрытные техники")
        if 'INSUFFICIENT_FRAGMENTATION' in problem_stats:
            print("     2. Увеличить агрессивность фрагментации")
        if 'TTL_INEFFECTIVE' in problem_stats:
            print("     3. Использовать более низкие TTL значения")
        
        print("     4. Рассмотреть экспериментальные подходы:")
        print("        - Обфускация SNI")
        print("        - Туннелирование через другие протоколы")
        print("        - Использование CDN/прокси")
    
    # Сохранение результатов
    with open("deep_strategy_analysis.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"\n💾 Детальные результаты сохранены в deep_strategy_analysis.json")

if __name__ == "__main__":
    main()