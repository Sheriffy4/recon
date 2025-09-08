#!/usr/bin/env python3
"""
Анализ различий между recon и zapret для понимания проблемы с 0 открытых доменов.

Сравнивает:
1. recon_report_20250902_115640.json (0 открытых доменов)
2. test_log_zapret_iter_4_20250901_105104.txt (27 открытых доменов)
3. out.pcap (трафик recon)
4. zapret.pcap (трафик zapret)

Цель: найти причину, почему recon не работает с той же стратегией.
"""

import json
import re
import sys
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    print("Scapy не установлен, анализ PCAP будет ограничен")
    SCAPY_AVAILABLE = False


@dataclass
class TestResult:
    """Результат тестирования домена."""
    domain: str
    status: str  # WORKING/NOT WORKING/BLOCKED
    latency: float
    error: Optional[str] = None
    http_code: Optional[int] = None


@dataclass
class StrategyComparison:
    """Сравнение стратегий между recon и zapret."""
    recon_strategy: str
    zapret_strategy: str
    recon_results: List[TestResult]
    zapret_results: List[TestResult]
    recon_success_count: int
    zapret_success_count: int


def parse_recon_report(report_path: str) -> Dict[str, Any]:
    """Парсит отчет recon."""
    print(f"Анализируем отчет recon: {report_path}")
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"✅ Отчет recon загружен:")
        print(f"   - Всего стратегий протестировано: {data.get('total_strategies_tested', 0)}")
        print(f"   - Рабочих стратегий найдено: {data.get('working_strategies_found', 0)}")
        print(f"   - Процент успеха: {data.get('success_rate', 0)*100:.1f}%")
        print(f"   - Время выполнения: {data.get('execution_time_seconds', 0):.1f} сек")
        
        # Анализируем статусы доменов
        domain_status = data.get('domain_status', {})
        blocked_count = sum(1 for status in domain_status.values() if status == 'BLOCKED')
        print(f"   - Заблокированных доменов: {blocked_count}/{len(domain_status)}")
        
        return data
        
    except Exception as e:
        print(f"❌ Ошибка при чтении отчета recon: {e}")
        return {}


def parse_zapret_log(log_path: str) -> Dict[str, List[TestResult]]:
    """Парсит лог zapret."""
    print(f"\nАнализируем лог zapret: {log_path}")
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        strategies = {}
        current_strategy = None
        current_results = []
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Ищем строки с параметрами стратегии
            if line.startswith('Raw Params:'):
                if current_strategy and current_results:
                    strategies[current_strategy] = current_results
                
                current_strategy = line.replace('Raw Params: ', '')
                current_results = []
                continue
            
            # Ищем строки с результатами
            if 'URL:' in line and ('WORKING' in line or 'NOT WORKING' in line):
                try:
                    # Парсим результат
                    status = 'WORKING' if 'WORKING' in line else 'NOT WORKING'
                    
                    # Извлекаем URL
                    url_match = re.search(r'URL: (https://[^\s|]+)', line)
                    domain = url_match.group(1).replace('https://', '') if url_match else 'unknown'
                    
                    # Извлекаем latency
                    latency_match = re.search(r'Latency: ([\d.]+) ms', line)
                    latency = float(latency_match.group(1)) if latency_match else 0.0
                    
                    # Извлекаем HTTP код
                    http_match = re.search(r'HTTP: (\d+)', line)
                    http_code = int(http_match.group(1)) if http_match else None
                    
                    # Извлекаем ошибку
                    error_match = re.search(r'Error: ([^)]+)', line)
                    error = error_match.group(1) if error_match else None
                    
                    result = TestResult(
                        domain=domain,
                        status=status,
                        latency=latency,
                        error=error,
                        http_code=http_code
                    )
                    current_results.append(result)
                    
                except Exception as e:
                    print(f"⚠️  Ошибка парсинга строки: {line[:100]}... - {e}")
                    continue
            
            # Ищем строки с количеством успехов
            if line.startswith('Successes:'):
                success_match = re.search(r'Successes: (\d+)/(\d+)', line)
                if success_match and current_strategy:
                    success_count = int(success_match.group(1))
                    total_count = int(success_match.group(2))
                    print(f"   Стратегия: {current_strategy[:50]}...")
                    print(f"   Успехов: {success_count}/{total_count}")
        
        # Добавляем последнюю стратегию
        if current_strategy and current_results:
            strategies[current_strategy] = current_results
        
        print(f"✅ Лог zapret проанализирован: найдено {len(strategies)} стратегий")
        
        return strategies
        
    except Exception as e:
        print(f"❌ Ошибка при чтении лога zapret: {e}")
        return {}


def analyze_pcap_file(pcap_path: str, name: str) -> Dict[str, Any]:
    """Анализирует PCAP файл."""
    print(f"\nАнализируем PCAP {name}: {pcap_path}")
    
    if not SCAPY_AVAILABLE:
        print("⚠️  Scapy недоступен, пропускаем анализ PCAP")
        return {}
    
    if not os.path.exists(pcap_path):
        print(f"❌ Файл {pcap_path} не найден")
        return {}
    
    try:
        packets = rdpcap(pcap_path)
        
        analysis = {
            'total_packets': len(packets),
            'tcp_packets': 0,
            'tls_packets': 0,
            'unique_destinations': set(),
            'ttl_values': defaultdict(int),
            'packet_sizes': [],
            'tcp_flags': defaultdict(int),
            'fake_packets': 0,
            'disorder_packets': 0
        }
        
        for packet in packets:
            if IP in packet:
                # TTL анализ
                ttl = packet[IP].ttl
                analysis['ttl_values'][ttl] += 1
                
                # Размеры пакетов
                analysis['packet_sizes'].append(len(packet))
                
                # Уникальные назначения
                analysis['unique_destinations'].add(packet[IP].dst)
                
                if TCP in packet:
                    analysis['tcp_packets'] += 1
                    
                    # TCP флаги
                    flags = packet[TCP].flags
                    analysis['tcp_flags'][flags] += 1
                    
                    # Проверяем на TLS (порт 443)
                    if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        analysis['tls_packets'] += 1
                    
                    # Ищем признаки fake/disorder атак
                    if Raw in packet:
                        payload = bytes(packet[Raw])
                        
                        # Простая эвристика для fake пакетов
                        if b'PAYLOADTLS' in payload or len(payload) < 10:
                            analysis['fake_packets'] += 1
                        
                        # Эвристика для disorder (дублированные seq)
                        # Это упрощенная проверка
                        if len(payload) > 0:
                            analysis['disorder_packets'] += 1
        
        # Конвертируем set в list для JSON
        analysis['unique_destinations'] = list(analysis['unique_destinations'])
        analysis['ttl_values'] = dict(analysis['ttl_values'])
        analysis['tcp_flags'] = dict(analysis['tcp_flags'])
        
        print(f"✅ PCAP {name} проанализирован:")
        print(f"   - Всего пакетов: {analysis['total_packets']}")
        print(f"   - TCP пакетов: {analysis['tcp_packets']}")
        print(f"   - TLS пакетов: {analysis['tls_packets']}")
        print(f"   - Уникальных назначений: {len(analysis['unique_destinations'])}")
        print(f"   - TTL значения: {analysis['ttl_values']}")
        print(f"   - Возможных fake пакетов: {analysis['fake_packets']}")
        
        return analysis
        
    except Exception as e:
        print(f"❌ Ошибка при анализе PCAP {name}: {e}")
        return {}


def find_matching_strategy(recon_data: Dict[str, Any], zapret_strategies: Dict[str, List[TestResult]]) -> Optional[str]:
    """Находит соответствующую стратегию zapret для recon."""
    
    # Получаем стратегию recon
    recon_results = recon_data.get('all_results', [])
    if not recon_results:
        return None
    
    recon_strategy_dict = recon_results[0].get('strategy_dict', {})
    recon_params = recon_strategy_dict.get('params', {})
    
    print(f"\nИщем соответствующую стратегию zapret для recon:")
    print(f"Recon стратегия: {recon_strategy_dict}")
    
    # Ключевые параметры для сравнения
    key_params = {
        'overlap_size': recon_params.get('overlap_size'),
        'split_pos': recon_params.get('split_pos'),
        'ttl': recon_params.get('ttl'),
        'autottl': recon_params.get('autottl'),
        'fooling': recon_params.get('fooling', [])
    }
    
    print(f"Ключевые параметры recon: {key_params}")
    
    # Ищем похожую стратегию в zapret
    for zapret_strategy, results in zapret_strategies.items():
        print(f"\nПроверяем zapret стратегию: {zapret_strategy}")
        
        # Проверяем основные параметры
        matches = 0
        total_checks = 0
        
        # Проверяем split-seqovl (overlap_size)
        if key_params['overlap_size'] is not None:
            total_checks += 1
            if f"split-seqovl={key_params['overlap_size']}" in zapret_strategy:
                matches += 1
                print(f"  ✅ split-seqovl совпадает: {key_params['overlap_size']}")
            else:
                print(f"  ❌ split-seqovl не совпадает: ожидали {key_params['overlap_size']}")
        
        # Проверяем split-pos
        if key_params['split_pos'] is not None:
            total_checks += 1
            if f"split-pos={key_params['split_pos']}" in zapret_strategy:
                matches += 1
                print(f"  ✅ split-pos совпадает: {key_params['split_pos']}")
            else:
                print(f"  ❌ split-pos не совпадает: ожидали {key_params['split_pos']}")
        
        # Проверяем autottl
        if key_params['autottl'] is not None:
            total_checks += 1
            if f"autottl={key_params['autottl']}" in zapret_strategy:
                matches += 1
                print(f"  ✅ autottl совпадает: {key_params['autottl']}")
            else:
                print(f"  ❌ autottl не совпадает: ожидали {key_params['autottl']}")
        
        # Проверяем fooling методы
        if key_params['fooling']:
            total_checks += 1
            fooling_str = ','.join(key_params['fooling'])
            if fooling_str in zapret_strategy or all(method in zapret_strategy for method in key_params['fooling']):
                matches += 1
                print(f"  ✅ fooling совпадает: {key_params['fooling']}")
            else:
                print(f"  ❌ fooling не совпадает: ожидали {key_params['fooling']}")
        
        # Проверяем fake,fakeddisorder
        if 'fakeddisorder' in recon_strategy_dict.get('name', ''):
            total_checks += 1
            if 'fake,fakeddisorder' in zapret_strategy or 'fakeddisorder' in zapret_strategy:
                matches += 1
                print(f"  ✅ fakeddisorder метод совпадает")
            else:
                print(f"  ❌ fakeddisorder метод не совпадает")
        
        match_ratio = matches / total_checks if total_checks > 0 else 0
        print(f"  Совпадений: {matches}/{total_checks} ({match_ratio*100:.1f}%)")
        
        # Если совпадает больше 70% параметров, считаем это соответствующей стратегией
        if match_ratio >= 0.7:
            success_count = sum(1 for r in results if r.status == 'WORKING')
            print(f"  🎯 НАЙДЕНА СООТВЕТСТВУЮЩАЯ СТРАТЕГИЯ! Успехов: {success_count}/{len(results)}")
            return zapret_strategy
    
    print("❌ Соответствующая стратегия zapret не найдена")
    return None


def compare_strategies(recon_data: Dict[str, Any], zapret_strategies: Dict[str, List[TestResult]]) -> StrategyComparison:
    """Сравнивает стратегии recon и zapret."""
    
    # Находим соответствующую стратегию
    matching_zapret_strategy = find_matching_strategy(recon_data, zapret_strategies)
    
    if not matching_zapret_strategy:
        print("❌ Не удалось найти соответствующую стратегию zapret")
        return None
    
    # Получаем результаты recon
    recon_results = []
    domain_status = recon_data.get('domain_status', {})
    for domain, status in domain_status.items():
        domain_clean = domain.replace('https://', '')
        result = TestResult(
            domain=domain_clean,
            status='BLOCKED' if status == 'BLOCKED' else 'NOT WORKING',
            latency=0.0
        )
        recon_results.append(result)
    
    # Получаем результаты zapret
    zapret_results = zapret_strategies[matching_zapret_strategy]
    
    # Подсчитываем успехи
    recon_success_count = sum(1 for r in recon_results if r.status == 'WORKING')
    zapret_success_count = sum(1 for r in zapret_results if r.status == 'WORKING')
    
    recon_strategy_str = str(recon_data.get('all_results', [{}])[0].get('strategy_dict', {}))
    
    comparison = StrategyComparison(
        recon_strategy=recon_strategy_str,
        zapret_strategy=matching_zapret_strategy,
        recon_results=recon_results,
        zapret_results=zapret_results,
        recon_success_count=recon_success_count,
        zapret_success_count=zapret_success_count
    )
    
    return comparison


def analyze_differences(comparison: StrategyComparison, recon_pcap: Dict[str, Any], zapret_pcap: Dict[str, Any]):
    """Анализирует различия между recon и zapret."""
    
    print(f"\n" + "="*80)
    print("АНАЛИЗ РАЗЛИЧИЙ МЕЖДУ RECON И ZAPRET")
    print("="*80)
    
    print(f"\n📊 СРАВНЕНИЕ РЕЗУЛЬТАТОВ:")
    print(f"   Recon успехов: {comparison.recon_success_count}/{len(comparison.recon_results)}")
    print(f"   Zapret успехов: {comparison.zapret_success_count}/{len(comparison.zapret_results)}")
    print(f"   Разница: {comparison.zapret_success_count - comparison.recon_success_count} доменов")
    
    print(f"\n🔧 СТРАТЕГИИ:")
    print(f"   Recon:  {comparison.recon_strategy[:100]}...")
    print(f"   Zapret: {comparison.zapret_strategy[:100]}...")
    
    print(f"\n📦 АНАЛИЗ ТРАФИКА:")
    if recon_pcap and zapret_pcap:
        print(f"   Recon PCAP:")
        print(f"     - Всего пакетов: {recon_pcap.get('total_packets', 0)}")
        print(f"     - TCP пакетов: {recon_pcap.get('tcp_packets', 0)}")
        print(f"     - TTL значения: {recon_pcap.get('ttl_values', {})}")
        print(f"     - Fake пакетов: {recon_pcap.get('fake_packets', 0)}")
        
        print(f"   Zapret PCAP:")
        print(f"     - Всего пакетов: {zapret_pcap.get('total_packets', 0)}")
        print(f"     - TCP пакетов: {zapret_pcap.get('tcp_packets', 0)}")
        print(f"     - TTL значения: {zapret_pcap.get('ttl_values', {})}")
        print(f"     - Fake пакетов: {zapret_pcap.get('fake_packets', 0)}")
        
        # Сравниваем TTL
        recon_ttls = recon_pcap.get('ttl_values', {})
        zapret_ttls = zapret_pcap.get('ttl_values', {})
        
        print(f"\n🎯 КЛЮЧЕВЫЕ РАЗЛИЧИЯ:")
        
        if recon_ttls != zapret_ttls:
            print(f"   ❌ TTL значения различаются:")
            print(f"      Recon TTL:  {recon_ttls}")
            print(f"      Zapret TTL: {zapret_ttls}")
        else:
            print(f"   ✅ TTL значения совпадают: {recon_ttls}")
        
        # Сравниваем количество пакетов
        recon_packets = recon_pcap.get('total_packets', 0)
        zapret_packets = zapret_pcap.get('total_packets', 0)
        
        if abs(recon_packets - zapret_packets) > zapret_packets * 0.1:  # Разница больше 10%
            print(f"   ❌ Значительная разница в количестве пакетов:")
            print(f"      Recon: {recon_packets}, Zapret: {zapret_packets}")
        else:
            print(f"   ✅ Количество пакетов сопоставимо: Recon={recon_packets}, Zapret={zapret_packets}")
    
    print(f"\n🔍 АНАЛИЗ ДОМЕНОВ:")
    
    # Создаем словари для быстрого поиска
    recon_domains = {r.domain: r for r in comparison.recon_results}
    zapret_domains = {r.domain: r for r in comparison.zapret_results}
    
    # Находим общие домены
    common_domains = set(recon_domains.keys()) & set(zapret_domains.keys())
    
    working_in_zapret_only = []
    
    for domain in common_domains:
        recon_result = recon_domains[domain]
        zapret_result = zapret_domains[domain]
        
        if zapret_result.status == 'WORKING' and recon_result.status != 'WORKING':
            working_in_zapret_only.append((domain, zapret_result, recon_result))
    
    if working_in_zapret_only:
        print(f"   ❌ Домены, работающие только в zapret ({len(working_in_zapret_only)}):")
        for domain, zapret_res, recon_res in working_in_zapret_only[:10]:  # Показываем первые 10
            print(f"      {domain}: zapret={zapret_res.status} (HTTP {zapret_res.http_code}), recon={recon_res.status}")
    else:
        print(f"   ✅ Нет доменов, работающих только в zapret")
    
    print(f"\n💡 ВОЗМОЖНЫЕ ПРИЧИНЫ ПРОБЛЕМЫ:")
    
    reasons = []
    
    # Проверяем TTL
    if recon_pcap and zapret_pcap:
        recon_ttls = recon_pcap.get('ttl_values', {})
        zapret_ttls = zapret_pcap.get('ttl_values', {})
        
        if recon_ttls != zapret_ttls:
            reasons.append("TTL значения различаются - возможно, неправильная реализация TTL в recon")
        
        # Проверяем наличие fake пакетов
        recon_fakes = recon_pcap.get('fake_packets', 0)
        zapret_fakes = zapret_pcap.get('fake_packets', 0)
        
        if recon_fakes == 0 and zapret_fakes > 0:
            reasons.append("Recon не генерирует fake пакеты, а zapret генерирует")
        elif recon_fakes != zapret_fakes:
            reasons.append(f"Разное количество fake пакетов: recon={recon_fakes}, zapret={zapret_fakes}")
    
    # Проверяем результаты
    if comparison.recon_success_count == 0 and comparison.zapret_success_count > 0:
        reasons.append("Recon вообще не открывает домены - возможно, атака не работает")
    
    if not reasons:
        reasons.append("Причина неясна - требуется более детальный анализ")
    
    for i, reason in enumerate(reasons, 1):
        print(f"   {i}. {reason}")
    
    return reasons


def main():
    """Основная функция анализа."""
    print("🔍 АНАЛИЗ РАЗЛИЧИЙ МЕЖДУ RECON И ZAPRET")
    print("="*60)
    
    # Пути к файлам
    recon_report_path = "recon_report_20250902_115640.json"
    zapret_log_path = "test_log_zapret_iter_4_20250901_105104.txt"
    recon_pcap_path = "out.pcap"
    zapret_pcap_path = "zapret.pcap"
    
    # Анализируем отчеты
    recon_data = parse_recon_report(recon_report_path)
    zapret_strategies = parse_zapret_log(zapret_log_path)
    
    if not recon_data or not zapret_strategies:
        print("❌ Не удалось загрузить данные для анализа")
        return 1
    
    # Анализируем PCAP файлы
    recon_pcap = analyze_pcap_file(recon_pcap_path, "recon")
    zapret_pcap = analyze_pcap_file(zapret_pcap_path, "zapret")
    
    # Сравниваем стратегии
    comparison = compare_strategies(recon_data, zapret_strategies)
    
    if not comparison:
        print("❌ Не удалось сравнить стратегии")
        return 1
    
    # Анализируем различия
    reasons = analyze_differences(comparison, recon_pcap, zapret_pcap)
    
    # Сохраняем результаты
    results = {
        'timestamp': '2025-09-02T12:00:00',
        'recon_report': recon_report_path,
        'zapret_log': zapret_log_path,
        'comparison': {
            'recon_success_count': comparison.recon_success_count,
            'zapret_success_count': comparison.zapret_success_count,
            'difference': comparison.zapret_success_count - comparison.recon_success_count,
            'recon_strategy': comparison.recon_strategy,
            'zapret_strategy': comparison.zapret_strategy
        },
        'pcap_analysis': {
            'recon': recon_pcap,
            'zapret': zapret_pcap
        },
        'possible_reasons': reasons
    }
    
    with open('recon_vs_zapret_analysis.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Анализ завершен! Результаты сохранены в recon_vs_zapret_analysis.json")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())