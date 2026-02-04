#!/usr/bin/env python3
"""
Анализ различий в сетевом поведении между режимами поиска и службы
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class NetworkMetrics:
    """Сетевые метрики"""
    retransmissions: int
    timing_intercept_to_send: float
    timing_total: float
    segments_sent: int
    packet_delays: List[int]  # Задержки между пакетами в мс
    success: bool
    http_status: Optional[int]
    connection_established: bool

@dataclass
class StrategyExecution:
    """Выполнение стратегии"""
    mode: str  # "search" или "service"
    domain: str
    strategy_name: str
    parameters: Dict[str, any]
    network_metrics: NetworkMetrics
    segments_details: List[Dict[str, any]]

class NetworkBehaviorAnalyzer:
    """Анализатор сетевого поведения"""
    
    def __init__(self):
        self.search_execution = None
        self.service_execution = None
    
    def analyze_log_file(self, log_file: str, mode: str) -> StrategyExecution:
        """Анализ лог файла"""
        
        print(f"\n=== АНАЛИЗ ЛОГА: {log_file} (режим: {mode}) ===")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except FileNotFoundError:
            print(f"❌ Файл {log_file} не найден")
            return None
        
        # Извлечение основной информации
        domain = self._extract_domain(content)
        strategy_name = self._extract_strategy_name(content)
        parameters = self._extract_parameters(content)
        
        # Анализ сетевых метрик
        network_metrics = self._analyze_network_metrics(content)
        
        # Анализ деталей сегментов
        segments_details = self._analyze_segments(content)
        
        return StrategyExecution(
            mode=mode,
            domain=domain,
            strategy_name=strategy_name,
            parameters=parameters,
            network_metrics=network_metrics,
            segments_details=segments_details
        )
    
    def _extract_domain(self, content: str) -> str:
        """Извлечение домена"""
        patterns = [
            r'Domain: ([^\s\n]+\.googlevideo\.com)',
            r'dst=([^\s:]+\.googlevideo\.com)',
            r'SNI: ([^\s\n]+\.googlevideo\.com)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(1)
        
        return "unknown"
    
    def _extract_strategy_name(self, content: str) -> str:
        """Извлечение названия стратегии"""
        patterns = [
            r'strategy=([a-zA-Z_,]+)',
            r'Strategy: ([a-zA-Z_,]+)',
            r'Attack Combination: \[([^\]]+)\]'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if matches:
                return matches[-1]  # Берём последнее совпадение
        
        return "unknown"
    
    def _extract_parameters(self, content: str) -> Dict[str, any]:
        """Извлечение параметров стратегии"""
        params = {}
        
        # Поиск параметров в логах
        param_patterns = [
            r"'split_pos': (\d+)",
            r"split_pos[=:]\s*(\d+)",
            r"'split_count': (\d+)",
            r"split_count[=:]\s*(\d+)",
            r"'disorder_method': '([^']+)'",
            r"disorder_method[=:]\s*'?([^',\s]+)'?",
            r"'ttl': (\d+)",
            r"ttl[=:]\s*(\d+)"
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, content)
            if matches:
                param_name = pattern.split("'")[1] if "'" in pattern else pattern.split("[")[0]
                param_name = param_name.replace("'", "").replace("[=:", "")
                
                try:
                    # Пытаемся преобразовать в число
                    params[param_name] = int(matches[-1])
                except ValueError:
                    # Если не число, оставляем как строку
                    params[param_name] = matches[-1]
        
        return params
    
    def _analyze_network_metrics(self, content: str) -> NetworkMetrics:
        """Анализ сетевых метрик"""
        
        # Поиск ретрансмиссий
        retrans_patterns = [
            r'RETRANSMISSION DETECTED.*total_retrans=(\d+)',
            r'retransmissions detected: (\d+)',
            r'Retransmissions detected: (\d+)'
        ]
        
        retransmissions = 0
        for pattern in retrans_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                retransmissions = max(int(match) for match in matches)
        
        # Поиск таймингов
        timing_patterns = [
            r'intercept_to_send=([0-9.]+)ms.*total_time=([0-9.]+)ms',
            r'Bypass timing: intercept_to_send=([0-9.]+)ms.*total_time=([0-9.]+)ms'
        ]
        
        intercept_to_send = 0.0
        total_time = 0.0
        
        for pattern in timing_patterns:
            matches = re.findall(pattern, content)
            if matches:
                intercept_to_send = float(matches[-1][0])
                total_time = float(matches[-1][1])
                break
        
        # Поиск количества сегментов
        segments_patterns = [
            r'All (\d+) segments sent successfully',
            r'Successfully sent (\d+) segments',
            r'Built (\d+) packets'
        ]
        
        segments_sent = 0
        for pattern in segments_patterns:
            matches = re.findall(pattern, content)
            if matches:
                segments_sent = int(matches[-1])
                break
        
        # Поиск задержек между пакетами
        delay_pattern = r'Delaying (\d+)ms after packet'
        delays = [int(match) for match in re.findall(delay_pattern, content)]
        
        # Определение успеха
        success_indicators = [
            r'HTTP code: (\d+)',
            r'Success: (True|False)',
            r'✅.*sent successfully'
        ]
        
        success = False
        http_status = None
        connection_established = False
        
        for pattern in success_indicators:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                if 'HTTP code' in pattern:
                    http_status = int(matches[-1])
                    connection_established = True
                    success = http_status in [200, 404]  # 404 тоже считается успехом соединения
                elif 'Success' in pattern:
                    success = matches[-1].lower() == 'true'
                elif 'sent successfully' in pattern:
                    success = True
        
        # Если есть ретрансмиссии, это не успех
        if retransmissions > 10:
            success = False
        
        return NetworkMetrics(
            retransmissions=retransmissions,
            timing_intercept_to_send=intercept_to_send,
            timing_total=total_time,
            segments_sent=segments_sent,
            packet_delays=delays,
            success=success,
            http_status=http_status,
            connection_established=connection_established
        )
    
    def _analyze_segments(self, content: str) -> List[Dict[str, any]]:
        """Анализ деталей сегментов"""
        segments = []
        
        # Поиск информации о сегментах
        segment_pattern = r'(REAL|FAKE) \[(\d+)/(\d+)\] seq=0x([A-F0-9]+).*len=(\d+)'
        
        matches = re.findall(segment_pattern, content)
        for match in matches:
            segment_type, num, total, seq, length = match
            segments.append({
                'type': segment_type,
                'number': int(num),
                'total': int(total),
                'sequence': seq,
                'length': int(length)
            })
        
        return segments
    
    def compare_executions(self, search_log: str, service_log: str) -> Dict[str, any]:
        """Сравнение выполнения стратегий"""
        
        print("СРАВНЕНИЕ СЕТЕВОГО ПОВЕДЕНИЯ")
        print("=" * 50)
        
        # Анализ логов
        self.search_execution = self.analyze_log_file(search_log, "search")
        self.service_execution = self.analyze_log_file(service_log, "service")
        
        if not self.search_execution or not self.service_execution:
            return {"error": "Не удалось проанализировать логи"}
        
        # Сравнение
        comparison = {
            "parameters_match": self._compare_parameters(),
            "network_behavior": self._compare_network_behavior(),
            "timing_analysis": self._compare_timing(),
            "segment_analysis": self._compare_segments(),
            "root_cause": self._identify_root_cause(),
            "recommendations": self._generate_recommendations()
        }
        
        return comparison
    
    def _compare_parameters(self) -> Dict[str, any]:
        """Сравнение параметров"""
        search_params = self.search_execution.parameters
        service_params = self.service_execution.parameters
        
        differences = {}
        all_keys = set(search_params.keys()) | set(service_params.keys())
        
        for key in all_keys:
            search_val = search_params.get(key)
            service_val = service_params.get(key)
            
            if search_val != service_val:
                differences[key] = {
                    "search": search_val,
                    "service": service_val
                }
        
        return {
            "search_params": search_params,
            "service_params": service_params,
            "differences": differences,
            "identical": len(differences) == 0
        }
    
    def _compare_network_behavior(self) -> Dict[str, any]:
        """Сравнение сетевого поведения"""
        search_net = self.search_execution.network_metrics
        service_net = self.service_execution.network_metrics
        
        return {
            "retransmissions": {
                "search": search_net.retransmissions,
                "service": service_net.retransmissions,
                "difference": service_net.retransmissions - search_net.retransmissions
            },
            "success": {
                "search": search_net.success,
                "service": service_net.success,
                "match": search_net.success == service_net.success
            },
            "connection": {
                "search": search_net.connection_established,
                "service": service_net.connection_established,
                "match": search_net.connection_established == service_net.connection_established
            },
            "http_status": {
                "search": search_net.http_status,
                "service": search_net.http_status
            },
            "segments_sent": {
                "search": search_net.segments_sent,
                "service": service_net.segments_sent,
                "match": search_net.segments_sent == service_net.segments_sent
            }
        }
    
    def _compare_timing(self) -> Dict[str, any]:
        """Сравнение таймингов"""
        search_net = self.search_execution.network_metrics
        service_net = self.service_execution.network_metrics
        
        return {
            "intercept_to_send": {
                "search": search_net.timing_intercept_to_send,
                "service": service_net.timing_intercept_to_send,
                "ratio": service_net.timing_intercept_to_send / search_net.timing_intercept_to_send if search_net.timing_intercept_to_send > 0 else 0
            },
            "total_time": {
                "search": search_net.timing_total,
                "service": service_net.timing_total,
                "ratio": service_net.timing_total / search_net.timing_total if search_net.timing_total > 0 else 0
            },
            "packet_delays": {
                "search": search_net.packet_delays,
                "service": service_net.packet_delays,
                "search_avg": sum(search_net.packet_delays) / len(search_net.packet_delays) if search_net.packet_delays else 0,
                "service_avg": sum(service_net.packet_delays) / len(service_net.packet_delays) if service_net.packet_delays else 0
            }
        }
    
    def _compare_segments(self) -> Dict[str, any]:
        """Сравнение сегментов"""
        search_segments = self.search_execution.segments_details
        service_segments = self.service_execution.segments_details
        
        return {
            "count": {
                "search": len(search_segments),
                "service": len(service_segments),
                "match": len(search_segments) == len(service_segments)
            },
            "types": {
                "search_real": len([s for s in search_segments if s['type'] == 'REAL']),
                "search_fake": len([s for s in search_segments if s['type'] == 'FAKE']),
                "service_real": len([s for s in service_segments if s['type'] == 'REAL']),
                "service_fake": len([s for s in service_segments if s['type'] == 'FAKE'])
            },
            "lengths": {
                "search": [s['length'] for s in search_segments],
                "service": [s['length'] for s in service_segments]
            }
        }
    
    def _identify_root_cause(self) -> List[str]:
        """Определение корневой причины"""
        causes = []
        
        search_net = self.search_execution.network_metrics
        service_net = self.service_execution.network_metrics
        
        # Анализ ретрансмиссий
        if service_net.retransmissions > search_net.retransmissions + 10:
            causes.append(f"❌ КРИТИЧНО: Массовые ретрансмиссии в службе ({service_net.retransmissions} vs {search_net.retransmissions})")
        
        # Анализ успеха соединения
        if search_net.connection_established and not service_net.connection_established:
            causes.append("❌ КРИТИЧНО: Служба не может установить соединение")
        
        # Анализ таймингов
        if service_net.timing_total > search_net.timing_total * 5:
            causes.append(f"⚠️ Служба работает в {service_net.timing_total / search_net.timing_total:.1f}x раз медленнее")
        
        # Анализ параметров
        param_comparison = self._compare_parameters()
        if not param_comparison["identical"]:
            causes.append("⚠️ Различные параметры стратегий")
        else:
            causes.append("✅ Параметры стратегий идентичны")
        
        return causes
    
    def _generate_recommendations(self) -> List[str]:
        """Генерация рекомендаций"""
        recommendations = []
        
        service_net = self.service_execution.network_metrics
        
        if service_net.retransmissions > 50:
            recommendations.extend([
                "1. Проверить сетевую конфигурацию службы обхода",
                "2. Увеличить задержки между отправкой пакетов",
                "3. Проверить настройки WinDivert в службе",
                "4. Добавить логирование сетевых ошибок"
            ])
        
        if not service_net.connection_established:
            recommendations.extend([
                "5. Проверить, что служба правильно перехватывает пакеты",
                "6. Убедиться, что bypass engine запущен корректно",
                "7. Проверить права доступа службы"
            ])
        
        if service_net.timing_total > 100:  # Более 100мс
            recommendations.extend([
                "8. Оптимизировать производительность службы",
                "9. Уменьшить количество логирования в продакшене"
            ])
        
        return recommendations

def main():
    """Основная функция"""
    
    analyzer = NetworkBehaviorAnalyzer()
    
    # Файлы логов
    search_log = "log2.txt"  # Режим поиска
    service_log = "log.txt"  # Режим службы
    
    # Проверка существования файлов
    if not Path(search_log).exists():
        print(f"❌ Файл {search_log} не найден")
        return
    
    if not Path(service_log).exists():
        print(f"❌ Файл {service_log} не найден")
        return
    
    # Выполнение сравнения
    comparison = analyzer.compare_executions(search_log, service_log)
    
    # Вывод результатов
    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТЫ АНАЛИЗА СЕТЕВОГО ПОВЕДЕНИЯ")
    print("=" * 60)
    
    # Параметры
    params = comparison.get("parameters_match", {})
    print(f"\n📋 ПАРАМЕТРЫ СТРАТЕГИЙ:")
    print(f"Идентичны: {'✅' if params.get('identical') else '❌'}")
    if not params.get('identical'):
        for key, diff in params.get('differences', {}).items():
            print(f"  {key}: поиск={diff['search']}, служба={diff['service']}")
    
    # Сетевое поведение
    network = comparison.get("network_behavior", {})
    print(f"\n🌐 СЕТЕВОЕ ПОВЕДЕНИЕ:")
    
    retrans = network.get("retransmissions", {})
    print(f"Ретрансмиссии: поиск={retrans.get('search', 0)}, служба={retrans.get('service', 0)}")
    
    success = network.get("success", {})
    print(f"Успех: поиск={'✅' if success.get('search') else '❌'}, служба={'✅' if success.get('service') else '❌'}")
    
    # Корневая причина
    root_causes = comparison.get("root_cause", [])
    print(f"\n🎯 КОРНЕВАЯ ПРИЧИНА:")
    for cause in root_causes:
        print(f"  {cause}")
    
    # Рекомендации
    recommendations = comparison.get("recommendations", [])
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    for rec in recommendations:
        print(f"  {rec}")
    
    # Сохранение отчёта
    import json
    report_file = "network_behavior_report.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(comparison, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"\n📄 Детальный отчёт сохранён в {report_file}")

if __name__ == "__main__":
    main()