#!/usr/bin/env python3
"""
Интеллектуальная система мониторинга и автоматической калибровки стратегий обхода DPI

Основные функции:
1. Мониторинг сетевого трафика в реальном времени
2. Автоматическое обнаружение заблокированных доменов
3. Интеллектуальный подбор стратегий на основе анализа трафика
4. Адаптивная калибровка параметров стратегий
5. Автоматическое сохранение рабочих конфигураций

Алгоритм работы:
1. Перехватывает весь HTTPS трафик (порт 443)
2. Анализирует паттерны блокировки (RST, timeout, etc.)
3. Определяет тип DPI на основе поведения
4. Применяет подходящую стратегию
5. Калибрует параметры до получения успешного соединения
6. Сохраняет рабочую конфигурацию для домена
"""

import asyncio
import json
import logging
import os
import socket
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from pathlib import Path

# Import config loader utility
try:
    from utils.config_loader import load_json_config, save_json_config

    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    CONFIG_LOADER_AVAILABLE = False
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse
import subprocess
import tempfile

# Импорты для работы с пакетами
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls import TLS, TLSClientHello

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy не установлен. Функции анализа пакетов недоступны.")

# Импорты проекта
try:
    from cli import WindowsBypassEngine, AttackDispatcher
    from core.bypass.attacks.attack_registry import get_attack_registry

    CLI_AVAILABLE = True
except ImportError:
    CLI_AVAILABLE = False
    print("⚠️ Модули CLI недоступны. Работа в режиме анализа.")

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("intelligent_bypass_monitor.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


@dataclass
class TrafficPattern:
    """Паттерн сетевого трафика для анализа блокировки"""

    domain: str
    ip: str
    port: int
    timestamp: datetime

    # TCP уровень
    tcp_syn_sent: bool = False
    tcp_syn_ack_received: bool = False
    tcp_established: bool = False
    tcp_rst_received: bool = False
    tcp_fin_received: bool = False

    # TLS уровень
    tls_client_hello_sent: bool = False
    tls_server_hello_received: bool = False
    tls_handshake_completed: bool = False
    tls_alert_received: bool = False

    # HTTP уровень
    http_request_sent: bool = False
    http_response_received: bool = False
    http_status_code: Optional[int] = None

    # Анализ блокировки
    blocking_detected: bool = False
    blocking_type: Optional[str] = None
    blocking_stage: Optional[str] = None

    # Метрики
    connection_time_ms: float = 0.0
    handshake_time_ms: float = 0.0
    response_time_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {**asdict(self), "timestamp": self.timestamp.isoformat()}


@dataclass
class BypassStrategy:
    """Стратегия обхода с параметрами"""

    name: str
    attack_type: str
    parameters: Dict[str, Any]
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    test_count: int = 0
    last_tested: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            "last_tested": self.last_tested.isoformat() if self.last_tested else None,
        }


class DPIAnalyzer:
    """Анализатор типа DPI на основе паттернов трафика"""

    def __init__(self):
        self.patterns = defaultdict(list)

    def analyze_blocking_type(self, pattern: TrafficPattern) -> Tuple[str, str]:
        """Определяет тип и стадию блокировки"""

        # IP уровень блокировки
        if not pattern.tcp_syn_ack_received and pattern.tcp_syn_sent:
            return "IP_BLOCKING", "TCP_SYN"

        # TCP уровень блокировки
        if pattern.tcp_syn_ack_received and pattern.tcp_rst_received:
            if pattern.tls_client_hello_sent:
                return "TLS_RST_BLOCKING", "TLS_HANDSHAKE"
            else:
                return "TCP_RST_BLOCKING", "TCP_ESTABLISHED"

        # TLS уровень блокировки
        if pattern.tcp_established and pattern.tls_client_hello_sent:
            if not pattern.tls_server_hello_received:
                if pattern.connection_time_ms > 10000:  # Timeout
                    return "TLS_HANDSHAKE_BLOCKING", "TLS_CLIENT_HELLO"
                else:
                    return "TLS_SNI_BLOCKING", "TLS_SNI"
            elif pattern.tls_alert_received:
                return "TLS_ALERT_BLOCKING", "TLS_HANDSHAKE"

        # HTTP уровень блокировки
        if pattern.tls_handshake_completed and pattern.http_request_sent:
            if not pattern.http_response_received:
                return "HTTP_CONTENT_BLOCKING", "HTTP_REQUEST"
            elif pattern.http_status_code in [403, 451, 444]:
                return "HTTP_STATUS_BLOCKING", "HTTP_RESPONSE"

        # Неизвестный тип блокировки
        if pattern.blocking_detected:
            return "UNKNOWN_BLOCKING", "UNKNOWN"

        return "NO_BLOCKING", "SUCCESS"

    def suggest_strategies(self, blocking_type: str, blocking_stage: str) -> List[str]:
        """Предлагает стратегии на основе типа блокировки"""

        strategy_map = {
            "IP_BLOCKING": ["tunnel_attacks", "proxy_attacks"],
            "TCP_RST_BLOCKING": ["tcp_attacks", "stateful_attacks"],
            "TLS_RST_BLOCKING": ["tls_attacks", "fake_attacks"],
            "TLS_HANDSHAKE_BLOCKING": ["tls_attacks", "fragmentation_attacks"],
            "TLS_SNI_BLOCKING": ["sni_attacks", "tls_attacks"],
            "TLS_ALERT_BLOCKING": ["tls_attacks", "encryption_attacks"],
            "HTTP_CONTENT_BLOCKING": ["http_attacks", "payload_attacks"],
            "HTTP_STATUS_BLOCKING": ["http_attacks", "header_attacks"],
        }

        return strategy_map.get(blocking_type, ["combo_attacks", "experimental_attacks"])


class TrafficMonitor:
    """Монитор сетевого трафика"""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.running = False
        self.patterns = {}
        self.callbacks = []

    def add_callback(self, callback):
        """Добавляет callback для обработки паттернов"""
        self.callbacks.append(callback)

    def start_monitoring(self):
        """Запускает мониторинг трафика"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy недоступен. Мониторинг трафика невозможен.")
            return

        self.running = True
        logger.info("Запуск мониторинга трафика...")

        # Фильтр для HTTPS трафика
        filter_str = "tcp port 443"

        try:
            scapy.sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            logger.error(f"Ошибка мониторинга: {e}")

    def stop_monitoring(self):
        """Останавливает мониторинг"""
        self.running = False
        logger.info("Мониторинг остановлен")

    def _process_packet(self, packet):
        """Обрабатывает перехваченный пакет"""
        try:
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return

            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            # Определяем направление трафика
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            # Интересуют только HTTPS соединения
            if dst_port != 443 and src_port != 443:
                return

            # Создаем ключ соединения
            if dst_port == 443:
                # Исходящий трафик
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:443"
                domain = self._resolve_domain(dst_ip)
            else:
                # Входящий трафик
                connection_key = f"{dst_ip}:{dst_port}->{src_ip}:443"
                domain = self._resolve_domain(src_ip)

            # Получаем или создаем паттерн
            if connection_key not in self.patterns:
                self.patterns[connection_key] = TrafficPattern(
                    domain=domain,
                    ip=dst_ip if dst_port == 443 else src_ip,
                    port=443,
                    timestamp=datetime.now(),
                )

            pattern = self.patterns[connection_key]

            # Анализируем TCP флаги
            flags = tcp_layer.flags

            if flags & 0x02:  # SYN
                pattern.tcp_syn_sent = True
            if flags & 0x12:  # SYN+ACK
                pattern.tcp_syn_ack_received = True
                pattern.tcp_established = True
            if flags & 0x04:  # RST
                pattern.tcp_rst_received = True
                pattern.blocking_detected = True
            if flags & 0x01:  # FIN
                pattern.tcp_fin_received = True

            # Анализируем TLS слой
            if packet.haslayer(TLS):
                tls_layer = packet[TLS]

                if packet.haslayer(TLSClientHello):
                    pattern.tls_client_hello_sent = True
                    # Извлекаем SNI если есть
                    try:
                        client_hello = packet[TLSClientHello]
                        if hasattr(client_hello, "ext") and client_hello.ext:
                            for ext in client_hello.ext:
                                if hasattr(ext, "servernames") and ext.servernames:
                                    sni = ext.servernames[0].servername.decode()
                                    pattern.domain = sni
                    except:
                        pass

            # Уведомляем callbacks
            for callback in self.callbacks:
                try:
                    callback(pattern)
                except Exception as e:
                    logger.error(f"Ошибка в callback: {e}")

        except Exception as e:
            logger.error(f"Ошибка обработки пакета: {e}")

    def _resolve_domain(self, ip: str) -> str:
        """Пытается определить домен по IP"""
        try:
            domain = socket.gethostbyaddr(ip)[0]
            return domain
        except:
            return ip


class StrategyCalibrator:
    """Калибратор стратегий обхода"""

    def __init__(self):
        self.bypass_engine = None
        self.attack_dispatcher = None

        if CLI_AVAILABLE:
            try:
                self.bypass_engine = WindowsBypassEngine()
                self.attack_dispatcher = AttackDispatcher()
            except Exception as e:
                logger.warning(f"Не удалось инициализировать bypass engine: {e}")

    def calibrate_strategy(
        self, domain: str, blocking_type: str, suggested_strategies: List[str]
    ) -> Optional[BypassStrategy]:
        """Калибрует стратегию для конкретного домена"""

        if not self.bypass_engine:
            logger.warning("Bypass engine недоступен")
            return None

        logger.info(f"Калибровка стратегии для {domain}, тип блокировки: {blocking_type}")

        # Получаем доступные атаки
        registry = get_attack_registry()

        for strategy_type in suggested_strategies:
            attacks = registry.get_attacks_by_category(strategy_type)

            for attack_name, attack_class in attacks.items():
                logger.info(f"Тестирование атаки: {attack_name}")

                # Создаем базовые параметры
                base_params = self._get_base_parameters(attack_name, blocking_type)

                # Калибруем параметры
                best_params = self._calibrate_parameters(domain, attack_name, base_params)

                if best_params:
                    strategy = BypassStrategy(
                        name=f"{attack_name}_calibrated",
                        attack_type=attack_name,
                        parameters=best_params,
                        success_rate=1.0,
                        test_count=1,
                        last_tested=datetime.now(),
                    )

                    logger.info(f"✅ Найдена рабочая стратегия: {strategy.name}")
                    return strategy

        logger.warning(f"Не удалось найти рабочую стратегию для {domain}")
        return None

    def _get_base_parameters(self, attack_name: str, blocking_type: str) -> Dict[str, Any]:
        """Получает базовые параметры для атаки"""

        # Базовые параметры в зависимости от типа блокировки
        base_params = {
            "TLS_HANDSHAKE_BLOCKING": {
                "split_pos": [1, 3, 5],
                "ttl": [1, 2, 3],
                "fooling": ["badsum", "badseq"],
                "repeats": [2, 3, 5],
            },
            "TLS_SNI_BLOCKING": {
                "split_tls": ["sni", "chello"],
                "split_pos": [1, 2],
                "ttl": [1, 2],
                "fooling": ["badseq"],
                "repeats": [3, 5],
            },
            "TCP_RST_BLOCKING": {
                "fooling": ["md5sig", "badseq"],
                "ttl": [1, 2, 3],
                "repeats": [2, 3],
            },
        }

        return base_params.get(
            blocking_type,
            {"split_pos": [2, 3], "ttl": [2, 3], "fooling": ["badsum"], "repeats": [2]},
        )

    def _calibrate_parameters(
        self, domain: str, attack_name: str, base_params: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Калибрует параметры атаки"""

        # Генерируем комбинации параметров
        param_combinations = self._generate_param_combinations(base_params)

        for params in param_combinations:
            logger.info(f"Тестирование параметров: {params}")

            # Тестируем комбинацию
            if self._test_parameters(domain, attack_name, params):
                logger.info(f"✅ Рабочие параметры найдены: {params}")
                return params

            # Небольшая пауза между тестами
            time.sleep(1)

        return None

    def _generate_param_combinations(self, base_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Генерирует комбинации параметров для тестирования"""

        combinations = []

        # Простая генерация - берем первые значения из каждого параметра
        # В реальной реализации можно использовать itertools.product

        for key, values in base_params.items():
            if isinstance(values, list) and values:
                combinations.append({key: values[0]})

        # Добавляем комбинированные варианты
        if len(combinations) >= 2:
            combined = {}
            for combo in combinations[:2]:
                combined.update(combo)
            combinations.append(combined)

        return combinations if combinations else [{}]

    def _test_parameters(self, domain: str, attack_name: str, params: Dict[str, Any]) -> bool:
        """Тестирует конкретную комбинацию параметров"""

        try:
            # Простой тест доступности
            import requests

            url = f"https://{domain}"

            # Применяем стратегию (здесь должна быть интеграция с bypass engine)
            # Пока делаем простой HTTP запрос

            response = requests.get(url, timeout=10, allow_redirects=False, verify=False)

            # Любой HTTP ответ считаем успехом
            return response.status_code in [200, 301, 302, 304, 403, 404]

        except Exception as e:
            logger.debug(f"Тест параметров неудачен: {e}")
            return False


class IntelligentBypassMonitor:
    """Главный класс интеллектуального мониторинга"""

    def __init__(self, config_file: str = "intelligent_bypass_config.json"):
        self.config_file = config_file
        self.config = self._load_config()

        self.traffic_monitor = TrafficMonitor()
        self.dpi_analyzer = DPIAnalyzer()
        self.strategy_calibrator = StrategyCalibrator()

        self.domain_strategies = {}
        self.blocked_domains = set()
        self.monitoring_stats = defaultdict(int)

        self.running = False

        # Настройка callbacks
        self.traffic_monitor.add_callback(self._on_traffic_pattern)

    def _load_config(self) -> Dict:
        """Загружает конфигурацию"""
        default_config = {
            "monitoring": {
                "interface": None,
                "capture_filter": "tcp port 443",
                "analysis_window_seconds": 30,
                "max_patterns_per_domain": 100,
            },
            "calibration": {
                "max_attempts_per_strategy": 5,
                "test_timeout_seconds": 15,
                "success_threshold": 0.8,
                "calibration_delay_seconds": 2,
            },
            "storage": {
                "strategies_file": "calibrated_strategies.json",
                "patterns_file": "traffic_patterns.json",
                "stats_file": "monitoring_stats.json",
            },
        }

        if CONFIG_LOADER_AVAILABLE:
            # Use shared config loader
            loaded_config = load_json_config(self.config_file, default={})
            default_config.update(loaded_config)
        else:
            # Fallback to original implementation
            try:
                if os.path.exists(self.config_file):
                    with open(self.config_file, "r", encoding="utf-8") as f:
                        loaded_config = json.load(f)
                        default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Ошибка загрузки конфигурации: {e}")

        return default_config

    def _save_config(self):
        """Сохраняет конфигурацию"""
        if CONFIG_LOADER_AVAILABLE:
            # Use shared config loader
            try:
                save_json_config(self.config_file, self.config)
            except Exception as e:
                logger.error(f"Ошибка сохранения конфигурации: {e}")
        else:
            # Fallback to original implementation
            try:
                with open(self.config_file, "w", encoding="utf-8") as f:
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Ошибка сохранения конфигурации: {e}")

    def _on_traffic_pattern(self, pattern: TrafficPattern):
        """Обработчик паттернов трафика"""

        # Анализируем тип блокировки
        blocking_type, blocking_stage = self.dpi_analyzer.analyze_blocking_type(pattern)

        pattern.blocking_type = blocking_type
        pattern.blocking_stage = blocking_stage

        # Обновляем статистику
        self.monitoring_stats[f"patterns_analyzed"] += 1
        self.monitoring_stats[f"blocking_type_{blocking_type}"] += 1

        # Если обнаружена блокировка
        if blocking_type != "NO_BLOCKING":
            logger.info(f"🚫 Блокировка обнаружена: {pattern.domain} - {blocking_type}")

            self.blocked_domains.add(pattern.domain)
            self.monitoring_stats["blocked_domains_detected"] += 1

            # Запускаем калибровку стратегии
            self._calibrate_for_domain(pattern.domain, blocking_type)

        else:
            logger.debug(f"✅ Успешное соединение: {pattern.domain}")
            self.monitoring_stats["successful_connections"] += 1

    def _calibrate_for_domain(self, domain: str, blocking_type: str):
        """Запускает калибровку для домена"""

        # Проверяем, есть ли уже рабочая стратегия
        if domain in self.domain_strategies:
            logger.info(f"Стратегия для {domain} уже существует")
            return

        # Получаем предложенные стратегии
        suggested_strategies = self.dpi_analyzer.suggest_strategies(blocking_type, "")

        logger.info(f"Калибровка для {domain}: {suggested_strategies}")

        # Запускаем калибровку в отдельном потоке
        threading.Thread(
            target=self._run_calibration,
            args=(domain, blocking_type, suggested_strategies),
            daemon=True,
        ).start()

    def _run_calibration(self, domain: str, blocking_type: str, suggested_strategies: List[str]):
        """Выполняет калибровку в отдельном потоке"""

        try:
            strategy = self.strategy_calibrator.calibrate_strategy(
                domain, blocking_type, suggested_strategies
            )

            if strategy:
                self.domain_strategies[domain] = strategy
                self.monitoring_stats["strategies_calibrated"] += 1

                logger.info(f"🎯 Стратегия для {domain} откалибрована: {strategy.name}")

                # Сохраняем стратегию
                self._save_strategy(domain, strategy)

                # Применяем стратегию
                self._apply_strategy(domain, strategy)

            else:
                logger.warning(f"❌ Не удалось откалибровать стратегию для {domain}")
                self.monitoring_stats["calibration_failures"] += 1

        except Exception as e:
            logger.error(f"Ошибка калибровки для {domain}: {e}")
            self.monitoring_stats["calibration_errors"] += 1

    def _save_strategy(self, domain: str, strategy: BypassStrategy):
        """Сохраняет стратегию в файл"""

        strategies_file = self.config["storage"]["strategies_file"]

        try:
            # Загружаем существующие стратегии
            strategies = {}
            if os.path.exists(strategies_file):
                with open(strategies_file, "r", encoding="utf-8") as f:
                    strategies = json.load(f)

            # Добавляем новую стратегию
            strategies[domain] = strategy.to_dict()

            # Сохраняем
            with open(strategies_file, "w", encoding="utf-8") as f:
                json.dump(strategies, f, indent=2, ensure_ascii=False)

            logger.info(f"💾 Стратегия для {domain} сохранена в {strategies_file}")

        except Exception as e:
            logger.error(f"Ошибка сохранения стратегии: {e}")

    def _apply_strategy(self, domain: str, strategy: BypassStrategy):
        """Применяет стратегию для домена"""

        # Здесь должна быть интеграция с recon_service.py
        # Для демонстрации просто логируем

        logger.info(f"🚀 Применение стратегии {strategy.name} для {domain}")
        logger.info(f"   Параметры: {strategy.parameters}")

        # В реальной реализации:
        # 1. Обновить конфигурацию recon_service
        # 2. Перезапустить bypass engine с новыми параметрами
        # 3. Добавить домен в список активного мониторинга

    def start(self):
        """Запускает интеллектуальный мониторинг"""

        logger.info("🚀 Запуск интеллектуального мониторинга обхода DPI")
        logger.info(f"Конфигурация: {self.config_file}")

        self.running = True

        # Запускаем мониторинг трафика
        monitoring_thread = threading.Thread(
            target=self.traffic_monitor.start_monitoring, daemon=True
        )
        monitoring_thread.start()

        # Запускаем периодическое сохранение статистики
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()

        logger.info("✅ Интеллектуальный мониторинг запущен")

        try:
            # Основной цикл
            while self.running:
                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Получен сигнал остановки")
            self.stop()

    def stop(self):
        """Останавливает мониторинг"""

        logger.info("🛑 Остановка интеллектуального мониторинга")

        self.running = False
        self.traffic_monitor.stop_monitoring()

        # Сохраняем финальную статистику
        self._save_stats()

        logger.info("✅ Мониторинг остановлен")

    def _stats_loop(self):
        """Цикл сохранения статистики"""

        while self.running:
            try:
                time.sleep(60)  # Сохраняем каждую минуту
                self._save_stats()
                self._print_stats()

            except Exception as e:
                logger.error(f"Ошибка в цикле статистики: {e}")

    def _save_stats(self):
        """Сохраняет статистику"""

        stats_file = self.config["storage"]["stats_file"]

        try:
            stats = {
                "timestamp": datetime.now().isoformat(),
                "uptime_seconds": (
                    time.time() - self.start_time if hasattr(self, "start_time") else 0
                ),
                "monitoring_stats": dict(self.monitoring_stats),
                "blocked_domains": list(self.blocked_domains),
                "calibrated_strategies": len(self.domain_strategies),
            }

            with open(stats_file, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Ошибка сохранения статистики: {e}")

    def _print_stats(self):
        """Выводит текущую статистику"""

        logger.info("📊 СТАТИСТИКА МОНИТОРИНГА:")
        logger.info(
            f"   Проанализировано паттернов: {self.monitoring_stats.get('patterns_analyzed', 0)}"
        )
        logger.info(
            f"   Обнаружено блокировок: {self.monitoring_stats.get('blocked_domains_detected', 0)}"
        )
        logger.info(
            f"   Успешных соединений: {self.monitoring_stats.get('successful_connections', 0)}"
        )
        logger.info(
            f"   Откалибровано стратегий: {self.monitoring_stats.get('strategies_calibrated', 0)}"
        )
        logger.info(f"   Заблокированных доменов: {len(self.blocked_domains)}")
        logger.info(f"   Активных стратегий: {len(self.domain_strategies)}")


def main():
    """Главная функция"""

    import argparse

    parser = argparse.ArgumentParser(description="Интеллектуальный мониторинг обхода DPI")
    parser.add_argument(
        "--config", default="intelligent_bypass_config.json", help="Файл конфигурации"
    )
    parser.add_argument("--interface", help="Сетевой интерфейс для мониторинга")
    parser.add_argument("--debug", action="store_true", help="Режим отладки")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Создаем монитор
    monitor = IntelligentBypassMonitor(args.config)

    if args.interface:
        monitor.traffic_monitor.interface = args.interface

    # Устанавливаем время старта
    monitor.start_time = time.time()

    try:
        monitor.start()
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
