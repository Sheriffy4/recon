# path: core/pcap/bypass_engine_integration.py
"""
Integration module for adding PCAP capture capabilities to WindowsBypassEngine.

This module provides extensions to the existing WindowsBypassEngine to support
temporary PCAP capture during strategy testing for the adaptive monitoring system.
"""

import logging
import time
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from .temporary_capturer import TemporaryPCAPCapturer, CaptureSession
from .analyzer import PCAPAnalyzer, StrategyAnalysisResult


@dataclass
class StrategyTestResult:
    """Enhanced test result with PCAP capture information"""
    success: bool
    domain: str
    strategy: Dict[str, Any]
    response_time: float
    error: Optional[str] = None
    pcap_file: Optional[str] = None
    packets_captured: int = 0
    capture_session_id: Optional[str] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class WindowsBypassEngineWithCapture:
    """
    Wrapper around WindowsBypassEngine that adds PCAP capture capabilities.
    
    This class extends the functionality of the existing WindowsBypassEngine
    to support temporary PCAP capture during strategy testing, which is essential
    for the adaptive monitoring system's failure analysis.
    """

    # Константы для задержек и лимитов
    CAPTURE_INIT_DELAY = 1.0               # время на старт WinDivert/pcap
    VERIFICATION_POST_CAPTURE_DELAY = 2.5  # доп. захват после теста в verification_mode
    MIN_CLIENT_HELLO_SIZE = 1200           # минимальный средний размер ClientHello (байт)
    MAX_PCAP_ANALYZE_SIZE = 50 * 1024 * 1024  # макс. размер PCAP для глубокого анализа (50 МБ)

    def __init__(self, bypass_engine, enable_capture: bool = True):
        """
        Initialize the enhanced bypass engine.
        
        Args:
            bypass_engine: WindowsBypassEngine instance
            enable_capture: Whether to enable PCAP capture (default: True)
        """
        self.bypass_engine = bypass_engine
        self.logger = logging.getLogger("WindowsBypassEngineWithCapture")
        
        # Initialize PCAP capturer
        self.pcap_capturer = TemporaryPCAPCapturer() if enable_capture else None
        self.capture_enabled = enable_capture and (self.pcap_capturer is not None)
        
        # Initialize PCAP analyzer
        self.pcap_analyzer = PCAPAnalyzer()
        
        if self.capture_enabled and self.pcap_capturer.is_capture_available():
            self.logger.info("✅ PCAP capture enabled for strategy testing")
        else:
            self.logger.warning("⚠️ PCAP capture disabled or unavailable - running in fallback mode")
    
    def test_strategy_with_analysis(
        self,
        domain: str,
        strategy: Dict[str, Any],
        capture_timeout: float = 15.0,
        verification_mode: bool = False,
    ) -> StrategyTestResult:
        """
        Test a strategy with automatic PCAP capture for failure analysis.
        
        Args:
            domain: Target domain to test
            strategy: Strategy configuration dictionary
            capture_timeout: Maximum time to capture packets (seconds)
            verification_mode: Enable extended PCAP capture for verification
            
        Returns:
            StrategyTestResult with PCAP capture information
        """
        start_time = time.time()
        test_end_time: Optional[float] = None

        # Рабочая копия стратегии, чтобы не мутировать исходный dict
        strategy_for_engine: Dict[str, Any] = dict(strategy)

        self.logger.info(f"🧪 Testing strategy for {domain}: {strategy.get('attack', strategy.get('type', 'unknown'))}")
        
        # Operation logging (verification mode)
        strategy_id: Optional[str] = None
        operation_logger = None

        try:
            if verification_mode:
                try:
                    from core.operation_logger import get_operation_logger
                    operation_logger = get_operation_logger()
                    
                    strategy_name = strategy.get('attack', strategy.get('type', 'unknown'))
                    metadata = {
                        'domain': domain,
                        'strategy': strategy,
                        'verification_mode': True
                    }
                    strategy_id = operation_logger.start_strategy_log(
                        strategy_name=strategy_name,
                        domain=domain,
                        metadata=metadata
                    )
                    self.logger.info(f"📝 Started operation logging: strategy_id={strategy_id[:8]}")
                    
                    # Привязываем strategy_id к стратегии для нижележащего движка
                    strategy_for_engine['_strategy_id'] = strategy_id
                except Exception as e:
                    self.logger.warning(f"⚠️ Failed to start operation logging: {e}")

            # Если захват недоступен — используем фоллбек без PCAP,
            # но operation_logger всё равно будет закрыт в finally.
            if not self.capture_enabled or not self.pcap_capturer.is_capture_available():
                return self._test_strategy_without_capture(
                    domain,
                    strategy_for_engine,
                    start_time,
                    timeout=capture_timeout,
                )
            
            # --- Тест с PCAP ---
            import socket
            try:
                target_ip = socket.gethostbyname(domain)
            except socket.gaierror as e:
                self.logger.warning(f"⚠️ Could not resolve domain {domain}: {e}")
                target_ip = None

            local_ip = self._get_local_ip(target_ip)

            # Убедиться, что WinDivert активен
            self._ensure_windivert_ready()

            pcap_file: Optional[str] = None
            packets_captured = 0
            session_id: Optional[str] = None
            test_connection: Optional[Dict[str, Any]] = None

            # Таймаут для самого теста (минус задержка на инициализацию захвата)
            effective_timeout = max(1.0, capture_timeout - self.CAPTURE_INIT_DELAY)

            with self.pcap_capturer.capture_session(
                domain,
                verification_mode=verification_mode,
                target_ip=target_ip,  # оптимизация BPF
            ) as session:
                # Ждём инициализации захвата
                time.sleep(self.CAPTURE_INIT_DELAY)

                # Выполняем реальный тест стратегии
                success, error, test_port = self._execute_strategy_test_with_tracking(
                    domain,
                    strategy_for_engine,
                    effective_timeout,
                )
                
                test_end_time = time.time()
                response_time = test_end_time - start_time

                # Доп. ожидание в verification_mode для захвата "хвоста"
                if verification_mode:
                    self.logger.info(
                        f"🔍 VERIFICATION MODE: Waiting {self.VERIFICATION_POST_CAPTURE_DELAY}s post-capture delay..."
                    )
                    time.sleep(self.VERIFICATION_POST_CAPTURE_DELAY)
                
                # Информация о тестовом соединении (порт может быть 0/None)
                test_connection = {
                    'src_ip': local_ip,
                    'src_port': test_port if test_port else 0,
                    'dst_ip': target_ip,
                    'dst_port': 443,
                    'domain': domain,
                }

                self.logger.info(
                    f"🔍 Test connection: {local_ip}:{test_connection['src_port']} → "
                    f"{target_ip or 'UNKNOWN'}:443 (port {'FOUND' if test_port else 'NOT FOUND'})"
                )

                # Сохраняем данные о сессии до выхода из контекста
                pcap_file = session.pcap_file if session.pcap_file else None
                packets_captured = session.packets_captured
                session_id = session.session_id

                self._last_capture_path = pcap_file

            # --- После выхода из контекста: PCAP полностью записан ---

            # Проверка размера ClientHello
            if pcap_file:
                clienthello_validation = self.validate_clienthello_size(pcap_file)
                
                # Метрики
                try:
                    from core.metrics.clienthello_metrics import get_clienthello_metrics_collector
                    metrics_collector = get_clienthello_metrics_collector()
                    metrics_collector.record_validation_result(
                        domain=domain,
                        validation_result=clienthello_validation,
                        strategy=strategy_for_engine.get('attack', strategy_for_engine.get('type', 'unknown')),
                        test_success=success,
                    )
                except Exception as e:
                    self.logger.warning(f"⚠️ Failed to record ClientHello metrics: {e}")
                
                if not clienthello_validation.get('valid', False):
                    self.logger.warning(f"⚠️ ClientHello validation failed: {clienthello_validation.get('reason')}")
                    self.logger.warning(f"💡 Recommendation: {clienthello_validation.get('recommendation')}")
                else:
                    self.logger.info(
                        f"✅ ClientHello size validated: avg={clienthello_validation['avg_size']:.0f} bytes"
                    )

            # PCAP-валидация успеха (ServerHello в тестовом соединении)
            if not success and pcap_file and test_connection:
                pcap_success = self._validate_success_with_pcap(
                    pcap_file,
                    test_connection,
                    test_start_time=start_time,
                    test_end_time=test_end_time,
                )
                if pcap_success:
                    self.logger.info(
                        "✅ PCAP валидация: TLS Handshake подтверждён в тестовом соединении. "
                        "Переопределяем результат на SUCCESS"
                    )
                    success = True
                    error = "Success detected via PCAP analysis (TLS handshake in test connection)"
                else:
                    self.logger.info("❌ PCAP валидация: Успешное TLS-соединение не подтверждено")
            
            result = StrategyTestResult(
                success=success,
                domain=domain,
                strategy=strategy_for_engine,
                response_time=response_time,
                error=error,
                pcap_file=pcap_file,
                packets_captured=packets_captured,
                capture_session_id=session_id,
            )

            self.logger.info(f"📊 Test completed: success={success}, packets={packets_captured}")
            return result

        except Exception as e:
            self.logger.error(f"❌ Strategy test failed: {e}", exc_info=True)
            return StrategyTestResult(
                success=False,
                domain=domain,
                strategy=strategy_for_engine,
                response_time=time.time() - start_time,
                error=str(e),
            )

        finally:
            # Гарантированное завершение operation logging (если он был запущен)
            if strategy_id and operation_logger:
                try:
                    strategy_log = operation_logger.end_strategy_log(strategy_id, save_to_file=True)
                    if strategy_log:
                        self.logger.info(
                            f"📝 Ended operation logging: {len(strategy_log.operations)} operations logged"
                        )
                except Exception as e:
                    self.logger.warning(f"⚠️ Failed to end operation logging: {e}")
    
    def _test_strategy_without_capture(
        self,
        domain: str,
        strategy: Dict[str, Any],
        start_time: float,
        timeout: float = 15.0,
    ) -> StrategyTestResult:
        """
        Fallback strategy testing without PCAP capture.
        """
        try:
            success, error = self._execute_strategy_test(domain, strategy, timeout)
            
            return StrategyTestResult(
                success=success,
                domain=domain,
                strategy=strategy,
                response_time=time.time() - start_time,
                error=error,
            )
            
        except Exception as e:
            return StrategyTestResult(
                success=False,
                domain=domain,
                strategy=strategy,
                response_time=time.time() - start_time,
                error=str(e),
            )
    
    def _execute_strategy_test(
        self,
        domain: str,
        strategy: Dict[str, Any],
        timeout: float,
    ) -> Tuple[bool, Optional[str]]:
        """
        Execute the actual strategy test using the bypass engine.
        """
        try:
            self.logger.debug(f"Executing strategy test: {strategy}")
            
            # Приоритет: bypass_engine.test_strategy_like_testing_mode
            if hasattr(self.bypass_engine, 'test_strategy_like_testing_mode'):
                try:
                    import socket
                    target_ip = socket.gethostbyname(domain)
                    
                    strategy_input = {
                        'type': strategy.get('attack', strategy.get('type', 'unknown')),
                        'params': strategy.get('params', {}),
                    }
                    
                    self.logger.info(f"🔧 Using bypass engine testing mode for {domain}")
                    
                    result = self.bypass_engine.test_strategy_like_testing_mode(
                        target_ip=target_ip,
                        strategy_input=strategy_input,
                        timeout=timeout,
                        domain=domain,
                    )
                    
                    if isinstance(result, dict):
                        success = result.get('success', False)
                        error = result.get('error')
                    else:
                        success = getattr(result, 'success', False)
                        error = getattr(result, 'error', None)
                    
                    self.logger.info(f"🔧 Bypass engine test result: success={success}, error={error}")
                    return success, error
                    
                except Exception as e:
                    self.logger.error(f"❌ Bypass engine test failed: {e}", exc_info=True)
                    return False, f"Bypass engine test failed: {str(e)}"
            
            # FALLBACK: обычный requests
            self.logger.warning("⚠️ Bypass engine test method not available, using requests fallback")
            
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            try:
                self.logger.info(f"🌐 Making HTTPS request to {domain} (timeout={timeout}s)")
                response = requests.get(
                    f"https://{domain}",
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                )
                # считаем успехом любые 2xx/3xx
                success = 200 <= response.status_code < 400
                error = None if success else f"HTTP {response.status_code}"
                
                self.logger.info(f"🌐 Request result: status={response.status_code}, success={success}")
                return success, error
                
            except requests.exceptions.Timeout:
                self.logger.warning(f"⏱️ Request timeout after {timeout}s")
                return False, "Timeout"
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"🔌 Connection error: {e}")
                return False, f"Connection error: {str(e)}"
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"❌ Request failed: {e}")
                return False, str(e)
            
        except Exception as e:
            self.logger.error(f"❌ Strategy execution failed: {e}", exc_info=True)
            return False, str(e)
    
    def get_capture_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about PCAP capture sessions.
        """
        if not self.pcap_capturer:
            return {"capture_enabled": False}
        
        active_sessions = self.pcap_capturer.get_active_sessions()
        
        return {
            "capture_enabled": self.capture_enabled,
            "capture_available": self.pcap_capturer.is_capture_available(),
            "active_sessions": len(active_sessions),
            "temp_directory": str(self.pcap_capturer.temp_dir),
            "max_file_size_mb": self.pcap_capturer.max_file_size_bytes / (1024 * 1024),
        }
    
    def cleanup_capture_files(self):
        """Clean up all temporary PCAP files"""
        if self.pcap_capturer:
            self.pcap_capturer.cleanup_all_temp_files()
            self.logger.info("🗑️ Cleaned up temporary PCAP files")
    
    def _validate_success_with_pcap(
        self,
        pcap_file: str,
        test_connection: dict,
        test_start_time: Optional[float] = None,
        test_end_time: Optional[float] = None,
    ) -> bool:
        """
        Точная валидация успеха теста через анализ PCAP.

        Улучшения:
        - фильтрация по HTTPS-потокам с SNI = домен;
        - учитываем RST сразу после ServerHello (не переопределяем на успех);
        - допустим override, если есть ServerHello и НЕТ RST сразу после него.
        """
        try:
            from scapy.all import rdpcap, TCP, IP, Raw
            import os
            
            if not os.path.exists(pcap_file):
                self.logger.warning(f"⚠️ PCAP файл не найден: {pcap_file}")
                return False
            
            file_size = os.path.getsize(pcap_file)
            if file_size == 0:
                self.logger.warning(f"⚠️ PCAP файл пустой: {pcap_file}")
                return False

            if file_size > self.MAX_PCAP_ANALYZE_SIZE:
                self.logger.warning(
                    f"⚠️ PCAP файл слишком большой для полного анализа ({file_size} bytes > "
                    f"{self.MAX_PCAP_ANALYZE_SIZE} bytes). Пропускаем PCAP-валидацию."
                )
                return False
            
            target_domain = test_connection.get("domain", "")
            target_ip = test_connection.get("dst_ip")
            target_port = int(test_connection.get("dst_port", 443))
            
            # Сейчас анализируем весь PCAP, без фильтрации по времени
            window_start = None
            window_end = None
            
            port_info = (
                f":{test_connection['src_port']}"
                if test_connection.get("src_port", 0) != 0
                else ":ANY"
            )
            self.logger.info(
                f"🔍 Анализ PCAP файла ({file_size} bytes) для домена {target_domain}:\n"
                f"   заявленное соединение: {test_connection.get('src_ip')}{port_info} → "
                f"{target_ip}:{target_port}\n"
                f"   временное окно: "
                f"{window_start if window_start else 'begin'} .. "
                f"{window_end if window_end else 'end'}"
            )
            
            packets = rdpcap(pcap_file)
            self.logger.debug(f"📦 Загружено {len(packets)} пакетов из PCAP")
            
            flows: Dict[tuple, Dict[str, Any]] = {}
            
            for idx, pkt in enumerate(packets, 1):
                if TCP not in pkt or IP not in pkt:
                    continue
                
                ts = float(getattr(pkt, "time", 0.0))
                if window_start is not None and ts < window_start:
                    continue
                if window_end is not None and ts > window_end:
                    continue
                
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                src_ip, dst_ip = ip_layer.src, ip_layer.dst
                sport, dport = int(tcp_layer.sport), int(tcp_layer.dport)
                
                # интересуют только потоки, где одна из сторон порт 443 (HTTPS)
                if sport == target_port or dport == target_port:
                    if dport == target_port:
                        client_ip, client_port = src_ip, sport
                        server_ip, server_port = dst_ip, dport
                        direction = "c2s"
                    else:
                        client_ip, client_port = dst_ip, dport
                        server_ip, server_port = src_ip, sport
                        direction = "s2c"
                else:
                    continue
                
                flow_key = (client_ip, client_port, server_ip, server_port)
                flow = flows.setdefault(
                    flow_key,
                    {
                        "packets": [],      # (idx, pkt)
                        "has_sni": False,
                        "first_time": ts,
                        "last_time": ts,
                        "c2s_payload": b"",
                    },
                )
                flow["packets"].append((idx, pkt))
                flow["first_time"] = min(flow["first_time"], ts)
                flow["last_time"] = max(flow["last_time"], ts)
                
                # Собираем payload client->server
                if direction == "c2s" and Raw in pkt:
                    flow["c2s_payload"] += bytes(pkt[Raw])
                
                # Быстрая проверка SNI
                if (
                    direction == "c2s"
                    and Raw in pkt
                    and target_domain
                    and self._packet_has_sni(pkt, target_domain)
                ):
                    flow["has_sni"] = True
                    self.logger.debug(
                        f"✅ Найден ClientHello с SNI={target_domain} "
                        f"в потоке {client_ip}:{client_port} → {server_ip}:{server_port} "
                        f"(пакет #{idx})"
                    )
            
            # Проверка фрагментированных ClientHello
            for flow_key, flow_meta in flows.items():
                if not flow_meta["has_sni"] and flow_meta["c2s_payload"]:
                    payload = flow_meta["c2s_payload"]
                    if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                        domain_bytes = target_domain.encode('utf-8')
                        if domain_bytes in payload:
                            flow_meta["has_sni"] = True
                            client_ip, client_port, server_ip, server_port = flow_key
                            self.logger.info(
                                f"✅ Найден фрагментированный ClientHello с SNI={target_domain} "
                                f"в потоке {client_ip}:{client_port} → {server_ip}:{server_port} "
                                f"(собрано {len(payload)} байт)"
                            )
            
            self.logger.info(f"📊 Найдено HTTPS-потоков в окне времени: {len(flows)}")
            
            flows_with_sni = [
                (key, meta)
                for key, meta in flows.items()
                if meta["has_sni"]
            ]
            self.logger.info(
                f"📊 Потоков с ClientHello(SNI={target_domain}) в окне: "
                f"{len(flows_with_sni)}"
            )

            def flow_has_valid_server_hello(flow_key, flow_meta) -> bool:
                """
                Проверяет, есть ли в данном потоке ServerHello, который не был немедленно
                убит RST без последующих данных.
                """
                from scapy.all import TCP, IP, Raw  # локальный импорт для явности

                has_serverhello = False
                rst_after_hello = False

                client_ip, client_port, server_ip, server_port = flow_key

                for i, pkt in flow_meta["packets"]:
                    if TCP not in pkt or IP not in pkt:
                        continue
                    ip_l = pkt[IP]
                    tcp_l = pkt[TCP]

                    # Определяем направление пакета
                    if ip_l.src == client_ip and tcp_l.sport == client_port:
                        direction = "c2s"
                    elif ip_l.src == server_ip and tcp_l.sport == server_port:
                        direction = "s2c"
                    else:
                        # Неконсистентный пакет для этого потока
                        continue

                    # Нас интересуют ServerHello и дальнейшие s2c-пакеты
                    if direction == "s2c":
                        if self._is_server_hello(pkt):
                            has_serverhello = True
                            self.logger.info(
                                f"✅ ServerHello найден в потоке {flow_key} (пакет #{i}):\n"
                                f"   {ip_l.src}:{tcp_l.sport} → {ip_l.dst}:{tcp_l.dport}"
                            )
                            continue

                        if has_serverhello:
                            # После ServerHello: проверяем RST и (опционально) Application Data
                            flags = int(tcp_l.flags)
                            if flags & 0x04:  # RST
                                rst_after_hello = True
                                self.logger.info(
                                    f"⚠️ RST после ServerHello в потоке {flow_key} (пакет #{i}) — "
                                    f"возможное DPI-прерывание"
                                )
                                # продолжаем просмотр, но факт RST уже зафиксирован
                            # При желании здесь можно искать Application Data (0x17),
                            # но для цели override достаточно отличать "ServerHello + RST сразу" от
                            # "ServerHello без немедленного RST".
                
                # Разрешаем override, если ServerHello был и НЕ было немедленного RST.
                return has_serverhello and not rst_after_hello
            
            # 1. Потоки с корректным SNI
            for flow_key, meta in flows_with_sni:
                client_ip, client_port, server_ip, server_port = flow_key
                if target_ip and server_ip != target_ip:
                    self.logger.info(
                        f"ℹ️ Поток с SNI={target_domain} к другому IP: {server_ip} "
                        f"(ожидался {target_ip}) - это нормально для CDN"
                    )
                
                if flow_has_valid_server_hello(flow_key, meta):
                    test_connection["src_ip"] = client_ip
                    test_connection["src_port"] = client_port
                    test_connection["dst_ip"] = server_ip
                    test_connection["dst_port"] = server_port
                    return True
            
            # 2. Фоллбек по IP (если SNI не нашли)
            if target_ip:
                candidate_flows = [
                    (key, meta)
                    for key, meta in flows.items()
                    if key[2] == target_ip and key[3] == target_port
                ]
                self.logger.info(
                    f"📊 Потоков к целевому IP {target_ip}:{target_port} "
                    f"в окне времени: {len(candidate_flows)}"
                )
                for flow_key, meta in candidate_flows:
                    if flow_has_valid_server_hello(flow_key, meta):
                        client_ip, client_port, server_ip, server_port = flow_key
                        self.logger.info(
                            "ℹ️ Использован фоллбек без SNI: "
                            "ServerHello найден в потоке к целевому IP (без немедленного RST)"
                        )
                        test_connection["src_ip"] = client_ip
                        test_connection["src_port"] = client_port
                        test_connection["dst_ip"] = server_ip
                        test_connection["dst_port"] = server_port
                        return True
            
            # 3. Ничего не нашли
            if flows_with_sni:
                self.logger.warning(
                    "⚠️ Найдены потоки с корректным SNI, но НИ В ОДНОМ из них "
                    "нет валидного ServerHello (без немедленного RST) — "
                    "тест, скорее всего, провалился на TLS-уровне."
                )
            else:
                self.logger.warning(
                    "⚠️ В PCAP в пределах окна теста не найдено ни одного потока\n"
                    f"   с ClientHello(SNI={target_domain}). Либо тест не дошёл "
                    "до отправки ClientHello, либо захват начался слишком поздно."
                )
            return False
            
        except ImportError:
            self.logger.warning("⚠️ Scapy недоступен для PCAP валидации")
            return False
        except Exception as e:
            self.logger.error(f"❌ Ошибка PCAP валидации: {e}", exc_info=True)
            return False
    
    def _is_server_hello(self, pkt) -> bool:
        """
        Вспомогательный метод для проверки наличия ServerHello в пакете.
        """
        from scapy.all import Raw, TCP
        
        # Вариант 1: Scapy распознал TLS слой
        try:
            from scapy.layers.tls.handshake import TLSServerHello
            if TLSServerHello in pkt:
                return True
        except ImportError:
            pass
        
        # Вариант 2: Анализ Raw payload
        if Raw in pkt and TCP in pkt:
            payload = bytes(pkt[Raw])
            if len(payload) > 5:
                # TLS Handshake (0x16) + ServerHello (0x02)
                if payload[0] == 0x16 and payload[5] == 0x02:
                    return True
        
        return False
    
    def _packet_has_sni(self, pkt, target_domain: str) -> bool:
        """
        Проверяет наличие SNI (Server Name Indication) в TLS ClientHello пакете.
        """
        from scapy.all import Raw, TCP
        
        if not target_domain:
            return False

        domain_parts = target_domain.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = target_domain
        
        def matches_domain(sni: str) -> bool:
            if sni == target_domain:
                return True
            if sni.endswith('.' + base_domain):
                return True
            return False
        
        # Вариант 1: Scapy TLS слой
        try:
            from scapy.layers.tls.handshake import TLSClientHello
            if TLSClientHello in pkt:
                if hasattr(pkt[TLSClientHello], 'ext'):
                    for ext in pkt[TLSClientHello].ext:
                        if hasattr(ext, 'servernames'):
                            for servername in ext.servernames:
                                if hasattr(servername, 'servername'):
                                    sni = servername.servername.decode('utf-8', errors='ignore')
                                    if matches_domain(sni):
                                        return True
        except (ImportError, AttributeError):
            pass
        
        # Вариант 2: Анализ Raw payload
        payload = None
        if Raw in pkt:
            payload = bytes(pkt[Raw])
        elif TCP in pkt and hasattr(pkt[TCP], 'payload'):
            try:
                payload = bytes(pkt[TCP].payload)
            except Exception:
                payload = None
        
        if payload and len(payload) > 5:
            try:
                is_clienthello = payload[0] == 0x16 and payload[5] == 0x01
                if is_clienthello:
                    domain_bytes = target_domain.encode('utf-8')
                    if domain_bytes in payload:
                        return True
                    
                    base_domain_bytes = base_domain.encode('utf-8')
                    if base_domain_bytes in payload:
                        return True
            except Exception:
                pass
        
        return False
    
    def test_strategy_like_testing_mode(
        self,
        target_ip: str,
        strategy_input: Dict[str, Any],
        timeout: float = 15.0,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Test strategy method compatible with AdaptiveEngine expectations.
        """
        domain = kwargs.get('domain', target_ip)
        verification_mode = kwargs.get('verification_mode', False)
        
        strategy = {
            'attack': strategy_input.get('type', 'unknown'),
            'params': strategy_input.get('params', {}),
            **strategy_input,
        }
        
        result = self.test_strategy_with_analysis(
            domain,
            strategy,
            capture_timeout=timeout,
            verification_mode=verification_mode,
        )
        
        return {
            'success': result.success,
            'error': result.error,
            'response_time': result.response_time,
            'pcap_file': result.pcap_file,
            'capture_path': result.pcap_file,
            'packets_captured': result.packets_captured,
            'timestamp': result.timestamp,
        }
    
    def test_strategy_as_service(
        self,
        target_ip: str,
        strategy_input: Dict[str, Any],
        domain: Optional[str] = None,
        timeout: float = 30.0,
        verification_mode: bool = False,
        enable_capture: bool = True,
    ) -> Dict[str, Any]:
        """
        Test strategy using service-based approach with curl HTTP/2 AND PCAP capture.
        """
        capture_mode = "WITH PCAP capture" if enable_capture else "WITHOUT individual PCAP capture"
        self.logger.info(f"[SERVICE] Testing strategy as service {capture_mode}: {strategy_input}")
        self.logger.info(f"   Target: {domain or target_ip}")

        capture_domain = domain or target_ip
        test_start_time = time.time()
        test_end_time: Optional[float] = None

        # Попытаемся включить индивидуальный PCAP, если это разрешено
        if enable_capture and self.capture_enabled and self.pcap_capturer and self.pcap_capturer.is_capture_available():
            self.logger.info("[SERVICE] PCAP capture enabled, wrapping test with capture")
            
            pcap_file: Optional[str] = None
            packets_captured = 0
            session_id: Optional[str] = None

            try:
                with self.pcap_capturer.capture_session(
                    capture_domain,
                    verification_mode=verification_mode,
                    target_ip=target_ip,
                ) as session:
                    time.sleep(self.CAPTURE_INIT_DELAY)
                    
                    # Вызываем реальный сервисный метод движка
                    if hasattr(self.bypass_engine, 'test_strategy_as_service'):
                        self.logger.info("[SERVICE] Using UnifiedBypassEngine.test_strategy_as_service()")
                        try:
                            result = self.bypass_engine.test_strategy_as_service(
                                target_ip=target_ip,
                                strategy_input=strategy_input,
                                domain=domain,
                                timeout=timeout,
                                verification_mode=verification_mode,
                            )
                        except TypeError as e:
                            if 'verification_mode' in str(e):
                                self.logger.warning(
                                    f"[SERVICE] verification_mode not supported, retrying without it: {e}"
                                )
                                result = self.bypass_engine.test_strategy_as_service(
                                    target_ip=target_ip,
                                    strategy_input=strategy_input,
                                    domain=domain,
                                    timeout=timeout,
                                )
                            else:
                                raise
                    else:
                        self.logger.warning("[SERVICE] test_strategy_as_service not available, using fallback")
                        result = self.test_strategy_like_testing_mode(
                            target_ip=target_ip,
                            strategy_input=strategy_input,
                            timeout=timeout,
                            domain=domain,
                        )
                    
                    test_end_time = time.time()

                    if verification_mode:
                        self.logger.info(
                            f"[SERVICE] VERIFICATION MODE: Waiting "
                            f"{self.VERIFICATION_POST_CAPTURE_DELAY}s post-capture delay..."
                        )
                        time.sleep(self.VERIFICATION_POST_CAPTURE_DELAY)
                    
                    pcap_file = session.pcap_file if session.pcap_file else None
                    packets_captured = session.packets_captured
                    session_id = session.session_id
                    self._last_capture_path = pcap_file

                # Добавляем PCAP-информацию в результат
                if isinstance(result, dict):
                    result['pcap_file'] = pcap_file
                    result['packets_captured'] = packets_captured
                    result['capture_session_id'] = session_id

                # Анализ ClientHello и возможное переопределение успеха
                if isinstance(result, dict) and pcap_file:
                    # Проверка размера ClientHello
                    clienthello_validation = self.validate_clienthello_size(pcap_file)
                    try:
                        from core.metrics.clienthello_metrics import get_clienthello_metrics_collector
                        metrics_collector = get_clienthello_metrics_collector()
                        strategy_label = (
                            strategy_input
                            if isinstance(strategy_input, str)
                            else strategy_input.get('attack', strategy_input.get('type', 'unknown'))
                        )
                        metrics_collector.record_validation_result(
                            domain=capture_domain,
                            validation_result=clienthello_validation,
                            strategy=strategy_label,
                            test_success=result.get('success', False),
                        )
                    except Exception as e:
                        self.logger.warning(f"[SERVICE] Failed to record ClientHello metrics: {e}")
                    
                    if not clienthello_validation.get('valid', False):
                        self.logger.warning(
                            f"[SERVICE] ClientHello validation failed: {clienthello_validation.get('reason')}"
                        )
                        self.logger.warning(
                            f"[SERVICE] Recommendation: {clienthello_validation.get('recommendation')}"
                        )
                    else:
                        self.logger.info(
                            f"[SERVICE] ClientHello size validated: "
                            f"avg={clienthello_validation['avg_size']:.0f} bytes"
                        )

                    # PCAP-валидация успеха
                    success = result.get('success', False)
                    if not success:
                        test_connection = {
                            'src_ip': self._get_local_ip(target_ip),
                            'src_port': getattr(self.bypass_engine, '_last_test_port', 0),
                            'dst_ip': target_ip,
                            'dst_port': 443,
                            'domain': capture_domain,
                        }
                        pcap_success = self._validate_success_with_pcap(
                            pcap_file,
                            test_connection,
                            test_start_time=test_start_time,
                            test_end_time=test_end_time,
                        )
                        if pcap_success:
                            self.logger.info(
                                "[SERVICE] PCAP validation: TLS handshake found in test connection, "
                                "overriding result to SUCCESS"
                            )
                            result['success'] = True
                            result['error'] = (
                                "Success detected via PCAP analysis (TLS handshake in test connection)"
                            )

                    self.logger.info(
                        f"[SERVICE] Test complete with PCAP: success={result.get('success')}, "
                        f"pcap_file={pcap_file}, packets={packets_captured}"
                    )

                return result

            except Exception as e:
                self.logger.error(f"[SERVICE] PCAP capture failed: {e}", exc_info=True)
                # Падаем в режим без индивидуального захвата
        
        # Фоллбек: без PCAP
        self.logger.warning("[SERVICE] PCAP capture not available, testing without capture")
        
        if hasattr(self.bypass_engine, 'test_strategy_as_service'):
            self.logger.info("[SERVICE] Using UnifiedBypassEngine.test_strategy_as_service() (no capture)")
            try:
                return self.bypass_engine.test_strategy_as_service(
                    target_ip=target_ip,
                    strategy_input=strategy_input,
                    domain=domain,
                    timeout=timeout,
                    verification_mode=verification_mode,
                )
            except TypeError as e:
                if 'verification_mode' in str(e):
                    self.logger.warning(
                        f"[SERVICE] verification_mode not supported, retrying without it: {e}"
                    )
                    return self.bypass_engine.test_strategy_as_service(
                        target_ip=target_ip,
                        strategy_input=strategy_input,
                        domain=domain,
                        timeout=timeout,
                    )
                else:
                    raise
        
        self.logger.warning("[SERVICE] test_strategy_as_service not available, using fallback")
        return self.test_strategy_like_testing_mode(
            target_ip=target_ip,
            strategy_input=strategy_input,
            timeout=timeout,
            domain=domain,
        )
    
    @property
    def last_capture_path(self) -> Optional[str]:
        """Property to get the last capture path for compatibility (per-engine, not per-domain)."""
        return getattr(self, '_last_capture_path', None)
    
    def get_capture_path(self, domain: str) -> Optional[str]:
        """
        Get capture path for a domain.

        NOTE: currently returns the last capture path regardless of domain.
        """
        return getattr(self, '_last_capture_path', None)
    
    def analyze_captured_pcap(
        self,
        pcap_file: str,
        expected_strategy: Optional[Dict[str, Any]] = None,
    ) -> StrategyAnalysisResult:
        """
        Analyze a captured PCAP file to verify strategy application.
        """
        return self.pcap_analyzer.analyze_strategy_application(pcap_file, expected_strategy)
    
    def compare_pcap_with_expected(
        self,
        pcap_file: str,
        expected_strategy: Dict[str, Any],
    ):
        """
        Compare captured PCAP with expected strategy.
        """
        return self.pcap_analyzer.compare_with_expected(pcap_file, expected_strategy)
    
    def validate_clienthello_size(self, pcap_file: str) -> Dict[str, Any]:
        """
        Validate that ClientHello size is adequate for DPI bypass.

        Потоково читает PCAP с помощью PcapReader, чтобы не держать весь файл в памяти.
        """
        try:
            from scapy.all import PcapReader, Raw, TCP
            import os
            
            if not os.path.exists(pcap_file):
                return {
                    'valid': False,
                    'reason': f'PCAP file not found: {pcap_file}',
                    'recommendation': 'Check PCAP capture configuration',
                }
            
            file_size = os.path.getsize(pcap_file)
            if file_size == 0:
                return {
                    'valid': False,
                    'reason': 'PCAP file is empty',
                    'recommendation': 'Ensure PCAP capture is running during test',
                }
            
            self.logger.info(f"📊 Analyzing ClientHello sizes in {pcap_file} ({file_size} bytes)")
            
            clienthello_sizes = []
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    if TCP not in pkt or Raw not in pkt:
                        continue
                    payload = bytes(pkt[Raw])
                    if len(payload) <= 5:
                        continue

                    # TLS Handshake (0x16) + ClientHello (0x01)
                    if payload[0] == 0x16 and payload[5] == 0x01:
                        # TLS record length (bytes 3-4)
                        record_length = (payload[3] << 8) | payload[4]
                        size_on_wire = record_length + 5  # 5 байт заголовка
                        clienthello_sizes.append(size_on_wire)
            
            if not clienthello_sizes:
                return {
                    'valid': False,
                    'reason': 'No ClientHello packets found in PCAP',
                    'recommendation': (
                        'Ensure test is making HTTPS connections and PCAP capture includes TLS handshake'
                    ),
                }
            
            avg_size = sum(clienthello_sizes) / len(clienthello_sizes)
            min_size = min(clienthello_sizes)
            max_size = max(clienthello_sizes)
            
            self.logger.info("📊 ClientHello statistics:")
            self.logger.info(f"   Count: {len(clienthello_sizes)}")
            self.logger.info(f"   Average: {avg_size:.0f} bytes")
            self.logger.info(f"   Min: {min_size} bytes")
            self.logger.info(f"   Max: {max_size} bytes")
            
            if avg_size < self.MIN_CLIENT_HELLO_SIZE:
                self.logger.warning(
                    f"⚠️ ClientHello too small: avg={avg_size:.0f} bytes (need >={self.MIN_CLIENT_HELLO_SIZE})"
                )
                self.logger.warning("⚠️ This may cause FALSE NEGATIVES in strategy testing!")
                self.logger.warning("⚠️ DPI systems easily analyze and block small ClientHello packets")
                
                return {
                    'valid': False,
                    'avg_size': avg_size,
                    'min_size': min_size,
                    'max_size': max_size,
                    'count': len(clienthello_sizes),
                    'sizes': clienthello_sizes,
                    'reason': (
                        f'ClientHello too small: avg={avg_size:.0f} bytes '
                        f'(need >={self.MIN_CLIENT_HELLO_SIZE})'
                    ),
                    'recommendation': (
                        'Use curl with HTTP/2 support (winget install curl.curl) or browser for testing'
                    ),
                }
            
            self.logger.info("✅ ClientHello size is adequate for DPI bypass testing")
            
            return {
                'valid': True,
                'avg_size': avg_size,
                'min_size': min_size,
                'max_size': max_size,
                'count': len(clienthello_sizes),
                'sizes': clienthello_sizes,
                'pcap_file': pcap_file,
            }
            
        except ImportError:
            self.logger.warning("⚠️ Scapy not available for ClientHello size validation")
            return {
                'valid': False,
                'reason': 'Scapy not available',
                'recommendation': 'Install scapy: pip install scapy',
            }
        except Exception as e:
            self.logger.error(f"❌ Error validating ClientHello size: {e}", exc_info=True)
            return {
                'valid': False,
                'reason': f'Error during validation: {str(e)}',
                'recommendation': 'Check PCAP file and try again',
            }
    
    def _ensure_windivert_ready(self):
        """
        Убедиться что WinDivert запущен и готов перехватывать пакеты.
        """
        try:
            if hasattr(self.bypass_engine, 'is_windivert_active'):
                is_active = self.bypass_engine.is_windivert_active()
                if is_active:
                    self.logger.info("✅ WinDivert is active and ready")
                else:
                    self.logger.warning("⚠️ WinDivert is not active - strategies may not be applied!")
            
            if hasattr(self.bypass_engine, 'get_mode'):
                mode = self.bypass_engine.get_mode()
                self.logger.info(f"🔧 Bypass engine mode: {mode}")
                if mode == 'testing':
                    self.logger.info("✅ Testing mode confirmed - WinDivert should intercept packets")
            
            time.sleep(0.2)
            
        except Exception as e:
            self.logger.warning(f"⚠️ Could not verify WinDivert status: {e}")
    
    def _get_local_ip(self, target: Optional[str] = None) -> str:
        """
        Get local IP address used for outgoing connections.

        Если указан target (IP), определяем IP интерфейса, который используется для маршрута к нему.
        """
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                target_addr = target or '8.8.8.8'
                s.connect((target_addr, 80))
                local_ip = s.getsockname()[0]
                return local_ip
            finally:
                s.close()
        except Exception as e:
            self.logger.warning(f"⚠️ Could not determine local IP: {e}, using 127.0.0.1")
            return "127.0.0.1"
    
    def _execute_strategy_test_with_tracking(
        self,
        domain: str,
        strategy: Dict[str, Any],
        timeout: float,
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Execute strategy test and return connection port for tracking.
        """
        success, error = self._execute_strategy_test(domain, strategy, timeout)
        
        test_port = getattr(self.bypass_engine, '_last_test_port', None)
        
        if test_port:
            self.logger.debug(f"📍 Extracted test port from engine: {test_port}")
        else:
            self.logger.debug(
                f"📍 Could not extract test port from engine (engine type: "
                f"{type(self.bypass_engine).__name__})"
            )
        
        return success, error, test_port
    
    def __getattr__(self, name):
        """
        Delegate unknown attributes to the wrapped bypass engine.
        """
        return getattr(self.bypass_engine, name)


def create_enhanced_bypass_engine(
    bypass_engine,
    enable_capture: bool = True,
) -> WindowsBypassEngineWithCapture:
    """
    Factory function to create an enhanced bypass engine with PCAP capture.
    """
    return WindowsBypassEngineWithCapture(bypass_engine, enable_capture)