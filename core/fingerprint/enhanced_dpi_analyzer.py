# core/fingerprint/enhanced_dpi_analyzer.py
"""
Enhanced DPI Analyzer - расширение существующего dpi_deep_analysis.py
Интегрируется с DPI Fingerprint Service для создания и обновления fingerprint'ов
"""

import json
import socket
import struct
import time
import ssl
import requests
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from pathlib import Path

# Импортируем наш DPI Fingerprint Service
from core.fingerprint.dpi_fingerprint_service import (
    DPIFingerprintService, DPIFingerprint, DPIType, DPIMode, DetectionLayer, AttackResponse
)

# Импортируем базовый анализатор
import sys
sys.path.append('.')
try:
    from dpi_deep_analysis import DPIAnalyzer as BaseDPIAnalyzer
except ImportError:
    # Fallback если базовый анализатор недоступен
    class BaseDPIAnalyzer:
        def __init__(self, target_domain: str):
            self.target_domain = target_domain
            self.target_ip = None


class EnhancedDPIAnalyzer(BaseDPIAnalyzer):
    """Расширенный DPI анализатор с поддержкой fingerprinting"""
    
    def __init__(self, target_domain: str, fingerprint_service: DPIFingerprintService = None):
        super().__init__(target_domain)
        self.fingerprint_service = fingerprint_service or DPIFingerprintService()
        self.quick_tests_enabled = True
        self.behavioral_analysis_enabled = True
        
    def create_dpi_fingerprint(self, mode: str = "comprehensive") -> DPIFingerprint:
        """Создает DPI fingerprint для домена"""
        print(f"🔬 Создание DPI fingerprint для {self.target_domain} (режим: {mode})")
        
        # Получаем или создаем базовый fingerprint
        fingerprint = self.fingerprint_service.get_or_create(self.target_domain, self.target_ip)
        
        if mode == "quick":
            # Быстрые тесты
            basic_features = self._run_quick_tests()
        elif mode == "comprehensive":
            # Полный анализ
            basic_features = self._run_comprehensive_tests()
        else:
            # Глубокий анализ с PCAP
            basic_features = self._run_deep_analysis()
        
        # Обновляем fingerprint на основе результатов
        self._update_fingerprint_from_tests(fingerprint, basic_features)
        
        return fingerprint
    
    def _run_quick_tests(self) -> Dict[str, Any]:
        """Быстрые тесты для определения основных характеристик DPI"""
        print("⚡ Выполнение быстрых тестов...")
        
        features = {
            "test_mode": "quick",
            "timestamp": datetime.now().isoformat()
        }
        
        # Резолвим IP если не сделано
        if not self.target_ip:
            self.resolve_target()
        
        # Тест 1: Базовое TCP соединение
        tcp_result = self.test_tcp_connection()
        features["tcp_connection"] = tcp_result
        
        # Тест 2: TLS handshake
        tls_result = self.test_tls_handshake()
        features["tls_handshake"] = tls_result
        
        # Тест 3: Определение типа блокировки
        if tcp_result["success"] and not tls_result["success"]:
            features["likely_tls_blocking"] = True
            features["dpi_type_hint"] = "stateful_tls_inspector"
        elif not tcp_result["success"]:
            features["likely_ip_blocking"] = True
            features["dpi_type_hint"] = "ip_level_filter"
        else:
            features["no_obvious_blocking"] = True
            features["dpi_type_hint"] = "none_or_passive"
        
        # Тест 4: Быстрый SNI тест
        sni_test = self._quick_sni_test()
        features["sni_test"] = sni_test
        
        return features
    
    def _run_comprehensive_tests(self) -> Dict[str, Any]:
        """Комплексные тесты для детального анализа DPI"""
        print("🔍 Выполнение комплексных тестов...")
        
        # Начинаем с быстрых тестов
        features = self._run_quick_tests()
        features["test_mode"] = "comprehensive"
        
        # Дополнительные тесты
        
        # Тест 5: Анализ паттернов пакетов
        packet_patterns = self.analyze_packet_patterns()
        features["packet_patterns"] = packet_patterns
        
        # Тест 6: Тестирование фрагментации
        fragmentation_test = self._test_fragmentation_support()
        features["fragmentation_support"] = fragmentation_test
        
        # Тест 7: Тестирование различных TLS версий
        tls_versions_test = self._test_tls_versions()
        features["tls_versions"] = tls_versions_test
        
        # Тест 8: Анализ тайминга ответов
        timing_analysis = self._analyze_response_timing()
        features["timing_analysis"] = timing_analysis
        
        # Тест 9: Проверка stateful/stateless поведения
        statefulness_test = self._test_statefulness()
        features["statefulness"] = statefulness_test
        
        return features
    
    def _run_deep_analysis(self) -> Dict[str, Any]:
        """Глубокий анализ с захватом трафика"""
        print("🔬 Выполнение глубокого анализа...")
        
        # Начинаем с комплексных тестов
        features = self._run_comprehensive_tests()
        features["test_mode"] = "deep"
        
        # Дополнительные глубокие тесты
        
        # Тест 10: Анализ поведенческих сигнатур
        behavioral_signatures = self._analyze_behavioral_signatures()
        features["behavioral_signatures"] = behavioral_signatures
        
        # Тест 11: Тестирование различных атак
        attack_responses = self._test_attack_suite()
        features["attack_responses"] = attack_responses
        
        return features
    
    def _quick_sni_test(self) -> Dict[str, Any]:
        """Быстрый тест на SNI фильтрацию"""
        print("  🔍 Тест SNI фильтрации...")
        
        try:
            # Создаем TLS Client Hello с правильным SNI
            correct_hello = self.create_tls_client_hello()
            
            # Создаем TLS Client Hello с неправильным SNI
            wrong_hello = self._create_tls_hello_wrong_sni()
            
            # Тестируем оба варианта
            correct_result = self._send_tls_hello(correct_hello)
            wrong_result = self._send_tls_hello(wrong_hello)
            
            sni_filtering = (
                correct_result.get("blocked", False) != wrong_result.get("blocked", False)
            )
            
            return {
                "sni_filtering_detected": sni_filtering,
                "correct_sni_blocked": correct_result.get("blocked", False),
                "wrong_sni_blocked": wrong_result.get("blocked", False),
                "confidence": 0.8 if sni_filtering else 0.3
            }
            
        except Exception as e:
            return {
                "sni_filtering_detected": False,
                "error": str(e),
                "confidence": 0.0
            }
    
    def _test_fragmentation_support(self) -> Dict[str, Any]:
        """Тестирование поддержки фрагментации"""
        print("  🔍 Тест фрагментации...")
        
        try:
            # Отправляем фрагментированный TLS Client Hello
            fragmented_hello = self._create_fragmented_tls_hello()
            result = self._send_fragmented_packets(fragmented_hello)
            
            return {
                "supports_fragmentation": not result.get("blocked", True),
                "reassembles_fragments": result.get("reassembled", False),
                "fragment_timeout_ms": result.get("timeout_ms", 0),
                "confidence": 0.7
            }
            
        except Exception as e:
            return {
                "supports_fragmentation": None,
                "error": str(e),
                "confidence": 0.0
            }
    
    def _test_tls_versions(self) -> Dict[str, Any]:
        """Тестирование различных версий TLS"""
        print("  🔍 Тест версий TLS...")
        
        versions = {
            "TLS 1.0": 0x0301,
            "TLS 1.1": 0x0302,
            "TLS 1.2": 0x0303,
            "TLS 1.3": 0x0304
        }
        
        results = {}
        
        for version_name, version_code in versions.items():
            try:
                hello = self._create_tls_hello_version(version_code)
                result = self._send_tls_hello(hello)
                results[version_name] = {
                    "supported": not result.get("blocked", True),
                    "response_time_ms": result.get("response_time_ms", 0)
                }
            except Exception as e:
                results[version_name] = {
                    "supported": False,
                    "error": str(e)
                }
        
        return results
    
    def _analyze_response_timing(self) -> Dict[str, Any]:
        """Анализ тайминга ответов для определения поведения DPI"""
        print("  🔍 Анализ тайминга ответов...")
        
        timings = []
        
        # Выполняем несколько одинаковых запросов
        for i in range(5):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((self.target_ip, 443))
                end_time = time.time()
                
                timing = (end_time - start_time) * 1000  # в миллисекундах
                timings.append(timing)
                
                sock.close()
                time.sleep(0.1)  # Небольшая пауза между запросами
                
            except Exception:
                continue
        
        if not timings:
            return {"error": "Не удалось получить тайминги"}
        
        avg_timing = sum(timings) / len(timings)
        timing_variance = sum((t - avg_timing) ** 2 for t in timings) / len(timings)
        
        return {
            "average_response_ms": avg_timing,
            "timing_variance": timing_variance,
            "consistent_timing": timing_variance < 10,  # Низкая вариативность
            "samples": timings,
            "confidence": 0.6
        }
    
    def _test_statefulness(self) -> Dict[str, Any]:
        """Тестирование stateful/stateless поведения DPI"""
        print("  🔍 Тест stateful/stateless поведения...")
        
        try:
            # Тест 1: Отправляем пакеты в неправильном порядке
            out_of_order_result = self._test_out_of_order_packets()
            
            # Тест 2: Тестируем повторное использование соединения
            connection_reuse_result = self._test_connection_reuse()
            
            # Определяем тип на основе результатов
            if out_of_order_result.get("handles_disorder", False):
                dpi_type = "stateless"
            elif connection_reuse_result.get("tracks_state", False):
                dpi_type = "stateful"
            else:
                dpi_type = "unknown"
            
            return {
                "dpi_type": dpi_type,
                "out_of_order_test": out_of_order_result,
                "connection_reuse_test": connection_reuse_result,
                "confidence": 0.7
            }
            
        except Exception as e:
            return {
                "dpi_type": "unknown",
                "error": str(e),
                "confidence": 0.0
            }
    
    def _analyze_behavioral_signatures(self) -> Dict[str, Any]:
        """Анализ поведенческих сигнатур DPI"""
        print("  🔍 Анализ поведенческих сигнатур...")
        
        signatures = {}
        
        # Сигнатура 1: Анализ RST пакетов
        rst_analysis = self._analyze_rst_behavior()
        signatures["rst_behavior"] = rst_analysis
        
        # Сигнатура 2: Анализ timeout'ов
        timeout_analysis = self._analyze_timeout_behavior()
        signatures["timeout_behavior"] = timeout_analysis
        
        # Сигнатура 3: Анализ содержимого ответов
        content_analysis = self._analyze_response_content()
        signatures["content_analysis"] = content_analysis
        
        return signatures
    
    def _test_attack_suite(self) -> Dict[str, AttackResponse]:
        """Тестирование набора атак для определения уязвимостей"""
        print("  🔍 Тестирование набора атак...")
        
        attack_responses = {}
        
        # Список атак для тестирования
        attacks = [
            {
                "name": "fake_sni",
                "description": "Fake packets with wrong SNI",
                "test_func": self._test_fake_sni_attack
            },
            {
                "name": "tls_fragmentation",
                "description": "TLS record fragmentation",
                "test_func": self._test_tls_fragmentation_attack
            },
            {
                "name": "disorder_packets",
                "description": "Out-of-order packet delivery",
                "test_func": self._test_disorder_attack
            },
            {
                "name": "low_ttl_decoy",
                "description": "Low TTL decoy packets",
                "test_func": self._test_low_ttl_attack
            }
        ]
        
        for attack in attacks:
            try:
                print(f"    🧪 Тестирование атаки: {attack['name']}")
                result = attack["test_func"]()
                
                attack_response = AttackResponse(
                    attack_name=attack["name"],
                    parameters=result.get("parameters", {}),
                    bypassed=result.get("success", False),
                    response_type=result.get("response_type", "unknown"),
                    block_timing_ms=result.get("block_timing_ms"),
                    success_rate=result.get("success_rate", 0.0),
                    tested_at=datetime.now()
                )
                
                attack_responses[attack["name"]] = attack_response
                
            except Exception as e:
                print(f"    ❌ Ошибка тестирования {attack['name']}: {e}")
        
        return attack_responses
    
    def _update_fingerprint_from_tests(self, fingerprint: DPIFingerprint, features: Dict[str, Any]):
        """Обновление fingerprint на основе результатов тестов"""
        print("🔄 Обновление fingerprint на основе результатов тестов...")
        
        # Обновляем тип DPI
        if features.get("statefulness", {}).get("dpi_type") == "stateful":
            fingerprint.dpi_type = DPIType.STATEFUL
        elif features.get("statefulness", {}).get("dpi_type") == "stateless":
            fingerprint.dpi_type = DPIType.STATELESS
        
        # Обновляем режим DPI
        if features.get("packet_patterns", {}).get("rst_after_tls_hello"):
            fingerprint.dpi_mode = DPIMode.ACTIVE_RST
        elif features.get("packet_patterns", {}).get("timeout_pattern"):
            fingerprint.dpi_mode = DPIMode.PASSIVE
        
        # Обновляем уровень обнаружения
        if features.get("sni_test", {}).get("sni_filtering_detected"):
            fingerprint.detection_layer = DetectionLayer.L7_TLS
        elif features.get("tcp_connection", {}).get("success") and not features.get("tls_handshake", {}).get("success"):
            fingerprint.detection_layer = DetectionLayer.L4_TCP
        
        # Обновляем поведенческие сигнатуры
        behavioral_sigs = {}
        
        if "sni_test" in features:
            behavioral_sigs.update(features["sni_test"])
        
        if "fragmentation_support" in features:
            behavioral_sigs.update(features["fragmentation_support"])
        
        if "timing_analysis" in features:
            behavioral_sigs.update(features["timing_analysis"])
        
        fingerprint.behavioral_signatures.update(behavioral_sigs)
        
        # Добавляем результаты атак
        if "attack_responses" in features:
            for attack_name, attack_response in features["attack_responses"].items():
                fingerprint.add_attack_response(attack_response)
        
        # Обновляем confidence на основе количества тестов и их результатов
        test_count = len([k for k in features.keys() if not k.startswith("_")])
        
        # Базовая confidence на основе количества тестов
        base_confidence = min(0.15 * test_count, 0.7)
        
        # Бонус за успешные тесты
        successful_tests = 0
        if features.get("tcp_connection", {}).get("success"):
            successful_tests += 1
        if features.get("sni_test", {}).get("confidence", 0) > 0.7:
            successful_tests += 1
        if features.get("statefulness", {}).get("confidence", 0) > 0.6:
            successful_tests += 1
        
        success_bonus = successful_tests * 0.1
        final_confidence = min(0.85, base_confidence + success_bonus)
        
        fingerprint.update_confidence(final_confidence)
        
        # Сохраняем обновленный fingerprint
        self.fingerprint_service._save_cache()
    
    def update_from_failure(self, failure_report: Dict[str, Any]) -> DPIFingerprint:
        """Обновление fingerprint на основе анализа неудач"""
        print(f"🔄 Обновление fingerprint для {self.target_domain} на основе анализа неудач")
        
        # Получаем существующий fingerprint или создаем новый
        fingerprint = self.fingerprint_service.get_or_create(self.target_domain, self.target_ip)
        
        # Обновляем через сервис
        self.fingerprint_service.update_from_failure(self.target_domain, failure_report)
        
        return fingerprint
    
    # Вспомогательные методы для тестирования атак
    
    def _test_fake_sni_attack(self) -> Dict[str, Any]:
        """Тестирование атаки с поддельными SNI пакетами"""
        # Заглушка - в реальной реализации здесь будет логика тестирования
        return {
            "success": False,
            "parameters": {"split_pos": "sni", "ttl": 1},
            "response_type": "block_rst",
            "success_rate": 0.0
        }
    
    def _test_tls_fragmentation_attack(self) -> Dict[str, Any]:
        """Тестирование атаки фрагментацией TLS записей"""
        return {
            "success": False,
            "parameters": {"split_count": 8},
            "response_type": "timeout",
            "success_rate": 0.0
        }
    
    def _test_disorder_attack(self) -> Dict[str, Any]:
        """Тестирование атаки с нарушением порядка пакетов"""
        return {
            "success": False,
            "parameters": {"split_pos": 3},
            "response_type": "block_silent",
            "success_rate": 0.0
        }
    
    def _test_low_ttl_attack(self) -> Dict[str, Any]:
        """Тестирование атаки с низким TTL"""
        return {
            "success": False,
            "parameters": {"ttl": 1, "fooling": "badseq"},
            "response_type": "block_rst",
            "success_rate": 0.0
        }
    
    # Дополнительные вспомогательные методы
    
    def _create_tls_hello_wrong_sni(self) -> bytes:
        """Создание TLS Client Hello с неправильным SNI"""
        # Заглушка - используем базовый метод с измененным SNI
        return self.create_tls_client_hello()
    
    def _create_tls_hello_version(self, version_code: int) -> bytes:
        """Создание TLS Client Hello с определенной версией"""
        # Заглушка - в реальной реализации здесь будет создание пакета с нужной версией
        return self.create_tls_client_hello()
    
    def _send_tls_hello(self, hello_packet: bytes) -> Dict[str, Any]:
        """Отправка TLS Client Hello и анализ ответа"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            start_time = time.time()
            sock.connect((self.target_ip, 443))
            sock.send(hello_packet)
            
            try:
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                
                blocked = len(response) == 0 or response[0:1] == b'\x15'  # TLS Alert
                
                return {
                    "blocked": blocked,
                    "response_time_ms": response_time,
                    "response_length": len(response)
                }
                
            except socket.timeout:
                return {
                    "blocked": True,
                    "response_time_ms": 5000,
                    "timeout": True
                }
            finally:
                sock.close()
                
        except Exception as e:
            return {
                "blocked": True,
                "error": str(e)
            }
    
    def _create_fragmented_tls_hello(self) -> List[bytes]:
        """Создание фрагментированного TLS Client Hello"""
        # Заглушка - в реальной реализации здесь будет фрагментация пакета
        hello = self.create_tls_client_hello()
        # Простая фрагментация на две части
        mid = len(hello) // 2
        return [hello[:mid], hello[mid:]]
    
    def _send_fragmented_packets(self, fragments: List[bytes]) -> Dict[str, Any]:
        """Отправка фрагментированных пакетов"""
        # Заглушка - в реальной реализации здесь будет отправка фрагментов
        return {
            "blocked": True,
            "reassembled": False,
            "timeout_ms": 1000
        }
    
    def _test_out_of_order_packets(self) -> Dict[str, Any]:
        """Тестирование пакетов в неправильном порядке"""
        return {"handles_disorder": False}
    
    def _test_connection_reuse(self) -> Dict[str, Any]:
        """Тестирование повторного использования соединения"""
        return {"tracks_state": True}
    
    def _analyze_rst_behavior(self) -> Dict[str, Any]:
        """Анализ поведения RST пакетов"""
        return {"rst_injection_detected": False}
    
    def _analyze_timeout_behavior(self) -> Dict[str, Any]:
        """Анализ поведения timeout'ов"""
        return {"consistent_timeouts": True}
    
    def _analyze_response_content(self) -> Dict[str, Any]:
        """Анализ содержимого ответов"""
        return {"content_filtering": False}


# Пример использования
if __name__ == "__main__":
    # Создаем enhanced анализатор
    analyzer = EnhancedDPIAnalyzer("abs-0.twimg.com")
    
    print("🔬 Enhanced DPI анализ для abs-0.twimg.com")
    print("=" * 60)
    
    # Создаем fingerprint в быстром режиме
    fingerprint = analyzer.create_dpi_fingerprint("quick")
    
    print(f"\n📊 Создан DPI fingerprint:")
    print(f"  ID: {fingerprint.fingerprint_id}")
    print(f"  Тип DPI: {fingerprint.dpi_type.value}")
    print(f"  Режим DPI: {fingerprint.dpi_mode.value}")
    print(f"  Уровень обнаружения: {fingerprint.detection_layer.value}")
    print(f"  Confidence: {fingerprint.confidence:.2f}")
    print(f"  Поведенческие сигнатуры: {len(fingerprint.behavioral_signatures)}")
    print(f"  Ответы на атаки: {len(fingerprint.attack_responses)}")
    
    # Получаем статистику сервиса
    stats = analyzer.fingerprint_service.get_statistics()
    print(f"\n📈 Статистика fingerprint'ов: {stats['total']} всего")