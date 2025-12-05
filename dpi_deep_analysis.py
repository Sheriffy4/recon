# path:  dpi_deep_analysis.py
"""
Глубокий анализ DPI для abs-0.twimg.com
Анализирует поведение DPI и создает целевые стратегии обхода
"""

import json
import subprocess
import time
import socket
import struct
from typing import Dict, List, Tuple, Optional
import scapy.all as scapy

class DPIAnalyzer:
    def __init__(self, target_domain: str = "abs-0.twimg.com"):
        self.target_domain = target_domain
        self.target_ip = None
        self.analysis_results = {}
        
    def resolve_target(self) -> Optional[str]:
        """Резолвит IP адрес целевого домена"""
        try:
            self.target_ip = socket.gethostbyname(self.target_domain)
            print(f"✅ Резолв {self.target_domain} -> {self.target_ip}")
            return self.target_ip
        except Exception as e:
            print(f"❌ Ошибка резолва {self.target_domain}: {e}")
            return None
    
    def test_tcp_connection(self) -> Dict:
        """Тестирует базовое TCP соединение"""
        print("🔍 Анализ TCP соединения...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            start_time = time.time()
            result = sock.connect_ex((self.target_ip, 443))
            connect_time = time.time() - start_time
            
            if result == 0:
                print(f"✅ TCP соединение успешно ({connect_time:.3f}s)")
                sock.close()
                return {"success": True, "time": connect_time, "error": None}
            else:
                print(f"❌ TCP соединение неудачно: {result}")
                return {"success": False, "time": connect_time, "error": result}
                
        except Exception as e:
            print(f"❌ Ошибка TCP соединения: {e}")
            return {"success": False, "time": 0, "error": str(e)}
    
    def test_tls_handshake(self) -> Dict:
        """Тестирует TLS handshake"""
        print("🔍 Анализ TLS handshake...")
        
        try:
            import ssl
            
            context = ssl.create_default_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            
            # Подключаемся
            sock.connect((self.target_ip, 443))
            
            # Оборачиваем в SSL
            start_time = time.time()
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target_domain)
            handshake_time = time.time() - start_time
            
            print(f"✅ TLS handshake успешно ({handshake_time:.3f}s)")
            
            # Получаем информацию о сертификате
            cert = ssl_sock.getpeercert()
            cipher = ssl_sock.cipher()
            
            ssl_sock.close()
            
            return {
                "success": True,
                "time": handshake_time,
                "cipher": cipher,
                "cert_subject": cert.get("subject"),
                "cert_issuer": cert.get("issuer")
            }
            
        except Exception as e:
            print(f"❌ TLS handshake неудачно: {e}")
            return {"success": False, "time": 0, "error": str(e)}
    
    def test_http_request(self) -> Dict:
        """Тестирует HTTP запрос"""
        print("🔍 Анализ HTTP запроса...")
        
        try:
            import requests
            
            start_time = time.time()
            response = requests.get(
                f"https://{self.target_domain}",
                timeout=15,
                allow_redirects=False
            )
            request_time = time.time() - start_time
            
            print(f"✅ HTTP запрос успешно ({request_time:.3f}s) - {response.status_code}")
            
            return {
                "success": True,
                "time": request_time,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content)
            }
            
        except Exception as e:
            print(f"❌ HTTP запрос неудачно: {e}")
            return {"success": False, "time": 0, "error": str(e)}
    
    def analyze_packet_patterns(self) -> Dict:
        """Анализирует паттерны пакетов для определения типа DPI"""
        print("🔍 Анализ паттернов пакетов...")
        
        patterns = {
            "rst_after_tls_hello": False,
            "connection_reset": False,
            "timeout_pattern": False,
            "packet_drop": False
        }
        
        try:
            # Простой тест - отправляем TLS Client Hello и смотрим на ответ
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, 443))
            
            # Создаем простой TLS Client Hello
            tls_hello = self.create_tls_client_hello()
            
            start_time = time.time()
            sock.send(tls_hello)
            
            try:
                response = sock.recv(4096)
                response_time = time.time() - start_time
                
                if len(response) == 0:
                    patterns["connection_reset"] = True
                elif response[0:1] == b'\x15':  # TLS Alert
                    patterns["rst_after_tls_hello"] = True
                    
            except socket.timeout:
                patterns["timeout_pattern"] = True
            except ConnectionResetError:
                patterns["connection_reset"] = True
            
            sock.close()
            
        except Exception as e:
            print(f"Ошибка анализа паттернов: {e}")
        
        return patterns
    
    def create_tls_client_hello(self) -> bytes:
        """Создает простой TLS Client Hello пакет"""
        # Упрощенный TLS 1.2 Client Hello
        tls_version = b'\x03\x03'  # TLS 1.2
        random = b'\x00' * 32  # 32 байта случайных данных
        session_id_len = b'\x00'  # Нет session ID
        
        # Cipher suites
        cipher_suites = b'\x00\x02\x00\x35'  # TLS_RSA_WITH_AES_256_CBC_SHA
        compression = b'\x01\x00'  # Нет сжатия
        
        # SNI extension
        sni_name = self.target_domain.encode()
        sni_len = len(sni_name)
        sni_ext = (
            b'\x00\x00' +  # SNI extension type
            struct.pack('>H', sni_len + 5) +  # Extension length
            struct.pack('>H', sni_len + 3) +  # Server name list length
            b'\x00' +  # Name type (hostname)
            struct.pack('>H', sni_len) +  # Name length
            sni_name
        )
        
        extensions_len = len(sni_ext)
        extensions = struct.pack('>H', extensions_len) + sni_ext
        
        # Собираем Client Hello
        hello_body = (
            tls_version + random + session_id_len + 
            cipher_suites + compression + extensions
        )
        
        hello_len = len(hello_body)
        handshake_header = b'\x01' + struct.pack('>I', hello_len)[1:]  # Client Hello type + length
        
        record_len = len(handshake_header) + len(hello_body)
        tls_record = (
            b'\x16' +  # Handshake record type
            tls_version +  # TLS version
            struct.pack('>H', record_len) +  # Record length
            handshake_header + hello_body
        )
        
        return tls_record
    
    def determine_dpi_type(self, tcp_result: Dict, tls_result: Dict, 
                          http_result: Dict, patterns: Dict) -> str:
        """Определяет тип DPI на основе результатов тестов"""
        
        if tcp_result["success"] and not tls_result["success"]:
            if patterns["rst_after_tls_hello"]:
                return "TLS_SNI_BLOCKING"
            elif patterns["timeout_pattern"]:
                return "TLS_DEEP_INSPECTION"
            elif patterns["connection_reset"]:
                return "CONNECTION_RESET_DPI"
        
        if not tcp_result["success"]:
            return "IP_BLOCKING"
        
        if tls_result["success"] and not http_result["success"]:
            return "HTTP_CONTENT_FILTERING"
        
        if all(r["success"] for r in [tcp_result, tls_result, http_result]):
            return "NO_BLOCKING_DETECTED"
        
        return "UNKNOWN_DPI_TYPE"
    
    def generate_targeted_strategies(self, dpi_type: str) -> List[Dict]:
        """Генерирует целевые стратегии на основе типа DPI"""
        
        strategies = []
        
        if dpi_type == "TLS_SNI_BLOCKING":
            strategies.extend([
                {
                    "name": "sni_fragmentation",
                    "strategy": "--dpi-desync=fake,disorder --dpi-desync-split-tls=sni --dpi-desync-fooling=badseq --dpi-desync-ttl=1"
                },
                {
                    "name": "sni_fake_packets",
                    "strategy": "--dpi-desync=fake --dpi-desync-fake-tls=0x160301 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=5"
                },
                {
                    "name": "sni_multisplit",
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-tls=sni --dpi-desync-split-count=10 --dpi-desync-fooling=badsum"
                }
            ])
        
        elif dpi_type == "TLS_DEEP_INSPECTION":
            strategies.extend([
                {
                    "name": "tls_record_fragmentation",
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=20 --dpi-desync-split-seqovl=100 --dpi-desync-fooling=badsum --dpi-desync-ttl=1"
                },
                {
                    "name": "tls_fake_handshake",
                    "strategy": "--dpi-desync=fake,disorder --dpi-desync-fake-tls=0x16030300 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1"
                },
                {
                    "name": "aggressive_fragmentation",
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=50 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=10"
                }
            ])
        
        elif dpi_type == "CONNECTION_RESET_DPI":
            strategies.extend([
                {
                    "name": "tcp_md5_bypass",
                    "strategy": "--dpi-desync=fake,disorder --dpi-desync-fooling=md5sig --dpi-desync-ttl=2"
                },
                {
                    "name": "syndata_bypass",
                    "strategy": "--dpi-desync=syndata --dpi-desync-fooling=badseq --dpi-desync-ttl=1"
                },
                {
                    "name": "ipfrag_bypass",
                    "strategy": "--dpi-desync=ipfrag2 --dpi-desync-fooling=badsum --dpi-desync-ttl=3"
                }
            ])
        
        # Универсальные стратегии для всех типов
        strategies.extend([
            {
                "name": "disorder_low_ttl",
                "strategy": "--dpi-desync=fake,disorder --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-ttl=1 --dpi-desync-repeats=3"
            },
            {
                "name": "multidisorder_aggressive",
                "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=1,3,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1"
            }
        ])
        
        return strategies
    
    def run_full_analysis(self) -> Dict:
        """Запускает полный анализ DPI"""
        print("🚀 Запуск полного анализа DPI")
        print("=" * 60)
        
        # Резолвим IP
        if not self.resolve_target():
            return {"error": "Не удалось резолвить домен"}
        
        # Тестируем соединения
        tcp_result = self.test_tcp_connection()
        tls_result = self.test_tls_handshake()
        http_result = self.test_http_request()
        
        # Анализируем паттерны
        patterns = self.analyze_packet_patterns()
        
        # Определяем тип DPI
        dpi_type = self.determine_dpi_type(tcp_result, tls_result, http_result, patterns)
        
        print(f"\n🎯 Определен тип DPI: {dpi_type}")
        
        # Генерируем целевые стратегии
        targeted_strategies = self.generate_targeted_strategies(dpi_type)
        
        analysis = {
            "target_domain": self.target_domain,
            "target_ip": self.target_ip,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tcp_test": tcp_result,
            "tls_test": tls_result,
            "http_test": http_result,
            "packet_patterns": patterns,
            "dpi_type": dpi_type,
            "targeted_strategies": targeted_strategies
        }
        
        # Сохраняем результаты
        with open(f"dpi_analysis_{self.target_domain}_{int(time.time())}.json", "w") as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        
        return analysis

def main():
    analyzer = DPIAnalyzer("abs-0.twimg.com")
    
    print("🔬 Глубокий анализ DPI для abs-0.twimg.com")
    print("=" * 60)
    
    analysis = analyzer.run_full_analysis()
    
    if "error" in analysis:
        print(f"❌ Ошибка анализа: {analysis['error']}")
        return
    
    print("\n📊 РЕЗУЛЬТАТЫ АНАЛИЗА:")
    print("=" * 40)
    print(f"Тип DPI: {analysis['dpi_type']}")
    print(f"TCP соединение: {'✅' if analysis['tcp_test']['success'] else '❌'}")
    print(f"TLS handshake: {'✅' if analysis['tls_test']['success'] else '❌'}")
    print(f"HTTP запрос: {'✅' if analysis['http_test']['success'] else '❌'}")
    
    print(f"\n🎯 Сгенерировано {len(analysis['targeted_strategies'])} целевых стратегий")
    
    for strategy in analysis['targeted_strategies']:
        print(f"  • {strategy['name']}: {strategy['strategy']}")

if __name__ == "__main__":
    main()