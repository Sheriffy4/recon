# recon/core/bypass/attacks/tls/early_data_smuggling.py
"""
TLS 1.3 Early Data Smuggling Attack
"""

import time
from typing import List

# Импорты из новой архитектуры
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack

# Импортируем config, чтобы получить доступ к шаблону TLS
import config


@register_attack
class EarlyDataSmugglingAttack(BaseAttack):
    """
    Tunnels a fake protocol message (e.g., HTTP GET) inside TLS 1.3 Early Data.
    """

    @property
    def name(self) -> str:
        return "early_data_smuggling"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Smuggles a fake HTTP request inside a TLS 1.3 0-RTT message"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute the Early Data Smuggling attack."""
        start_time = time.time()

        try:
            domain = context.domain or "example.com"

            # 1. Создаем "контрабандный" payload - фейковый HTTP GET
            smuggled_payload = f"GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode(
                "utf-8"
            )

            # 2. Создаем TLS 1.3 ClientHello
            # Импортируем TLSHandler здесь, чтобы избежать циклических зависимостей на уровне модуля
            from core.protocols.tls import TLSHandler

            # ИСПРАВЛЕНО: Передаем обязательный шаблон tls_template в конструктор
            tls_handler = TLSHandler(tls_template=config.TLS_CLIENT_HELLO_TEMPLATE)

            client_hello = tls_handler.build_client_hello(
                domain, version=b"\x03\x04"
            )  # TLS 1.3

            # 3. Создаем фейковый Early Data record с контрабандой внутри
            # Тип записи 0x17 (Application Data) используется для Early Data
            early_data_record = b"\x17"
            early_data_record += (
                b"\x03\x03"  # Legacy version (TLS 1.2) для совместимости
            )
            early_data_record += len(smuggled_payload).to_bytes(2, "big")
            early_data_record += smuggled_payload

            # 4. Объединяем ClientHello и фейковый Early Data в один большой payload для отправки
            # Это запутает DPI, который может ожидать ServerHello после ClientHello
            combined_payload = client_hello + early_data_record

            # Результат атаки - это один сегмент с комбинированной нагрузкой
            segments = [(combined_payload, 0)]

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=1,
                bytes_sent=len(combined_payload),
                connection_established=True,  # Предполагаем успех для генерации
                data_transmitted=True,
                metadata={
                    "smuggled_protocol": "http",
                    "smuggled_data_size": len(smuggled_payload),
                    "client_hello_size": len(client_hello),
                    "segments": segments,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
