#!/usr/bin/env python3
"""
Детальный отладочный скрипт для AttackAdapter.
"""

import asyncio
import logging
from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.bypass.strategies.parser import UnifiedStrategyParser

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)


async def debug_attack_adapter_detailed():
    """Детальная отладка AttackAdapter."""

    print("🔧 Debugging AttackAdapter Detailed")
    print("=" * 50)

    # Точно такие же параметры как в CLI
    strategy_string = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum"
    domain = "nnmclub.to"
    port = 443
    pinned_ip = "104.21.32.1"

    # Создаем AttackAdapter
    adapter = AttackAdapter()

    # Парсим стратегию
    parser = UnifiedStrategyParser()
    parsed_strategy = parser.parse(strategy_string)

    # Создаем контекст
    hostname = domain
    context = AttackContext(
        dst_ip=pinned_ip,
        dst_port=port,
        domain=hostname,
        payload=b"GET / HTTP/1.1\r\nHost: "
        + hostname.encode()
        + b"\r\nConnection: close\r\n\r\n",
        debug=True,
    )

    # Получаем параметры
    attack_name = (
        parsed_strategy.attack_types[0] if parsed_strategy.attack_types else "unknown"
    )
    strategy_params = parser.translate_to_engine_task(parsed_strategy)

    print(f"📋 Attack name: {attack_name}")
    print(f"📋 Strategy params: {strategy_params}")
    print(f"📋 Context: {context.dst_ip}:{context.dst_port}")

    try:
        # Выполняем атаку с детальным логированием
        print("\n🚀 Executing attack with detailed logging...")

        # Добавляем обработчик для перехвата всех логов
        import logging

        # Создаем обработчик для перехвата логов AttackAdapter
        class LogCapture(logging.Handler):
            def __init__(self):
                super().__init__()
                self.logs = []

            def emit(self, record):
                self.logs.append(self.format(record))

        log_capture = LogCapture()
        log_capture.setLevel(logging.DEBUG)

        # Добавляем обработчик к логгеру AttackAdapter
        adapter_logger = logging.getLogger("AttackAdapter")
        adapter_logger.addHandler(log_capture)

        attack_result = await adapter.execute_attack_by_name(
            attack_name=attack_name, context=context, strategy_params=strategy_params
        )

        # Убираем обработчик
        adapter_logger.removeHandler(log_capture)

        print("\n📊 Attack Result Details:")
        print(f"   Status: {attack_result.status}")
        print(f"   Status type: {type(attack_result.status)}")
        print(f"   Status value: {attack_result.status.value}")
        print(f"   Status == SUCCESS: {attack_result.status == AttackStatus.SUCCESS}")
        print(f"   Status != SUCCESS: {attack_result.status != AttackStatus.SUCCESS}")
        print(f"   Error message: {attack_result.error_message}")
        print(f"   Technique used: {attack_result.technique_used}")
        print(f"   Latency: {attack_result.latency_ms}")
        print(f"   Packets sent: {attack_result.packets_sent}")
        print(f"   Bytes sent: {attack_result.bytes_sent}")

        # Проверяем segments
        print("\n🔍 Segments Details:")
        print(f"   has_segments(): {attack_result.has_segments()}")
        if hasattr(attack_result, "segments"):
            print(f"   segments attribute: {attack_result.segments}")
        if attack_result.metadata and "segments" in attack_result.metadata:
            segments = attack_result.metadata["segments"]
            print(f"   metadata segments: {segments}")

        # Показываем перехваченные логи
        print("\n📝 Captured Logs from AttackAdapter:")
        for log in log_capture.logs:
            print(f"   {log}")

        # Проверяем, что CLI будет делать
        print("\n🎯 CLI Logic Simulation:")
        if attack_result.status != AttackStatus.SUCCESS:
            print("   ❌ CLI will show error")
            print("   ❌ Condition: attack_result.status != AttackStatus.SUCCESS")
            print(f"   ❌ attack_result.status = {attack_result.status}")
            print(f"   ❌ AttackStatus.SUCCESS = {AttackStatus.SUCCESS}")
            return False
        else:
            print("   ✅ CLI will show success")
            return True

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


async def main():
    """Главная функция."""

    success = await debug_attack_adapter_detailed()

    if success:
        print("\n✅ SUCCESS: AttackAdapter returns SUCCESS status!")
    else:
        print("\n❌ FAILED: AttackAdapter does not return SUCCESS status")


if __name__ == "__main__":
    asyncio.run(main())
