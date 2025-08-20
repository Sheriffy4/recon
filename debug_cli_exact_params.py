#!/usr/bin/env python3
"""
Отладочный скрипт для проверки точных параметров CLI.
"""

import asyncio
import logging
from urllib.parse import urlparse
from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.bypass.strategies.parser import UnifiedStrategyParser

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)


async def debug_cli_exact_params():
    """Отладка точных параметров как в CLI."""

    print("🔧 Debugging CLI Exact Parameters")
    print("=" * 50)

    # Точно такие же параметры как в CLI
    strategy_string = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum"
    domain = "nnmclub.to"
    port = 443

    # Создаем AttackAdapter как в CLI
    adapter = AttackAdapter()

    # Парсим стратегию точно как в CLI
    parser = UnifiedStrategyParser()
    parsed_strategy = parser.parse(strategy_string)

    if not parsed_strategy:
        print(f"❌ Could not parse strategy: {strategy_string}")
        return False

    print(f"📋 Parsed strategy: {parsed_strategy.name}")
    print(f"📋 Attack types: {parsed_strategy.attack_types}")

    # Получаем hostname точно как в CLI
    hostname = urlparse(domain).hostname or domain
    print(f"📋 Hostname: {hostname}")

    # Используем фиксированный IP как в CLI
    pinned_ip = "104.21.96.1"  # Пример IP из логов
    print(f"📋 Pinned IP: {pinned_ip}")

    # Создаем контекст точно как в CLI
    context = AttackContext(
        dst_ip=pinned_ip,
        dst_port=port,
        domain=hostname,
        payload=b"GET / HTTP/1.1\r\nHost: "
        + hostname.encode()
        + b"\r\n\r\n",  # Dummy payload как в CLI
        debug=True,
    )

    print(f"📋 Context: {context.dst_ip}:{context.dst_port}")
    print(f"📋 Payload: {context.payload}")

    # Получаем attack_name точно как в CLI
    attack_name = (
        parsed_strategy.attack_types[0] if parsed_strategy.attack_types else "unknown"
    )
    print(f"📋 Attack name: {attack_name}")

    # Получаем strategy_params точно как в CLI
    strategy_params = parser.translate_to_engine_task(parsed_strategy)
    print(f"📋 Strategy params: {strategy_params}")

    try:
        # Выполняем атаку точно как в CLI ЭТАП 2
        print("\n🚀 Executing attack exactly as in CLI STAGE 2...")
        attack_result = await adapter.execute_attack_by_name(
            attack_name=attack_name, context=context, strategy_params=strategy_params
        )

        print("\n📊 Attack Result (STAGE 2 - Recipe Generation):")
        print(f"   Status: {attack_result.status}")
        print(f"   Status value: {attack_result.status.value}")
        print(f"   Error: {attack_result.error_message}")
        print(f"   Technique used: {attack_result.technique_used}")

        # Проверяем segments
        if hasattr(attack_result, "segments") and attack_result.segments:
            print(f"   Segments: {len(attack_result.segments)} segments")
        else:
            print("   Segments: None")

        # Проверяем, что CLI будет делать с этим результатом
        print("\n🎯 CLI STAGE 2 Logic Check:")
        if attack_result.status != AttackStatus.SUCCESS:
            print(
                "   ❌ CLI will show: 'Error: Failed to generate a valid attack recipe.'"
            )
            print(f"   ❌ Reason: {attack_result.error_message}")
            return False
        else:
            print("   ✅ CLI will show: 'Recipe generated successfully'")
            print(
                f"   ✅ Segments to be tested: {len(attack_result.segments) if attack_result.segments else 0}"
            )
            return True

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


async def main():
    """Главная функция."""

    success = await debug_cli_exact_params()

    if success:
        print("\n✅ SUCCESS: CLI STAGE 2 should work correctly!")
    else:
        print("\n❌ FAILED: CLI STAGE 2 will show error")


if __name__ == "__main__":
    asyncio.run(main())
