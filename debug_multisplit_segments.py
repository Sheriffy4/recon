#!/usr/bin/env python3
"""
Отладочный скрипт для проверки создания segments в multisplit атаке.
"""

import asyncio
import logging
from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.base import AttackContext

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)


async def debug_multisplit_segments():
    """Отладка создания segments в multisplit атаке."""

    print("🔧 Debugging Multisplit Segments Creation")
    print("=" * 50)

    # Создаем AttackAdapter
    adapter = AttackAdapter()

    # Создаем контекст атаки
    context = AttackContext(
        dst_ip="104.21.96.1",
        dst_port=443,
        payload=b"GET / HTTP/1.1\r\nHost: nnmclub.to\r\nConnection: close\r\n\r\n",
        connection_id="test_conn_1",
    )

    # Параметры стратегии как из CLI
    strategy_params = {
        "dpi-desync": "multisplit",
        "dpi-desync-split-count": "5",
        "dpi-desync-split-seqovl": "20",
        "dpi-desync-fooling": "badsum",
    }

    print(f"📋 Context: {context.dst_ip}:{context.dst_port}")
    print(f"📋 Payload length: {len(context.payload)} bytes")
    print(f"📋 Strategy params: {strategy_params}")

    try:
        # Выполняем атаку
        print("\n🚀 Executing tcp_multisplit attack...")
        result = await adapter.execute_attack_by_name(
            "tcp_multisplit", context, strategy_params=strategy_params
        )

        print("\n📊 Attack Result:")
        print(f"   Status: {result.status}")
        print(f"   Latency: {result.latency_ms:.2f}ms")
        print(f"   Packets sent: {result.packets_sent}")
        print(f"   Bytes sent: {result.bytes_sent}")
        print(f"   Error: {result.error_message}")

        # Проверяем segments
        print("\n🔍 Segments Analysis:")
        print(f"   has_segments(): {result.has_segments()}")

        if result.metadata:
            print(f"   Metadata keys: {list(result.metadata.keys())}")
            if "segments" in result.metadata:
                segments = result.metadata["segments"]
                print(f"   Segments count: {len(segments) if segments else 0}")

                if segments:
                    for i, segment in enumerate(segments):
                        if isinstance(segment, tuple) and len(segment) >= 3:
                            payload_data, seq_offset, options = segment
                            print(
                                f"     Segment {i}: {len(payload_data)} bytes, offset={seq_offset}, options={options}"
                            )
                        else:
                            print(f"     Segment {i}: Invalid format - {segment}")
                else:
                    print("   ❌ Segments is None or empty")
            else:
                print("   ❌ No 'segments' key in metadata")
        else:
            print("   ❌ No metadata")

        # Проверяем segments property
        segments_prop = result.segments
        print(f"   segments property: {segments_prop is not None}")
        if segments_prop:
            print(f"   segments property count: {len(segments_prop)}")

        return result.has_segments()

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


async def main():
    """Главная функция."""

    success = await debug_multisplit_segments()

    if success:
        print("\n✅ SUCCESS: Multisplit creates segments correctly!")
    else:
        print("\n❌ FAILED: Multisplit does not create segments")


if __name__ == "__main__":
    asyncio.run(main())
