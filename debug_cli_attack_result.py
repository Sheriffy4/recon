#!/usr/bin/env python3
"""
Отладочный скрипт для проверки AttackResult в CLI.
"""

import asyncio
import logging
from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.base import AttackContext
from core.bypass.strategies.parser import UnifiedStrategyParser

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)

async def debug_cli_attack_result():
    """Отладка AttackResult как в CLI."""
    
    print("🔧 Debugging CLI AttackResult")
    print("=" * 50)
    
    # Создаем AttackAdapter как в CLI
    adapter = AttackAdapter()
    
    # Создаем контекст атаки как в CLI
    context = AttackContext(
        dst_ip="104.21.96.1",
        dst_port=443,
        payload=b"GET / HTTP/1.1\r\nHost: nnmclub.to\r\nConnection: close\r\n\r\n",
        connection_id="test_conn_1"
    )
    
    # Парсим стратегию как в CLI
    strategy_string = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum"
    parser = UnifiedStrategyParser()
    parsed_strategy = parser.parse(strategy_string)
    
    print(f"📋 Parsed strategy: {parsed_strategy}")
    print(f"📋 Attack types: {parsed_strategy.attack_types}")
    
    # Получаем attack_name как в CLI
    attack_name = parsed_strategy.attack_types[0] if parsed_strategy.attack_types else "unknown"
    print(f"📋 Attack name: {attack_name}")
    
    # Получаем strategy_params как в CLI
    strategy_params = parser.translate_to_engine_task(parsed_strategy)
    print(f"📋 Strategy params: {strategy_params}")
    
    try:
        # Выполняем атаку точно как в CLI
        print(f"\n🚀 Executing attack as in CLI...")
        attack_result = await adapter.execute_attack_by_name(
            attack_name=attack_name,
            context=context,
            strategy_params=strategy_params
        )
        
        print(f"\n📊 Attack Result (as returned to CLI):")
        print(f"   Status: {attack_result.status}")
        print(f"   Status value: {attack_result.status.value}")
        print(f"   Latency: {attack_result.latency_ms:.2f}ms")
        print(f"   Packets sent: {attack_result.packets_sent}")
        print(f"   Bytes sent: {attack_result.bytes_sent}")
        print(f"   Error: {attack_result.error_message}")
        print(f"   Technique used: {attack_result.technique_used}")
        
        # Проверяем segments
        print(f"\n🔍 Segments Analysis:")
        print(f"   has_segments(): {attack_result.has_segments()}")
        
        if hasattr(attack_result, 'segments') and attack_result.segments:
            print(f"   segments property: {len(attack_result.segments)} segments")
        else:
            print(f"   segments property: None")
        
        if attack_result.metadata and "segments" in attack_result.metadata:
            segments = attack_result.metadata["segments"]
            print(f"   metadata segments: {len(segments) if segments else 0} segments")
        else:
            print(f"   metadata segments: None")
        
        # Проверяем, что CLI будет делать с этим результатом
        print(f"\n🎯 CLI Logic Check:")
        if attack_result.status != AttackStatus.SUCCESS:
            print(f"   ❌ CLI will show: 'Error: Failed to generate a valid attack recipe.'")
            print(f"   ❌ Reason: {attack_result.error_message}")
            return False
        else:
            print(f"   ✅ CLI will show: 'Recipe generated successfully'")
            print(f"   ✅ Segments to be tested: {len(attack_result.segments) if attack_result.segments else 0}")
            return True
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Главная функция."""
    
    success = await debug_cli_attack_result()
    
    if success:
        print(f"\n✅ SUCCESS: CLI should work correctly!")
    else:
        print(f"\n❌ FAILED: CLI will show error")

if __name__ == "__main__":
    from core.bypass.attacks.base import AttackStatus
    asyncio.run(main())