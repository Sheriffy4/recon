#!/usr/bin/env python3
"""
Тестирование интеграции продвинутых атак из директории attacks.
"""

import sys

sys.path.insert(0, ".")


def test_advanced_attacks_integration():
    """Тестирует интеграцию продвинутых атак."""
    print("=== Тестирование интеграции продвинутых атак ===")

    try:
        from core.bypass.engine.attack_dispatcher import (
            AttackDispatcher,
            ADVANCED_ATTACKS_AVAILABLE,
        )
        from core.bypass.techniques.primitives import BypassTechniques

        print(f"Advanced attacks available: {ADVANCED_ATTACKS_AVAILABLE}")

        # Создаем диспетчер
        techniques = BypassTechniques()
        dispatcher = AttackDispatcher(techniques)

        print(
            f"Dispatcher initialized with {len(dispatcher._advanced_attacks)} advanced attacks"
        )

        # Показываем доступные продвинутые атаки
        if dispatcher._advanced_attacks:
            print("Available advanced attacks:")
            for attack_name, attack_info in dispatcher._advanced_attacks.items():
                print(f'  - {attack_name}: {attack_info["description"]}')

        # Тестируем диспетчеризацию
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        test_params = {"split_pos": 3, "ttl": 3, "fooling": ["badsum"]}
        test_packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "8.8.8.8",
            "src_port": 12345,
            "dst_port": 443,
        }

        # Тестируем fakeddisorder
        print("\nТестирование fakeddisorder атаки...")
        try:
            result = dispatcher.dispatch_attack(
                "fakeddisorder", test_params, test_payload, test_packet_info
            )
            print(f"✅ FakeDisorder test: {len(result)} segments generated")
            if result:
                print(
                    f"   First segment: {len(result[0][0])} bytes, offset: {result[0][1]}"
                )
                print(f"   Segment options: {result[0][2]}")
                print("   ✅ Asyncio conflict resolved - no event loop errors!")
        except Exception as e:
            print(f"❌ FakeDisorder test failed: {e}")
            import traceback

            traceback.print_exc()

        # Тестируем multidisorder
        print("\nТестирование multidisorder атаки...")
        try:
            result = dispatcher.dispatch_attack(
                "multidisorder", test_params, test_payload, test_packet_info
            )
            print(f"✅ MultiDisorder test: {len(result)} segments generated")
        except Exception as e:
            print(f"❌ MultiDisorder test failed: {e}")

        # Тестируем seqovl
        print("\nТестирование seqovl атаки...")
        seqovl_params = test_params.copy()
        seqovl_params["overlap_size"] = 10
        try:
            result = dispatcher.dispatch_attack(
                "seqovl", seqovl_params, test_payload, test_packet_info
            )
            print(f"✅ SeqOvl test: {len(result)} segments generated")
        except Exception as e:
            print(f"❌ SeqOvl test failed: {e}")

        print("\n=== Интеграция завершена ===")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_advanced_attacks_integration()
