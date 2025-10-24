#!/usr/bin/env python3
"""
Тест новых продвинутых атак.
"""

import sys
from pathlib import Path

project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def test_new_attacks_loading():
    """Тестирует загрузку новых атак."""
    print("🔍 Тестируем загрузку новых атак...")
    
    try:
        from core.bypass.attacks import get_attack_registry
        
        registry = get_attack_registry()
        
        # Список новых атак
        new_attacks = [
            # TCP
            'tcp_window_manipulation',
            'tcp_sequence_manipulation',
            'tcp_window_scaling',
            'urgent_pointer_manipulation',
            'tcp_options_padding',
            'tcp_timestamp_manipulation',
            'tcp_wssize_limit',
            # TLS
            'sni_manipulation',
            'alpn_manipulation',
            'grease_injection',
            # IP/Obfuscation
            'ip_ttl_manipulation',
            'ip_id_manipulation',
            'payload_padding',
            'noise_injection',
            'timing_obfuscation',
        ]
        
        loaded = []
        missing = []
        
        for attack in new_attacks:
            try:
                metadata = registry.get_attack_metadata(attack)
                if metadata is not None:
                    loaded.append(attack)
                    print(f"✅ {attack}")
                else:
                    missing.append(attack)
                    print(f"❌ {attack} - не загружена")
            except Exception:
                missing.append(attack)
                print(f"❌ {attack} - не загружена")
        
        print(f"\n📊 Статистика:")
        print(f"   Загружено: {len(loaded)}/{len(new_attacks)}")
        print(f"   Отсутствует: {len(missing)}")
        
        return len(missing) == 0
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_attack_execution():
    """Тестирует выполнение новых атак."""
    print("\n🔍 Тестируем выполнение атак...")
    
    try:
        from core.bypass.attacks import get_attack_registry
        
        registry = get_attack_registry()
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        test_cases = [
            ('tcp_window_manipulation', {'window_size': 1024, 'split_pos': 10}),
            ('sni_manipulation', {'mode': 'fake', 'fake_sni': 'google.com'}),
            ('payload_padding', {'padding_size': 50}),
            ('noise_injection', {'noise_size': 20, 'position': 'end'}),
        ]
        
        success_count = 0
        
        for attack_name, params in test_cases:
            try:
                handler = registry.get_attack_handler(attack_name)
                if handler:
                    result = handler(test_payload, **params)
                    if result:
                        print(f"✅ {attack_name}: {len(result)} сегментов")
                        success_count += 1
                    else:
                        print(f"⚠️ {attack_name}: пустой результат")
                else:
                    print(f"❌ {attack_name}: handler не найден")
            except Exception as e:
                print(f"❌ {attack_name}: {e}")
        
        print(f"\n📊 Успешно выполнено: {success_count}/{len(test_cases)}")
        return success_count == len(test_cases)
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("🧪 ТЕСТ НОВЫХ ПРОДВИНУТЫХ АТАК")
    print("=" * 60)
    
    results = []
    
    # Тест 1: Загрузка
    results.append(("Attack Loading", test_new_attacks_loading()))
    
    # Тест 2: Выполнение
    results.append(("Attack Execution", test_attack_execution()))
    
    # Результаты
    print("\n" + "=" * 60)
    print("📊 РЕЗУЛЬТАТЫ:")
    
    all_passed = True
    for test_name, result in results:
        status = "✅ ПРОШЕЛ" if result else "❌ ПРОВАЛЕН"
        print(f"   {test_name}: {status}")
        if not result:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ!")
        print("   Новые атаки успешно интегрированы")
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)