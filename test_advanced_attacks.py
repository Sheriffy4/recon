#!/usr/bin/env python3
"""
Тест для проверки регистрации и работы продвинутых атак.
"""

import sys
sys.path.insert(0, '.')

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.attacks.base import AttackContext

def test_advanced_attacks():
    """Тестирует регистрацию и выполнение продвинутых атак."""
    
    # Импортируем модули для регистрации атак
    import core.bypass.attacks.tcp_advanced
    import core.bypass.attacks.tls_advanced
    import core.bypass.attacks.ip_obfuscation
    
    # Получаем реестр после импорта
    registry = get_attack_registry()
    
    # Отладка: выводим все зарегистрированные атаки
    print(f"\nВсего атак в реестре: {len(registry.attacks)}")
    print(f"Атаки с 'tcp_': {[k for k in registry.attacks.keys() if 'tcp_' in k]}")
    print(f"Атаки с 'sni' или 'alpn': {[k for k in registry.attacks.keys() if 'sni' in k or 'alpn' in k]}")
    print(f"Атаки с 'ip_': {[k for k in registry.attacks.keys() if 'ip_' in k]}")
    print()
    
    # Проверяем TCP атаки
    tcp_attacks = [
        'tcp_window_manipulation',
        'tcp_sequence_manipulation',
        'tcp_window_scaling',
        'urgent_pointer_manipulation',
        'tcp_options_padding',
        'tcp_timestamp_manipulation',
        'tcp_wssize_limit'
    ]
    
    # Проверяем TLS атаки
    tls_attacks = [
        'sni_manipulation',
        'alpn_manipulation',
        'grease_injection'
    ]
    
    # Проверяем IP/Obfuscation атаки
    ip_attacks = [
        'ip_ttl_manipulation',
        'ip_id_manipulation',
        'payload_padding',
        'noise_injection',
        'timing_obfuscation'
    ]
    
    all_attacks = tcp_attacks + tls_attacks + ip_attacks
    
    print(f"Проверка регистрации {len(all_attacks)} атак...")
    print()
    
    missing = []
    registered = []
    
    for attack_name in all_attacks:
        if attack_name in registry.attacks:
            registered.append(attack_name)
            print(f"✓ {attack_name}")
        else:
            missing.append(attack_name)
            print(f"✗ {attack_name} - НЕ ЗАРЕГИСТРИРОВАНА")
    
    print()
    print(f"Зарегистрировано: {len(registered)}/{len(all_attacks)}")
    
    if missing:
        print(f"\nОтсутствуют: {', '.join(missing)}")
        return False
    
    # Тестируем выполнение нескольких атак
    print("\n" + "="*60)
    print("Тестирование выполнения атак...")
    print("="*60)
    
    test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    test_cases = [
        ('tcp_window_manipulation', {'window_size': 1024}),
        ('sni_manipulation', {'mode': 'fake', 'fake_sni': 'test.com'}),
        ('ip_ttl_manipulation', {'ttl': 128}),
        ('payload_padding', {'padding_size': 50}),
    ]
    
    for attack_name, params in test_cases:
        print(f"\nТест: {attack_name}")
        try:
            # Получаем handler атаки
            attack_info = registry.attacks.get(attack_name)
            if not attack_info:
                print(f"  ✗ Атака не найдена в реестре")
                continue
            
            handler = attack_info['handler']
            
            # Создаем контекст
            context = AttackContext(
                dst_ip="127.0.0.1",
                dst_port=443,
                payload=test_payload,
                params=params
            )
            
            # Выполняем атаку (handler может быть async)
            import asyncio
            if asyncio.iscoroutinefunction(handler):
                result = asyncio.run(handler(None, test_payload, **params))
            else:
                result = handler(None, test_payload, **params)
            
            # Проверяем результат
            if hasattr(result, 'status'):
                from core.bypass.attacks.base import AttackStatus
                if result.status == AttackStatus.SUCCESS:
                    print(f"  ✓ Успешно выполнена")
                    if hasattr(result, 'segments'):
                        print(f"  Сегментов: {len(result.segments)}")
                else:
                    print(f"  ✗ Ошибка: {result.error_message}")
            else:
                print(f"  ✓ Выполнена (старый формат)")
                
        except Exception as e:
            print(f"  ✗ Исключение: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print("Тест завершен!")
    print("="*60)
    
    return len(missing) == 0


if __name__ == '__main__':
    success = test_advanced_attacks()
    sys.exit(0 if success else 1)
