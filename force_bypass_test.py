#!/usr/bin/env python3
"""
Принудительный тест обхода с zapret совместимостью
"""
import sys
import os
import socket
import time
import ssl

# Add recon directory to path
recon_dir = os.path.dirname(os.path.abspath(__file__))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

def test_direct_connection():
    """Тестирует прямое подключение к заблокированному домену."""
    print("🔌 Тест прямого подключения")
    print("=" * 40)
    
    # Тестируем подключение к потенциально заблокированным доменам
    test_domains = [
        ("x.com", 443),
        ("twitter.com", 443),
        ("api.x.com", 443)
    ]
    
    for domain, port in test_domains:
        print(f"\nТестируем {domain}:{port}")
        try:
            # Создаем сокет
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            start_time = time.time()
            result = sock.connect_ex((domain, port))
            end_time = time.time()
            
            if result == 0:
                print(f"  ✅ Подключение успешно за {(end_time - start_time)*1000:.1f}ms")
                
                # Пробуем TLS handshake
                try:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        print(f"  ✅ TLS handshake успешен")
                except Exception as e:
                    print(f"  ❌ TLS handshake неудачен: {e}")
            else:
                print(f"  ❌ Подключение неудачно: код {result}")
                
            sock.close()
            
        except Exception as e:
            print(f"  ❌ Ошибка подключения: {e}")

def create_test_with_blocked_domain():
    """Создает тест с принудительно заблокированным доменом."""
    print("\n🚫 Создание теста с заблокированным доменом")
    print("=" * 50)
    
    # Добавляем домен в hosts файл для имитации блокировки
    hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
    test_domain = "test-blocked-domain.com"
    
    print(f"Добавляем {test_domain} в hosts файл для имитации блокировки...")
    
    try:
        # Читаем текущий hosts файл
        with open(hosts_file, 'r') as f:
            hosts_content = f.read()
        
        # Проверяем, есть ли уже наш домен
        if test_domain not in hosts_content:
            # Добавляем блокировку
            with open(hosts_file, 'a') as f:
                f.write(f"\n127.0.0.1 {test_domain}\n")
            print(f"  ✅ Домен {test_domain} добавлен в hosts")
        else:
            print(f"  ℹ️  Домен {test_domain} уже в hosts")
            
        # Создаем файл с заблокированным доменом
        with open("blocked_test.txt", "w") as f:
            f.write(f"{test_domain}\n")
        
        print(f"  ✅ Создан файл blocked_test.txt с доменом {test_domain}")
        
        return test_domain
        
    except PermissionError:
        print("  ❌ Нет прав для изменения hosts файла")
        print("  💡 Запустите скрипт от имени администратора")
        return None
    except Exception as e:
        print(f"  ❌ Ошибка: {e}")
        return None

def run_bypass_test(domain):
    """Запускает тест обхода."""
    if not domain:
        print("❌ Нет домена для тестирования")
        return
        
    print(f"\n🧪 Запуск теста обхода для {domain}")
    print("=" * 50)
    
    # Импортируем и запускаем CLI
    try:
        import subprocess
        
        cmd = [
            sys.executable, "smart_bypass_cli.py",
            "test-file",
            "blocked_test.txt",
            "--verbose"
        ]
        
        print(f"Команда: {' '.join(cmd)}")
        print("-" * 50)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        # Анализируем результат
        output = result.stdout + result.stderr
        
        print("\n" + "=" * 50)
        print("🔍 АНАЛИЗ РЕЗУЛЬТАТОВ:")
        
        zapret_indicators = [
            ("ZAPRET-COMPATIBLE CONDITIONS DETECTED", "Zapret-совместимые условия"),
            ("ZAPRET-STYLE ACTIVATED", "Zapret-style режим"),
            ("Sending FULL fake with corrupted checksum", "Полный fake с испорченной checksum"),
            ("CHECKSUM DEBUG", "Отладка checksum"),
            ("REAL segment", "Реальные сегменты"),
            ("PSH|ACK", "PSH|ACK флаги"),
            (".edu", "Fake SNI с .edu")
        ]
        
        for indicator, description in zapret_indicators:
            if indicator in output:
                print(f"  ✅ {description}")
            else:
                print(f"  ❌ {description}")
                
    except subprocess.TimeoutExpired:
        print("❌ Тест превысил время ожидания")
    except Exception as e:
        print(f"❌ Ошибка выполнения теста: {e}")

def main():
    """Основная функция."""
    print("🧪 Принудительный тест zapret совместимости")
    print("=" * 60)
    
    # Тест 1: Прямое подключение
    test_direct_connection()
    
    # Тест 2: Создание заблокированного домена
    blocked_domain = create_test_with_blocked_domain()
    
    # Тест 3: Запуск обхода
    if blocked_domain:
        run_bypass_test(blocked_domain)
    
    print("\n" + "=" * 60)
    print("✅ Принудительный тест завершен")

if __name__ == "__main__":
    main()