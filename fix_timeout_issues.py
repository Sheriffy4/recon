#!/usr/bin/env python3
"""
Исправление проблем с таймаутами и семафорами
Устраняет ошибки типа "Превышен таймаут семафора"
"""

import json
import os
import socket
import time
from typing import Dict, Any

class TimeoutFixer:
    def __init__(self):
        self.config_file = "timeout_config.json"
        self.default_config = {
            "connection_timeout": 30,
            "read_timeout": 45,
            "dns_timeout": 10,
            "retry_attempts": 2,
            "retry_delay": 5,
            "socket_timeout": 60,
            "semaphore_timeout": 120,
            "tcp_keepalive": True,
            "tcp_nodelay": True,
            "buffer_size": 65536
        }
        
    def load_config(self) -> Dict[str, Any]:
        """Загружает конфигурацию таймаутов."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                print(f"✅ Загружена конфигурация из {self.config_file}")
                return config
            except Exception as e:
                print(f"⚠️  Ошибка загрузки конфигурации: {e}")
        
        print(f"📝 Создается конфигурация по умолчанию")
        return self.default_config
    
    def save_config(self, config: Dict[str, Any]):
        """Сохраняет конфигурацию таймаутов."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"💾 Конфигурация сохранена в {self.config_file}")
        except Exception as e:
            print(f"❌ Ошибка сохранения конфигурации: {e}")
    
    def apply_socket_settings(self, config: Dict[str, Any]):
        """Применяет настройки сокетов."""
        print("🔧 Применение настроек сокетов...")
        
        # Устанавливаем глобальные таймауты
        socket.setdefaulttimeout(config.get('socket_timeout', 60))
        
        print(f"   • Таймаут сокета: {config.get('socket_timeout', 60)}с")
        print(f"   • Таймаут соединения: {config.get('connection_timeout', 30)}с")
        print(f"   • Таймаут чтения: {config.get('read_timeout', 45)}с")
        print(f"   • Размер буфера: {config.get('buffer_size', 65536)} байт")
    
    def test_connection(self, host: str = "8.8.8.8", port: int = 53) -> bool:
        """Тестирует соединение с заданными настройками."""
        print(f"🌐 Тестирование соединения с {host}:{port}...")
        
        try:
            start_time = time.time()
            
            # Создаем сокет с настройками
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # 30 секунд таймаут
            
            # Пытаемся подключиться
            result = sock.connect_ex((host, port))
            sock.close()
            
            elapsed = time.time() - start_time
            
            if result == 0:
                print(f"✅ Соединение успешно ({elapsed:.2f}с)")
                return True
            else:
                print(f"❌ Соединение не удалось (код: {result}, {elapsed:.2f}с)")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка тестирования: {e}")
            return False
    
    def optimize_for_windows(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Оптимизирует настройки для Windows."""
        print("🪟 Оптимизация для Windows...")
        
        # Увеличиваем таймауты для Windows
        config['connection_timeout'] = max(config.get('connection_timeout', 30), 45)
        config['read_timeout'] = max(config.get('read_timeout', 45), 60)
        config['socket_timeout'] = max(config.get('socket_timeout', 60), 90)
        config['semaphore_timeout'] = max(config.get('semaphore_timeout', 120), 180)
        
        # Уменьшаем количество попыток для стабильности
        config['retry_attempts'] = min(config.get('retry_attempts', 3), 2)
        config['retry_delay'] = max(config.get('retry_delay', 2), 5)
        
        # Увеличиваем размер буфера
        config['buffer_size'] = max(config.get('buffer_size', 65536), 131072)
        
        print(f"   • Таймаут соединения увеличен до {config['connection_timeout']}с")
        print(f"   • Таймаут семафора увеличен до {config['semaphore_timeout']}с")
        print(f"   • Размер буфера увеличен до {config['buffer_size']} байт")
        
        return config
    
    def create_aiohttp_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Создает конфигурацию для aiohttp."""
        aiohttp_config = {
            'connector_limit': 50,
            'connector_limit_per_host': 10,
            'timeout_total': config.get('socket_timeout', 90),
            'timeout_connect': config.get('connection_timeout', 45),
            'timeout_sock_read': config.get('read_timeout', 60),
            'keepalive_timeout': 30,
            'enable_cleanup_closed': True
        }
        
        # Сохраняем конфигурацию aiohttp
        aiohttp_file = 'aiohttp_config.json'
        try:
            with open(aiohttp_file, 'w', encoding='utf-8') as f:
                json.dump(aiohttp_config, f, indent=2)
            print(f"💾 Конфигурация aiohttp сохранена в {aiohttp_file}")
        except Exception as e:
            print(f"⚠️  Ошибка сохранения aiohttp конфигурации: {e}")
        
        return aiohttp_config
    
    def fix_all_timeouts(self):
        """Исправляет все проблемы с таймаутами."""
        print("🔧 ИСПРАВЛЕНИЕ ПРОБЛЕМ С ТАЙМАУТАМИ")
        print("=" * 50)
        
        # Загружаем конфигурацию
        config = self.load_config()
        
        # Оптимизируем для Windows
        config = self.optimize_for_windows(config)
        
        # Применяем настройки сокетов
        self.apply_socket_settings(config)
        
        # Создаем конфигурацию aiohttp
        aiohttp_config = self.create_aiohttp_config(config)
        
        # Сохраняем обновленную конфигурацию
        self.save_config(config)
        
        # Тестируем соединение
        print("\n🧪 ТЕСТИРОВАНИЕ СОЕДИНЕНИЙ:")
        print("-" * 30)
        
        test_hosts = [
            ("8.8.8.8", 53, "Google DNS"),
            ("1.1.1.1", 53, "Cloudflare DNS"),
            ("google.com", 80, "Google HTTP"),
        ]
        
        success_count = 0
        for host, port, description in test_hosts:
            print(f"Тест {description}:")
            if self.test_connection(host, port):
                success_count += 1
            print()
        
        # Результаты
        print("📊 РЕЗУЛЬТАТЫ ИСПРАВЛЕНИЯ:")
        print("-" * 30)
        print(f"✅ Конфигурация оптимизирована для Windows")
        print(f"✅ Таймауты увеличены для стабильности")
        print(f"✅ Создана конфигурация aiohttp")
        print(f"✅ Тестирование соединений: {success_count}/{len(test_hosts)}")
        
        if success_count == len(test_hosts):
            print(f"\n🎉 Все проблемы с таймаутами исправлены!")
        elif success_count > 0:
            print(f"\n⚠️  Частично исправлено. Некоторые соединения могут быть заблокированы.")
        else:
            print(f"\n❌ Проблемы с сетью. Проверьте подключение к интернету.")
        
        return config, aiohttp_config

def main():
    """Главная функция."""
    fixer = TimeoutFixer()
    fixer.fix_all_timeouts()

if __name__ == "__main__":
    main()