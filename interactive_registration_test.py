#!/usr/bin/env python3
"""
Интерактивный тестер автоматической регистрации атак.

Позволяет пользователю вводить имена стратегий и видеть результаты
парсинга и регистрации в реальном времени.
"""

import sys
import logging
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent))

from core.bypass.attacks.dynamic_attack_registry_fixed import (
    DynamicAttackRegistry,
    get_dynamic_registry,
    auto_register_if_missing,
    patch_attack_registry
)
from core.bypass.attacks.attack_registry import get_attack_registry

# Настройка логирования (только ошибки для чистого вывода)
logging.basicConfig(level=logging.ERROR)


class InteractiveRegistrationTester:
    """Интерактивный тестер регистрации."""
    
    def __init__(self):
        self.base_registry = get_attack_registry()
        self.dynamic_registry = get_dynamic_registry()
        
        # Применяем патч для автоматической регистрации
        patch_attack_registry()
        
        print("🚀 Интерактивный тестер автоматической регистрации")
        print("=" * 55)
        print()
        
        # Показываем доступные базовые атаки
        self.show_available_attacks()
    
    def show_available_attacks(self):
        """Показывает доступные базовые атаки."""
        print("📋 Доступные базовые атаки:")
        available_attacks = self.base_registry.list_attacks()
        for i, attack in enumerate(sorted(available_attacks), 1):
            print(f"  {i:2d}. {attack}")
        print()
    
    def show_help(self):
        """Показывает справку по командам."""
        print("📖 Доступные команды:")
        print("  help, h          - показать эту справку")
        print("  list, l          - показать доступные базовые атаки")
        print("  status, s        - показать статус динамических регистраций")
        print("  cleanup, c       - очистить все динамические регистрации")
        print("  examples, e      - показать примеры имен стратегий")
        print("  quit, q, exit    - выйти из программы")
        print("  <strategy_name>  - протестировать стратегию")
        print()
    
    def show_examples(self):
        """Показывает примеры имен стратегий."""
        print("💡 Примеры имен стратегий:")
        examples = [
            "disorder_www_googlevideo_com_spl2_dis1",
            "fake_domain_com_splsni",
            "fragmentation_example_com_spl5_spl16",
            "seqovl_test_domain_spl3_ovl2",
            "fooling_site_com_foobadseq",
            "disorder_youtube_com_spl10_dis3_ttl64",
        ]
        
        for example in examples:
            print(f"  {example}")
        print()
    
    def show_status(self):
        """Показывает статус динамических регистраций."""
        registrations = self.dynamic_registry.get_dynamic_registrations()
        
        print(f"📊 Статус динамических регистраций: {len(registrations)}")
        
        if registrations:
            print("Зарегистрированные стратегии:")
            for name, timestamp in registrations.items():
                print(f"  - {name}")
                print(f"    Время регистрации: {timestamp.strftime('%H:%M:%S')}")
        else:
            print("Нет активных динамических регистраций")
        print()
    
    def cleanup_registrations(self):
        """Очищает все динамические регистрации."""
        removed = self.dynamic_registry.force_cleanup()
        print(f"🗑️  Очищено регистраций: {removed}")
        print()
    
    def test_strategy(self, strategy_name: str):
        """Тестирует конкретную стратегию."""
        print(f"🔍 Тестирование стратегии: {strategy_name}")
        print("-" * 50)
        
        # 1. Парсинг имени
        parsed = self.dynamic_registry._parse_strategy_name(strategy_name)
        if parsed:
            base_attack, domain, params = parsed
            print(f"✅ Парсинг успешен:")
            print(f"   Базовая атака: {base_attack}")
            print(f"   Домен: {domain}")
            print(f"   Параметры: {params}")
            
            # Проверяем, существует ли базовая атака
            base_handler = self.base_registry.get_attack_handler(base_attack)
            if base_handler:
                print(f"✅ Базовая атака найдена: {base_handler.__name__}")
            else:
                print(f"❌ Базовая атака '{base_attack}' не найдена")
                print("   Регистрация невозможна")
                print()
                return
        else:
            print("❌ Не удалось распарсить имя стратегии")
            print("   Проверьте формат имени")
            print()
            return
        
        # 2. Проверяем, существует ли уже
        existing_handler = self.base_registry.get_attack_handler(strategy_name)
        if existing_handler:
            print(f"ℹ️  Стратегия уже зарегистрирована")
            
            # Показываем метаданные
            metadata = self.base_registry.get_attack_metadata(strategy_name)
            if metadata:
                print(f"   Описание: {metadata.description}")
                print(f"   Категория: {metadata.category}")
                if metadata.optional_params:
                    print(f"   Параметры: {metadata.optional_params}")
            print()
            return
        
        # 3. Пытаемся зарегистрировать
        print("🔄 Попытка автоматической регистрации...")
        success = auto_register_if_missing(strategy_name)
        
        if success:
            print("✅ Регистрация успешна!")
            
            # Получаем и показываем информацию о зарегистрированной стратегии
            handler = self.base_registry.get_attack_handler(strategy_name)
            metadata = self.base_registry.get_attack_metadata(strategy_name)
            
            if handler:
                print(f"   Обработчик: {handler.__name__}")
            
            if metadata:
                print(f"   Описание: {metadata.description}")
                if metadata.optional_params:
                    print(f"   Параметры: {metadata.optional_params}")
            
            # Проверяем, что это алиас
            if self.base_registry.is_alias(strategy_name):
                canonical = self.base_registry.get_canonical_attack(strategy_name)
                print(f"   Алиас для: {canonical}")
        else:
            print("❌ Регистрация не удалась")
        
        print()
    
    def run(self):
        """Запускает интерактивный режим."""
        self.show_help()
        
        while True:
            try:
                user_input = input("🎯 Введите команду или имя стратегии: ").strip()
                
                if not user_input:
                    continue
                
                # Обработка команд
                if user_input.lower() in ['quit', 'q', 'exit']:
                    print("👋 До свидания!")
                    break
                
                elif user_input.lower() in ['help', 'h']:
                    self.show_help()
                
                elif user_input.lower() in ['list', 'l']:
                    self.show_available_attacks()
                
                elif user_input.lower() in ['status', 's']:
                    self.show_status()
                
                elif user_input.lower() in ['cleanup', 'c']:
                    self.cleanup_registrations()
                
                elif user_input.lower() in ['examples', 'e']:
                    self.show_examples()
                
                else:
                    # Тестируем как имя стратегии
                    self.test_strategy(user_input)
            
            except KeyboardInterrupt:
                print("\n👋 До свидания!")
                break
            
            except Exception as e:
                print(f"❌ Ошибка: {e}")
                print()


def main():
    """Основная функция."""
    try:
        tester = InteractiveRegistrationTester()
        tester.run()
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())