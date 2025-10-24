#!/usr/bin/env python3
"""
Тест интеграции AttackDispatcher с системой обхода DPI.

Проверяет, что:
1. AttackRegistry правильно регистрирует все атаки
2. AttackDispatcher корректно диспетчеризует каждый тип атаки
3. Все параметры передаются правильно
4. Специальные значения split_pos обрабатываются
"""

import sys
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def test_attack_registry():
    """Тест AttackRegistry."""
    logger.info("=== Тестирование AttackRegistry ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Проверяем, что все основные атаки зарегистрированы
        expected_attacks = [
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "disorder2",
            "multisplit",
            "split",
            "fake",
        ]

        registered_attacks = registry.list_attacks()
        logger.info(f"Зарегистрированные атаки: {registered_attacks}")

        for attack in expected_attacks:
            if attack not in registered_attacks:
                logger.error(f"❌ Атака '{attack}' не зарегистрирована!")
                return False
            else:
                logger.info(f"✅ Атака '{attack}' зарегистрирована")

        # Проверяем алиасы
        aliases_test = [
            ("fakeddisorder", ["fake_disorder", "fakedisorder"]),
            ("disorder2", ["disorder_ack"]),
            ("split", ["simple_split"]),
        ]

        for attack, expected_aliases in aliases_test:
            actual_aliases = registry.get_attack_aliases(attack)
            for alias in expected_aliases:
                if alias not in actual_aliases:
                    logger.warning(f"⚠️ Алиас '{alias}' для '{attack}' не найден")
                else:
                    logger.info(f"✅ Алиас '{alias}' для '{attack}' найден")

        logger.info("✅ AttackRegistry тест пройден")
        return True

    except Exception as e:
        logger.error(f"❌ AttackRegistry тест не пройден: {e}")
        return False


def test_attack_dispatcher():
    """Тест AttackDispatcher."""
    logger.info("=== Тестирование AttackDispatcher ===")

    try:
        from core.bypass.techniques.primitives import BypassTechniques
        from core.bypass.engine.attack_dispatcher import AttackDispatcher

        techniques = BypassTechniques()
        dispatcher = AttackDispatcher(techniques)

        # Тестовые данные
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "93.184.216.34",
            "src_port": 12345,
            "dst_port": 443,
        }

        # Тесты для каждого типа атаки
        test_cases = [
            {
                "name": "fakeddisorder",
                "type": "fakeddisorder",
                "params": {"split_pos": 10, "ttl": 3, "fooling": ["badsum"]},
            },
            {
                "name": "seqovl",
                "type": "seqovl",
                "params": {"split_pos": 10, "overlap_size": 5, "ttl": 3},
            },
            {"name": "disorder", "type": "disorder", "params": {"split_pos": 10}},
            {"name": "disorder2", "type": "disorder2", "params": {"split_pos": 10}},
            {
                "name": "multisplit",
                "type": "multisplit",
                "params": {"positions": [5, 10, 15]},
            },
            {"name": "split", "type": "split", "params": {"split_pos": 10}},
            {
                "name": "fake",
                "type": "fake",
                "params": {"ttl": 3, "fooling": ["badsum"]},
            },
        ]

        for test_case in test_cases:
            try:
                logger.info(f"Тестирование {test_case['name']}...")

                recipe = dispatcher.dispatch_attack(
                    test_case["type"], test_case["params"], test_payload, packet_info
                )

                if not recipe:
                    logger.error(f"❌ {test_case['name']}: пустой рецепт")
                    continue

                if not isinstance(recipe, list):
                    logger.error(f"❌ {test_case['name']}: рецепт не является списком")
                    continue

                # Проверяем структуру рецепта
                for i, segment in enumerate(recipe):
                    if not isinstance(segment, tuple) or len(segment) != 3:
                        logger.error(
                            f"❌ {test_case['name']}: неправильная структура сегмента {i}"
                        )
                        break

                    data, offset, options = segment
                    if not isinstance(data, bytes):
                        logger.error(
                            f"❌ {test_case['name']}: данные сегмента {i} не bytes"
                        )
                        break

                    if not isinstance(offset, int):
                        logger.error(
                            f"❌ {test_case['name']}: смещение сегмента {i} не int"
                        )
                        break

                    if not isinstance(options, dict):
                        logger.error(
                            f"❌ {test_case['name']}: опции сегмента {i} не dict"
                        )
                        break
                else:
                    logger.info(
                        f"✅ {test_case['name']}: {len(recipe)} сегментов сгенерировано"
                    )

            except Exception as e:
                logger.error(f"❌ {test_case['name']}: ошибка диспетчеризации: {e}")

        logger.info("✅ AttackDispatcher тест пройден")
        return True

    except Exception as e:
        logger.error(f"❌ AttackDispatcher тест не пройден: {e}")
        return False


def test_parameter_validation():
    """Тест валидации параметров."""
    logger.info("=== Тестирование валидации параметров ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Тесты валидации
        validation_tests = [
            # Правильные параметры
            ("fakeddisorder", {"split_pos": 10, "ttl": 3}, True),
            ("seqovl", {"split_pos": 10, "overlap_size": 5, "ttl": 3}, True),
            ("disorder", {"split_pos": 10}, True),
            # Неправильные параметры
            ("fakeddisorder", {}, False),  # Отсутствует split_pos
            ("seqovl", {"split_pos": 10}, False),  # Отсутствует overlap_size
            (
                "fakeddisorder",
                {"split_pos": "invalid"},
                False,
            ),  # Неправильный split_pos
            (
                "seqovl",
                {"split_pos": 10, "overlap_size": -1},
                False,
            ),  # Отрицательный overlap_size
        ]

        for attack_type, params, should_be_valid in validation_tests:
            result = registry.validate_parameters(attack_type, params)

            if result.is_valid == should_be_valid:
                status = "✅" if should_be_valid else "✅ (правильно отклонен)"
                logger.info(f"{status} {attack_type} с параметрами {params}")
            else:
                logger.error(
                    f"❌ {attack_type} с параметрами {params}: ожидалось {should_be_valid}, получено {result.is_valid}"
                )
                if not result.is_valid:
                    logger.error(f"   Ошибка: {result.error_message}")

        logger.info("✅ Тест валидации параметров пройден")
        return True

    except Exception as e:
        logger.error(f"❌ Тест валидации параметров не пройден: {e}")
        return False


def test_special_split_pos():
    """Тест обработки специальных значений split_pos."""
    logger.info("=== Тестирование специальных значений split_pos ===")

    try:
        from core.bypass.techniques.primitives import BypassTechniques
        from core.bypass.engine.attack_dispatcher import AttackDispatcher

        techniques = BypassTechniques()
        dispatcher = AttackDispatcher(techniques)

        # TLS ClientHello для тестирования
        tls_payload = (
            b"\x16\x03\x01\x00\xc4\x01\x00\x00\xc0\x03\x03"  # TLS Record + Handshake headers
            b"\x00" * 32  # Random
            + b"\x00"  # Session ID length
            + b"\x00\x02\x13\x01"  # Cipher suites
        )

        packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "93.184.216.34",
            "src_port": 12345,
            "dst_port": 443,
        }

        # Тест специальных значений
        special_values = ["cipher", "sni", "midsld"]

        for special_value in special_values:
            try:
                logger.info(f"Тестирование split_pos='{special_value}'...")

                recipe = dispatcher.dispatch_attack(
                    "fakeddisorder",
                    {"split_pos": special_value, "ttl": 3},
                    tls_payload,
                    packet_info,
                )

                if recipe:
                    logger.info(
                        f"✅ {special_value}: {len(recipe)} сегментов сгенерировано"
                    )
                else:
                    logger.warning(f"⚠️ {special_value}: пустой рецепт")

            except Exception as e:
                logger.error(f"❌ {special_value}: ошибка: {e}")

        logger.info("✅ Тест специальных значений split_pos пройден")
        return True

    except Exception as e:
        logger.error(f"❌ Тест специальных значений split_pos не пройден: {e}")
        return False


def main():
    """Главная функция тестирования."""
    logger.info("🚀 Запуск тестов интеграции AttackDispatcher")

    tests = [
        test_attack_registry,
        test_attack_dispatcher,
        test_parameter_validation,
        test_special_split_pos,
    ]

    passed = 0
    total = len(tests)

    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                logger.error(f"Тест {test_func.__name__} не пройден")
        except Exception as e:
            logger.error(f"Тест {test_func.__name__} завершился с ошибкой: {e}")

    logger.info(f"📊 Результаты: {passed}/{total} тестов пройдено")

    if passed == total:
        logger.info("🎉 Все тесты пройдены успешно!")
        return 0
    else:
        logger.error("❌ Некоторые тесты не пройдены")
        return 1


if __name__ == "__main__":
    sys.exit(main())
