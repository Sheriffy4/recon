#!/usr/bin/env python3
"""
Тест исправления обработки специального значения 'midsld' в split_pos.
"""

import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def test_midsld_split_pos():
    """Тест обработки split_pos='midsld'."""
    logger.info("=== Тестирование split_pos='midsld' ===")

    try:
        from core.bypass.techniques.primitives import BypassTechniques
        from core.bypass.engine.attack_dispatcher import AttackDispatcher

        techniques = BypassTechniques()
        dispatcher = AttackDispatcher(techniques)

        # Создаем TLS ClientHello с SNI для тестирования midsld
        # Имитируем реальный TLS handshake с доменом example.com
        tls_payload = (
            b"\x16\x03\x01\x02\x00"  # TLS Record Header
            b"\x01\x00\x01\xfc"  # Handshake Header
            b"\x03\x03"  # Version
            + b"\x00" * 32  # Random
            + b"\x20"  # Session ID Length
            + b"\x00" * 32  # Session ID
            + b"\x00\x02\x13\x01"  # Cipher Suites
            b"\x01\x00"  # Compression Methods
            b"\x01\x91"  # Extensions Length
            b"\x00\x00"  # SNI Extension Type
            b"\x00\x18"  # SNI Extension Length
            b"\x00\x16"  # Server Name List Length
            b"\x00"  # Name Type (hostname)
            b"\x00\x13"  # Name Length
            b"www.example.com" + b"\x00" * 300  # Hostname  # Padding
        )

        packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "172.66.0.227",
            "src_port": 12345,
            "dst_port": 443,
        }

        # Параметры из реального лога ошибки
        params = {
            "split_pos": "midsld",
            "ttl": 2,
            "repeats": 2,
            "fooling": ["badseq"],
            "fake_ttl": 2,
            "overlap_size": 0,
            "tcp_flags": {"psh": True, "ack": True},
            "window_div": 8,
            "ipid_step": 2048,
        }

        logger.info("Тестирование fakeddisorder с split_pos='midsld'")
        logger.info(f"Payload length: {len(tls_payload)} bytes")
        logger.info(f"Параметры: {params}")

        recipe = dispatcher.dispatch_attack(
            "fakeddisorder", params, tls_payload, packet_info
        )

        if not recipe:
            logger.error("❌ fakeddisorder с midsld: пустой рецепт")
            return False

        if not isinstance(recipe, list):
            logger.error("❌ fakeddisorder с midsld: рецепт не является списком")
            return False

        # Проверяем структуру рецепта
        for i, segment in enumerate(recipe):
            if not isinstance(segment, tuple) or len(segment) != 3:
                logger.error(
                    f"❌ fakeddisorder с midsld: неправильная структура сегмента {i}"
                )
                return False

            data, offset, options = segment
            if not isinstance(data, bytes):
                logger.error(f"❌ fakeddisorder с midsld: данные сегмента {i} не bytes")
                return False

            if not isinstance(offset, int):
                logger.error(f"❌ fakeddisorder с midsld: смещение сегмента {i} не int")
                return False

            if not isinstance(options, dict):
                logger.error(f"❌ fakeddisorder с midsld: опции сегмента {i} не dict")
                return False

        logger.info(
            f"✅ fakeddisorder с midsld: {len(recipe)} сегментов сгенерировано успешно"
        )

        # Выводим детали рецепта
        for i, (data, offset, options) in enumerate(recipe):
            is_fake = options.get("is_fake", False)
            fake_str = " (FAKE)" if is_fake else ""
            logger.info(f"  Сегмент {i}: {len(data)}b @ offset {offset}{fake_str}")

        # Проверяем, что split_pos был разрешен в разумное значение
        # (не в начало или конец payload)
        split_positions = []
        for i, (data, offset, options) in enumerate(recipe):
            if not options.get("is_fake", False):
                split_positions.append(offset)

        if split_positions:
            max_split = max(split_positions)
            if 10 < max_split < len(tls_payload) - 10:
                logger.info(f"✅ midsld разрешен в разумную позицию: {max_split}")
            else:
                logger.warning(f"⚠️ midsld разрешен в граничную позицию: {max_split}")

        return True

    except Exception as e:
        logger.error(f"❌ fakeddisorder с midsld тест не пройден: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Главная функция тестирования."""
    logger.info("🚀 Запуск теста исправления midsld")

    if test_midsld_split_pos():
        logger.info("🎉 Тест пройден успешно!")
        return 0
    else:
        logger.error("❌ Тест не пройден")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
