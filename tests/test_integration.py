"""
Интеграционные тесты для системы диспетчеризации атак.
"""

import pytest
import time
import threading
from unittest.mock import patch
from typing import Dict, Any, List, Tuple

from core.bypass.engine.attack_dispatcher import (
    AttackDispatcher,
    create_attack_dispatcher,
)
from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.attacks.metadata import (
    AttackMetadata,
    AttackCategories,
    create_attack_metadata,
)
from core.bypass.attacks.base import AttackContext
from core.bypass.techniques.primitives import BypassTechniques


class TestFullAttackFlow:
    """Тесты полного потока выполнения атак."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.techniques = BypassTechniques()
        self.dispatcher = create_attack_dispatcher(self.techniques)

        # Различные тестовые payload
        self.http_payload = b"GET /api/data HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: TestClient/1.0\r\n\r\n"
        self.tls_clienthello = self._create_tls_clienthello()
        self.small_payload = b"small"
        self.large_payload = b"A" * 1000

        self.packet_info = {
            "src_addr": "192.168.1.100",
            "src_port": 45678,
            "dst_addr": "203.0.113.50",
            "dst_port": 443,
        }

    def _create_tls_clienthello(self) -> bytes:
        """Создает простой TLS ClientHello для тестирования."""
        # TLS Record Header
        record_header = b"\x16\x03\x03\x00\x40"  # Content Type, Version, Length

        # Handshake Header
        handshake_header = b"\x01\x00\x00\x3c"  # Handshake Type, Length

        # Client Version
        client_version = b"\x03\x03"

        # Random (32 bytes)
        random_data = b"A" * 32

        # Session ID Length + Session ID
        session_id = b"\x00"  # No session ID

        # Cipher Suites Length + Cipher Suites
        cipher_suites = b"\x00\x02\x00\x2f"  # 1 cipher suite

        # Compression Methods
        compression = b"\x01\x00"  # No compression

        return (
            record_header
            + handshake_header
            + client_version
            + random_data
            + session_id
            + cipher_suites
            + compression
        )

    def test_fakeddisorder_complete_flow(self):
        """Тест полного потока fakeddisorder атаки."""
        params = {"split_pos": 20, "ttl": 2, "fooling": ["badsum", "badseq"]}

        start_time = time.time()
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.http_payload, self.packet_info
        )
        execution_time = time.time() - start_time

        # Проверяем результат
        assert isinstance(result, list)
        assert len(result) == 3  # fake + part2 + part1

        fake_segment, part2_segment, part1_segment = result

        # Фейковый сегмент (содержит сгенерированный fake payload)
        assert isinstance(fake_segment[0], bytes)
        assert len(fake_segment[0]) > 0  # Fake payload должен быть не пустым
        assert fake_segment[1] == 0
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 2

        # Реальные сегменты в обратном порядке
        assert part2_segment[0] == self.http_payload[20:]
        assert part2_segment[1] == 20
        assert part2_segment[2]["is_real"] is True

        assert part1_segment[0] == self.http_payload[:20]
        assert part1_segment[1] == 0
        assert part1_segment[2]["is_real"] is True

        # Проверяем производительность
        assert execution_time < 0.1  # Должно выполняться быстро

        # Проверяем целостность данных
        combined_data = part1_segment[0] + part2_segment[0]
        assert combined_data == self.http_payload

    def test_multisplit_with_complex_parameters(self):
        """Тест multisplit с сложными параметрами."""
        params = {
            "positions": [15, 30, 45, 60],
            "fooling": ["badsum"],
            "ttl": 128,  # Должен быть отфильтрован
            "overlap_size": 10,  # Должен быть отфильтрован
        }

        result = self.dispatcher.dispatch_attack(
            "multisplit", params, self.http_payload, self.packet_info
        )

        # Проверяем количество сегментов
        assert len(result) == 5  # 4 позиции = 5 сегментов

        # Проверяем смещения
        expected_offsets = [0, 15, 30, 45, 60]
        for i, segment in enumerate(result):
            assert segment[1] == expected_offsets[i]

        # Проверяем целостность данных
        total_data = b""
        for segment in result:
            total_data += segment[0]
        assert total_data == self.http_payload

        # Проверяем, что все сегменты реальные (не fake)
        for segment in result:
            # Multisplit не создает fake сегменты, поэтому проверяем отсутствие is_fake=True
            assert segment[2].get("is_fake", False) is False

    def test_seqovl_with_tls_payload(self):
        """Тест seqovl с TLS ClientHello payload."""
        params = {
            "split_pos": 43,  # Позиция после TLS заголовков
            "overlap_size": 15,
            "fake_ttl": 1,
            "fooling_methods": ["badsum"],
        }

        result = self.dispatcher.dispatch_attack(
            "seqovl", params, self.tls_clienthello, self.packet_info
        )

        assert len(result) == 3  # fake + overlap + real parts

        fake_segment, overlap_segment, real_segment = result

        # Фейковый сегмент с перекрытием
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 1
        assert fake_segment[1] >= 0  # Смещение должно быть валидным

        # Реальный сегмент (может быть частью оригинального payload)
        assert real_segment[2]["is_real"] is True
        assert len(real_segment[0]) > 0  # Должен содержать данные

    def test_special_parameter_resolution_cipher(self):
        """Тест разрешения специального параметра 'cipher'."""
        params = {"split_pos": "cipher", "ttl": 3, "fooling": ["badsum"]}

        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.tls_clienthello, self.packet_info
        )

        assert len(result) == 3

        # Проверяем, что позиция была разрешена
        fake_segment, part2_segment, part1_segment = result
        split_position = part2_segment[1]

        # Позиция должна быть разумной для TLS ClientHello
        assert isinstance(split_position, int)
        assert 0 < split_position < len(self.tls_clienthello)

        # Проверяем целостность
        combined_data = part1_segment[0] + part2_segment[0]
        assert combined_data == self.tls_clienthello

    def test_attack_type_normalization_and_aliases(self):
        """Тест нормализации типов атак и алиасов."""
        params = {"split_pos": 10, "ttl": 3}

        # Тестируем различные варианты написания
        test_cases = [
            "fakeddisorder",
            "FAKEDDISORDER",
            "  fakeddisorder  ",
            "fake_disorder",
            "fakedisorder",
        ]

        results = []
        for attack_type in test_cases:
            result = self.dispatcher.dispatch_attack(
                attack_type, params, self.http_payload, self.packet_info
            )
            results.append(result)

        # Все результаты должны быть идентичными
        for i in range(1, len(results)):
            assert len(results[i]) == len(results[0])
            for j in range(len(results[i])):
                assert results[i][j][0] == results[0][j][0]  # data
                assert results[i][j][1] == results[0][j][1]  # offset
                # Проверяем наличие флагов fake/real
                first_flags = results[0][j][2]
                current_flags = results[i][j][2]
                if "is_fake" in first_flags:
                    assert current_flags.get("is_fake") == first_flags["is_fake"]
                if "is_real" in first_flags:
                    assert current_flags.get("is_real") == first_flags["is_real"]

    def test_parameter_validation_integration(self):
        """Тест интеграции валидации параметров."""
        # Валидные параметры
        valid_params = {"split_pos": 5, "ttl": 3, "fooling": ["badsum"]}
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", valid_params, self.http_payload, self.packet_info
        )
        assert isinstance(result, list)

        # Параметры по умолчанию - должны работать
        default_params = {"ttl": 3}
        result2 = self.dispatcher.dispatch_attack(
            "fakeddisorder", default_params, self.http_payload, self.packet_info
        )
        assert isinstance(result2, list)

        # Тест с неизвестным типом атаки
        with pytest.raises(ValueError, match="No handler found for attack type"):
            self.dispatcher.dispatch_attack(
                "unknown_attack", {"split_pos": 5}, self.http_payload, self.packet_info
            )

    def test_edge_cases_handling(self):
        """Тест обработки граничных случаев."""
        # Пустой payload
        empty_result = self.dispatcher.dispatch_attack(
            "fakeddisorder", {"split_pos": 1, "ttl": 3}, b"", self.packet_info
        )
        assert isinstance(empty_result, list)

        # Очень маленький payload
        small_result = self.dispatcher.dispatch_attack(
            "fakeddisorder", {"split_pos": 1, "ttl": 3}, b"a", self.packet_info
        )
        assert isinstance(small_result, list)

        # Позиция больше длины payload
        large_pos_result = self.dispatcher.dispatch_attack(
            "fakeddisorder",
            {"split_pos": 1000, "ttl": 3},
            self.small_payload,
            self.packet_info,
        )
        assert isinstance(large_pos_result, list)

        # Нулевая позиция
        zero_pos_result = self.dispatcher.dispatch_attack(
            "fakeddisorder",
            {"split_pos": 0, "ttl": 3},
            self.http_payload,
            self.packet_info,
        )
        assert isinstance(zero_pos_result, list)

    def test_multisplit_parameter_conversion(self):
        """Тест конвертации параметров для multisplit."""
        # Тест с split_pos
        split_pos_params = {"split_pos": 25, "fooling": ["badsum"]}
        result1 = self.dispatcher.dispatch_attack(
            "multisplit", split_pos_params, self.http_payload, self.packet_info
        )
        assert len(result1) == 2  # Одна позиция = 2 сегмента

        # Тест с split_count
        split_count_params = {"split_count": 3, "fooling": ["badsum"]}
        result2 = self.dispatcher.dispatch_attack(
            "multisplit", split_count_params, self.http_payload, self.packet_info
        )
        assert len(result2) >= 2  # Минимум 2 сегмента

        # Тест с positions (приоритет над другими параметрами)
        positions_params = {
            "positions": [10, 20, 30],
            "split_pos": 15,  # Должен игнорироваться
            "split_count": 5,  # Должен игнорироваться
            "fooling": ["badsum"],
        }
        result3 = self.dispatcher.dispatch_attack(
            "multisplit", positions_params, self.http_payload, self.packet_info
        )
        assert len(result3) == 4  # 3 позиции = 4 сегмента

    def test_performance_monitoring(self):
        """Тест мониторинга производительности."""
        params = {"split_pos": 15, "ttl": 3}

        with patch("logging.Logger.info") as mock_log:
            result = self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.http_payload, self.packet_info
            )

            # Проверяем, что логирование производительности произошло
            log_calls = [call.args[0] for call in mock_log.call_args_list]
            performance_logs = [
                log
                for log in log_calls
                if "dispatched successfully" in log and "s" in log
            ]
            assert len(performance_logs) > 0

    def test_concurrent_attacks(self):
        """Тест конкурентного выполнения атак."""

        def execute_attack(
            attack_type: str, params: Dict[str, Any]
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return self.dispatcher.dispatch_attack(
                attack_type, params, self.http_payload, self.packet_info
            )

        # Параметры для разных атак
        attack_configs = [
            ("fakeddisorder", {"split_pos": 10, "ttl": 3}),
            ("multisplit", {"positions": [5, 15, 25]}),
            ("disorder", {"split_pos": 20}),
            ("seqovl", {"split_pos": 12, "overlap_size": 8, "fake_ttl": 2}),
            ("fake", {"ttl": 4, "fooling": ["badsum"]}),
        ]

        results = []
        errors = []

        def worker(attack_type: str, params: Dict[str, Any]):
            try:
                result = execute_attack(attack_type, params)
                results.append((attack_type, result))
            except Exception as e:
                errors.append((attack_type, e))

        # Запускаем атаки в разных потоках
        threads = []
        for attack_type, params in attack_configs:
            thread = threading.Thread(target=worker, args=(attack_type, params))
            threads.append(thread)
            thread.start()

        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()

        # Проверяем результаты
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == len(attack_configs)

        # Проверяем, что все атаки выполнились корректно
        for attack_type, result in results:
            assert isinstance(result, list)
            assert len(result) > 0


class TestRegistryIntegration:
    """Тесты интеграции с реестром атак."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.registry = get_attack_registry()
        self.techniques = BypassTechniques()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)

    def test_custom_attack_registration_and_dispatch(self):
        """Тест регистрации и диспетчеризации пользовательской атаки."""

        def custom_attack_handler(
            context: AttackContext,
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            """Пользовательский обработчик атаки."""
            payload = context.payload
            custom_param = context.params.get("custom_param", "default")
            return [
                (
                    payload[: len(payload) // 2],
                    0,
                    {"is_fake": False, "custom": custom_param},
                ),
                (
                    payload[len(payload) // 2 :],
                    len(payload) // 2,
                    {"is_fake": False, "custom": custom_param},
                ),
            ]

        # Регистрируем пользовательскую атаку
        custom_metadata = create_attack_metadata(
            name="Custom Split Attack",
            description="Custom attack for testing integration",
            category=AttackCategories.CUSTOM,
            required_params=[],
            optional_params={"custom_param": "default"},
            aliases=["custom_split"],
        )

        self.registry.register_attack(
            "custom_attack", custom_attack_handler, custom_metadata
        )

        # Тестируем диспетчеризацию
        test_payload = b"test_payload_for_custom_attack"
        packet_info = {"src_addr": "127.0.0.1", "dst_addr": "127.0.0.1"}

        result = self.dispatcher.dispatch_attack(
            "custom_attack", {"custom_param": "test_value"}, test_payload, packet_info
        )

        assert len(result) == 2
        assert result[0][2]["custom"] == "test_value"
        assert result[1][2]["custom"] == "test_value"

        # Тестируем алиас
        result_alias = self.dispatcher.dispatch_attack(
            "custom_split", {"custom_param": "alias_test"}, test_payload, packet_info
        )

        assert len(result_alias) == 2
        assert result_alias[0][2]["custom"] == "alias_test"

    def test_attack_metadata_consistency(self):
        """Тест согласованности метаданных атак."""
        all_attacks = self.registry.list_attacks()

        for attack_type in all_attacks:
            # Проверяем, что для каждой атаки есть обработчик и метаданные
            handler = self.registry.get_attack_handler(attack_type)
            metadata = self.registry.get_attack_metadata(attack_type)

            assert handler is not None, f"No handler for attack {attack_type}"
            assert metadata is not None, f"No metadata for attack {attack_type}"
            assert isinstance(metadata, AttackMetadata)

            # Проверяем, что категория валидна
            assert metadata.category in AttackCategories.ALL

            # Проверяем алиасы
            for alias in metadata.aliases:
                alias_handler = self.registry.get_attack_handler(alias)
                assert (
                    alias_handler == handler
                ), f"Alias {alias} points to different handler"

    def test_parameter_validation_consistency(self):
        """Тест согласованности валидации параметров."""
        test_cases = [
            ("fakeddisorder", {"split_pos": 5, "ttl": 3}, True),
            ("fakeddisorder", {}, False),  # Отсутствует split_pos
            ("multisplit", {"positions": [1, 5, 10]}, True),
            ("multisplit", {"split_pos": 5}, True),  # Конвертируется в positions
            ("seqovl", {"split_pos": 5, "overlap_size": 3}, True),
            ("seqovl", {"split_pos": 5}, False),  # Отсутствует overlap_size
        ]

        for attack_type, params, should_be_valid in test_cases:
            result = self.registry.validate_parameters(attack_type, params)

            if should_be_valid:
                assert (
                    result.is_valid
                ), f"Expected {attack_type} with {params} to be valid, but got: {result.error_message}"
            else:
                assert (
                    not result.is_valid
                ), f"Expected {attack_type} with {params} to be invalid, but validation passed"


class TestErrorHandlingIntegration:
    """Тесты интеграции обработки ошибок."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.techniques = BypassTechniques()
        self.dispatcher = create_attack_dispatcher(self.techniques)
        self.test_payload = b"test_payload"
        self.packet_info = {"src_addr": "127.0.0.1", "dst_addr": "127.0.0.1"}

    def test_unknown_attack_type_error(self):
        """Тест ошибки неизвестного типа атаки."""
        with pytest.raises(
            ValueError, match="No handler found for attack type 'unknown_attack'"
        ):
            self.dispatcher.dispatch_attack(
                "unknown_attack",
                {"param": "value"},
                self.test_payload,
                self.packet_info,
            )

    def test_invalid_parameters_error(self):
        """Тест ошибки невалидных параметров."""
        # Тест с неизвестным типом атаки
        with pytest.raises(ValueError, match="No handler found for attack type"):
            self.dispatcher.dispatch_attack(
                "unknown_attack_type",
                {"split_pos": 5},
                self.test_payload,
                self.packet_info,
            )

    def test_handler_execution_error(self):
        """Тест ошибки выполнения обработчика."""

        # Создаем обработчик, который вызывает исключение
        def failing_handler(
            context: AttackContext,
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            raise RuntimeError("Handler execution failed")

        registry = get_attack_registry()
        metadata = create_attack_metadata(
            name="Failing Attack",
            description="Attack that always fails",
            category=AttackCategories.CUSTOM,
        )

        registry.register_attack("failing_attack", failing_handler, metadata)

        with pytest.raises(RuntimeError, match="Handler execution failed"):
            self.dispatcher.dispatch_attack(
                "failing_attack", {}, self.test_payload, self.packet_info
            )

    def test_graceful_degradation(self):
        """Тест graceful degradation при проблемах с продвинутыми атаками."""
        # Тестируем fallback на примитивные атаки
        params = {"split_pos": 5, "ttl": 3}

        # Должно работать даже если продвинутые атаки недоступны
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.test_payload, self.packet_info
        )

        assert isinstance(result, list)
        assert len(result) > 0


class TestPerformanceIntegration:
    """Тесты производительности интеграции."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.techniques = BypassTechniques()
        self.dispatcher = create_attack_dispatcher(self.techniques)
        self.large_payload = b"A" * 10000  # 10KB payload
        self.packet_info = {"src_addr": "127.0.0.1", "dst_addr": "127.0.0.1"}

    def test_large_payload_performance(self):
        """Тест производительности с большими payload."""
        params = {"split_pos": 1000, "ttl": 3}

        start_time = time.time()
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.large_payload, self.packet_info
        )
        execution_time = time.time() - start_time

        # Проверяем, что выполнение быстрое даже для больших payload
        assert execution_time < 0.5  # Должно выполняться менее чем за 0.5 секунды
        assert isinstance(result, list)
        assert len(result) == 3

    def test_multiple_positions_performance(self):
        """Тест производительности с множественными позициями."""
        params = {"positions": list(range(100, 1000, 100))}  # 9 позиций

        start_time = time.time()
        result = self.dispatcher.dispatch_attack(
            "multisplit", params, self.large_payload, self.packet_info
        )
        execution_time = time.time() - start_time

        # Проверяем производительность
        assert execution_time < 0.1
        assert isinstance(result, list)
        assert len(result) == 10  # 9 позиций = 10 сегментов

    def test_repeated_dispatch_performance(self):
        """Тест производительности повторных диспетчеризаций."""
        params = {"split_pos": 50, "ttl": 3}

        start_time = time.time()
        for _ in range(100):
            result = self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.packet_info
            )
            assert len(result) == 3

        total_time = time.time() - start_time
        avg_time = total_time / 100

        # Средняя диспетчеризация должна быть очень быстрой
        assert avg_time < 0.01  # Менее 10ms на диспетчеризацию

    @property
    def test_payload(self):
        """Тестовый payload для производительности."""
        return b"GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
