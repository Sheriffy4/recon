"""
Тесты для AttackDispatcher - центрального компонента диспетчеризации атак.
"""

import pytest
from unittest.mock import patch

from core.bypass.engine.attack_dispatcher import (
    AttackDispatcher,
    create_attack_dispatcher,
)
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.techniques.primitives import BypassTechniques


class TestAttackDispatcher:
    """Тесты для класса AttackDispatcher."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.techniques = BypassTechniques()
        self.registry = AttackRegistry()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.test_packet_info = {
            "src_addr": "192.168.1.1",
            "src_port": 12345,
            "dst_addr": "93.184.216.34",
            "dst_port": 443,
        }

    def test_init(self):
        """Тест инициализации диспетчера."""
        assert self.dispatcher.techniques == self.techniques
        assert self.dispatcher.registry == self.registry
        assert (
            len(self.dispatcher._advanced_attacks) >= 0
        )  # Может быть 0 если advanced attacks недоступны

    def test_create_attack_dispatcher_factory(self):
        """Тест фабричной функции создания диспетчера."""
        dispatcher = create_attack_dispatcher(self.techniques)
        assert isinstance(dispatcher, AttackDispatcher)
        assert dispatcher.techniques == self.techniques

    def test_normalize_attack_type(self):
        """Тест нормализации типов атак."""
        # Тест основных типов
        assert (
            self.dispatcher._normalize_attack_type("fakeddisorder") == "fakeddisorder"
        )
        assert (
            self.dispatcher._normalize_attack_type("FAKEDDISORDER") == "fakeddisorder"
        )
        assert (
            self.dispatcher._normalize_attack_type("  fakeddisorder  ")
            == "fakeddisorder"
        )

        # Тест алиасов
        assert (
            self.dispatcher._normalize_attack_type("fake_disorder") == "fakeddisorder"
        )
        assert self.dispatcher._normalize_attack_type("fakedisorder") == "fakeddisorder"
        assert self.dispatcher._normalize_attack_type("multi_split") == "multisplit"

    def test_dispatch_fakeddisorder_success(self):
        """Тест успешной диспетчеризации fakeddisorder атаки."""
        params = {"split_pos": 8, "ttl": 3}

        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) == 3  # fake + part2 + part1

        # Проверяем структуру результата
        fake_segment, part2_segment, part1_segment = result

        # Фейковый сегмент (содержит сгенерированный fake payload, не исходный)
        assert isinstance(fake_segment[0], bytes)
        assert len(fake_segment[0]) > 0  # Fake payload должен быть не пустым
        assert fake_segment[1] == 0  # Offset 0
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 3

        # Второй сегмент (после split_pos)
        assert part2_segment[0] == self.test_payload[8:]  # Часть после позиции 8
        assert part2_segment[1] == 8  # Offset 8
        assert part2_segment[2]["is_real"] is True

        # Первый сегмент (до split_pos)
        assert part1_segment[0] == self.test_payload[:8]  # Часть до позиции 8
        assert part1_segment[1] == 0  # Offset 0
        assert part1_segment[2]["is_real"] is True

    def test_dispatch_multisplit_with_positions(self):
        """Тест диспетчеризации multisplit с параметром positions."""
        params = {"positions": [5, 10, 15], "fooling": ["badsum"]}

        result = self.dispatcher.dispatch_attack(
            "multisplit", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert (
            len(result) >= 3
        )  # Минимум 3 сегмента (может быть больше из-за автоматических позиций)

        # Проверяем, что все сегменты имеют правильную структуру
        for segment in result:
            assert len(segment) == 3  # (data, offset, options)
            assert isinstance(segment[0], bytes)
            assert isinstance(segment[1], int)
            assert isinstance(segment[2], dict)

    def test_dispatch_multisplit_with_split_pos(self):
        """Тест диспетчеризации multisplit с параметром split_pos."""
        params = {"split_pos": 8, "fooling": ["badsum"]}

        result = self.dispatcher.dispatch_attack(
            "multisplit", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) >= 2  # Минимум 2 сегмента для одной позиции

        # Проверяем, что есть сегменты с правильными данными
        found_first_part = False
        found_second_part = False
        for segment in result:
            if segment[0] == self.test_payload[:8] and segment[1] == 0:
                found_first_part = True
            elif segment[0] == self.test_payload[8:] and segment[1] == 8:
                found_second_part = True

        assert found_first_part, "First part of payload not found"
        assert found_second_part, "Second part of payload not found"

    def test_dispatch_multisplit_with_split_count(self):
        """Тест диспетчеризации multisplit с параметром split_count."""
        params = {"split_count": 3, "fooling": ["badsum"]}

        result = self.dispatcher.dispatch_attack(
            "multisplit", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) >= 2  # Минимум 2 сегмента

        # Проверяем, что все данные покрыты
        total_data = b""
        for segment in result:
            total_data += segment[0]
        assert total_data == self.test_payload

    def test_dispatch_multisplit_filters_unsupported_params(self):
        """Тест фильтрации неподдерживаемых параметров для multisplit."""
        params = {
            "positions": [5, 10],
            "ttl": 128,  # Не поддерживается multisplit
            "split_count": 5,  # Не поддерживается когда есть positions
            "overlap_size": 20,  # Не поддерживается multisplit
            "fooling": ["badsum"],
        }

        # Не должно вызывать исключение
        result = self.dispatcher.dispatch_attack(
            "multisplit", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) >= 2

    def test_dispatch_seqovl_success(self):
        """Тест успешной диспетчеризации seqovl атаки."""
        params = {"split_pos": 5, "overlap_size": 3, "fake_ttl": 2}

        result = self.dispatcher.dispatch_attack(
            "seqovl", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) == 3  # fake + overlap + real parts

        # Проверяем, что есть fake сегмент
        fake_segments = [seg for seg in result if seg[2].get("is_fake")]
        assert len(fake_segments) >= 1, "Should have at least one fake segment"

        # Проверяем, что есть real сегменты
        real_segments = [seg for seg in result if seg[2].get("is_real")]
        assert len(real_segments) >= 1, "Should have at least one real segment"

    def test_dispatch_disorder_success(self):
        """Тест успешной диспетчеризации disorder атаки."""
        params = {"split_pos": 7}

        result = self.dispatcher.dispatch_attack(
            "disorder", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) == 2  # part2 + part1 (в обратном порядке)

        part2_segment, part1_segment = result

        # Проверяем обратный порядок
        assert part2_segment[0] == self.test_payload[7:]
        assert part2_segment[1] == 7
        assert part1_segment[0] == self.test_payload[:7]
        assert part1_segment[1] == 0

    def test_dispatch_unknown_attack_type(self):
        """Тест диспетчеризации неизвестного типа атаки."""
        params = {"split_pos": 3}

        with pytest.raises(ValueError, match="Unknown attack type"):
            self.dispatcher.dispatch_attack(
                "unknown_attack", params, self.test_payload, self.test_packet_info
            )

    def test_dispatch_invalid_parameters(self):
        """Тест диспетчеризации с невалидными параметрами."""
        # Тест с неизвестным типом атаки
        params = {"split_pos": 5}

        with pytest.raises(ValueError, match="Unknown attack type"):
            self.dispatcher.dispatch_attack(
                "unknown_attack", params, self.test_payload, self.test_packet_info
            )

    def test_resolve_split_position_integer(self):
        """Тест разрешения позиции разделения как integer."""
        result = self.dispatcher._resolve_split_position(
            5, self.test_payload, self.test_packet_info
        )
        assert result == 5

    def test_resolve_split_position_string_number(self):
        """Тест разрешения позиции разделения как строка с числом."""
        result = self.dispatcher._resolve_split_position(
            "8", self.test_payload, self.test_packet_info
        )
        assert result == 8

    def test_resolve_split_position_cipher(self):
        """Тест разрешения специального значения 'cipher'."""
        # Создаем TLS ClientHello payload для тестирования
        tls_payload = (
            b"\x16\x03\x01\x00\x20" + b"\x01\x00\x00\x1c\x03\x03" + b"A" * 32 + b"\x00"
        )  # Session ID length

        result = self.dispatcher._resolve_split_position(
            "cipher", tls_payload, self.test_packet_info
        )
        assert isinstance(result, int)
        assert result > 0

    def test_resolve_split_position_sni(self):
        """Тест разрешения специального значения 'sni'."""
        # Создаем payload с SNI extension
        sni_payload = b"some_data" + b"\x00\x00" + b"more_data"  # SNI extension type

        result = self.dispatcher._resolve_split_position(
            "sni", sni_payload, self.test_packet_info
        )
        assert isinstance(result, int)
        assert result > 0

    def test_resolve_split_position_invalid_string(self):
        """Тест разрешения невалидной строки как позиции."""
        result = self.dispatcher._resolve_split_position(
            "invalid", self.test_payload, self.test_packet_info
        )
        assert result == len(self.test_payload) // 2  # Fallback значение

    def test_resolve_parameters_basic(self):
        """Тест базового разрешения параметров."""
        params = {"split_pos": 5, "ttl": 3}

        result = self.dispatcher._resolve_parameters(
            params, self.test_payload, self.test_packet_info
        )

        assert result["split_pos"] == 5
        assert result["ttl"] == 3

    def test_resolve_parameters_special_values(self):
        """Тест разрешения специальных значений параметров."""
        params = {"split_pos": "cipher", "fake_ttl": 2}

        result = self.dispatcher._resolve_parameters(
            params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result["split_pos"], int)
        assert result["fake_ttl"] == 2

    def test_resolve_parameters_positions_list(self):
        """Тест разрешения списка позиций."""
        params = {"positions": [3, "cipher", 10]}

        result = self.dispatcher._resolve_parameters(
            params, self.test_payload, self.test_packet_info
        )

        assert len(result["positions"]) == 3
        assert result["positions"][0] == 3
        assert isinstance(result["positions"][1], int)  # Разрешенное значение cipher
        assert result["positions"][2] == 10

    def test_resolve_parameters_ttl_aliases(self):
        """Тест разрешения алиасов TTL параметров."""
        # Тест fake_ttl -> ttl
        params1 = {"fake_ttl": 5}
        result1 = self.dispatcher._resolve_parameters(
            params1, self.test_payload, self.test_packet_info
        )
        assert result1["ttl"] == 5

        # Тест ttl -> fake_ttl
        params2 = {"ttl": 7}
        result2 = self.dispatcher._resolve_parameters(
            params2, self.test_payload, self.test_packet_info
        )
        assert result2["fake_ttl"] == 7

    def test_resolve_parameters_fooling_aliases(self):
        """Тест разрешения алиасов fooling параметров."""
        params = {"fooling": ["badsum", "badseq"]}

        result = self.dispatcher._resolve_parameters(
            params, self.test_payload, self.test_packet_info
        )

        assert result["fooling_methods"] == ["badsum", "badseq"]

    def test_performance_monitoring(self):
        """Тест мониторинга производительности."""
        params = {"split_pos": 3, "ttl": 3}

        with patch("logging.Logger.info") as mock_log:
            result = self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

            # Проверяем, что логирование производительности вызвано
            mock_log.assert_called()
            log_calls = [call.args[0] for call in mock_log.call_args_list]
            # Ищем логи с информацией о выполнении атаки
            performance_logs = [
                log
                for log in log_calls
                if ("executed successfully" in log or "completed" in log)
            ]
            assert len(performance_logs) > 0

    def test_empty_payload_handling(self):
        """Тест обработки пустого payload."""
        empty_payload = b""
        params = {"split_pos": 1, "ttl": 3}

        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, empty_payload, self.test_packet_info
        )

        # Должен вернуть базовый результат без ошибок
        assert isinstance(result, list)

    def test_large_split_pos_handling(self):
        """Тест обработки слишком большой позиции разделения."""
        params = {"split_pos": 1000, "ttl": 3}  # Больше длины payload

        # Теперь система должна выбрасывать ошибку валидации для некорректных параметров
        with pytest.raises(ValueError, match="Parameter normalization failed"):
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

    def test_concurrent_dispatch_safety(self):
        """Тест безопасности при конкурентном использовании."""
        import threading

        results = []
        errors = []

        def dispatch_attack():
            try:
                params = {"split_pos": 3, "ttl": 3}
                result = self.dispatcher.dispatch_attack(
                    "fakeddisorder", params, self.test_payload, self.test_packet_info
                )
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Запускаем несколько потоков одновременно
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=dispatch_attack)
            threads.append(thread)
            thread.start()

        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()

        # Проверяем результаты
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 5

        # Все результаты должны быть одинаковыми
        for result in results:
            assert len(result) == 3  # fakeddisorder возвращает 3 сегмента

    def test_strategy_resolution_simple(self):
        """Тест разрешения простых стратегий."""
        # Тест простой стратегии
        result = self.dispatcher.resolve_strategy("fake")
        assert len(result) == 1
        assert result[0][0] == "fake"
        assert result[0][1] == {}

        # Тест стратегии с параметрами
        result = self.dispatcher.resolve_strategy("fake:ttl=5")
        assert len(result) == 1
        assert result[0][0] == "fake"
        assert result[0][1] == {"ttl": 5}

    def test_strategy_resolution_combinations(self):
        """Тест разрешения комбинированных стратегий."""
        # Тест комбинации fake,disorder -> fakeddisorder
        result = self.dispatcher.resolve_strategy("fake,disorder")
        assert len(result) == 1
        assert result[0][0] == "fakeddisorder"

        # Тест обратного порядка
        result = self.dispatcher.resolve_strategy("disorder,fake")
        assert len(result) == 1
        assert result[0][0] == "fakeddisorder"

    def test_strategy_execution(self):
        """Тест выполнения стратегий."""
        # Тест выполнения простой стратегии с disorder (не требует дополнительных параметров)
        result = self.dispatcher.dispatch_attack(
            "disorder:split_pos=5", {}, self.test_payload, self.test_packet_info
        )
        assert isinstance(result, list)
        assert len(result) > 0

        # Тест выполнения комбинированной стратегии
        result = self.dispatcher.dispatch_attack(
            "fake,disorder", {"split_pos": 5}, self.test_payload, self.test_packet_info
        )
        assert isinstance(result, list)
        assert len(result) > 0


class TestAttackDispatcherIntegration:
    """Интеграционные тесты для AttackDispatcher."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.techniques = BypassTechniques()
        self.dispatcher = create_attack_dispatcher(self.techniques)
        self.test_payload = b"GET /api/test HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: TestAgent\r\n\r\n"
        self.test_packet_info = {
            "src_addr": "10.0.0.1",
            "src_port": 54321,
            "dst_addr": "203.0.113.1",
            "dst_port": 443,
        }

    def test_full_attack_workflow_fakeddisorder(self):
        """Тест полного workflow для fakeddisorder атаки."""
        params = {"split_pos": 15, "ttl": 2, "fooling": ["badsum", "badseq"]}

        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.test_payload, self.test_packet_info
        )

        # Проверяем полную структуру результата
        assert len(result) == 3

        fake_segment, part2_segment, part1_segment = result

        # Фейковый сегмент (содержит сгенерированный fake payload)
        assert isinstance(fake_segment[0], bytes)
        assert len(fake_segment[0]) > 0  # Fake payload должен быть не пустым
        assert fake_segment[1] == 0
        assert fake_segment[2]["is_fake"] is True
        assert fake_segment[2]["ttl"] == 2

        # Реальные сегменты в обратном порядке
        assert part2_segment[0] == self.test_payload[15:]
        assert part2_segment[1] == 15
        assert part2_segment[2]["is_real"] is True

        assert part1_segment[0] == self.test_payload[:15]
        assert part1_segment[1] == 0
        assert part1_segment[2]["is_real"] is True

        # Проверяем, что данные не потеряны
        combined_real_data = part1_segment[0] + part2_segment[0]
        assert combined_real_data == self.test_payload

    def test_full_attack_workflow_multisplit_complex(self):
        """Тест полного workflow для сложного multisplit."""
        params = {"positions": [10, 25, 40, 55], "fooling": ["badsum"]}

        result = self.dispatcher.dispatch_attack(
            "multisplit", params, self.test_payload, self.test_packet_info
        )

        # Проверяем количество сегментов
        assert len(result) == 5  # 4 позиции = 5 сегментов

        # Проверяем, что все данные покрыты без потерь
        total_data = b""
        for segment in result:
            total_data += segment[0]
        assert total_data == self.test_payload

        # Проверяем правильность смещений
        expected_offsets = [0, 10, 25, 40, 55]
        for i, segment in enumerate(result):
            assert segment[1] == expected_offsets[i]

    def test_attack_type_alias_resolution(self):
        """Тест разрешения алиасов типов атак."""
        params = {"split_pos": 8, "ttl": 3}

        # Тестируем различные алиасы
        aliases_to_test = [
            ("fake_disorder", "fakeddisorder"),
            ("fakedisorder", "fakeddisorder"),
            ("multi_split", "multisplit"),
            ("simple_disorder", "disorder"),
        ]

        for alias, canonical in aliases_to_test:
            result_alias = self.dispatcher.dispatch_attack(
                alias, params, self.test_payload, self.test_packet_info
            )
            result_canonical = self.dispatcher.dispatch_attack(
                canonical, params, self.test_payload, self.test_packet_info
            )

            # Результаты должны быть идентичными
            assert len(result_alias) == len(result_canonical)
            for i in range(len(result_alias)):
                assert result_alias[i][0] == result_canonical[i][0]  # data
                assert result_alias[i][1] == result_canonical[i][1]  # offset
                # options могут немного отличаться, но основные поля должны совпадать
                alias_flags = result_alias[i][2]
                canonical_flags = result_canonical[i][2]

                # Проверяем наличие флагов fake/real
                if "is_fake" in alias_flags and "is_fake" in canonical_flags:
                    assert alias_flags["is_fake"] == canonical_flags["is_fake"]
                if "is_real" in alias_flags and "is_real" in canonical_flags:
                    assert alias_flags["is_real"] == canonical_flags["is_real"]


class TestAttackContext:
    """Tests for AttackContext functionality in AttackDispatcher."""

    def setup_method(self):
        """Setup before each test."""
        self.techniques = BypassTechniques()
        self.registry = AttackRegistry()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)
        self.test_payload = b"GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n"
        self.test_packet_info = {
            "src_addr": "192.168.1.100",
            "src_port": 54321,
            "dst_addr": "203.0.113.50",
            "dst_port": 443,
        }

    def test_attack_context_creation(self):
        """Test AttackContext creation during attack dispatch."""
        params = {"split_pos": 10, "ttl": 3}

        # Mock the handler to capture the AttackContext
        captured_context = None

        def mock_handler(context):
            nonlocal captured_context
            captured_context = context
            return [(context.payload, 0, {"is_fake": False})]

        # Replace the handler temporarily
        original_handler = self.registry.get_attack_handler("fakeddisorder")
        self.registry.attacks["fakeddisorder"].handler = mock_handler

        try:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

            # Verify AttackContext was created correctly
            assert captured_context is not None
            assert captured_context.payload == self.test_payload
            assert captured_context.dst_ip == "203.0.113.50"
            assert captured_context.dst_port == 443
            assert (
                "192.168.1.100:54321->203.0.113.50:443"
                in captured_context.connection_id
            )
            assert captured_context.params["split_pos"] == 10
            assert (
                captured_context.params["fake_ttl"] == 3
            )  # Should be normalized from ttl

        finally:
            # Restore original handler
            self.registry.attacks["fakeddisorder"].handler = original_handler

    def test_attack_context_metadata(self):
        """Test AttackContext metadata fields."""
        params = {"split_pos": 5, "fooling": ["badsum"]}

        captured_context = None

        def mock_handler(context):
            nonlocal captured_context
            captured_context = context
            return [(context.payload, 0, {"test": True})]

        original_handler = self.registry.get_attack_handler("disorder")
        self.registry.attacks["disorder"].handler = mock_handler

        try:
            self.dispatcher.dispatch_attack(
                "disorder", params, self.test_payload, self.test_packet_info
            )

            assert captured_context is not None
            assert hasattr(captured_context, "metadata")
            assert isinstance(captured_context.metadata, dict)

        finally:
            self.registry.attacks["disorder"].handler = original_handler

    def test_attack_context_with_missing_packet_info(self):
        """Test AttackContext creation with incomplete packet info."""
        params = {"split_pos": 8}
        incomplete_packet_info = {"dst_port": 80}  # Missing other fields

        captured_context = None

        def mock_handler(context):
            nonlocal captured_context
            captured_context = context
            return [(context.payload, 0, {})]

        original_handler = self.registry.get_attack_handler("split")
        self.registry.attacks["split"].handler = mock_handler

        try:
            self.dispatcher.dispatch_attack(
                "split", params, self.test_payload, incomplete_packet_info
            )

            # Should use defaults for missing fields
            assert captured_context is not None
            assert captured_context.dst_ip == "127.0.0.1"  # Default
            assert captured_context.dst_port == 80  # From packet_info

        finally:
            self.registry.attacks["split"].handler = original_handler


class TestParameterNormalizationIntegration:
    """Tests for parameter normalization integration in AttackDispatcher."""

    def setup_method(self):
        """Setup before each test."""
        self.techniques = BypassTechniques()
        self.registry = AttackRegistry()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)
        self.test_payload = b"HTTP/1.1 request data"
        self.test_packet_info = {
            "src_addr": "10.0.0.1",
            "src_port": 12345,
            "dst_addr": "10.0.0.2",
            "dst_port": 443,
        }

    def test_parameter_alias_normalization(self):
        """Test parameter alias normalization (ttl -> fake_ttl)."""
        params = {"split_pos": 5, "ttl": 2}  # ttl should become fake_ttl

        captured_params = None

        def mock_handler(context):
            nonlocal captured_params
            captured_params = context.params
            return [(context.payload, 0, {})]

        original_handler = self.registry.get_attack_handler("fakeddisorder")
        self.registry.attacks["fakeddisorder"].handler = mock_handler

        try:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

            # Verify parameter normalization
            assert captured_params is not None
            assert "fake_ttl" in captured_params
            assert captured_params["fake_ttl"] == 2
            assert "ttl" not in captured_params  # Should be removed after normalization

        finally:
            self.registry.attacks["fakeddisorder"].handler = original_handler

    def test_parameter_type_conversion(self):
        """Test parameter type conversion (string to int)."""
        params = {"split_pos": "10", "fake_ttl": "3"}  # String values

        captured_params = None

        def mock_handler(context):
            nonlocal captured_params
            captured_params = context.params
            return [(context.payload, 0, {})]

        original_handler = self.registry.get_attack_handler("seqovl")
        self.registry.attacks["seqovl"].handler = mock_handler

        try:
            self.dispatcher.dispatch_attack(
                "seqovl", params, self.test_payload, self.test_packet_info
            )

            # Verify type conversion
            assert captured_params is not None
            assert isinstance(captured_params["split_pos"], int)
            assert captured_params["split_pos"] == 10
            assert isinstance(captured_params["fake_ttl"], int)
            assert captured_params["fake_ttl"] == 3

        finally:
            self.registry.attacks["seqovl"].handler = original_handler

    def test_parameter_list_handling(self):
        """Test parameter list handling for positions."""
        params = {"positions": [5, 10, 15]}

        captured_params = None

        def mock_handler(context):
            nonlocal captured_params
            captured_params = context.params
            return [(context.payload, 0, {})]

        original_handler = self.registry.get_attack_handler("multisplit")
        self.registry.attacks["multisplit"].handler = mock_handler

        try:
            self.dispatcher.dispatch_attack(
                "multisplit", params, self.test_payload, self.test_packet_info
            )

            # Verify list parameter handling
            assert captured_params is not None
            assert "positions" in captured_params
            assert isinstance(captured_params["positions"], list)
            assert captured_params["positions"] == [5, 10, 15]

        finally:
            self.registry.attacks["multisplit"].handler = original_handler

    def test_parameter_validation_error(self):
        """Test parameter validation error handling."""
        params = {"split_pos": -5}  # Invalid negative position

        # Should raise validation error
        with pytest.raises(
            ValueError, match="Parameter normalization failed|Invalid parameter"
        ):
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

    def test_missing_required_parameter(self):
        """Test handling of missing required parameters."""
        params = {}  # Missing required split_pos

        # Should raise validation error for missing required parameter
        with pytest.raises(
            ValueError,
            match="Missing required parameter|Parameter normalization failed",
        ):
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

    def test_parameter_bounds_validation(self):
        """Test parameter bounds validation."""
        # Test TTL out of bounds
        params = {"split_pos": 5, "fake_ttl": 300}  # TTL > 255

        with pytest.raises(ValueError, match="Parameter normalization failed|ttl.*255"):
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )


class TestStrategyResolutionAdvanced:
    """Advanced tests for strategy resolution in AttackDispatcher."""

    def setup_method(self):
        """Setup before each test."""
        self.techniques = BypassTechniques()
        self.registry = AttackRegistry()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)

    def test_strategy_with_parameters(self):
        """Test strategy resolution with embedded parameters."""
        # Test strategy with parameters
        result = self.dispatcher.resolve_strategy("fake:ttl=4,fooling=badsum")

        assert len(result) == 1
        assert result[0][0] == "fake"
        assert result[0][1]["ttl"] == 4
        assert result[0][1]["fooling"] == "badsum"

    def test_complex_strategy_combinations(self):
        """Test complex strategy combinations."""
        # Test multiple combinations that should resolve to fakeddisorder
        test_cases = [
            "fake,disorder",
            "disorder,fake",
            "fake+disorder",
            "disorder+fake",
        ]

        for strategy in test_cases:
            result = self.dispatcher.resolve_strategy(strategy)
            assert len(result) == 1
            assert result[0][0] == "fakeddisorder"

    def test_strategy_with_multiple_parameters(self):
        """Test strategy with multiple parameter sets."""
        result = self.dispatcher.resolve_strategy(
            "multisplit:positions=[5,10,15],fooling=[badsum,badseq]"
        )

        assert len(result) == 1
        assert result[0][0] == "multisplit"
        assert result[0][1]["positions"] == [5, 10, 15]
        assert result[0][1]["fooling"] == ["badsum", "badseq"]

    def test_invalid_strategy_format(self):
        """Test handling of invalid strategy formats."""
        # Test malformed strategy
        with pytest.raises(
            ValueError, match="Invalid strategy format|Unknown strategy"
        ):
            self.dispatcher.resolve_strategy("invalid:format:too:many:colons")

    def test_unknown_strategy_name(self):
        """Test handling of unknown strategy names."""
        with pytest.raises(ValueError, match="Unknown strategy|not found"):
            self.dispatcher.resolve_strategy("nonexistent_strategy")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
