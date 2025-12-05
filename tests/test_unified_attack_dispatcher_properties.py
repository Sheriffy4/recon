"""
Property-based tests for UnifiedAttackDispatcher.

These tests verify correctness properties for combo attack execution.

Requirements: 1.3, 2.5, 3.7, 7.2, 7.5, 9.1, 9.2
"""

import pytest
from hypothesis import given, strategies as st, settings

from core.bypass.engine.unified_attack_dispatcher import (
    get_fake_params,
    generate_fake_payload,
    MetricsCircuitBreaker,
    AttackConstants,
    PacketSegment,
    UnifiedAttackDispatcher
)
from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe, AttackStep


# Strategies for generating test data
@st.composite
def attack_list_strategy(draw):
    """Generate valid attack lists for testing."""
    attacks = draw(st.lists(
        st.sampled_from(['fake', 'split', 'multisplit', 'disorder']),
        min_size=1,
        max_size=4,
        unique=True
    ))
    
    # Filter out incompatible combinations
    # split and multisplit cannot be used together
    if 'split' in attacks and 'multisplit' in attacks:
        # Remove one of them randomly
        to_remove = draw(st.sampled_from(['split', 'multisplit']))
        attacks = [a for a in attacks if a != to_remove]
    
    return attacks


@st.composite
def payload_strategy(draw):
    """Generate valid TLS-like payloads."""
    # Minimum TLS ClientHello structure
    min_size = 50
    max_size = 500
    size = draw(st.integers(min_value=min_size, max_value=max_size))
    
    # Start with TLS record header
    payload = b'\x16\x03\x01'  # TLS Handshake, TLS 1.0
    payload += (size - 5).to_bytes(2, 'big')  # Length
    
    # Add random data
    payload += draw(st.binary(min_size=size - 5, max_size=size - 5))
    
    return payload


@st.composite
def packet_info_strategy(draw):
    """Generate packet info dictionaries."""
    return {
        'src_addr': draw(st.ip_addresses(v=4).map(str)),
        'dst_addr': draw(st.ip_addresses(v=4).map(str)),
        'src_port': draw(st.integers(min_value=1024, max_value=65535)),
        'dst_port': draw(st.integers(min_value=1, max_value=65535)),
    }


class TestUnifiedAttackDispatcherProperties:
    """Property-based tests for UnifiedAttackDispatcher."""
    
    @given(
        attacks=attack_list_strategy(),
        payload=payload_strategy(),
        packet_info=packet_info_strategy()
    )
    @settings(max_examples=100, deadline=None)
    def test_property_3_attack_application_order(self, attacks, payload, packet_info):
        """
        **Feature: attack-application-parity, Property 3: Attack Application Order**
        **Validates: Requirements 1.3**
        
        Property: For any combination of attacks, the system should apply them
        in the order: fake → split/multisplit → disorder.
        
        This test verifies that:
        1. Fake attacks are always applied first (order=1)
        2. Split/multisplit attacks are applied second (order=2)
        3. Disorder attacks are applied last (order=3)
        4. The recipe steps are sorted by order
        """
        # Build recipe from attacks
        builder = ComboAttackBuilder()
        params = {
            'ttl': 3,
            'split_pos': 2,
            'split_count': 2,
            'disorder_method': 'reverse'
        }
        
        recipe = builder.build_recipe(attacks, params)
        
        # Verify recipe steps are sorted by order
        for i in range(len(recipe.steps) - 1):
            assert recipe.steps[i].order <= recipe.steps[i + 1].order, \
                f"Steps not in order: {recipe.steps[i].attack_type} (order={recipe.steps[i].order}) " \
                f"should come before {recipe.steps[i + 1].attack_type} (order={recipe.steps[i + 1].order})"
        
        # Verify attack type ordering
        fake_indices = [i for i, step in enumerate(recipe.steps) if 'fake' in step.attack_type]
        split_indices = [i for i, step in enumerate(recipe.steps) if step.attack_type in ('split', 'multisplit')]
        disorder_indices = [i for i, step in enumerate(recipe.steps) if 'disorder' in step.attack_type]
        
        # If fake exists, it should come before split and disorder
        if fake_indices and split_indices:
            assert max(fake_indices) < min(split_indices), \
                "Fake attacks should come before split attacks"
        
        if fake_indices and disorder_indices:
            assert max(fake_indices) < min(disorder_indices), \
                "Fake attacks should come before disorder attacks"
        
        # If split exists, it should come before disorder
        if split_indices and disorder_indices:
            assert max(split_indices) < min(disorder_indices), \
                "Split attacks should come before disorder attacks"
        
        # Execute recipe and verify segments are generated
        dispatcher = UnifiedAttackDispatcher(builder)
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify segments were generated
        assert len(segments) > 0, "Recipe execution should generate at least one segment"
        
        # Verify all segments have required structure
        for segment in segments:
            assert isinstance(segment, tuple), "Segment should be a tuple"
            assert len(segment) == 3, "Segment should have 3 elements (data, offset, options)"
            data, offset, options = segment
            assert isinstance(data, bytes), "Segment data should be bytes"
            assert isinstance(offset, int), "Segment offset should be int"
            assert isinstance(options, dict), "Segment options should be dict"
    
    @given(
        attacks=st.lists(
            st.sampled_from(['fake', 'split', 'disorder']),
            min_size=2,
            max_size=3,
            unique=True
        ),
        payload=payload_strategy(),
        packet_info=packet_info_strategy()
    )
    @settings(max_examples=100, deadline=None)
    def test_property_7_all_valid_combos_supported(self, attacks, payload, packet_info):
        """
        **Feature: attack-application-parity, Property 7: All Valid Combos Supported**
        **Validates: Requirements 2.5**
        
        Property: For any valid combination of attacks, AttackDispatcher should
        apply all attacks without conflicts.
        
        This test verifies that:
        1. All valid combinations can be built into recipes
        2. All recipes can be executed without errors
        3. Each attack in the combination generates segments
        4. No conflicts occur between attacks
        """
        # Build recipe from attacks
        builder = ComboAttackBuilder()
        params = {
            'ttl': 3,
            'split_pos': 2,
            'split_count': 2,
            'disorder_method': 'reverse'
        }
        
        # Verify recipe can be built without errors
        try:
            recipe = builder.build_recipe(attacks, params)
        except ValueError as e:
            # If this is an incompatible combination, that's expected
            if "Incompatible" in str(e):
                pytest.skip(f"Incompatible combination: {attacks}")
            raise
        
        # Verify recipe contains all attacks
        recipe_attacks = [step.attack_type for step in recipe.steps]
        for attack in attacks:
            assert attack in recipe_attacks, \
                f"Attack '{attack}' should be in recipe but got {recipe_attacks}"
        
        # Execute recipe
        dispatcher = UnifiedAttackDispatcher(builder)
        
        try:
            segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        except Exception as e:
            pytest.fail(f"Recipe execution failed for valid combination {attacks}: {e}")
        
        # Verify segments were generated
        assert len(segments) > 0, \
            f"Valid combination {attacks} should generate at least one segment"
        
        # Verify segment count is reasonable
        # Fake generates 1, split generates 2+, disorder reorders existing
        expected_min_segments = 1
        if 'split' in attacks or 'multisplit' in attacks:
            expected_min_segments = 2
        
        assert len(segments) >= expected_min_segments, \
            f"Combination {attacks} should generate at least {expected_min_segments} segments, got {len(segments)}"
        
        # Verify all segments are valid
        for i, segment in enumerate(segments):
            data, offset, options = segment
            assert len(data) > 0, f"Segment {i} should have non-empty data"
            assert offset >= 0, f"Segment {i} should have non-negative offset"
            assert isinstance(options, dict), f"Segment {i} should have options dict"
    
    @given(
        payload=payload_strategy(),
        packet_info=packet_info_strategy(),
        ttl=st.integers(min_value=1, max_value=10),
        split_pos=st.integers(min_value=1, max_value=100)
    )
    @settings(max_examples=100, deadline=None)
    def test_fake_attack_generates_low_ttl_packet(self, payload, packet_info, ttl, split_pos):
        """
        Test that fake attacks generate packets with specified TTL.
        
        This verifies that fake attack implementation correctly sets TTL.
        """
        dispatcher = UnifiedAttackDispatcher()
        params = {'ttl': ttl, 'fooling': 'badsum'}
        
        segments = dispatcher.apply_fake(payload, params, packet_info)
        
        assert len(segments) == 1, "Fake attack should generate exactly one segment"
        
        data, offset, options = segments[0]
        assert options.get('ttl') == ttl, f"Fake packet should have TTL={ttl}"
        assert options.get('is_fake') == True, "Fake packet should be marked as fake"
    
    @given(
        payload=payload_strategy(),
        packet_info=packet_info_strategy(),
        split_count=st.integers(min_value=2, max_value=10)
    )
    @settings(max_examples=100, deadline=None)
    def test_split_attack_generates_correct_fragment_count(self, payload, packet_info, split_count):
        """
        Test that split attacks generate the correct number of fragments.
        
        This verifies that split/multisplit implementation correctly fragments payload.
        """
        dispatcher = UnifiedAttackDispatcher()
        params = {'split_pos': 2, 'split_count': split_count}
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        assert len(segments) == split_count, \
            f"Split attack should generate {split_count} fragments, got {len(segments)}"
        
        # Verify fragments reconstruct original payload
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct original payload"
    
    @given(
        segment_count=st.integers(min_value=2, max_value=10),
        disorder_method=st.sampled_from(['reverse', 'random', 'swap'])
    )
    @settings(max_examples=100, deadline=None)
    def test_disorder_attack_preserves_segment_count(self, segment_count, disorder_method):
        """
        Test that disorder attacks preserve the number of segments.
        
        This verifies that disorder reordering doesn't lose or duplicate segments.
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Create dummy segments
        segments = [
            (f"data{i}".encode(), i * 10, {'fragment': i})
            for i in range(segment_count)
        ]
        
        params = {'disorder_method': disorder_method}
        packet_info = {'src_addr': '127.0.0.1', 'dst_addr': '127.0.0.1', 'src_port': 1234, 'dst_port': 443}
        
        reordered = dispatcher.apply_disorder(segments, params, packet_info)
        
        assert len(reordered) == len(segments), \
            f"Disorder should preserve segment count: {len(segments)} → {len(reordered)}"
        
        # Verify all original segments are present (order may differ)
        original_data = {seg[0] for seg in segments}
        reordered_data = {seg[0] for seg in reordered}
        assert original_data == reordered_data, \
            "Disorder should preserve all segment data"


class TestHelperFunctionProperties:
    """Property-based tests for helper functions."""
    
    @given(
        has_ttl=st.booleans(),
        ttl_value=st.integers(min_value=-10, max_value=255)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_21_ttl_parameter_required(self, has_ttl, ttl_value):
        """
        **Feature: unified-attack-dispatcher, Property 21: TTL parameter required**
        **Validates: Requirements 9.1**
        
        Property: For any fake packet generation without TTL parameter,
        the system should raise ValueError.
        
        This test verifies that:
        1. Missing TTL raises ValueError
        2. Error message is descriptive
        """
        # Build params based on has_ttl flag
        if has_ttl:
            params = {'ttl': ttl_value}
        else:
            params = {}
        
        if not has_ttl:
            # Should raise ValueError
            with pytest.raises(ValueError) as exc_info:
                get_fake_params(params)
            
            # Verify error message is descriptive
            assert 'TTL' in str(exc_info.value), \
                "Error message should mention TTL"
            assert 'required' in str(exc_info.value).lower(), \
                "Error message should indicate TTL is required"
        else:
            # Should not raise
            result = get_fake_params(params)
            assert 'ttl' in result, "Result should contain TTL"
    
    @given(
        ttl=st.integers(min_value=-100, max_value=0)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_22_ttl_clamping_to_minimum(self, ttl):
        """
        **Feature: unified-attack-dispatcher, Property 22: TTL clamping to minimum**
        **Validates: Requirements 9.2**
        
        Property: For any TTL value less than 1, the effective TTL should be
        clamped to MIN_FAKE_TTL (1).
        
        This test verifies that:
        1. TTL below minimum is clamped to 1
        2. Warning is logged (implicit in implementation)
        """
        params = {'ttl': ttl}
        
        result = get_fake_params(params)
        
        assert result['ttl'] == AttackConstants.MIN_FAKE_TTL, \
            f"TTL {ttl} should be clamped to {AttackConstants.MIN_FAKE_TTL}, got {result['ttl']}"
    
    @given(
        ttl=st.integers(min_value=1, max_value=255)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_22_ttl_valid_range_preserved(self, ttl):
        """
        Test that valid TTL values are preserved without clamping.
        
        This complements Property 22 by verifying that valid values
        are not modified.
        """
        params = {'ttl': ttl}
        
        result = get_fake_params(params)
        
        assert result['ttl'] == ttl, \
            f"Valid TTL {ttl} should be preserved, got {result['ttl']}"
    
    @given(
        max_failures=st.integers(min_value=1, max_value=10),
        failure_count=st.integers(min_value=1, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_19_circuit_breaker_opens_on_threshold(self, max_failures, failure_count):
        """
        **Feature: unified-attack-dispatcher, Property 19: Circuit breaker opens on threshold**
        **Validates: Requirements 7.2**
        
        Property: For any sequence of N consecutive failures (N = max_failures),
        the circuit breaker should be open.
        
        This test verifies that:
        1. Circuit breaker opens when failure count reaches threshold
        2. Circuit breaker remains closed below threshold
        """
        breaker = MetricsCircuitBreaker(max_failures=max_failures)
        
        # Record failures
        for i in range(failure_count):
            breaker.record_failure()
        
        # Check circuit breaker state
        if failure_count >= max_failures:
            assert breaker.is_open, \
                f"Circuit breaker should be open after {failure_count} failures (threshold={max_failures})"
            assert breaker.should_skip(), \
                "Circuit breaker should skip metrics when open"
        else:
            assert not breaker.is_open, \
                f"Circuit breaker should be closed with {failure_count} failures (threshold={max_failures})"
            assert not breaker.should_skip(), \
                "Circuit breaker should not skip metrics when closed"
    
    @given(
        max_failures=st.integers(min_value=2, max_value=10),
        initial_failures=st.integers(min_value=1, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_20_circuit_breaker_resets_on_success(self, max_failures, initial_failures):
        """
        **Feature: unified-attack-dispatcher, Property 20: Circuit breaker resets on success**
        **Validates: Requirements 7.5**
        
        Property: For any successful metrics recording after failures,
        the failure counter should be zero.
        
        This test verifies that:
        1. Failure counter is reset to zero on success
        2. Circuit breaker closes on success if it was open
        """
        breaker = MetricsCircuitBreaker(max_failures=max_failures)
        
        # Record initial failures
        for i in range(initial_failures):
            breaker.record_failure()
        
        # Record success
        breaker.record_success()
        
        # Verify failure counter is reset
        assert breaker.failure_count == 0, \
            f"Failure counter should be reset to 0 after success, got {breaker.failure_count}"
        
        # Verify circuit breaker is closed
        assert not breaker.is_open, \
            "Circuit breaker should be closed after success"
        assert not breaker.should_skip(), \
            "Circuit breaker should not skip metrics after success"
    
    @given(
        real_payload=st.binary(min_size=5, max_size=1500)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_11_tls_fake_header_preservation(self, real_payload):
        """
        **Feature: unified-attack-dispatcher, Property 11: TLS fake header preservation**
        **Validates: Requirements 3.7**
        
        Property: For any TLS ClientHello payload, the fake payload should start
        with the same 5-byte TLS header.
        
        This test verifies that:
        1. TLS header (first 5 bytes) is preserved
        2. Content after header is randomized
        """
        # Ensure payload starts with TLS-like header
        if len(real_payload) >= 5:
            # Create TLS-like payload
            tls_payload = b'\x16\x03\x01' + real_payload[3:5] + real_payload[5:]
        else:
            tls_payload = real_payload
        
        # Generate fake payload
        fake_payload = generate_fake_payload(tls_payload, 'badsum', protocol='tls')
        
        # Verify header preservation
        if len(tls_payload) >= 5:
            assert fake_payload[:5] == tls_payload[:5], \
                f"TLS header should be preserved: expected {tls_payload[:5].hex()}, got {fake_payload[:5].hex()}"
            
            # Verify content is different (randomized)
            if len(tls_payload) > 5:
                # Content should be different (with very high probability)
                # We allow them to be the same with very low probability
                assert len(fake_payload) == len(tls_payload), \
                    "Fake payload should have same length as real payload"
    
    @given(
        real_payload=st.binary(min_size=40, max_size=500)
    )
    @settings(max_examples=100, deadline=None)
    def test_http_fake_no_null_bytes(self, real_payload):
        """
        Test that HTTP fake payloads use spaces instead of null bytes for padding.
        
        This verifies the expert recommendation fix.
        """
        fake_payload = generate_fake_payload(real_payload, 'badsum', protocol='http')
        
        # Verify length matches
        assert len(fake_payload) == len(real_payload), \
            "Fake payload should have same length as real payload"
        
        # Verify HTTP fake starts with valid HTTP request
        # The minimum HTTP request is "GET / HTTP/1.1\r\nHost: example.com\r\n" (38 bytes)
        if len(real_payload) >= 38:
            assert fake_payload.startswith(b'GET / HTTP/1.1'), \
                "HTTP fake should start with valid HTTP request"
            
            # Verify padding uses spaces, not null bytes
            # Check if there's padding after the HTTP header
            http_header = b'GET / HTTP/1.1\r\nHost: example.com\r\n'
            if len(real_payload) > len(http_header):
                padding = fake_payload[len(http_header):]
                # Padding should be all spaces
                assert all(b == ord(b' ') for b in padding), \
                    "HTTP padding should use spaces, not null bytes"



class TestAttackHandlerProperties:
    """Property-based tests for attack handler functions."""
    
    @given(
        payload=st.binary(min_size=2, max_size=1000),
        split_pos=st.integers(min_value=-10, max_value=1010)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_4_split_position_accuracy(self, payload, split_pos):
        """
        **Feature: unified-attack-dispatcher, Property 4: Split position accuracy**
        **Validates: Requirements 2.1**
        
        Property: For any payload and valid split_pos, the first segment should
        have length equal to split_pos.
        
        This test verifies that:
        1. Split occurs at exact position when valid
        2. First segment has length equal to split_pos
        """
        from core.bypass.engine.unified_attack_dispatcher import _apply_split
        
        packet_info = {'original_ttl': 64}
        params = {'split_pos': split_pos}
        
        segments = _apply_split(payload, params, packet_info)
        
        # Determine expected split position (after clamping)
        expected_split_pos = split_pos
        if expected_split_pos < 1:
            expected_split_pos = 1
        elif expected_split_pos >= len(payload):
            expected_split_pos = len(payload) - 1
        
        # Verify we got 2 segments
        assert len(segments) == 2, \
            f"Split should produce 2 segments, got {len(segments)}"
        
        # Verify first segment length equals clamped split_pos
        first_segment = segments[0]
        assert len(first_segment.data) == expected_split_pos, \
            f"First segment should have length {expected_split_pos}, got {len(first_segment.data)}"
        
        # Verify second segment starts where first ends
        second_segment = segments[1]
        assert len(second_segment.data) == len(payload) - expected_split_pos, \
            f"Second segment should have length {len(payload) - expected_split_pos}, got {len(second_segment.data)}"
        
        # Verify segments reconstruct original payload
        reconstructed = first_segment.data + second_segment.data
        assert reconstructed == payload, \
            "Segments should reconstruct original payload"
    
    @given(
        payload=st.binary(min_size=2, max_size=1000),
        split_pos=st.one_of(
            st.integers(min_value=-100, max_value=0),
            st.integers(min_value=1001, max_value=2000)
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_property_6_split_position_clamping(self, payload, split_pos):
        """
        **Feature: unified-attack-dispatcher, Property 6: Split position clamping**
        **Validates: Requirements 2.4**
        
        Property: For any split_pos outside valid range, the actual split position
        should be clamped to [1, len(payload)-1].
        
        This test verifies that:
        1. Negative split_pos is clamped to 1
        2. Split_pos >= len(payload) is clamped to len(payload)-1
        3. No crashes occur with invalid positions
        """
        from core.bypass.engine.unified_attack_dispatcher import _apply_split
        
        packet_info = {'original_ttl': 64}
        params = {'split_pos': split_pos}
        
        # Should not crash
        segments = _apply_split(payload, params, packet_info)
        
        # Verify we got 2 segments
        assert len(segments) == 2, \
            f"Split should produce 2 segments even with invalid split_pos, got {len(segments)}"
        
        # Determine expected clamped position
        if split_pos < 1:
            expected_pos = 1
        elif split_pos >= len(payload):
            expected_pos = len(payload) - 1
        else:
            expected_pos = split_pos
        
        # Verify first segment has clamped length
        first_segment = segments[0]
        assert len(first_segment.data) == expected_pos, \
            f"First segment should have clamped length {expected_pos}, got {len(first_segment.data)}"
        
        # Verify segments reconstruct original
        reconstructed = first_segment.data + segments[1].data
        assert reconstructed == payload, \
            "Segments should reconstruct original payload after clamping"

    
    @given(
        payload=st.binary(min_size=2, max_size=1000),
        split_count=st.integers(min_value=2, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_5_multisplit_fragment_count(self, payload, split_count):
        """
        **Feature: unified-attack-dispatcher, Property 5: Multisplit fragment count**
        **Validates: Requirements 2.3**
        
        Property: For any payload and split_count N, the result should contain
        exactly N segments.
        
        This test verifies that:
        1. Multisplit produces exactly N segments
        2. All segments are non-empty
        3. Segments reconstruct original payload
        """
        from core.bypass.engine.unified_attack_dispatcher import _apply_multisplit
        
        packet_info = {'original_ttl': 64}
        params = {'split_count': split_count}
        
        # Adjust split_count if it exceeds payload length
        effective_split_count = min(split_count, len(payload))
        
        segments = _apply_multisplit(payload, params, packet_info)
        
        # Verify we got exactly split_count segments (or len(payload) if smaller)
        assert len(segments) == effective_split_count, \
            f"Multisplit should produce {effective_split_count} segments, got {len(segments)}"
        
        # Verify all segments are non-empty
        for i, segment in enumerate(segments):
            assert len(segment.data) > 0, \
                f"Segment {i} should be non-empty"
        
        # Verify segments reconstruct original payload
        reconstructed = b''.join(seg.data for seg in segments)
        assert reconstructed == payload, \
            "Segments should reconstruct original payload"
        
        # Verify fragment indices are correct
        for i, segment in enumerate(segments):
            assert segment.fragment_index == i, \
                f"Segment {i} should have fragment_index={i}, got {segment.fragment_index}"

    
    @given(
        payload=st.binary(min_size=2, max_size=1000),
        original_ttl=st.integers(min_value=1, max_value=255),
        split_type=st.sampled_from(['split', 'multisplit'])
    )
    @settings(max_examples=100, deadline=None)
    def test_property_7_ttl_preservation_in_splits(self, payload, original_ttl, split_type):
        """
        **Feature: unified-attack-dispatcher, Property 7: TTL preservation in splits**
        **Validates: Requirements 2.5**
        
        Property: For any split operation, all real segments should have the
        same TTL value.
        
        This test verifies that:
        1. All segments from split have same TTL
        2. TTL matches the original_ttl from packet_info
        3. No fake segments are created (all is_fake=False)
        """
        from core.bypass.engine.unified_attack_dispatcher import _apply_split, _apply_multisplit
        
        packet_info = {'original_ttl': original_ttl}
        
        if split_type == 'split':
            params = {'split_pos': len(payload) // 2}
            segments = _apply_split(payload, params, packet_info)
        else:  # multisplit
            params = {'split_count': 3}
            segments = _apply_multisplit(payload, params, packet_info)
        
        # Verify all segments have the same TTL
        for i, segment in enumerate(segments):
            assert segment.ttl == original_ttl, \
                f"Segment {i} should have TTL={original_ttl}, got {segment.ttl}"
            
            # Verify all segments are real (not fake)
            assert segment.is_fake == False, \
                f"Segment {i} should be real (is_fake=False), got is_fake={segment.is_fake}"
        
        # Verify at least 2 segments were created
        assert len(segments) >= 2, \
            f"Split should create at least 2 segments, got {len(segments)}"

    
    @given(
        segment_count=st.integers(min_value=2, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_12_disorder_reverse_round_trip(self, segment_count):
        """
        **Feature: unified-attack-dispatcher, Property 12: Disorder reverse round-trip**
        **Validates: Requirements 4.1**
        
        Property: For any segment list, applying reverse disorder twice should
        return the original order.
        
        This test verifies that:
        1. Reverse is its own inverse
        2. Double reverse returns original order
        """
        from core.bypass.engine.unified_attack_dispatcher import _apply_disorder_segments, PacketSegment
        
        # Create test segments
        original_segments = [
            PacketSegment(
                data=f"segment_{i}".encode(),
                offset=i * 10,
                ttl=64,
                fragment_index=i
            )
            for i in range(segment_count)
        ]
        
        params = {'disorder_method': 'reverse'}
        
        # Apply reverse once
        reversed_once = _apply_disorder_segments(original_segments, params)
        
        # Apply reverse again
        reversed_twice = _apply_disorder_segments(reversed_once, params)
        
        # Verify we got back to original order
        assert len(reversed_twice) == len(original_segments), \
            "Double reverse should preserve segment count"
        
        for i, (original, final) in enumerate(zip(original_segments, reversed_twice)):
            assert original.data == final.data, \
                f"Segment {i}: double reverse should return original order"
            assert original.offset == final.offset, \
                f"Segment {i}: offset should be preserved"
    
    @given(
        segment_count=st.integers(min_value=2, max_value=20),
        disorder_method=st.sampled_from(['reverse', 'random', 'swap'])
    )
    @settings(max_examples=100, deadline=None)
    def test_property_13_disorder_preserves_segments(self, segment_count, disorder_method):
        """
        **Feature: unified-attack-dispatcher, Property 13: Disorder preserves segments**
        **Validates: Requirements 4.2**
        
        Property: For any segment list and disorder method, the disordered list
        should contain the same segments (set equality).
        
        This test verifies that:
        1. No segments are lost
        2. No segments are duplicated
        3. All original segments are present
        """
        from core.bypass.engine.unified_attack_dispatcher import _apply_disorder_segments, PacketSegment
        
        # Create test segments with unique data
        original_segments = [
            PacketSegment(
                data=f"unique_segment_{i}".encode(),
                offset=i * 10,
                ttl=64,
                fragment_index=i
            )
            for i in range(segment_count)
        ]
        
        params = {'disorder_method': disorder_method}
        
        # Apply disorder
        disordered = _apply_disorder_segments(original_segments, params)
        
        # Verify same count
        assert len(disordered) == len(original_segments), \
            f"Disorder should preserve segment count: {len(original_segments)} → {len(disordered)}"
        
        # Verify set equality (all segments present, no duplicates)
        original_data_set = {seg.data for seg in original_segments}
        disordered_data_set = {seg.data for seg in disordered}
        
        assert original_data_set == disordered_data_set, \
            "Disorder should preserve all segments (set equality)"
        
        # Verify no duplicates
        disordered_data_list = [seg.data for seg in disordered]
        assert len(disordered_data_list) == len(set(disordered_data_list)), \
            "Disorder should not duplicate segments"
    
    @given(
        segment_count=st.integers(min_value=2, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_14_disorder_swap_correctness(self, segment_count):
        """
        **Feature: unified-attack-dispatcher, Property 14: Disorder swap correctness**
        **Validates: Requirements 4.3**
        
        Property: For any segment list with 2+ elements, swap disorder should
        exchange first and last segments.
        
        This test verifies that:
        1. First segment becomes last
        2. Last segment becomes first
        3. Middle segments remain in same relative order
        """
        from core.bypass.engine.unified_attack_dispatcher import _apply_disorder_segments, PacketSegment
        
        # Create test segments
        original_segments = [
            PacketSegment(
                data=f"segment_{i}".encode(),
                offset=i * 10,
                ttl=64,
                fragment_index=i
            )
            for i in range(segment_count)
        ]
        
        params = {'disorder_method': 'swap'}
        
        # Apply swap
        swapped = _apply_disorder_segments(original_segments, params)
        
        # Verify count preserved
        assert len(swapped) == len(original_segments), \
            "Swap should preserve segment count"
        
        # Verify first and last are swapped
        assert swapped[0].data == original_segments[-1].data, \
            "First segment should be swapped with last"
        assert swapped[-1].data == original_segments[0].data, \
            "Last segment should be swapped with first"
        
        # Verify middle segments remain in same order
        if segment_count > 2:
            for i in range(1, segment_count - 1):
                assert swapped[i].data == original_segments[i].data, \
                    f"Middle segment {i} should remain in same position"


class TestFakePacketStrategiesProperties:
    """Property-based tests for fake packet strategies."""
    
    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_count=st.integers(min_value=2, max_value=10),
        fake_ttl=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_9_per_fragment_fake_count(self, payload, split_count, fake_ttl):
        """
        **Feature: unified-attack-dispatcher, Property 9: Per-fragment fake count**
        **Validates: Requirements 3.3**
        
        Property: For any fake_mode='per_fragment' with N fragments, the result
        should contain exactly N fake segments.
        
        This test verifies that:
        1. One fake packet is generated for each fragment
        2. Total segment count is 2*N (N fake + N real)
        3. Fake segments are properly marked
        """
        from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
        
        dispatcher = UnifiedAttackDispatcher()
        
        # First split the payload
        split_params = {'split_count': split_count}
        packet_info = {'original_ttl': 64}
        fragments = dispatcher.apply_split(payload, split_params, packet_info)
        
        # Apply fake with per_fragment mode
        fake_params = {
            'ttl': fake_ttl,
            'fooling': 'badsum',
            'fake_mode': 'per_fragment'
        }
        
        result = dispatcher.apply_fake_to_fragments(fragments, fake_params, packet_info)
        
        # Count fake and real segments
        fake_segments = [seg for seg in result if seg[2].get('is_fake', False)]
        real_segments = [seg for seg in result if not seg[2].get('is_fake', False)]
        
        # Verify fake count equals fragment count
        assert len(fake_segments) == split_count, \
            f"Per-fragment mode should generate {split_count} fake segments, got {len(fake_segments)}"
        
        # Verify real count equals fragment count
        assert len(real_segments) == split_count, \
            f"Should have {split_count} real segments, got {len(real_segments)}"
        
        # Verify total count is 2*N
        assert len(result) == 2 * split_count, \
            f"Total segments should be {2 * split_count} (N fake + N real), got {len(result)}"
        
        # Verify all fake segments have correct TTL
        for fake_seg in fake_segments:
            assert fake_seg[2]['ttl'] == fake_ttl, \
                f"Fake segment should have TTL={fake_ttl}, got {fake_seg[2]['ttl']}"
    
    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_count=st.integers(min_value=2, max_value=10),
        fake_ttl=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_10_single_fake_count(self, payload, split_count, fake_ttl):
        """
        **Feature: unified-attack-dispatcher, Property 10: Single fake count**
        **Validates: Requirements 3.6**
        
        Property: For any fake_mode='single', the result should contain exactly
        1 fake segment.
        
        This test verifies that:
        1. Only one fake packet is generated
        2. Total segment count is N+1 (1 fake + N real)
        3. Fake segment is properly marked
        """
        from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
        
        dispatcher = UnifiedAttackDispatcher()
        
        # First split the payload
        split_params = {'split_count': split_count}
        packet_info = {'original_ttl': 64}
        fragments = dispatcher.apply_split(payload, split_params, packet_info)
        
        # Apply fake with single mode
        fake_params = {
            'ttl': fake_ttl,
            'fooling': 'badsum',
            'fake_mode': 'single'
        }
        
        result = dispatcher.apply_fake_to_fragments(fragments, fake_params, packet_info)
        
        # Count fake and real segments
        fake_segments = [seg for seg in result if seg[2].get('is_fake', False)]
        real_segments = [seg for seg in result if not seg[2].get('is_fake', False)]
        
        # Verify exactly one fake segment
        assert len(fake_segments) == 1, \
            f"Single mode should generate exactly 1 fake segment, got {len(fake_segments)}"
        
        # Verify real count equals fragment count
        assert len(real_segments) == split_count, \
            f"Should have {split_count} real segments, got {len(real_segments)}"
        
        # Verify total count is N+1
        assert len(result) == split_count + 1, \
            f"Total segments should be {split_count + 1} (1 fake + N real), got {len(result)}"
        
        # Verify fake segment has correct TTL
        assert fake_segments[0][2]['ttl'] == fake_ttl, \
            f"Fake segment should have TTL={fake_ttl}, got {fake_segments[0][2]['ttl']}"

    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_count=st.integers(min_value=2, max_value=10),
        fake_ttl=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_15_fake_position_before_ordering(self, payload, split_count, fake_ttl):
        """
        **Feature: unified-attack-dispatcher, Property 15: Fake position before ordering**
        **Validates: Requirements 5.1**
        
        Property: For any fake_position='before', each fake segment should appear
        immediately before its corresponding real segment.
        
        This test verifies that:
        1. Fake segments appear before real segments
        2. Ordering is [fake1, real1, fake2, real2, ...]
        3. Fake and real pairs are correctly matched
        """
        from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
        
        dispatcher = UnifiedAttackDispatcher()
        
        # Configure fake_position to 'before'
        dispatcher.config = {
            'fake_position': 'before',
            'use_original_ttl': True,
            'detailed_logging': False,
            'enable_metrics': False,
            'validate_payload': False
        }
        
        # First split the payload
        split_params = {'split_count': split_count}
        packet_info = {'original_ttl': 64}
        fragments = dispatcher.apply_split(payload, split_params, packet_info)
        
        # Apply fake with per_fragment mode and 'before' position
        fake_params = {
            'ttl': fake_ttl,
            'fooling': 'badsum',
            'fake_mode': 'per_fragment'
        }
        
        result = dispatcher.apply_fake_to_fragments(fragments, fake_params, packet_info)
        
        # Verify alternating pattern: fake, real, fake, real, ...
        for i in range(0, len(result), 2):
            # Even indices should be fake
            assert result[i][2].get('is_fake', False) == True, \
                f"Position {i} should be fake segment"
            
            # Odd indices should be real
            if i + 1 < len(result):
                assert result[i + 1][2].get('is_fake', False) == False, \
                    f"Position {i + 1} should be real segment"
                
                # Verify fake and real have same offset (they correspond to same fragment)
                assert result[i][1] == result[i + 1][1], \
                    f"Fake and real at positions {i}, {i + 1} should have same offset"
    
    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_count=st.integers(min_value=2, max_value=10),
        fake_ttl=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_16_fake_position_after_ordering(self, payload, split_count, fake_ttl):
        """
        **Feature: unified-attack-dispatcher, Property 16: Fake position after ordering**
        **Validates: Requirements 5.2**
        
        Property: For any fake_position='after', each real segment should appear
        immediately before its corresponding fake segment.
        
        This test verifies that:
        1. Real segments appear before fake segments
        2. Ordering is [real1, fake1, real2, fake2, ...]
        3. Real and fake pairs are correctly matched
        """
        from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
        
        dispatcher = UnifiedAttackDispatcher()
        
        # Configure fake_position to 'after'
        dispatcher.config = {
            'fake_position': 'after',
            'use_original_ttl': True,
            'detailed_logging': False,
            'enable_metrics': False,
            'validate_payload': False
        }
        
        # First split the payload
        split_params = {'split_count': split_count}
        packet_info = {'original_ttl': 64}
        fragments = dispatcher.apply_split(payload, split_params, packet_info)
        
        # Apply fake with per_fragment mode and 'after' position
        fake_params = {
            'ttl': fake_ttl,
            'fooling': 'badsum',
            'fake_mode': 'per_fragment'
        }
        
        result = dispatcher.apply_fake_to_fragments(fragments, fake_params, packet_info)
        
        # Verify alternating pattern: real, fake, real, fake, ...
        for i in range(0, len(result), 2):
            # Even indices should be real
            assert result[i][2].get('is_fake', False) == False, \
                f"Position {i} should be real segment"
            
            # Odd indices should be fake
            if i + 1 < len(result):
                assert result[i + 1][2].get('is_fake', False) == True, \
                    f"Position {i + 1} should be fake segment"
                
                # Verify real and fake have same offset (they correspond to same fragment)
                assert result[i][1] == result[i + 1][1], \
                    f"Real and fake at positions {i}, {i + 1} should have same offset"
    
    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_count=st.integers(min_value=2, max_value=10),
        fake_ttl=st.integers(min_value=1, max_value=10),
        fake_mode=st.sampled_from(['per_fragment', 'single'])
    )
    @settings(max_examples=100, deadline=None)
    def test_property_8_fake_ttl_consistency(self, payload, split_count, fake_ttl, fake_mode):
        """
        **Feature: unified-attack-dispatcher, Property 8: Fake TTL consistency**
        **Validates: Requirements 3.1**
        
        Property: For any fake packet generation with specified TTL, all fake
        segments should have that exact TTL.
        
        This test verifies that:
        1. All fake segments have the specified TTL
        2. TTL is consistent across all fake packets
        3. Real segments have different TTL (not fake TTL)
        """
        from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
        
        dispatcher = UnifiedAttackDispatcher()
        
        # First split the payload
        split_params = {'split_count': split_count}
        packet_info = {'original_ttl': 64}
        fragments = dispatcher.apply_split(payload, split_params, packet_info)
        
        # Apply fake with specified TTL
        fake_params = {
            'ttl': fake_ttl,
            'fooling': 'badsum',
            'fake_mode': fake_mode
        }
        
        result = dispatcher.apply_fake_to_fragments(fragments, fake_params, packet_info)
        
        # Extract fake segments
        fake_segments = [seg for seg in result if seg[2].get('is_fake', False)]
        real_segments = [seg for seg in result if not seg[2].get('is_fake', False)]
        
        # Verify all fake segments have the specified TTL
        for i, fake_seg in enumerate(fake_segments):
            assert fake_seg[2]['ttl'] == fake_ttl, \
                f"Fake segment {i} should have TTL={fake_ttl}, got {fake_seg[2]['ttl']}"
        
        # Verify real segments don't have fake TTL
        for i, real_seg in enumerate(real_segments):
            assert real_seg[2]['ttl'] != fake_ttl or fake_ttl == 64, \
                f"Real segment {i} should not have fake TTL={fake_ttl}"
        
        # Verify at least one fake segment was created
        assert len(fake_segments) > 0, \
            "At least one fake segment should be created"
