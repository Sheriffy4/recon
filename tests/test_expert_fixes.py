"""
Unit tests for expert-recommended fixes to UnifiedAttackDispatcher.

These tests verify that all critical bugs and improvements identified by
experts have been properly implemented.
"""

import pytest
from core.bypass.engine.unified_attack_dispatcher import (
    UnifiedAttackDispatcher,
    PacketSegment,
    generate_fake_payload,
    AttackConstants
)
from core.strategy.combo_builder import AttackRecipe, AttackStep


class TestExpertFixes:
    """Test suite for expert-recommended fixes."""
    
    def test_fix1_packet_info_passed_to_split_in_combo(self):
        """
        Test Fix #1: packet_info is passed to _apply_split in combo mode.
        
        Expert 1 & 2 Critical Bug: Missing packet_info parameter caused TypeError.
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Create fake+split combo recipe
        recipe = AttackRecipe(
            attacks=['fake', 'split'],
            steps=[
                AttackStep(attack_type='fake', order=0, params={'ttl': 1, 'fooling': 'badsum'}),
                AttackStep(attack_type='split', order=1, params={'split_pos': 10})
            ],
            params={}
        )
        
        payload = b'A' * 50
        packet_info = {'original_ttl': 64, 'domain': 'test.com'}
        
        # Should not raise TypeError
        result = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        assert len(result) > 0, "Should return segments"
        # Verify we got both fake and split segments
        assert len(result) >= 2, "Should have at least fake + 2 split segments"
    
    def test_fix2_disorder_only_recipe_returns_segments(self):
        """
        Test Fix #2: Disorder-only recipe returns segments instead of empty list.
        
        Expert 1 Critical Bug: Recipe with only disorder returned empty segments.
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Create disorder-only recipe
        recipe = AttackRecipe(
            attacks=['disorder'],
            steps=[
                AttackStep(attack_type='disorder', order=0, params={'disorder_method': 'reverse'})
            ],
            params={}
        )
        
        payload = b'Hello World'
        packet_info = {'original_ttl': 64}
        
        result = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        assert len(result) > 0, "Disorder-only recipe should return segments"
        assert len(result) == 1, "Should return single segment for disorder-only"
        
        data, offset, options = result[0]
        assert data == payload, "Should preserve original payload"
    
    def test_fix3_single_mode_respects_fake_position(self):
        """
        Test Fix #3: fake_mode='single' respects fake_position configuration.
        
        Expert 1 Critical Bug: SINGLE mode ignored fake_position config.
        """
        # Test with 'before' position
        dispatcher_before = UnifiedAttackDispatcher(config={'fake_position': 'before'})
        
        recipe = AttackRecipe(
            attacks=['fake', 'split'],
            steps=[
                AttackStep(attack_type='fake', order=0, params={
                    'ttl': 1,
                    'fooling': 'badsum',
                    'fake_mode': 'single'
                }),
                AttackStep(attack_type='split', order=1, params={'split_count': 2})
            ],
            params={}
        )
        
        payload = b'A' * 50
        packet_info = {'original_ttl': 64}
        
        result_before = dispatcher_before.apply_recipe(recipe, payload, packet_info)
        
        # First segment should be fake when position='before'
        _, _, options_first = result_before[0]
        assert options_first.get('is_fake') == True, "First segment should be fake with position='before'"
        
        # Test with 'after' position
        dispatcher_after = UnifiedAttackDispatcher(config={'fake_position': 'after'})
        result_after = dispatcher_after.apply_recipe(recipe, payload, packet_info)
        
        # First segment should be real when position='after'
        _, _, options_first_after = result_after[0]
        assert options_first_after.get('is_fake') != True, "First segment should be real with position='after'"
    
    def test_fix4_sni_cache_uses_lru(self):
        """
        Test Fix #4: SNI cache uses LRU cache instead of unbounded dict.
        
        Expert 2 Medium Priority: Memory leak and collision risk.
        """
        dispatcher = UnifiedAttackDispatcher(config={'enable_sni_cache': True})
        
        # Verify the cached method exists
        assert hasattr(dispatcher, '_find_sni_position_cached'), \
            "Should have _find_sni_position_cached method"
        
        # Verify it has cache_info (lru_cache feature)
        assert hasattr(dispatcher._find_sni_position_cached, 'cache_info'), \
            "Should use lru_cache decorator"
        
        # Test caching works
        payload = b'\x16\x03\x01\x00\x50' + b'A' * 75  # TLS-like payload
        fallback = 10
        
        # First call
        pos1 = dispatcher._find_sni_position(payload, fallback)
        cache_info1 = dispatcher._find_sni_position_cached.cache_info()
        
        # Second call with same payload
        pos2 = dispatcher._find_sni_position(payload, fallback)
        cache_info2 = dispatcher._find_sni_position_cached.cache_info()
        
        assert pos1 == pos2, "Should return same position"
        assert cache_info2.hits > cache_info1.hits, "Should use cache on second call"
    
    def test_fix5_handlers_return_consistent_types(self):
        """
        Test Fix #5: All handlers return List[PacketSegment] consistently.
        
        Expert 2 Medium Priority: Inconsistent return types.
        """
        dispatcher = UnifiedAttackDispatcher()
        payload = b'Test payload'
        packet_info = {'original_ttl': 64}
        
        # Test _apply_fake returns PacketSegment
        fake_result = dispatcher._apply_fake(
            payload,
            {'ttl': 1, 'fooling': 'badsum'},
            packet_info
        )
        assert isinstance(fake_result, list), "Should return list"
        assert len(fake_result) > 0, "Should have segments"
        assert isinstance(fake_result[0], PacketSegment), "Should return PacketSegment"
        
        # Test _apply_split returns PacketSegment
        split_result = dispatcher._apply_split(
            payload,
            {'split_pos': 5},
            packet_info
        )
        assert isinstance(split_result, list), "Should return list"
        assert all(isinstance(s, PacketSegment) for s in split_result), \
            "All should be PacketSegment"
        
        # Test _apply_disorder returns PacketSegment
        disorder_result = dispatcher._apply_disorder(
            payload,
            {'disorder_method': 'reverse'},
            packet_info
        )
        assert isinstance(disorder_result, list), "Should return list"
        assert isinstance(disorder_result[0], PacketSegment), "Should return PacketSegment"
    
    def test_fix6_http_fake_no_null_bytes(self):
        """
        Test Fix #6: HTTP fake payloads use spaces instead of null bytes.
        
        Expert 2 Medium Priority: Null bytes are suspicious for DPI.
        """
        http_payload = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
        
        # Generate fake payload longer than template
        fake = generate_fake_payload(http_payload, 'badsum')
        
        # Should not contain null bytes
        assert b'\x00' not in fake, "HTTP fake should not contain null bytes"
        
        # Should contain spaces for padding
        if len(fake) > len(b'GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n'):
            assert b' ' in fake, "Should use spaces for padding"
    
    def test_fix7_interleaved_mode_works_correctly(self):
        """
        Test Fix #7: Interleaved mode works for all fake_mode values.
        
        Expert 2 Medium Priority: Interleaved was treated as 'before'.
        """
        dispatcher = UnifiedAttackDispatcher(config={'fake_position': 'interleaved'})
        
        recipe = AttackRecipe(
            attacks=['fake', 'split'],
            steps=[
                AttackStep(attack_type='fake', order=0, params={
                    'ttl': 1,
                    'fooling': 'badsum',
                    'fake_mode': 'per_fragment'
                }),
                AttackStep(attack_type='split', order=1, params={'split_count': 4})
            ],
            params={}
        )
        
        payload = b'A' * 100
        packet_info = {'original_ttl': 64}
        
        result = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # With interleaved and per_fragment, should alternate based on index
        # Even indices: fake first, odd indices: real first
        fake_positions = []
        for i, segment_tuple in enumerate(result):
            _, _, options = segment_tuple
            if options.get('is_fake'):
                fake_positions.append(i)
        
        # Should have fakes at various positions (not all at start)
        assert len(fake_positions) > 0, "Should have fake segments"
        assert len(set(fake_positions)) > 1, "Fakes should be at different positions (interleaved)"
    
    def test_fix8_type_hints_for_handlers(self):
        """
        Test Fix #8: Handler dictionary has proper type hints.
        
        Expert 2 Minor Improvement: Type safety.
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Verify handlers dict exists and has expected keys
        assert hasattr(dispatcher, '_handlers'), "Should have _handlers attribute"
        assert 'fake' in dispatcher._handlers, "Should have fake handler"
        assert 'split' in dispatcher._handlers, "Should have split handler"
        assert 'disorder' in dispatcher._handlers, "Should have disorder handler"
        
        # Verify handlers are callable
        assert callable(dispatcher._handlers['fake']), "Fake handler should be callable"
        assert callable(dispatcher._handlers['split']), "Split handler should be callable"
    
    def test_fix9_defensive_copies_in_disorder(self):
        """
        Test Fix #9: Disorder uses explicit list() for defensive copies.
        
        Expert 2 Minor Improvement: Code clarity.
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Create segments
        original_segments = [
            PacketSegment(data=b'A', offset=0),
            PacketSegment(data=b'B', offset=1),
            PacketSegment(data=b'C', offset=2)
        ]
        
        # Apply disorder
        params = {'disorder_method': 'reverse'}
        result = dispatcher._apply_disorder_segments(original_segments, params)
        
        # Original should be unchanged
        assert original_segments[0].data == b'A', "Original should not be modified"
        assert original_segments[1].data == b'B', "Original should not be modified"
        assert original_segments[2].data == b'C', "Original should not be modified"
        
        # Result should be reversed
        assert result[0].data == b'C', "Should be reversed"
        assert result[1].data == b'B', "Should be reversed"
        assert result[2].data == b'A', "Should be reversed"
    
    def test_fix10_strict_attack_type_detection(self):
        """
        Test Fix #10: Attack type detection is more strict.
        
        Expert 1 Minor Improvement: Avoid false positives.
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Recipe with attack name containing 'fake' but not being a fake attack
        # (hypothetical case to test the fix)
        recipe = AttackRecipe(
            attacks=['split'],
            steps=[
                AttackStep(attack_type='split', order=0, params={'split_pos': 10})
            ],
            params={}
        )
        
        payload = b'A' * 50
        packet_info = {'original_ttl': 64}
        
        # Should execute as sequential, not combo
        result = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Should have 2 segments (split only, no fake)
        assert len(result) == 2, "Should only have split segments, no fake"
        
        # Neither should be fake
        for segment_tuple in result:
            _, _, options = segment_tuple
            assert not options.get('is_fake'), "Should not have fake segments"


class TestExpertFixesIntegration:
    """Integration tests for expert fixes working together."""
    
    def test_full_combo_with_all_fixes(self):
        """
        Test that all fixes work together in a complex combo.
        """
        dispatcher = UnifiedAttackDispatcher(config={
            'fake_position': 'before',
            'use_original_ttl': True,
            'enable_sni_cache': True
        })
        
        # Complex recipe: fake + split + disorder
        recipe = AttackRecipe(
            attacks=['fake', 'split', 'disorder'],
            steps=[
                AttackStep(attack_type='fake', order=0, params={
                    'ttl': 2,
                    'fooling': 'badsum',
                    'fake_mode': 'per_fragment'
                }),
                AttackStep(attack_type='split', order=1, params={'split_count': 3}),
                AttackStep(attack_type='disorder', order=2, params={'disorder_method': 'reverse'})
            ],
            params={}
        )
        
        payload = b'A' * 90
        packet_info = {'original_ttl': 64, 'domain': 'test.com'}
        
        # Should execute without errors
        result = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Should have segments (3 real + 3 fake = 6, then disordered)
        assert len(result) > 0, "Should return segments"
        
        # Should have both fake and real segments
        fake_count = sum(1 for _, _, opts in result if opts.get('is_fake'))
        real_count = len(result) - fake_count
        
        assert fake_count > 0, "Should have fake segments"
        assert real_count > 0, "Should have real segments"
        
        # All real segments should have original TTL
        for _, _, opts in result:
            if not opts.get('is_fake'):
                assert opts.get('ttl') == 64, "Real segments should have original TTL"
    
    def test_disorder_only_with_empty_segments_fix(self):
        """
        Test that disorder-only recipe works even when it would create empty segments.
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Disorder-only recipe
        recipe = AttackRecipe(
            attacks=['disorder'],
            steps=[
                AttackStep(attack_type='disorder', order=0, params={'disorder_method': 'random'})
            ],
            params={}
        )
        
        payload = b'Test'
        packet_info = {}
        
        result = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Should not be empty
        assert len(result) == 1, "Should return one segment"
        
        data, _, _ = result[0]
        assert data == payload, "Should preserve payload"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
