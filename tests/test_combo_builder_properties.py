"""
Property-based tests for ComboAttackBuilder.

Feature: attack-application-parity
Tests correctness properties for recipe building and attack combination.
"""

import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.strategy.combo_builder import (
    ComboAttackBuilder,
    AttackRecipe,
    AttackStep,
    ValidationResult
)


# Hypothesis strategies for generating test data

@st.composite
def valid_attack_list(draw):
    """Generate valid attack lists (no incompatible combinations)."""
    # Define attack types
    base_attacks = ['fake', 'disorder']
    split_attacks = ['split', 'multisplit']
    combined_attacks = ['fakeddisorder', 'disorder_short_ttl_decoy']
    
    # Choose attack category
    category = draw(st.sampled_from(['base', 'base_with_split', 'combined']))
    
    if category == 'base':
        # Just base attacks
        num_attacks = draw(st.integers(min_value=1, max_value=2))
        attacks = draw(st.lists(
            st.sampled_from(base_attacks),
            min_size=num_attacks,
            max_size=num_attacks,
            unique=True
        ))
    elif category == 'base_with_split':
        # Base attacks + one split attack
        base = draw(st.lists(
            st.sampled_from(base_attacks),
            min_size=0,
            max_size=2,
            unique=True
        ))
        split = [draw(st.sampled_from(split_attacks))]
        attacks = base + split
    else:  # combined
        # Just one combined attack
        attacks = [draw(st.sampled_from(combined_attacks))]
    
    return attacks


@st.composite
def attack_params(draw, attacks):
    """Generate valid parameters for given attacks."""
    params = {}
    
    attack_set = set(attacks)
    
    # Fake attack params
    if any(a in attack_set for a in ['fake', 'fakeddisorder', 'disorder_short_ttl_decoy']):
        params['ttl'] = draw(st.integers(min_value=1, max_value=10))
        params['fooling'] = draw(st.sampled_from(['badsum', 'badseq', 'none']))
        params['fake_sni'] = draw(st.booleans())
    
    # Split attack params
    if 'split' in attack_set or 'multisplit' in attack_set:
        params['split_pos'] = draw(st.one_of(
            st.integers(min_value=1, max_value=20),
            st.just('sni')
        ))
        if 'multisplit' in attack_set:
            params['split_count'] = draw(st.integers(min_value=2, max_value=8))
    
    # Disorder attack params
    if any(a in attack_set for a in ['disorder', 'fakeddisorder']):
        params['disorder_method'] = draw(st.sampled_from(['reverse', 'random']))
    
    return params


@st.composite
def incompatible_attack_list(draw):
    """Generate incompatible attack combinations."""
    # The main incompatibility is split + multisplit
    return ['split', 'multisplit']


class TestRecipeBuildingCorrectness:
    """
    **Feature: attack-application-parity, Property 6: Recipe Building Correctness**
    **Validates: Requirements 2.1**
    
    Property: For any list of attacks, ComboAttackBuilder should create a recipe
    containing all attacks in the correct order.
    """
    
    @given(attacks=valid_attack_list())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_recipe_contains_all_attacks(self, attacks):
        """
        Test that recipe contains all attacks from the input list.
        
        For any valid attack list, the recipe should include all attacks.
        """
        builder = ComboAttackBuilder()
        params = {}
        
        # Build recipe
        recipe = builder.build_recipe(attacks, params)
        
        # Assert: recipe should contain all attacks
        assert recipe is not None, "Recipe should not be None"
        assert len(recipe.steps) == len(attacks), \
            f"Recipe should have {len(attacks)} steps, got {len(recipe.steps)}"
        
        # Check that all attacks are present
        recipe_attacks = {step.attack_type for step in recipe.steps}
        input_attacks = set(attacks)
        assert recipe_attacks == input_attacks, \
            f"Recipe attacks {recipe_attacks} should match input {input_attacks}"
    
    @given(attacks=valid_attack_list())
    @settings(max_examples=100)
    def test_recipe_correct_order(self, attacks):
        """
        Test that recipe steps are in correct order: fake → split → disorder.
        
        For any valid attack list, the recipe should order attacks correctly.
        """
        builder = ComboAttackBuilder()
        params = {}
        
        # Build recipe
        recipe = builder.build_recipe(attacks, params)
        
        # Define expected order
        order_map = {
            'fake': 1,
            'split': 2,
            'multisplit': 2,
            'disorder': 3,
            'fakeddisorder': 1,
            'disorder_short_ttl_decoy': 1
        }
        
        # Assert: steps should be ordered correctly
        for i in range(len(recipe.steps) - 1):
            current_order = order_map.get(recipe.steps[i].attack_type, 999)
            next_order = order_map.get(recipe.steps[i + 1].attack_type, 999)
            assert current_order <= next_order, \
                f"Step {i} ({recipe.steps[i].attack_type}) should come before " \
                f"step {i+1} ({recipe.steps[i+1].attack_type})"
    
    @given(
        attacks=valid_attack_list(),
        params_data=st.data()
    )
    @settings(max_examples=100)
    def test_recipe_preserves_parameters(self, attacks, params_data):
        """
        Test that recipe preserves all input parameters.
        
        For any valid attack list and parameters, the recipe should contain
        all input parameters.
        """
        builder = ComboAttackBuilder()
        params = params_data.draw(attack_params(attacks))
        
        # Build recipe
        recipe = builder.build_recipe(attacks, params)
        
        # Assert: all input params should be in merged params
        for key, value in params.items():
            assert key in recipe.params, \
                f"Parameter {key} should be in recipe params"
            assert recipe.params[key] == value, \
                f"Parameter {key} should have value {value}, got {recipe.params[key]}"
    
    @given(attacks=valid_attack_list())
    @settings(max_examples=100)
    def test_recipe_applies_defaults(self, attacks):
        """
        Test that recipe applies default parameters when not provided.
        
        For any valid attack list with empty params, the recipe should
        apply sensible defaults.
        """
        builder = ComboAttackBuilder()
        params = {}  # Empty params
        
        # Build recipe
        recipe = builder.build_recipe(attacks, params)
        
        # Assert: defaults should be applied based on attacks
        attack_set = set(attacks)
        
        if any(a in attack_set for a in ['fake', 'fakeddisorder', 'disorder_short_ttl_decoy']):
            assert 'ttl' in recipe.params, "Default TTL should be applied for fake attacks"
            assert 'fooling' in recipe.params, "Default fooling should be applied for fake attacks"
        
        if 'split' in attack_set or 'multisplit' in attack_set:
            assert 'split_pos' in recipe.params, "Default split_pos should be applied for split attacks"
            if 'multisplit' in attack_set:
                assert 'split_count' in recipe.params, \
                    "Default split_count should be applied for multisplit"
        
        if any(a in attack_set for a in ['disorder', 'fakeddisorder']):
            assert 'disorder_method' in recipe.params, \
                "Default disorder_method should be applied for disorder attacks"
    
    @given(attacks=valid_attack_list())
    @settings(max_examples=100)
    def test_recipe_steps_have_relevant_params(self, attacks):
        """
        Test that each step has only relevant parameters.
        
        For any valid attack list, each step should contain only parameters
        relevant to that specific attack type.
        """
        builder = ComboAttackBuilder()
        params = {
            'ttl': 5,
            'fooling': 'badsum',
            'split_pos': 3,
            'split_count': 4,
            'disorder_method': 'reverse'
        }
        
        # Build recipe
        recipe = builder.build_recipe(attacks, params)
        
        # Assert: each step should have only relevant params
        for step in recipe.steps:
            if step.attack_type == 'fake':
                # Fake should have ttl, fooling, but not split or disorder params
                assert 'ttl' in step.params or 'fooling' in step.params, \
                    "Fake step should have ttl or fooling"
                assert 'split_pos' not in step.params, \
                    "Fake step should not have split_pos"
                assert 'disorder_method' not in step.params, \
                    "Fake step should not have disorder_method"
            
            elif step.attack_type in ['split', 'multisplit']:
                # Split should have split_pos, but not fake or disorder params
                assert 'split_pos' in step.params, \
                    "Split step should have split_pos"
                # Note: ttl and fooling should not be in split params
                # (they're for fake attacks only)
            
            elif step.attack_type == 'disorder':
                # Disorder should have disorder_method, but not fake or split params
                assert 'disorder_method' in step.params, \
                    "Disorder step should have disorder_method"
                assert 'split_pos' not in step.params, \
                    "Disorder step should not have split_pos"
    
    @given(attacks=valid_attack_list())
    @settings(max_examples=100)
    def test_recipe_is_deterministic(self, attacks):
        """
        Test that building recipe twice with same inputs produces same result.
        
        For any valid attack list, building the recipe multiple times should
        produce identical results.
        """
        builder = ComboAttackBuilder()
        params = {'ttl': 5, 'split_pos': 3}
        
        # Build recipe twice
        recipe1 = builder.build_recipe(attacks, params)
        recipe2 = builder.build_recipe(attacks, params)
        
        # Assert: recipes should be identical
        assert len(recipe1.steps) == len(recipe2.steps), \
            "Both recipes should have same number of steps"
        
        for i, (step1, step2) in enumerate(zip(recipe1.steps, recipe2.steps)):
            assert step1.attack_type == step2.attack_type, \
                f"Step {i} attack type should match"
            assert step1.order == step2.order, \
                f"Step {i} order should match"
            assert step1.params == step2.params, \
                f"Step {i} params should match"


class TestIncompatibleCombinationDetection:
    """
    Tests for incompatible attack combination detection.
    
    **Validates: Requirements 2.6**
    """
    
    def test_split_and_multisplit_incompatible(self):
        """
        Test that split and multisplit cannot be combined.
        
        This is a specific incompatibility that should be detected.
        """
        builder = ComboAttackBuilder()
        attacks = ['split', 'multisplit']
        params = {}
        
        # Assert: should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            builder.build_recipe(attacks, params)
        
        assert "Incompatible" in str(exc_info.value), \
            "Error message should mention incompatibility"
        assert "split" in str(exc_info.value).lower(), \
            "Error message should mention split"
    
    def test_validate_compatibility_detects_incompatible(self):
        """
        Test that validate_compatibility detects incompatible combinations.
        """
        builder = ComboAttackBuilder()
        attacks = ['split', 'multisplit']
        
        # Validate
        result = builder.validate_compatibility(attacks)
        
        # Assert: should be invalid
        assert not result.valid, "Combination should be invalid"
        assert len(result.errors) > 0, "Should have at least one error"
        assert any('split' in err.lower() for err in result.errors), \
            "Error should mention split incompatibility"
    
    def test_validate_compatibility_accepts_valid(self):
        """
        Test that validate_compatibility accepts valid combinations.
        """
        builder = ComboAttackBuilder()
        valid_combos = [
            ['fake'],
            ['fake', 'split'],
            ['fake', 'disorder'],
            ['fake', 'split', 'disorder'],
            ['split', 'disorder'],
            ['multisplit', 'disorder'],
            ['fakeddisorder']
        ]
        
        for attacks in valid_combos:
            result = builder.validate_compatibility(attacks)
            assert result.valid, \
                f"Combination {attacks} should be valid, got errors: {result.errors}"
    
    def test_empty_attacks_list_invalid(self):
        """
        Test that empty attacks list is invalid.
        """
        builder = ComboAttackBuilder()
        attacks = []
        
        # Validate
        result = builder.validate_compatibility(attacks)
        
        # Assert: should be invalid
        assert not result.valid, "Empty attacks list should be invalid"
        assert len(result.errors) > 0, "Should have at least one error"
    
    def test_build_recipe_rejects_empty_list(self):
        """
        Test that build_recipe rejects empty attacks list.
        """
        builder = ComboAttackBuilder()
        attacks = []
        params = {}
        
        # Assert: should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            builder.build_recipe(attacks, params)
        
        assert "empty" in str(exc_info.value).lower(), \
            "Error message should mention empty list"
