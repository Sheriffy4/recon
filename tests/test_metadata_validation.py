#!/usr/bin/env python3
"""
Test script to validate metadata completeness enforcement in BaseAttack.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.metadata import AttackCategories


def test_metadata_validation():
    """Test that BaseAttack enforces metadata completeness."""
    
    print("Testing metadata validation...")
    
    # Test 1: Valid attack class should work
    try:
        class ValidAttack(BaseAttack):
            @property
            def name(self) -> str:
                return "test_attack"
            
            @property
            def category(self) -> str:
                return AttackCategories.TCP
            
            @property
            def required_params(self) -> list:
                return ["target"]
            
            @property
            def optional_params(self) -> dict:
                return {"ttl": 3}
            
            def execute(self, context: AttackContext) -> AttackResult:
                return AttackResult(status=AttackStatus.SUCCESS)
        
        print("✅ Valid attack class created successfully")
        
        # Test instantiation
        attack = ValidAttack()
        print(f"✅ Valid attack instantiated: {attack.name}")
        
    except Exception as e:
        print(f"❌ Valid attack class failed: {e}")
        return False
    
    # Test 2: Missing name property should fail
    try:
        class MissingNameAttack(BaseAttack):
            @property
            def category(self) -> str:
                return AttackCategories.TCP
            
            @property
            def required_params(self) -> list:
                return []
            
            @property
            def optional_params(self) -> dict:
                return {}
            
            def execute(self, context: AttackContext) -> AttackResult:
                return AttackResult(status=AttackStatus.SUCCESS)
        
        print("❌ Missing name attack should have failed but didn't")
        return False
        
    except TypeError as e:
        if "name" in str(e):
            print("✅ Missing name property correctly rejected")
        else:
            print(f"❌ Wrong error for missing name: {e}")
            return False
    except Exception as e:
        print(f"❌ Unexpected error for missing name: {e}")
        return False
    
    # Test 3: Invalid category should fail
    try:
        class InvalidCategoryAttack(BaseAttack):
            @property
            def name(self) -> str:
                return "invalid_category_attack"
            
            @property
            def category(self) -> str:
                return "invalid_category"
            
            @property
            def required_params(self) -> list:
                return []
            
            @property
            def optional_params(self) -> dict:
                return {}
            
            def execute(self, context: AttackContext) -> AttackResult:
                return AttackResult(status=AttackStatus.SUCCESS)
        
        print("❌ Invalid category attack should have failed but didn't")
        return False
        
    except (ValueError, TypeError) as e:
        if "category" in str(e):
            print("✅ Invalid category correctly rejected")
        else:
            print(f"❌ Wrong error for invalid category: {e}")
            return False
    except Exception as e:
        print(f"❌ Unexpected error for invalid category: {e}")
        return False
    
    # Test 4: Wrong type for required_params should fail
    try:
        class WrongTypeAttack(BaseAttack):
            @property
            def name(self) -> str:
                return "wrong_type_attack"
            
            @property
            def category(self) -> str:
                return AttackCategories.TCP
            
            @property
            def required_params(self) -> str:  # Wrong type - should be list
                return "not_a_list"
            
            @property
            def optional_params(self) -> dict:
                return {}
            
            def execute(self, context: AttackContext) -> AttackResult:
                return AttackResult(status=AttackStatus.SUCCESS)
        
        print("❌ Wrong type attack should have failed but didn't")
        return False
        
    except TypeError as e:
        if "required_params" in str(e) and "list" in str(e):
            print("✅ Wrong type for required_params correctly rejected")
        else:
            print(f"❌ Wrong error for wrong type: {e}")
            return False
    except Exception as e:
        print(f"❌ Unexpected error for wrong type: {e}")
        return False
    
    print("✅ All metadata validation tests passed!")
    return True


if __name__ == "__main__":
    success = test_metadata_validation()
    sys.exit(0 if success else 1)