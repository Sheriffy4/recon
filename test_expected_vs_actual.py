#!/usr/bin/env python3
"""
Test to show expected vs actual output for genes_to_zapret_strategy()
"""

from cli import SimpleEvolutionarySearcher

def test_expected_vs_actual():
    """Compare expected vs actual output."""
    
    searcher = SimpleEvolutionarySearcher(1, 1)
    
    # Test cases with expected outputs
    test_cases = [
        {
            'genes': {'type': 'seqovl', 'split_pos': 5, 'overlap_size': 20, 'ttl': 3},
            'expected': '--dpi-desync=fake,disorder --dpi-desync-split-pos=5 --dpi-desync-split-seqovl=20 --dpi-desync-ttl=3',
            'description': 'seqovl should include split-seqovl parameter'
        },
        {
            'genes': {'type': 'multisplit', 'positions': [1, 5, 10], 'ttl': 4},
            'expected': '--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=0 --dpi-desync-ttl=4',
            'description': 'multisplit should use positions length as split-count'
        },
        {
            'genes': {'type': 'disorder', 'split_pos': 3},
            'expected': '--dpi-desync=disorder --dpi-desync-split-pos=3',
            'description': 'disorder should use disorder, not fake'
        },
        {
            'genes': {'type': 'split', 'split_pos': 5},
            'expected': '--dpi-desync=split --dpi-desync-split-pos=5',
            'description': 'split should use split, not fake'
        }
    ]
    
    print("Expected vs Actual Output Analysis:")
    print("=" * 80)
    
    for i, case in enumerate(test_cases, 1):
        genes = case['genes']
        expected = case['expected']
        description = case['description']
        
        try:
            actual = searcher.genes_to_zapret_strategy(genes)
            
            print(f"\nTest {i}: {description}")
            print(f"Genes:    {genes}")
            print(f"Expected: {expected}")
            print(f"Actual:   {actual}")
            
            if actual == expected:
                print("✅ PASS")
            else:
                print("❌ FAIL")
                
        except Exception as e:
            print(f"\nTest {i}: {description}")
            print(f"Genes:    {genes}")
            print(f"Expected: {expected}")
            print(f"Actual:   ERROR: {e}")
            print("❌ ERROR")

if __name__ == "__main__":
    test_expected_vs_actual()