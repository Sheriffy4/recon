#!/usr/bin/env python3
"""
Test script to identify issues with genes_to_zapret_strategy()
"""

from cli import SimpleEvolutionarySearcher

def test_genes_to_zapret_strategy():
    """Test the genes_to_zapret_strategy function with various attack types."""
    
    searcher = SimpleEvolutionarySearcher(1, 1)
    
    # Test different attack types
    test_genes = [
        {'type': 'fakeddisorder', 'split_pos': 3, 'ttl': 4},
        {'type': 'seqovl', 'split_pos': 5, 'overlap_size': 20, 'ttl': 3},
        {'type': 'multidisorder', 'split_pos': 3, 'ttl': 4},
        {'type': 'multisplit', 'positions': [1, 5, 10], 'ttl': 4},
        {'type': 'disorder', 'split_pos': 3},
        {'type': 'split', 'split_pos': 5},
        {'type': 'fake_disorder', 'split_pos': 3, 'ttl': 4},
        {'type': 'tcp_multisplit', 'split_count': 3, 'split_seqovl': 20, 'ttl': 4},
        {'type': 'tcp_multidisorder', 'split_pos': 3, 'ttl': 4},
        {'type': 'badsum_race', 'ttl': 4, 'split_pos': 3},
        {'type': 'md5sig_race', 'ttl': 6, 'split_pos': 3},
        {'type': 'ip_fragmentation', 'fragment_size': 8, 'ttl': 4},
        {'type': 'force_tcp', 'split_pos': 3, 'ttl': 4}
    ]
    
    print("Testing genes_to_zapret_strategy():")
    print("=" * 80)
    
    for genes in test_genes:
        try:
            strategy = searcher.genes_to_zapret_strategy(genes)
            print(f"{genes['type']:20} -> {strategy}")
        except Exception as e:
            print(f"{genes['type']:20} -> ERROR: {e}")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    test_genes_to_zapret_strategy()