import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.strategy_interpreter_fixed import parse_zapret_strategy, convert_to_legacy

def test_strategy():
    strategy_str = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
    print(f"Testing strategy: {strategy_str}")
    
    try:
        parsed = parse_zapret_strategy(strategy_str)
        print(f"Parsed strategy: {parsed}")
        print(f"Methods: {[m.value for m in parsed.methods]}")
        print(f"Split pos: {parsed.split_pos}")
        print(f"Split seqovl: {parsed.split_seqovl}")
        print(f"TTL: {parsed.ttl}")
        print(f"Fooling: {[f.value for f in parsed.fooling]}")
        
        legacy = convert_to_legacy(parsed)
        print(f"Legacy format: {legacy}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_strategy()