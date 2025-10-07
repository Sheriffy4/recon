#!/usr/bin/env python3
"""
Прямой тест enhanced_find_rst_triggers без subprocess
"""

import asyncio
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_enhanced_find_rst_triggers_direct():
    """Тест enhanced_find_rst_triggers напрямую"""
    
    try:
        from enhanced_find_rst_triggers import EnhancedRSTTriggerFinder
        
        # Создаем анализатор
        finder = EnhancedRSTTriggerFinder(
            pcap_file="out2.pcap",
            recon_summary_file="recon_summary.json",
            sites_file="sites.txt"
        )
        
        # Запускаем анализ
        results = await finder.run_comprehensive_analysis(
            max_strategies=3,
            test_strategies=False,  # Отключаем тестирование для скорости
            compare_with_original=False
        )
        
        if results and "enhanced_analysis" in results:
            enhanced = results["enhanced_analysis"]
            if "second_pass_summary" in enhanced:
                summary = enhanced["second_pass_summary"]
                print(f"✅ Enhanced Find RST Triggers: анализ завершен")
                print(f"   Стратегий сгенерировано: {summary.get('strategies_generated', 0)}")
                print(f"   Стратегий протестировано: {summary.get('strategies_tested', 0)}")
                return True
        
        print("❌ Enhanced Find RST Triggers не дал результатов")
        return False
        
    except Exception as e:
        print(f"❌ Ошибка Enhanced Find RST Triggers: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_enhanced_find_rst_triggers_direct())
    print(f"Test result: {result}")
    sys.exit(0 if result else 1)