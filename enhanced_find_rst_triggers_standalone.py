#!/usr/bin/env python3
"""
Standalone Enhanced Find RST Triggers
Версия без сложных зависимостей для работы в subprocess
"""

import argparse
import sys
import os
import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

# Setup logging
LOG = logging.getLogger("enhanced_find_rst_triggers_standalone")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

class StandaloneEnhancedAnalyzer:
    """Standalone версия enhanced analyzer"""
    
    def __init__(self, pcap_file: str, recon_summary_file: str = "recon_summary.json"):
        self.pcap_file = pcap_file
        self.recon_summary_file = recon_summary_file
        self.recon_data = None
        
    def load_recon_summary(self) -> bool:
        """Загружает recon_summary.json"""
        try:
            if not os.path.exists(self.recon_summary_file):
                LOG.warning(f"Recon summary not found: {self.recon_summary_file}")
                return False
            
            with open(self.recon_summary_file, 'r', encoding='utf-8') as f:
                self.recon_data = json.load(f)
            
            LOG.info("Recon summary loaded successfully")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to load recon summary: {e}")
            return False
    
    def extract_historical_strategies(self) -> List[Dict[str, Any]]:
        """Извлекает исторические стратегии"""
        strategies = []
        
        if not self.recon_data:
            return strategies
        
        # Извлекаем лучшую стратегию
        best_strategy = self.recon_data.get("best_strategy", {})
        if best_strategy:
            strategies.append({
                "name": "historical_best",
                "description": best_strategy.get("strategy", ""),
                "success_rate": best_strategy.get("success_rate", 0.0),
                "confidence": best_strategy.get("dpi_confidence", 0.0),
                "dpi_type": best_strategy.get("dpi_type", "unknown"),
                "successful_sites": best_strategy.get("successful_sites", 0),
                "total_sites": best_strategy.get("total_sites", 0)
            })
        
        return strategies
    
    def generate_enhanced_strategies(self, count: int = 5) -> List[Dict[str, Any]]:
        """Генерирует улучшенные стратегии на основе исторических данных"""
        
        historical_strategies = self.extract_historical_strategies()
        enhanced_strategies = []
        
        # Базовые стратегии на основе исторических данных
        for hist_strat in historical_strategies:
            if hist_strat["success_rate"] > 0.3:  # Только относительно успешные
                enhanced_strategies.append({
                    "strategy_name": f"enhanced_{hist_strat['name']}",
                    "zapret_command": self._convert_to_zapret_command(hist_strat["description"]),
                    "confidence_score": hist_strat["success_rate"],
                    "reasoning": [f"Based on historical success rate: {hist_strat['success_rate']:.2%}"],
                    "source": "historical_data",
                    "expected_success_rate": hist_strat["success_rate"] * 0.9
                })
        
        # Добавляем вариации успешных стратегий
        if enhanced_strategies:
            base_strategy = enhanced_strategies[0]
            
            # Вариация с другим TTL
            ttl_variation = base_strategy.copy()
            ttl_variation["strategy_name"] = "enhanced_ttl_variation"
            ttl_variation["zapret_command"] = base_strategy["zapret_command"].replace("ttl=3", "ttl=1")
            ttl_variation["reasoning"] = ["TTL variation of successful strategy"]
            ttl_variation["confidence_score"] = base_strategy["confidence_score"] * 0.8
            enhanced_strategies.append(ttl_variation)
            
            # Вариация с другим fooling
            fooling_variation = base_strategy.copy()
            fooling_variation["strategy_name"] = "enhanced_fooling_variation"
            fooling_variation["zapret_command"] = base_strategy["zapret_command"].replace("badseq", "md5sig")
            fooling_variation["reasoning"] = ["Fooling method variation of successful strategy"]
            fooling_variation["confidence_score"] = base_strategy["confidence_score"] * 0.7
            enhanced_strategies.append(fooling_variation)
        
        # Добавляем fallback стратегии если мало данных
        if len(enhanced_strategies) < count:
            fallback_strategies = [
                {
                    "strategy_name": "fallback_fakeddisorder",
                    "zapret_command": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=5",
                    "confidence_score": 0.6,
                    "reasoning": ["Proven fallback strategy"],
                    "source": "expert_knowledge",
                    "expected_success_rate": 0.5
                },
                {
                    "strategy_name": "fallback_multisplit",
                    "zapret_command": "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-fooling=badsum",
                    "confidence_score": 0.55,
                    "reasoning": ["Fragmentation-based fallback"],
                    "source": "expert_knowledge", 
                    "expected_success_rate": 0.45
                }
            ]
            enhanced_strategies.extend(fallback_strategies)
        
        return enhanced_strategies[:count]
    
    def _convert_to_zapret_command(self, strategy_description: str) -> str:
        """Конвертирует описание стратегии в zapret команду"""
        
        # Простой парсер для распространенных форматов
        if "multidisorder" in strategy_description:
            command = "--dpi-desync=multidisorder"
            
            # Извлекаем параметры
            if "split_pos=1" in strategy_description:
                command += " --dpi-desync-split-pos=1"
            elif "split_pos=" in strategy_description:
                import re
                match = re.search(r"split_pos=(\d+)", strategy_description)
                if match:
                    command += f" --dpi-desync-split-pos={match.group(1)}"
            
            if "ttl=" in strategy_description:
                import re
                match = re.search(r"ttl=(\d+)", strategy_description)
                if match:
                    command += f" --dpi-desync-ttl={match.group(1)}"
            
            if "fooling=" in strategy_description or "badsum" in strategy_description:
                if "badsum" in strategy_description and "badseq" in strategy_description:
                    command += " --dpi-desync-fooling=badsum,badseq"
                elif "badsum" in strategy_description:
                    command += " --dpi-desync-fooling=badsum"
                elif "badseq" in strategy_description:
                    command += " --dpi-desync-fooling=badseq"
            
            return command
        
        # Fallback
        return "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=5"
    
    async def run_analysis(self, max_strategies: int = 5) -> Dict[str, Any]:
        """Запускает полный анализ"""
        
        LOG.info("Starting standalone enhanced analysis...")
        
        # Загружаем данные
        summary_loaded = self.load_recon_summary()
        
        # Генерируем стратегии
        strategies = self.generate_enhanced_strategies(max_strategies)
        
        # Компилируем результаты
        results = {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "pcap_file": self.pcap_file,
                "recon_summary_file": self.recon_summary_file,
                "summary_loaded": summary_loaded
            },
            "enhanced_analysis": {
                "second_pass_summary": {
                    "strategies_generated": len(strategies),
                    "strategies_tested": 0,
                    "successful_strategies": 0,
                    "success_rate": 0.0
                },
                "generated_strategies": strategies
            },
            "recommendations": [
                {
                    "type": "best_strategy",
                    "title": "Recommended Strategy",
                    "description": f"Use strategy based on historical data",
                    "confidence": "MEDIUM"
                }
            ]
        }
        
        LOG.info(f"Standalone analysis complete: {len(strategies)} strategies generated")
        
        return results


async def main():
    """Main function"""
    
    parser = argparse.ArgumentParser(description="Standalone Enhanced RST Trigger Analysis")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--recon-summary", default="recon_summary.json", help="Path to recon_summary.json")
    parser.add_argument("--max-strategies", type=int, default=5, help="Max strategies to generate")
    parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    # Validate files
    if not os.path.exists(args.pcap_file):
        LOG.error(f"PCAP file not found: {args.pcap_file}")
        return 1
    
    # Create analyzer
    analyzer = StandaloneEnhancedAnalyzer(args.pcap_file, args.recon_summary)
    
    try:
        # Run analysis
        results = await analyzer.run_analysis(args.max_strategies)
        
        # Print summary
        enhanced = results["enhanced_analysis"]["second_pass_summary"]
        print(f"\nStandalone Enhanced Analysis Results:")
        print(f"  Strategies Generated: {enhanced['strategies_generated']}")
        print(f"  Based on: {args.recon_summary}")
        
        # Save results
        output_file = args.output or f"standalone_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        LOG.info(f"Results saved to {output_file}")
        return 0
        
    except Exception as e:
        LOG.error(f"Analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))