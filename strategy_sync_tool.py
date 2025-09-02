#!/usr/bin/env python3
"""
Strategy Synchronization Tool
Автоматически синхронизирует стратегии между CLI discovery режимом и service режимом
Решает проблему несоответствия между best_strategy.json и strategies.json
"""

import os
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import argparse


class StrategySync:
    def __init__(self):
        self.best_strategy_file = "best_strategy.json"
        self.strategies_file = "strategies.json"
        self.backup_dir = "backups"
        
    def backup_file(self, file_path: str) -> str:
        """Создать резервную копию файла"""
        if not os.path.exists(file_path):
            return None
            
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.basename(file_path)
        backup_path = os.path.join(self.backup_dir, f"{filename}.backup_{timestamp}")
        
        shutil.copy2(file_path, backup_path)
        print(f"💾 Backup created: {backup_path}")
        return backup_path
    
    def load_json(self, file_path: str) -> Optional[Dict]:
        """Загрузить JSON файл"""
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading {file_path}: {e}")
            return None
    
    def save_json(self, data: Dict, file_path: str) -> bool:
        """Сохранить JSON файл"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"❌ Error saving {file_path}: {e}")
            return False
    
    def sync_best_to_strategies(self, domain_specific: bool = True) -> bool:
        """
        Синхронизировать лучшую стратегию в strategies.json
        
        Args:
            domain_specific: если True, добавляет для конкретных доменов,
                           если False, добавляет как глобальную стратегию
        """
        print("🔄 Starting strategy synchronization...")
        
        # Загрузить best_strategy.json
        best_data = self.load_json(self.best_strategy_file)
        if not best_data:
            return False
        
        # Загрузить strategies.json
        strategies_data = self.load_json(self.strategies_file)
        if strategies_data is None:
            strategies_data = {}
        
        # Создать резервную копию strategies.json
        self.backup_file(self.strategies_file)
        
        # Получить лучшую стратегию
        if isinstance(best_data, list) and len(best_data) > 0:
            best_strategy_info = best_data[0]
        elif isinstance(best_data, dict):
            best_strategy_info = best_data
        else:
            print("❌ Invalid best_strategy.json format")
            return False
        
        # Извлечь стратегию
        strategy = best_strategy_info.get('strategy', '')
        zapret_format = best_strategy_info.get('zapret_format', '')
        successful_domains = best_strategy_info.get('successful_domains', [])
        
        if not strategy and not zapret_format:
            print("❌ No strategy found in best_strategy.json")
            return False
        
        # Использовать zapret_format если доступен, иначе конвертировать
        if zapret_format:
            strategy_cmd = zapret_format
        else:
            strategy_cmd = self._convert_to_zapret(strategy)
        
        print(f"📋 Found strategy: {strategy}")
        print(f"🔧 Zapret format: {strategy_cmd}")
        
        if domain_specific and successful_domains:
            # Вариант B: Добавить для конкретных доменов
            print(f"🎯 Adding domain-specific strategies for {len(successful_domains)} domains:")
            
            for domain in successful_domains:
                strategies_data[domain] = strategy_cmd
                print(f"  ✅ {domain}")
        else:
            # Вариант A: Добавить как глобальную стратегию
            print("🌐 Adding as global default strategy")
            strategies_data["_default"] = strategy_cmd
        
        # Сохранить обновленные стратегии
        if self.save_json(strategies_data, self.strategies_file):
            print(f"✅ Successfully updated {self.strategies_file}")
            return True
        else:
            print(f"❌ Failed to update {self.strategies_file}")
            return False
    
    def merge_strategy_updates(self, update_file: str) -> bool:
        """Объединить обновления стратегий с существующим файлом"""
        print(f"🔄 Merging strategies from {update_file}...")
        
        # Загрузить файл обновлений
        updates = self.load_json(update_file)
        if not updates:
            return False
        
        # Загрузить текущие стратегии
        strategies_data = self.load_json(self.strategies_file)
        if strategies_data is None:
            strategies_data = {}
        
        # Создать резервную копию
        self.backup_file(self.strategies_file)
        
        # Объединить стратегии
        added_count = 0
        updated_count = 0
        
        for domain, strategy in updates.items():
            if domain in strategies_data:
                if strategies_data[domain] != strategy:
                    print(f"🔄 Updating {domain}")
                    strategies_data[domain] = strategy
                    updated_count += 1
            else:
                print(f"➕ Adding {domain}")
                strategies_data[domain] = strategy
                added_count += 1
        
        # Сохранить результат
        if self.save_json(strategies_data, self.strategies_file):
            print(f"✅ Merge completed: {added_count} added, {updated_count} updated")
            return True
        else:
            print(f"❌ Failed to merge strategies")
            return False
    
    def _convert_to_zapret(self, strategy_str: str) -> str:
        """Конвертировать внутренний формат стратегии в zapret формат"""
        if '(' in strategy_str and ')' in strategy_str:
            strategy_name = strategy_str.split('(')[0]
            params_str = strategy_str.split('(')[1].rstrip(')')
            
            # Парсинг параметров
            params = {}
            if params_str:
                for param in params_str.split(', '):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        try:
                            if '.' in value:
                                params[key] = float(value)
                            else:
                                params[key] = int(value)
                        except ValueError:
                            params[key] = value.strip('\'"[]')
            
            # Конвертация в zapret формат
            if strategy_name == 'fakedisorder':
                base = "--dpi-desync=fake,disorder"
                if 'split_pos' in params:
                    base += f" --dpi-desync-split-pos={params['split_pos']}"
                if 'ttl' in params:
                    base += f" --dpi-desync-ttl={params['ttl']}"
                base += " --dpi-desync-fooling=badseq --dpi-desync-repeats=2"
                return base
            
            elif strategy_name == 'multidisorder':
                base = "--dpi-desync=multisplit"
                if 'positions' in params:
                    positions = str(params['positions']).strip('[]')
                    count = len(positions.split(',')) if positions else 3
                    base += f" --dpi-desync-split-count={count}"
                if 'ttl' in params:
                    base += f" --dpi-desync-ttl={params['ttl']}"
                base += " --dpi-desync-fooling=badsum --dpi-desync-repeats=2"
                return base
        
        # Fallback
        return "--dpi-desync=fake,disorder --dpi-desync-split-pos=1 --dpi-desync-ttl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2"
    
    def status(self) -> None:
        """Показать статус синхронизации стратегий"""
        print("📊 Strategy Synchronization Status")
        print("=" * 50)
        
        # Проверить файлы
        best_exists = os.path.exists(self.best_strategy_file)
        strategies_exists = os.path.exists(self.strategies_file)
        
        print(f"📁 best_strategy.json: {'✅ Found' if best_exists else '❌ Missing'}")
        print(f"📁 strategies.json: {'✅ Found' if strategies_exists else '❌ Missing'}")
        
        if best_exists:
            best_data = self.load_json(self.best_strategy_file)
            if best_data:
                print(f"📋 Best strategy available: {'✅ Yes' if best_data else '❌ No'}")
        
        if strategies_exists:
            strategies_data = self.load_json(self.strategies_file)
            if strategies_data:
                print(f"🎯 Strategies count: {len(strategies_data)}")
                print(f"📝 Strategy domains: {', '.join(list(strategies_data.keys())[:5])}{'...' if len(strategies_data) > 5 else ''}")
        
        # Проверить update файлы
        update_files = ['strategies_update.json', 'domain_strategy_recommendations.json']
        for update_file in update_files:
            if os.path.exists(update_file):
                print(f"🔄 Update file available: {update_file}")


def main():
    parser = argparse.ArgumentParser(description='Strategy Synchronization Tool')
    parser.add_argument('--action', choices=['sync', 'merge', 'status'], 
                       default='status', help='Action to perform')
    parser.add_argument('--domain-specific', action='store_true', 
                       help='Use domain-specific strategies (recommended)')
    parser.add_argument('--update-file', type=str, 
                       help='Strategy update file to merge')
    
    args = parser.parse_args()
    
    sync_tool = StrategySync()
    
    if args.action == 'status':
        sync_tool.status()
    
    elif args.action == 'sync':
        if sync_tool.sync_best_to_strategies(domain_specific=args.domain_specific):
            print("\n🎉 Synchronization completed successfully!")
        else:
            print("\n❌ Synchronization failed!")
    
    elif args.action == 'merge':
        if not args.update_file:
            print("❌ --update-file required for merge action")
            return
        
        if sync_tool.merge_strategy_updates(args.update_file):
            print("\n🎉 Merge completed successfully!")
        else:
            print("\n❌ Merge failed!")


if __name__ == "__main__":
    main()