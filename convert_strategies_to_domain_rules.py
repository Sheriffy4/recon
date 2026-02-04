#!/usr/bin/env python3
"""
Конвертация domain_strategies.json → domain_rules.json
Преобразует строковые стратегии zapret в структурированный формат
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, Optional


class StrategyConverter:
    """Конвертер стратегий из командной строки в структурированный формат"""
    
    def __init__(self):
        self.strategy_type_map = {
            'fake': 'fake',
            'disorder': 'disorder',
            'disorder2': 'disorder',
            'split': 'split',
            'multisplit': 'multisplit',
            'fakeddisorder': 'fakeddisorder',
            'fake_disorder': 'fake_disorder',
            'fake_multisplit': 'fake_multisplit',
            'fake_multisplit_disorder': 'fake_multisplit_disorder',
            'seqovl': 'seqovl'
        }
    
    def parse_strategy_string(self, strategy_str: str) -> Optional[Dict[str, Any]]:
        """Парсит строку стратегии zapret в структурированный формат"""
        if not strategy_str or not isinstance(strategy_str, str):
            return None
        
        # Определяем тип стратегии из --dpi-desync=
        desync_match = re.search(r'--dpi-desync=([^\s]+)', strategy_str)
        if not desync_match:
            return None
        
        # PARITY FIX: Normalize attacks - strip whitespace and lowercase
        desync_types = [t.strip().lower() for t in desync_match.group(1).split(',') if t.strip()]
        
        # Определяем основной тип стратегии
        strategy_type = self._determine_strategy_type(desync_types)
        
        # Парсим параметры
        params = {}
        
        # split_pos
        split_pos_match = re.search(r'--dpi-desync-split-pos=([^\s]+)', strategy_str)
        if split_pos_match:
            split_pos = split_pos_match.group(1)
            if split_pos == 'sni':
                params['split_pos'] = 'sni'
            elif split_pos == 'midsld':
                params['split_pos'] = 'midsld'
            elif ',' in split_pos:
                params['split_pos'] = [int(x) for x in split_pos.split(',')]
            else:
                try:
                    params['split_pos'] = int(split_pos)
                except ValueError:
                    params['split_pos'] = split_pos
        
        # ttl
        ttl_match = re.search(r'--dpi-desync-ttl=(\d+)', strategy_str)
        if ttl_match:
            params['ttl'] = int(ttl_match.group(1))
        
        # fake_ttl (для fake стратегий)
        if 'fake' in desync_types:
            params['fake_ttl'] = params.get('ttl', 4)
        
        # fooling
        fooling_match = re.search(r'--dpi-desync-fooling=([^\s]+)', strategy_str)
        if fooling_match:
            fooling = fooling_match.group(1)
            if ',' in fooling:
                params['fooling'] = fooling.split(',')
            else:
                params['fooling'] = fooling
        
        # split_count (для multisplit)
        split_count_match = re.search(r'--dpi-desync-split-count=(\d+)', strategy_str)
        if split_count_match:
            params['split_count'] = int(split_count_match.group(1))
        
        # overlap_size (seqovl)
        overlap_match = re.search(r'--dpi-desync-split-seqovl=(\d+)', strategy_str)
        if overlap_match:
            params['overlap_size'] = int(overlap_match.group(1))
        
        # window_div
        window_match = re.search(r'--dpi-desync-window-div=(\d+)', strategy_str)
        if window_match:
            params['window_div'] = int(window_match.group(1))
        
        # repeats
        repeats_match = re.search(r'--dpi-desync-repeats=(\d+)', strategy_str)
        if repeats_match:
            params['repeats'] = int(repeats_match.group(1))
        
        # Дополнительные параметры по умолчанию
        if strategy_type in ['multisplit', 'fake_multisplit']:
            params.setdefault('split_count', 5)
            params.setdefault('overlap_size', 20)
        
        params.setdefault('window_div', 8)
        params.setdefault('repeats', 1)
        
        # TCP flags (стандартные для всех)
        params['tcp_flags'] = {
            'psh': True,
            'ack': True
        }
        
        # ipid_step (стандартный)
        params['ipid_step'] = 2048
        
        return {
            'type': strategy_type,
            'params': params
        }
    
    def _determine_strategy_type(self, desync_types: list) -> str:
        """Определяет тип стратегии из списка desync типов"""
        # Комбинированные стратегии
        if 'fake' in desync_types and 'disorder' in desync_types:
            if 'multisplit' in desync_types:
                return 'fake_multisplit_disorder'
            return 'fakeddisorder'
        
        if 'fake' in desync_types and 'multisplit' in desync_types:
            return 'fake_multisplit'
        
        # Простые стратегии
        if 'fakeddisorder' in desync_types:
            return 'fakeddisorder'
        
        if 'multisplit' in desync_types:
            return 'multisplit'
        
        if 'disorder2' in desync_types or 'disorder' in desync_types:
            return 'disorder'
        
        if 'split' in desync_types:
            return 'split'
        
        if 'fake' in desync_types:
            return 'fake'
        
        if 'seqovl' in desync_types:
            return 'seqovl'
        
        return desync_types[0] if desync_types else 'disorder'
    
    def convert_file(self, input_file: str, output_file: str, backup: bool = True):
        """Конвертирует domain_strategies.json в domain_rules.json"""
        input_path = Path(input_file)
        output_path = Path(output_file)
        
        if not input_path.exists():
            print(f"❌ Файл {input_file} не найден")
            return False
        
        # Создаем бэкап если нужно
        if backup and output_path.exists():
            backup_path = output_path.with_suffix('.json.backup')
            print(f"📦 Создание бэкапа: {backup_path}")
            output_path.rename(backup_path)
        
        # Загружаем исходный файл
        print(f"📖 Чтение {input_file}...")
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Конвертируем
        domain_rules = {
            'version': '1.0',
            'domain_rules': {}
        }
        
        converted_count = 0
        failed_count = 0
        
        # Обрабатываем domain_strategies
        domain_strategies = data.get('domain_strategies', {})
        for domain, strategy_data in domain_strategies.items():
            if domain == 'default':
                continue
            
            # Получаем строку стратегии
            if isinstance(strategy_data, str):
                strategy_str = strategy_data
            elif isinstance(strategy_data, dict):
                strategy_str = strategy_data.get('strategy', '')
            else:
                print(f"⚠️  Пропуск {domain}: неизвестный формат")
                failed_count += 1
                continue
            
            # Конвертируем
            converted = self.parse_strategy_string(strategy_str)
            if converted:
                domain_rules['domain_rules'][domain] = converted
                converted_count += 1
                print(f"✅ {domain}: {converted['type']}")
            else:
                print(f"❌ Не удалось конвертировать {domain}: {strategy_str}")
                failed_count += 1
        
        # Обрабатываем default стратегию
        default_strategy = None
        if 'default' in domain_strategies:
            default_data = domain_strategies['default']
            if isinstance(default_data, str):
                default_strategy = default_data
            elif isinstance(default_data, dict):
                default_strategy = default_data.get('strategy', '')
        elif 'default_strategy' in data:
            default_data = data['default_strategy']
            if isinstance(default_data, str):
                default_strategy = default_data
            elif isinstance(default_data, dict):
                default_strategy = default_data.get('strategy', '')
        
        if default_strategy:
            converted_default = self.parse_strategy_string(default_strategy)
            if converted_default:
                domain_rules['default_strategy'] = converted_default
                print(f"✅ default: {converted_default['type']}")
            else:
                # Используем базовую стратегию по умолчанию
                domain_rules['default_strategy'] = {
                    'type': 'fake_disorder',
                    'params': {
                        'fake_ttl': 4,
                        'split_pos': 3,
                        'fooling': 'badsum',
                        'repeats': 2,
                        'window_div': 8,
                        'tcp_flags': {'psh': True, 'ack': True},
                        'ipid_step': 2048
                    }
                }
                print(f"⚠️  Использована базовая default стратегия")
        
        # Сохраняем результат
        print(f"\n💾 Сохранение в {output_file}...")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(domain_rules, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Конвертация завершена!")
        print(f"   Успешно: {converted_count}")
        print(f"   Ошибок: {failed_count}")
        print(f"   Файл: {output_file}")
        
        return True


def main():
    """Основная функция"""
    print("=" * 70)
    print("🔄 Конвертация domain_strategies.json → domain_rules.json")
    print("=" * 70)
    print()
    
    converter = StrategyConverter()
    success = converter.convert_file(
        'domain_strategies.json',
        'domain_rules.json',
        backup=True
    )
    
    if success:
        print("\n" + "=" * 70)
        print("✅ Готово! Теперь можно включить Domain-Based Filtering")
        print("=" * 70)
    else:
        print("\n❌ Конвертация не удалась")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
