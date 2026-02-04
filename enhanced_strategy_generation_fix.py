#!/usr/bin/env python3

"""
Исправление проблемы генерации стратегий для googlevideo.com

Проблемы:
1. StrategyDiversifier генерирует только один тип стратегии "fragmentation"
2. Все 25 стратегий имеют одинаковое имя
3. Отсутствует разнообразие в типах атак
4. Стратегии падают мгновенно из-за проблем валидации

Решение:
1. Улучшить генератор стратегий для создания разнообразных типов
2. Добавить специфичные для CDN/googlevideo стратегии
3. Исправить валидацию стратегий
4. Добавить больше типов атак
"""

import logging
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass

LOG = logging.getLogger("enhanced_strategy_generation")

class CDNOptimizedAttackType(Enum):
    """Оптимизированные типы атак для CDN сетей"""
    SPLIT_SNI = "split_sni"
    MULTISPLIT_AGGRESSIVE = "multisplit_aggressive"
    DISORDER_TIMING = "disorder_timing"
    FAKE_BADSUM = "fake_badsum"
    COMBO_SPLIT_DISORDER = "combo_split_disorder"
    COMBO_FAKE_MULTISPLIT = "combo_fake_multisplit"
    COMBO_DISORDER_FAKE = "combo_disorder_fake"
    ADVANCED_FRAGMENTATION = "advanced_fragmentation"
    SNI_CONCEALMENT = "sni_concealment"
    TIMING_ATTACK = "timing_attack"

@dataclass
class EnhancedStrategy:
    """Улучшенная стратегия с метаданными"""
    name: str
    attack_type: str
    attacks: List[str]
    parameters: Dict[str, Any]
    priority: float
    description: str
    cdn_optimized: bool = False

class EnhancedStrategyGenerator:
    """
    Улучшенный генератор стратегий для googlevideo.com и других CDN
    """
    
    def __init__(self):
        self.cdn_strategies = self._initialize_cdn_strategies()
        self.parameter_variations = self._initialize_parameter_variations()
        
    def _initialize_cdn_strategies(self) -> List[EnhancedStrategy]:
        """Инициализация стратегий, оптимизированных для CDN"""
        
        strategies = []
        
        # 1. SNI-based стратегии (эффективны для googlevideo)
        strategies.append(EnhancedStrategy(
            name="sni_split_googlevideo",
            attack_type="split",
            attacks=["split"],
            parameters={
                "split_pos": "sni",
                "ttl": 3,
                "fooling": "badsum"
            },
            priority=0.9,
            description="Split на SNI позиции для скрытия домена",
            cdn_optimized=True
        ))
        
        strategies.append(EnhancedStrategy(
            name="sni_multisplit_googlevideo",
            attack_type="multisplit",
            attacks=["multisplit"],
            parameters={
                "split_pos": "sni",
                "split_count": 8,
                "ttl": 2,
                "fooling": "badsum"
            },
            priority=0.85,
            description="Множественная фрагментация SNI",
            cdn_optimized=True
        ))
        
        # 2. Disorder стратегии (эффективны против stateless DPI)
        strategies.append(EnhancedStrategy(
            name="disorder_short_ttl_googlevideo",
            attack_type="disorder",
            attacks=["disorder"],
            parameters={
                "split_pos": 3,
                "ttl": 1,
                "fooling": "badseq",
                "disorder_method": "reverse"
            },
            priority=0.8,
            description="Переупорядочивание с коротким TTL",
            cdn_optimized=True
        ))
        
        strategies.append(EnhancedStrategy(
            name="disorder_multisplit_googlevideo",
            attack_type="disorder,multisplit",
            attacks=["disorder", "multisplit"],
            parameters={
                "split_pos": 2,
                "split_count": 6,
                "ttl": 2,
                "disorder_method": "reverse"
            },
            priority=0.82,
            description="Комбинация disorder + multisplit",
            cdn_optimized=True
        ))
        
        # 3. Fake packet стратегии
        strategies.append(EnhancedStrategy(
            name="fake_badsum_googlevideo",
            attack_type="fake",
            attacks=["fake"],
            parameters={
                "split_pos": 3,
                "ttl": 1,
                "fooling": "badsum",
                "fake_count": 2
            },
            priority=0.75,
            description="Fake пакеты с плохой контрольной суммой",
            cdn_optimized=True
        ))
        
        strategies.append(EnhancedStrategy(
            name="fake_disorder_googlevideo",
            attack_type="fake,disorder",
            attacks=["fake", "disorder"],
            parameters={
                "split_pos": 2,
                "ttl": 1,
                "fooling": "badseq",
                "disorder_method": "random"
            },
            priority=0.78,
            description="Комбинация fake + disorder",
            cdn_optimized=True
        ))
        
        # 4. Агрессивные стратегии для упорных DPI
        strategies.append(EnhancedStrategy(
            name="aggressive_multisplit_googlevideo",
            attack_type="multisplit",
            attacks=["multisplit"],
            parameters={
                "split_pos": 1,
                "split_count": 16,
                "ttl": 1,
                "fooling": "badsum",
                "positions": [1, 3, 5, 7, 9, 11, 13, 15]
            },
            priority=0.7,
            description="Агрессивная множественная фрагментация",
            cdn_optimized=True
        ))
        
        strategies.append(EnhancedStrategy(
            name="smart_combo_split_fake_googlevideo",
            attack_type="split,fake",
            attacks=["split", "fake"],
            parameters={
                "split_pos": 3,
                "ttl": 1,
                "fooling": "badsum",
                "fake_ttl": 1
            },
            priority=0.83,
            description="Умная комбинация split + fake",
            cdn_optimized=True
        ))
        
        # 5. Timing-based стратегии
        strategies.append(EnhancedStrategy(
            name="timing_disorder_googlevideo",
            attack_type="disorder",
            attacks=["disorder"],
            parameters={
                "split_pos": 4,
                "ttl": 2,
                "fooling": "badseq",
                "disorder_method": "timing",
                "delay_ms": 10
            },
            priority=0.72,
            description="Disorder с временными задержками",
            cdn_optimized=True
        ))
        
        # 6. Специальные стратегии для Google CDN
        strategies.append(EnhancedStrategy(
            name="google_cdn_bypass_googlevideo",
            attack_type="multisplit,disorder",
            attacks=["multisplit", "disorder"],
            parameters={
                "split_pos": "sni",
                "split_count": 4,
                "ttl": 3,
                "fooling": "badsum",
                "disorder_method": "reverse"
            },
            priority=0.88,
            description="Специально для Google CDN",
            cdn_optimized=True
        ))
        
        return strategies
    
    def _initialize_parameter_variations(self) -> Dict[str, List[Any]]:
        """Инициализация вариаций параметров"""
        
        return {
            "split_pos": [1, 2, 3, 4, 5, "sni", "random"],
            "split_count": [2, 4, 6, 8, 12, 16, 20],
            "ttl": [1, 2, 3, 4, 5],
            "fooling": ["badsum", "badseq", "md5sig", "none"],
            "disorder_method": ["reverse", "random", "timing"],
            "fake_count": [1, 2, 3, 4],
            "delay_ms": [5, 10, 15, 20, 50]
        }
    
    def generate_diverse_strategies(self, 
                                  domain: str, 
                                  max_strategies: int = 25) -> List[EnhancedStrategy]:
        """
        Генерирует разнообразные стратегии для домена
        
        Args:
            domain: Целевой домен
            max_strategies: Максимальное количество стратегий
            
        Returns:
            Список разнообразных стратегий
        """
        
        LOG.info(f"Генерация {max_strategies} разнообразных стратегий для {domain}")
        
        strategies = []
        
        # 1. Добавляем базовые CDN-оптимизированные стратегии
        base_strategies = self.cdn_strategies.copy()
        
        # Адаптируем имена под домен
        domain_clean = domain.replace('.', '_')
        for strategy in base_strategies:
            strategy.name = strategy.name.replace('googlevideo', domain_clean)
        
        strategies.extend(base_strategies)
        
        # 2. Генерируем вариации параметров
        variations = self._generate_parameter_variations(base_strategies, domain_clean)
        strategies.extend(variations)
        
        # 3. Генерируем экспериментальные стратегии
        experimental = self._generate_experimental_strategies(domain_clean)
        strategies.extend(experimental)
        
        # 4. Сортируем по приоритету и ограничиваем количество
        strategies.sort(key=lambda s: s.priority, reverse=True)
        final_strategies = strategies[:max_strategies]
        
        # 5. Обеспечиваем уникальность имен
        final_strategies = self._ensure_unique_names(final_strategies)
        
        LOG.info(f"Сгенерировано {len(final_strategies)} уникальных стратегий")
        
        return final_strategies
    
    def _generate_parameter_variations(self, 
                                     base_strategies: List[EnhancedStrategy],
                                     domain_clean: str) -> List[EnhancedStrategy]:
        """Генерирует вариации параметров базовых стратегий"""
        
        variations = []
        
        for base_strategy in base_strategies[:5]:  # Берем топ-5 стратегий
            for param_name, param_values in self.parameter_variations.items():
                if param_name in base_strategy.parameters:
                    for value in param_values[:2]:  # По 2 вариации каждого параметра
                        if value != base_strategy.parameters[param_name]:
                            # Создаем вариацию
                            new_params = base_strategy.parameters.copy()
                            new_params[param_name] = value
                            
                            variation = EnhancedStrategy(
                                name=f"{base_strategy.name}_{param_name}_{value}",
                                attack_type=base_strategy.attack_type,
                                attacks=base_strategy.attacks.copy(),
                                parameters=new_params,
                                priority=base_strategy.priority * 0.9,  # Немного ниже приоритет
                                description=f"{base_strategy.description} (вариация {param_name}={value})",
                                cdn_optimized=base_strategy.cdn_optimized
                            )
                            
                            variations.append(variation)
        
        return variations[:10]  # Ограничиваем количество вариаций
    
    def _generate_experimental_strategies(self, domain_clean: str) -> List[EnhancedStrategy]:
        """Генерирует экспериментальные стратегии"""
        
        experimental = []
        
        # 1. Экстремальные параметры
        experimental.append(EnhancedStrategy(
            name=f"extreme_multisplit_{domain_clean}",
            attack_type="multisplit",
            attacks=["multisplit"],
            parameters={
                "split_pos": 1,
                "split_count": 32,
                "ttl": 1,
                "fooling": "badsum"
            },
            priority=0.6,
            description="Экстремальная фрагментация",
            cdn_optimized=False
        ))
        
        # 2. Минимальные параметры
        experimental.append(EnhancedStrategy(
            name=f"minimal_split_{domain_clean}",
            attack_type="split",
            attacks=["split"],
            parameters={
                "split_pos": 1,
                "ttl": 5,
                "fooling": "none"
            },
            priority=0.5,
            description="Минимальная фрагментация",
            cdn_optimized=False
        ))
        
        # 3. Тройные комбинации
        experimental.append(EnhancedStrategy(
            name=f"triple_combo_{domain_clean}",
            attack_type="split,disorder,fake",
            attacks=["split", "disorder", "fake"],
            parameters={
                "split_pos": 2,
                "split_count": 4,
                "ttl": 1,
                "fooling": "badseq",
                "disorder_method": "random"
            },
            priority=0.65,
            description="Тройная комбинация атак",
            cdn_optimized=False
        ))
        
        return experimental
    
    def _ensure_unique_names(self, strategies: List[EnhancedStrategy]) -> List[EnhancedStrategy]:
        """Обеспечивает уникальность имен стратегий"""
        
        seen_names = set()
        unique_strategies = []
        
        for strategy in strategies:
            original_name = strategy.name
            counter = 1
            
            while strategy.name in seen_names:
                strategy.name = f"{original_name}_v{counter}"
                counter += 1
            
            seen_names.add(strategy.name)
            unique_strategies.append(strategy)
        
        return unique_strategies
    
    def convert_to_discovery_format(self, strategies: List[EnhancedStrategy]) -> List[Dict[str, Any]]:
        """Конвертирует стратегии в формат discovery системы"""
        
        discovery_strategies = []
        
        for strategy in strategies:
            discovery_strategy = {
                'name': strategy.name,
                'type': strategy.attack_type,
                'attacks': strategy.attacks,
                'parameters': strategy.parameters,
                'priority': strategy.priority,
                'description': strategy.description,
                'cdn_optimized': strategy.cdn_optimized
            }
            
            discovery_strategies.append(discovery_strategy)
        
        return discovery_strategies

def test_enhanced_generator():
    """Тестирование улучшенного генератора"""
    
    print("🔧 Тестирование улучшенного генератора стратегий")
    
    generator = EnhancedStrategyGenerator()
    strategies = generator.generate_diverse_strategies("www.googlevideo.com", 25)
    
    print(f"\n✅ Сгенерировано {len(strategies)} стратегий:")
    
    attack_types = set()
    for i, strategy in enumerate(strategies, 1):
        print(f"  {i:2d}. {strategy.name}")
        print(f"      Тип: {strategy.attack_type}")
        print(f"      Атаки: {strategy.attacks}")
        print(f"      Приоритет: {strategy.priority:.2f}")
        print(f"      CDN-оптимизированная: {strategy.cdn_optimized}")
        print()
        
        attack_types.add(strategy.attack_type)
    
    print(f"📊 Статистика:")
    print(f"   Уникальных типов атак: {len(attack_types)}")
    print(f"   Типы: {sorted(attack_types)}")
    
    cdn_optimized = sum(1 for s in strategies if s.cdn_optimized)
    print(f"   CDN-оптимизированных: {cdn_optimized}/{len(strategies)}")
    
    return strategies

if __name__ == "__main__":
    test_enhanced_generator()