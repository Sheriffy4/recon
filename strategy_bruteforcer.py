# strategy_bruteforcer.py
import asyncio
import itertools
import json
import time
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field
import logging

@dataclass
class StrategyVariant:
    """Вариант стратегии для тестирования"""
    segment_order: str  # 'fake_first' or 'real_first'
    fake_ttl: int
    split_pos: int
    overlap_size: int
    fooling: List[str]
    delay_ms: int
    tcp_flags_fake: int  # 0x10 (ACK) or 0x18 (PSH+ACK)
    tcp_flags_real: int
    window_mode: str  # 'original', 'reduced', 'zero'
    
    def to_dict(self) -> Dict:
        return {
            'type': 'fakeddisorder',
            'params': {
                'segment_order': self.segment_order,
                'ttl': self.fake_ttl,
                'split_pos': self.split_pos,
                'overlap_size': self.overlap_size,
                'fooling': self.fooling,
                'delay_ms': self.delay_ms,
                'tcp_flags_fake': self.tcp_flags_fake,
                'tcp_flags_real': self.tcp_flags_real,
                'window_mode': self.window_mode
            }
        }
    
    def to_string(self) -> str:
        return (f"order={self.segment_order}, ttl={self.fake_ttl}, "
                f"split={self.split_pos}, overlap={self.overlap_size}, "
                f"fooling={','.join(self.fooling)}, delay={self.delay_ms}ms")

@dataclass
class TestResult:
    """Результат тестирования варианта"""
    variant: StrategyVariant
    success_rate: float
    avg_latency: float
    successful_sites: List[str]
    failed_sites: List[str]
    error_types: Dict[str, int] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

class StrategyBruteforcer:
    """Интеллектуальный перебор вариантов стратегий"""
    
    def __init__(self, hybrid_engine, test_sites: List[str], dns_cache: Dict[str, str]):
        self.engine = hybrid_engine
        self.test_sites = test_sites
        self.dns_cache = dns_cache
        self.logger = logging.getLogger("StrategyBruteforcer")
        self.results: List[TestResult] = []
        
    def generate_variants(self, base_strategy: Dict = None) -> List[StrategyVariant]:
        """Генерация вариантов для тестирования"""
        variants = []
        
        # Базовые параметры из текущей стратегии или дефолты
        if base_strategy:
            base_params = base_strategy.get('params', {})
        else:
            base_params = {}
        
        # Параметры для перебора
        param_grid = {
            'segment_order': ['fake_first', 'real_first'],
            'fake_ttl': [1, 2, 3, 4],
            'split_pos': [3, 40, 76, 100, 'midsld'],
            'overlap_size': [0, 20, 76, 160, 336],
            'fooling': [
                ['badsum'],
                ['badseq'],
                ['md5sig'],
                ['badsum', 'badseq'],
                [],
            ],
            'delay_ms': [0, 1, 2, 5, 10],
            'tcp_flags_fake': [0x10, 0x18],  # ACK vs PSH+ACK
            'tcp_flags_real': [0x18, 0x10],
            'window_mode': ['original', 'reduced', 'zero']
        }
        
        # Интеллектуальная генерация (не полный перебор, а эвристики)
        # 1. Приоритетные комбинации для разных CDN
        priority_variants = [
            # Cloudflare
            StrategyVariant('fake_first', 1, 76, 336, ['badsum'], 2, 0x10, 0x18, 'original'),
            StrategyVariant('fake_first', 2, 76, 160, ['badsum'], 1, 0x10, 0x18, 'original'),
            
            # Meta/Instagram
            StrategyVariant('fake_first', 1, 40, 20, ['badsum'], 5, 0x10, 0x18, 'reduced'),
            StrategyVariant('real_first', 1, 3, 0, ['badsum', 'badseq'], 7, 0x18, 0x10, 'original'),
            
            # Fastly
            StrategyVariant('fake_first', 2, 100, 50, ['md5sig'], 3, 0x10, 0x18, 'original'),
            
            # Росkomnadzor
            StrategyVariant('fake_first', 3, 3, 0, [], 1, 0x10, 0x18, 'original'),
            StrategyVariant('fake_first', 1, 'midsld', 20, ['badsum'], 2, 0x10, 0x18, 'original'),
        ]
        
        variants.extend(priority_variants)
        
        # 2. Адаптивная генерация на основе предыдущих результатов
        if self.results:
            best_result = max(self.results, key=lambda r: r.success_rate)
            if best_result.success_rate > 0:
                # Мутации лучшего результата
                mutations = self._generate_mutations(best_result.variant)
                variants.extend(mutations[:10])
        
        # 3. Случайная выборка из полной сетки (для разнообразия)
        import random
        for _ in range(20):
            variant = StrategyVariant(
                segment_order=random.choice(param_grid['segment_order']),
                fake_ttl=random.choice(param_grid['fake_ttl']),
                split_pos=random.choice(param_grid['split_pos']),
                overlap_size=random.choice(param_grid['overlap_size']),
                fooling=random.choice(param_grid['fooling']),
                delay_ms=random.choice(param_grid['delay_ms']),
                tcp_flags_fake=random.choice(param_grid['tcp_flags_fake']),
                tcp_flags_real=random.choice(param_grid['tcp_flags_real']),
                window_mode=random.choice(param_grid['window_mode'])
            )
            if variant not in variants:
                variants.append(variant)
        
        return variants
    
    def _generate_mutations(self, base_variant: StrategyVariant) -> List[StrategyVariant]:
        """Генерация мутаций успешного варианта"""
        mutations = []
        
        # Мутация TTL
        for ttl_delta in [-1, 1]:
            new_ttl = max(1, min(10, base_variant.fake_ttl + ttl_delta))
            if new_ttl != base_variant.fake_ttl:
                mutant = StrategyVariant(**base_variant.__dict__)
                mutant.fake_ttl = new_ttl
                mutations.append(mutant)
        
        # Мутация split_pos
        if isinstance(base_variant.split_pos, int):
            for split_delta in [-20, -10, 10, 20]:
                new_split = max(1, base_variant.split_pos + split_delta)
                mutant = StrategyVariant(**base_variant.__dict__)
                mutant.split_pos = new_split
                mutations.append(mutant)
        
        # Мутация overlap
        for overlap_delta in [-50, 50]:
            new_overlap = max(0, base_variant.overlap_size + overlap_delta)
            mutant = StrategyVariant(**base_variant.__dict__)
            mutant.overlap_size = new_overlap
            mutations.append(mutant)
        
        # Инверсия порядка
        mutant = StrategyVariant(**base_variant.__dict__)
        mutant.segment_order = 'real_first' if base_variant.segment_order == 'fake_first' else 'fake_first'
        mutations.append(mutant)
        
        return mutations
    
    async def test_variant(self, variant: StrategyVariant) -> TestResult:
        """Тестирование одного варианта"""
        self.logger.info(f"Testing variant: {variant.to_string()}")
        
        # Модифицируем движок для использования варианта
        strategy_task = variant.to_dict()
        
        # Запускаем тест
        try:
            result = await self.engine.execute_strategy_real_world(
                strategy_task,
                self.test_sites,
                set(),  # target_ips
                self.dns_cache,
                return_details=True
            )
            
            if len(result) >= 5:
                status, success_count, total_count, avg_latency, site_results = result[:5]
            else:
                status, success_count, total_count, avg_latency = result
                site_results = {}
            
            # Анализ результатов
            successful_sites = []
            failed_sites = []
            error_types = {}
            
            for site, (site_status, _, _, _) in site_results.items():
                if site_status == 'WORKING':
                    successful_sites.append(site)
                else:
                    failed_sites.append(site)
                    error_types[site_status] = error_types.get(site_status, 0) + 1
            
            return TestResult(
                variant=variant,
                success_rate=success_count / total_count if total_count > 0 else 0,
                avg_latency=avg_latency,
                successful_sites=successful_sites,
                failed_sites=failed_sites,
                error_types=error_types
            )
            
        except Exception as e:
            self.logger.error(f"Error testing variant: {e}")
            return TestResult(
                variant=variant,
                success_rate=0,
                avg_latency=0,
                successful_sites=[],
                failed_sites=self.test_sites,
                error_types={'ERROR': len(self.test_sites)}
            )
    
    async def run_bruteforce(self, max_variants: int = 50, early_stop_threshold: float = 0.9):
        """Запуск брутфорса с ранней остановкой"""
        self.logger.info(f"Starting bruteforce with max {max_variants} variants")
        
        variants = self.generate_variants()[:max_variants]
        
        for i, variant in enumerate(variants, 1):
            self.logger.info(f"Testing variant {i}/{len(variants)}")
            
            result = await self.test_variant(variant)
            self.results.append(result)
            
            self.logger.info(f"Result: {result.success_rate:.1%} success, {result.avg_latency:.1f}ms latency")
            
            # Ранняя остановка при достижении хорошего результата
            if result.success_rate >= early_stop_threshold:
                self.logger.info(f"Early stop: found variant with {result.success_rate:.1%} success rate")
                break
            
            # Адаптивная генерация новых вариантов на основе результатов
            if i % 10 == 0 and i < len(variants) - 10:
                # Добавляем мутации лучших вариантов
                best_so_far = sorted(self.results, key=lambda r: r.success_rate, reverse=True)[:3]
                for best in best_so_far:
                    if best.success_rate > 0.3:
                        new_mutations = self._generate_mutations(best.variant)[:2]
                        variants.extend(new_mutations)
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Генерация отчета о результатах"""
        if not self.results:
            return {'error': 'No results'}
        
        # Сортировка по успешности
        sorted_results = sorted(self.results, key=lambda r: (r.success_rate, -r.avg_latency), reverse=True)
        
        report = {
            'total_variants_tested': len(self.results),
            'best_variant': {
                'params': sorted_results[0].variant.to_dict(),
                'string': sorted_results[0].variant.to_string(),
                'success_rate': sorted_results[0].success_rate,
                'avg_latency': sorted_results[0].avg_latency,
                'successful_sites': sorted_results[0].successful_sites
            },
            'top_5_variants': [
                {
                    'params': r.variant.to_dict(),
                    'string': r.variant.to_string(),
                    'success_rate': r.success_rate,
                    'avg_latency': r.avg_latency
                }
                for r in sorted_results[:5]
            ],
            'parameter_analysis': self._analyze_parameters(),
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _analyze_parameters(self) -> Dict:
        """Анализ влияния параметров на успешность"""
        analysis = {}
        
        # Группировка по параметрам
        param_stats = {
            'segment_order': {},
            'fake_ttl': {},
            'fooling': {},
            'overlap_size': {}
        }
        
        for result in self.results:
            # Segment order
            order = result.variant.segment_order
            if order not in param_stats['segment_order']:
                param_stats['segment_order'][order] = []
            param_stats['segment_order'][order].append(result.success_rate)
            
            # TTL
            ttl = result.variant.fake_ttl
            if ttl not in param_stats['fake_ttl']:
                param_stats['fake_ttl'][ttl] = []
            param_stats['fake_ttl'][ttl].append(result.success_rate)
            
            # Fooling
            fooling_key = ','.join(sorted(result.variant.fooling)) if result.variant.fooling else 'none'
            if fooling_key not in param_stats['fooling']:
                param_stats['fooling'][fooling_key] = []
            param_stats['fooling'][fooling_key].append(result.success_rate)
        
        # Расчет средних
        for param_name, param_values in param_stats.items():
            analysis[param_name] = {}
            for value, rates in param_values.items():
                analysis[param_name][str(value)] = {
                    'avg_success_rate': sum(rates) / len(rates) if rates else 0,
                    'count': len(rates)
                }
        
        return analysis
    
    def _generate_recommendations(self) -> List[str]:
        """Генерация рекомендаций на основе анализа"""
        recommendations = []
        
        if not self.results:
            return ["No test results available"]
        
        best = max(self.results, key=lambda r: r.success_rate)
        
        # Рекомендации по порядку сегментов
        if best.variant.segment_order == 'fake_first':
            recommendations.append("Use fake_first segment order (send fake segment before real)")
        else:
            recommendations.append("Use real_first segment order (send real segment before fake)")
        
        # Рекомендации по TTL
        recommendations.append(f"Optimal fake TTL: {best.variant.fake_ttl}")
        
        # Рекомендации по fooling
        if best.variant.fooling:
            recommendations.append(f"Use fooling methods: {', '.join(best.variant.fooling)}")
        else:
            recommendations.append("Don't use fooling methods")
        
        # Рекомендации по overlap
        if best.variant.overlap_size > 0:
            recommendations.append(f"Use overlap size: {best.variant.overlap_size}")
        else:
            recommendations.append("Don't use overlap (set overlap_size=0)")
        
        return recommendations

# Использование
async def run_optimization(hybrid_engine, test_sites, dns_cache):
    """Запуск оптимизации"""
    bruteforcer = StrategyBruteforcer(hybrid_engine, test_sites, dns_cache)
    
    report = await bruteforcer.run_bruteforce(max_variants=30)
    
    # Сохранение отчета
    with open("bruteforce_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "="*50)
    print("OPTIMIZATION COMPLETE")
    print("="*50)
    print(f"\nBest variant found:")
    print(f"  {report['best_variant']['string']}")
    print(f"  Success rate: {report['best_variant']['success_rate']:.1%}")
    print(f"  Latency: {report['best_variant']['avg_latency']:.1f}ms")
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  • {rec}")
    
    return report