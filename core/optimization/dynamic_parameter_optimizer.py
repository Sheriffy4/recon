import time
import random
import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from recon.core.bypass.attacks.base import AttackContext
    from recon.core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester
LOG = logging.getLogger('DynamicParameterOptimizer')

class OptimizationStrategy(Enum):
    """Parameter optimization strategies."""
    GRID_SEARCH = 'grid_search'
    RANDOM_SEARCH = 'random_search'
    BAYESIAN = 'bayesian'
    EVOLUTIONARY = 'evolutionary'

@dataclass
class ParameterRange:
    """Defines a parameter range for optimization."""
    name: str
    type: str
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    choices: Optional[List[Any]] = None
    step: Optional[Union[int, float]] = None
    default: Any = None

@dataclass
class OptimizationResult:
    """Result of parameter optimization."""
    attack_name: str
    optimal_parameters: Dict[str, Any]
    best_effectiveness: float
    total_tests: int
    optimization_time_ms: float
    convergence_iteration: int
    parameter_history: List[Dict[str, Any]] = field(default_factory=list)
    effectiveness_history: List[float] = field(default_factory=list)

class DynamicParameterOptimizer:
    """
    Dynamic Parameter Optimizer for automatic attack parameter tuning.
    """

    def __init__(self, effectiveness_tester: 'RealEffectivenessTester'):
        """
        Initialize the parameter optimizer.

        Args:
            effectiveness_tester: Real effectiveness tester for parameter evaluation
        """
        if not effectiveness_tester:
            raise ValueError('effectiveness_tester is a required dependency.')
        self.effectiveness_tester = effectiveness_tester
        self.logger = LOG
        self._parameter_ranges = self._initialize_parameter_ranges()
        self._optimization_history: Dict[str, List[OptimizationResult]] = {}

    def generate_parameter_ranges(self, attack_name: str) -> Dict[str, ParameterRange]:
        """
        Generate parameter ranges for a specific attack type.

        Args:
            attack_name: Name of the attack to generate ranges for

        Returns:
            Dictionary of parameter name -> ParameterRange
        """
        if attack_name in self._parameter_ranges:
            return self._parameter_ranges[attack_name].copy()
        try:
            from recon.core.bypass.attacks.registry import AttackRegistry
            attack_class = AttackRegistry.get(attack_name)
            if attack_class:
                try:
                    attack_instance = attack_class()
                    category = attack_instance.category
                    if category in self._parameter_ranges:
                        self.logger.info(f'Using category-based ranges for {attack_name} (category: {category})')
                        return self._parameter_ranges[category].copy()
                except Exception as e:
                    self.logger.warning(f'Could not instantiate attack {attack_name}: {e}')
        except ImportError:
            self.logger.warning('AttackRegistry not available, using default ranges')
        self.logger.info(f'Using default parameter ranges for {attack_name}')
        return self._parameter_ranges.get('default', {}).copy()

    async def optimize_parameters(self, attack_name: str, context: 'AttackContext', strategy: OptimizationStrategy=OptimizationStrategy.RANDOM_SEARCH, max_iterations: int=20, convergence_threshold: float=0.95, timeout_seconds: int=300) -> OptimizationResult:
        """
        Optimize parameters for a specific attack through real testing.

        Args:
            attack_name: Name of the attack to optimize
            context: Attack execution context
            strategy: Optimization strategy to use
            max_iterations: Maximum number of parameter combinations to test
            convergence_threshold: Stop when effectiveness reaches this threshold
            timeout_seconds: Maximum optimization time

        Returns:
            OptimizationResult with optimal parameters and metrics
        """
        start_time = time.time()
        self.logger.info(f'Starting parameter optimization for {attack_name} using {strategy.value}')
        try:
            param_ranges = self.generate_parameter_ranges(attack_name)
            if not param_ranges:
                raise ValueError(f'No parameter ranges defined for attack {attack_name}')
            best_params = {}
            best_effectiveness = 0.0
            parameter_history = []
            effectiveness_history = []
            convergence_iteration = -1
            if strategy == OptimizationStrategy.GRID_SEARCH:
                param_combinations = self._generate_grid_search_combinations(param_ranges, max_iterations)
            elif strategy == OptimizationStrategy.RANDOM_SEARCH:
                param_combinations = self._generate_random_search_combinations(param_ranges, max_iterations)
            elif strategy == OptimizationStrategy.BAYESIAN:
                param_combinations = await self._generate_bayesian_combinations(param_ranges, max_iterations, attack_name)
            elif strategy == OptimizationStrategy.EVOLUTIONARY:
                param_combinations = await self._generate_evolutionary_combinations(param_ranges, max_iterations, context, attack_name)
            else:
                raise ValueError(f'Unsupported optimization strategy: {strategy}')
            for iteration, params in enumerate(param_combinations):
                if time.time() - start_time > timeout_seconds:
                    self.logger.warning(f'Optimization timeout reached after {iteration} iterations')
                    break
                try:
                    effectiveness = await self._test_parameters(attack_name, params, context)
                    parameter_history.append(params.copy())
                    effectiveness_history.append(effectiveness)
                    if effectiveness > best_effectiveness:
                        best_effectiveness = effectiveness
                        best_params = params.copy()
                        self.logger.info(f'New best parameters for {attack_name}: effectiveness={effectiveness:.3f}, params={params}')
                        if effectiveness >= convergence_threshold:
                            convergence_iteration = iteration
                            self.logger.info(f'Convergence reached at iteration {iteration}')
                            break
                except Exception as e:
                    self.logger.error(f'Error testing parameters {params}: {e}')
                    effectiveness_history.append(0.0)
                    parameter_history.append(params.copy())
            optimization_time = (time.time() - start_time) * 1000
            result = OptimizationResult(attack_name=attack_name, optimal_parameters=best_params, best_effectiveness=best_effectiveness, total_tests=len(effectiveness_history), optimization_time_ms=optimization_time, convergence_iteration=convergence_iteration, parameter_history=parameter_history, effectiveness_history=effectiveness_history)
            if attack_name not in self._optimization_history:
                self._optimization_history[attack_name] = []
            self._optimization_history[attack_name].append(result)
            self.logger.info(f'Parameter optimization completed for {attack_name}: best_effectiveness={best_effectiveness:.3f}, total_tests={len(effectiveness_history)}, time={optimization_time:.1f}ms')
            return result
        except Exception as e:
            self.logger.error(f'Parameter optimization failed for {attack_name}: {e}')
            return OptimizationResult(attack_name=attack_name, optimal_parameters={}, best_effectiveness=0.0, total_tests=0, optimization_time_ms=(time.time() - start_time) * 1000, convergence_iteration=-1)

    async def _test_parameters(self, attack_name: str, parameters: Dict[str, Any], context: 'AttackContext') -> float:
        """
        Test a specific parameter combination and return effectiveness score.

        Args:
            attack_name: Name of the attack
            parameters: Parameters to test
            context: Attack execution context

        Returns:
            Effectiveness score (0.0 - 1.0)
        """
        try:
            from recon.core.bypass.attacks.registry import AttackRegistry
            from recon.core.bypass.attacks.base import AttackContext, AttackStatus
            attack = AttackRegistry.create(attack_name)
            if not attack:
                raise ValueError(f'Could not create attack instance for {attack_name}')
            test_context = AttackContext(dst_ip=context.dst_ip, dst_port=context.dst_port, src_ip=context.src_ip, src_port=context.src_port, domain=context.domain, payload=context.payload, protocol=context.protocol, params=parameters, timeout=context.timeout, debug=context.debug)
            attack_result = attack.execute(test_context)
            if attack_result.status != AttackStatus.SUCCESS:
                return 0.0
            domain = context.domain or 'example.com'
            port = context.dst_port or 443
            baseline = await self.effectiveness_tester.test_baseline(domain, port)
            bypass = await self.effectiveness_tester.test_with_bypass(domain, port, attack_result)
            effectiveness = await self.effectiveness_tester.compare_results(baseline, bypass)
            return effectiveness.effectiveness_score
        except Exception as e:
            self.logger.error(f'Error testing parameters {parameters} for {attack_name}: {e}')
            return 0.0

    def _generate_grid_search_combinations(self, param_ranges: Dict[str, ParameterRange], max_combinations: int) -> List[Dict[str, Any]]:
        """Generate parameter combinations using grid search."""
        combinations = []
        param_values = {}
        for name, param_range in param_ranges.items():
            param_values[name] = self._generate_parameter_values(param_range)
        import itertools
        param_names = list(param_values.keys())
        value_lists = [param_values[name] for name in param_names]
        count = 0
        for combination in itertools.product(*value_lists):
            if count >= max_combinations:
                break
            params = dict(zip(param_names, combination))
            combinations.append(params)
            count += 1
        random.shuffle(combinations)
        return combinations

    def _generate_random_search_combinations(self, param_ranges: Dict[str, ParameterRange], max_combinations: int) -> List[Dict[str, Any]]:
        """Generate parameter combinations using random search."""
        combinations = []
        for _ in range(max_combinations):
            params = {}
            for name, param_range in param_ranges.items():
                params[name] = self._sample_parameter_value(param_range)
            combinations.append(params)
        return combinations

    async def _generate_bayesian_combinations(self, param_ranges: Dict[str, ParameterRange], max_combinations: int, attack_name: str) -> List[Dict[str, Any]]:
        """Generate parameter combinations using Bayesian optimization."""
        combinations = []
        random_count = min(5, max_combinations // 4)
        combinations.extend(self._generate_random_search_combinations(param_ranges, random_count))
        if attack_name in self._optimization_history:
            history = self._optimization_history[attack_name]
            for result in sorted(history, key=lambda x: x.best_effectiveness, reverse=True)[:3]:
                base_params = result.optimal_parameters
                for _ in range((max_combinations - random_count) // 3):
                    if len(combinations) >= max_combinations:
                        break
                    varied_params = self._create_parameter_variation(base_params, param_ranges)
                    combinations.append(varied_params)
        while len(combinations) < max_combinations:
            params = {}
            for name, param_range in param_ranges.items():
                params[name] = self._sample_parameter_value(param_range)
            combinations.append(params)
        return combinations

    async def _generate_evolutionary_combinations(self, param_ranges: Dict[str, ParameterRange], max_combinations: int, context: 'AttackContext', attack_name: str) -> List[Dict[str, Any]]:
        """Generate parameter combinations using evolutionary algorithm."""
        population_size = min(10, max_combinations // 2)
        generations = max_combinations // population_size
        population = self._generate_random_search_combinations(param_ranges, population_size)
        all_combinations = population.copy()
        for generation in range(generations):
            if len(all_combinations) >= max_combinations:
                break
            fitness_scores = []
            for params in population:
                fitness = self._estimate_parameter_fitness(params, param_ranges)
                fitness_scores.append(fitness)
            sorted_indices = sorted(range(len(population)), key=lambda i: fitness_scores[i], reverse=True)
            elite_count = population_size // 3
            elite = [population[i] for i in sorted_indices[:elite_count]]
            new_population = elite.copy()
            while len(new_population) < population_size and len(all_combinations) < max_combinations:
                parent1, parent2 = random.sample(elite, 2)
                child = self._crossover_parameters(parent1, parent2, param_ranges)
                if random.random() < 0.3:
                    child = self._mutate_parameters(child, param_ranges)
                new_population.append(child)
                all_combinations.append(child)
            population = new_population
        return all_combinations[:max_combinations]

    def _generate_parameter_values(self, param_range: ParameterRange) -> List[Any]:
        """Generate all possible values for a parameter range."""
        if param_range.type == 'choice':
            return param_range.choices or []
        elif param_range.type == 'bool':
            return [True, False]
        elif param_range.type == 'int':
            if param_range.min_value is not None and param_range.max_value is not None:
                step = param_range.step or 1
                return list(range(int(param_range.min_value), int(param_range.max_value) + 1, int(step)))
        elif param_range.type == 'float':
            if param_range.min_value is not None and param_range.max_value is not None:
                step = param_range.step or 0.1
                values = []
                current = param_range.min_value
                while current <= param_range.max_value:
                    values.append(round(current, 2))
                    current += step
                return values
        return [param_range.default] if param_range.default is not None else []

    def _sample_parameter_value(self, param_range: ParameterRange) -> Any:
        """Sample a random value from a parameter range."""
        if param_range.type == 'choice':
            return random.choice(param_range.choices or [param_range.default])
        elif param_range.type == 'bool':
            return random.choice([True, False])
        elif param_range.type == 'int':
            if param_range.min_value is not None and param_range.max_value is not None:
                return random.randint(int(param_range.min_value), int(param_range.max_value))
        elif param_range.type == 'float':
            if param_range.min_value is not None and param_range.max_value is not None:
                return round(random.uniform(param_range.min_value, param_range.max_value), 2)
        return param_range.default

    def _create_parameter_variation(self, base_params: Dict[str, Any], param_ranges: Dict[str, ParameterRange]) -> Dict[str, Any]:
        """Create a variation of base parameters."""
        varied_params = base_params.copy()
        params_to_vary = random.sample(list(param_ranges.keys()), min(2, len(param_ranges)))
        for param_name in params_to_vary:
            if param_name in param_ranges:
                param_range = param_ranges[param_name]
                varied_params[param_name] = self._sample_parameter_value(param_range)
        return varied_params

    def _estimate_parameter_fitness(self, params: Dict[str, Any], param_ranges: Dict[str, ParameterRange]) -> float:
        """Estimate parameter fitness using heuristics (for evolutionary algorithm)."""
        fitness = 0.5
        if 'split_pos' in params and isinstance(params['split_pos'], int):
            if 1 <= params['split_pos'] <= 5:
                fitness += 0.2
        if 'ttl' in params and isinstance(params['ttl'], int):
            if 3 <= params['ttl'] <= 8:
                fitness += 0.1
        if 'fooling' in params and 'split_pos' in params:
            if params.get('fooling') in ['badsum', 'badseq'] and isinstance(params.get('split_pos'), int):
                fitness += 0.15
        return min(1.0, fitness)

    def _crossover_parameters(self, parent1: Dict[str, Any], parent2: Dict[str, Any], param_ranges: Dict[str, ParameterRange]) -> Dict[str, Any]:
        """Create offspring through parameter crossover."""
        child = {}
        for param_name in param_ranges.keys():
            if param_name in parent1 and param_name in parent2:
                child[param_name] = random.choice([parent1[param_name], parent2[param_name]])
            elif param_name in parent1:
                child[param_name] = parent1[param_name]
            elif param_name in parent2:
                child[param_name] = parent2[param_name]
            else:
                child[param_name] = self._sample_parameter_value(param_ranges[param_name])
        return child

    def _mutate_parameters(self, params: Dict[str, Any], param_ranges: Dict[str, ParameterRange]) -> Dict[str, Any]:
        """Mutate parameters."""
        mutated = params.copy()
        param_to_mutate = random.choice(list(param_ranges.keys()))
        mutated[param_to_mutate] = self._sample_parameter_value(param_ranges[param_to_mutate])
        return mutated

    def _initialize_parameter_ranges(self) -> Dict[str, Dict[str, ParameterRange]]:
        """Initialize parameter ranges for different attack types and categories."""
        ranges = {}
        ranges['tcp'] = {'split_pos': ParameterRange('split_pos', 'choice', choices=[1, 2, 3, 4, 5, 10, 'midsld'], default=3), 'positions': ParameterRange('positions', 'choice', choices=[[1, 3], [1, 3, 10], [2, 5, 8]], default=[1, 3, 10]), 'overlap_size': ParameterRange('overlap_size', 'int', min_value=5, max_value=50, step=5, default=10), 'window_size': ParameterRange('window_size', 'int', min_value=1, max_value=16, default=1)}
        ranges['tcp_manipulation'] = {'window_scale': ParameterRange('window_scale', 'int', min_value=1, max_value=8, default=2), 'urgent_data_size': ParameterRange('urgent_data_size', 'int', min_value=1, max_value=10, default=2), 'padding_size': ParameterRange('padding_size', 'int', min_value=4, max_value=32, step=4, default=8), 'split_pos': ParameterRange('split_pos', 'int', min_value=1, max_value=10, default=3)}
        ranges['tcp_timing'] = {'delay_ms': ParameterRange('delay_ms', 'int', min_value=10, max_value=500, step=10, default=50), 'burst_size': ParameterRange('burst_size', 'int', min_value=1, max_value=10, default=3), 'jitter_range': ParameterRange('jitter_range', 'int', min_value=5, max_value=100, step=5, default=20)}
        ranges['tcp_fooling'] = {'ttl': ParameterRange('ttl', 'int', min_value=1, max_value=15, default=5), 'fooling': ParameterRange('fooling', 'choice', choices=['badsum', 'badseq', 'md5sig'], default='badsum'), 'repeats': ParameterRange('repeats', 'int', min_value=1, max_value=5, default=1)}
        ranges['ip'] = {'fragment_size': ParameterRange('fragment_size', 'int', min_value=8, max_value=1024, step=8, default=64), 'ttl_value': ParameterRange('ttl_value', 'int', min_value=1, max_value=255, default=64), 'tos_value': ParameterRange('tos_value', 'int', min_value=0, max_value=255, default=0)}
        ranges['tls'] = {'record_size': ParameterRange('record_size', 'int', min_value=1, max_value=16384, step=64, default=1024), 'extension_padding': ParameterRange('extension_padding', 'int', min_value=0, max_value=512, step=16, default=64), 'cipher_suite': ParameterRange('cipher_suite', 'choice', choices=['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'], default='TLS_AES_128_GCM_SHA256')}
        ranges['http'] = {'header_case': ParameterRange('header_case', 'choice', choices=['upper', 'lower', 'mixed', 'random'], default='mixed'), 'method': ParameterRange('method', 'choice', choices=['GET', 'POST', 'PUT', 'HEAD'], default='GET'), 'user_agent_type': ParameterRange('user_agent_type', 'choice', choices=['chrome', 'firefox', 'safari', 'edge'], default='chrome')}
        ranges['http2'] = {'frame_size': ParameterRange('frame_size', 'int', min_value=1, max_value=16384, step=64, default=1024), 'stream_priority': ParameterRange('stream_priority', 'int', min_value=0, max_value=255, default=0), 'window_update_size': ParameterRange('window_update_size', 'int', min_value=1, max_value=65535, default=65535)}
        ranges['quic'] = {'packet_size': ParameterRange('packet_size', 'int', min_value=64, max_value=1200, step=64, default=512), 'connection_id_length': ParameterRange('connection_id_length', 'int', min_value=4, max_value=18, default=8), 'migration_frequency': ParameterRange('migration_frequency', 'int', min_value=1, max_value=10, default=3)}
        ranges['payload'] = {'encryption_key_size': ParameterRange('encryption_key_size', 'choice', choices=[8, 16, 32], default=16), 'obfuscation_rounds': ParameterRange('obfuscation_rounds', 'int', min_value=1, max_value=5, default=2), 'noise_ratio': ParameterRange('noise_ratio', 'float', min_value=0.1, max_value=0.5, step=0.1, default=0.2)}
        ranges['tunneling'] = {'tunnel_protocol': ParameterRange('tunnel_protocol', 'choice', choices=['dns', 'icmp', 'http'], default='dns'), 'chunk_size': ParameterRange('chunk_size', 'int', min_value=32, max_value=512, step=32, default=128), 'encoding_type': ParameterRange('encoding_type', 'choice', choices=['base64', 'base32', 'hex'], default='base64')}
        ranges['combo'] = {'max_iterations': ParameterRange('max_iterations', 'int', min_value=1, max_value=10, default=3), 'detection_threshold': ParameterRange('detection_threshold', 'float', min_value=0.3, max_value=0.9, step=0.1, default=0.7), 'learning_rate': ParameterRange('learning_rate', 'float', min_value=0.05, max_value=0.3, step=0.05, default=0.1), 'adaptation_level': ParameterRange('adaptation_level', 'choice', choices=['light', 'medium', 'heavy'], default='medium')}
        ranges['default'] = {'split_pos': ParameterRange('split_pos', 'int', min_value=1, max_value=10, default=3), 'ttl': ParameterRange('ttl', 'int', min_value=1, max_value=15, default=5), 'delay_ms': ParameterRange('delay_ms', 'int', min_value=10, max_value=200, step=10, default=50)}
        ranges['tcp_fakeddisorder'] = ranges['tcp'].copy()
        ranges['tcp_multisplit'] = ranges['tcp'].copy()
        ranges['tcp_multidisorder'] = ranges['tcp'].copy()
        ranges['tcp_seqovl'] = ranges['tcp'].copy()
        ranges['tcp_wssize_limit'] = ranges['tcp'].copy()
        ranges['tcp_window_scaling'] = ranges['tcp_manipulation'].copy()
        ranges['urgent_pointer_manipulation'] = ranges['tcp_manipulation'].copy()
        ranges['tcp_options_padding'] = ranges['tcp_manipulation'].copy()
        ranges['tcp_timestamp_manipulation'] = ranges['tcp_manipulation'].copy()
        return ranges

    def get_optimization_history(self, attack_name: Optional[str]=None) -> Dict[str, List[OptimizationResult]]:
        """
        Get optimization history for analysis.

        Args:
            attack_name: Specific attack name, or None for all attacks

        Returns:
            Dictionary of attack name -> list of optimization results
        """
        if attack_name:
            return {attack_name: self._optimization_history.get(attack_name, [])}
        return self._optimization_history.copy()

    def clear_history(self, attack_name: Optional[str]=None):
        """
        Clear optimization history.

        Args:
            attack_name: Specific attack name, or None to clear all
        """
        if attack_name:
            self._optimization_history.pop(attack_name, None)
        else:
            self._optimization_history.clear()
        self.logger.info(f"Cleared optimization history for {attack_name or 'all attacks'}")