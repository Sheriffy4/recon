#!/usr/bin/env python3
"""
Integration module for Evolutionary Search optimization in DPI bypass system.
"""

import logging
import time
import random
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime, timedelta

from core.async_utils import AsyncOperationWrapper, BackgroundTaskConfig

# Import evolutionary search components
try:
    from ml.evolutionary_search import EvolutionarySearcher
    from ml.strategy_generator import StrategyGenerator

    EVOLUTIONARY_AVAILABLE = True
except ImportError as e:
    EVOLUTIONARY_AVAILABLE = False
    logging.warning(f"Evolutionary optimization not available: {e}")

LOG = logging.getLogger("evolutionary_optimization_integration")


@dataclass
class OptimizationResult:
    """Result of evolutionary optimization."""

    best_strategy: Dict[str, Any]
    fitness_score: float
    generations_run: int
    optimization_time_seconds: float
    fitness_history: List[Dict[str, Any]]
    target_domains: List[str]
    timestamp: datetime


@dataclass
class OptimizationTask:
    """Background optimization task."""

    task_id: str
    domains: List[str]
    target_ips: Set[str]
    status: str  # 'pending', 'running', 'completed', 'failed'
    start_time: Optional[datetime]
    result: Optional[OptimizationResult]
    error: Optional[str]


class EvolutionaryOptimizationIntegrator:
    """
    Integrates Evolutionary Search into bypass engines.
    Provides background parameter optimization for attack strategies.
    """

    def __init__(self, enable_optimization: bool = True):
        self.enable_optimization = enable_optimization and EVOLUTIONARY_AVAILABLE
        self.evolutionary_searcher = None
        self.strategy_generator = None

        # Background optimization management
        self.optimization_tasks = {}  # task_id -> OptimizationTask
        self.background_tasks = set()  # Active asyncio tasks
        self.optimization_results = {}  # domain -> OptimizationResult
        self.results_cache_ttl = 3600  # 1 hour cache for optimization results

        # Configuration
        self.population_size = 15  # Smaller for production use
        self.generations = 3  # Fewer generations for faster optimization
        self.mutation_rate = 0.15
        self.elite_size = 2

        if self.enable_optimization:
            try:
                self._initialize_evolutionary_components()
                LOG.info("Evolutionary optimization initialized successfully")
            except Exception as e:
                LOG.error(f"Failed to initialize evolutionary optimization: {e}")
                self.enable_optimization = False

        if not self.enable_optimization:
            LOG.info("Using static parameter optimization fallback")

    def _initialize_evolutionary_components(self):
        """Initialize evolutionary search components."""

        # Create strategy generator
        self.strategy_generator = SimplifiedStrategyGenerator()

        # Create attack adapter (reuse existing one)
        from core.integration.attack_adapter import AttackAdapter

        attack_adapter = AttackAdapter()

        # Initialize evolutionary searcher
        self.evolutionary_searcher = EvolutionarySearcher(
            attack_adapter=attack_adapter,
            strategy_generator=self.strategy_generator,
            population_size=self.population_size,
            generations=self.generations,
            mutation_rate=self.mutation_rate,
            elite_size=self.elite_size,
        )

    def start_background_optimization(
        self, domains: List[str], target_ips: Set[str], task_id: Optional[str] = None
    ) -> str:
        """
        Start background evolutionary optimization for given domains.

        Args:
            domains: List of target domains
            target_ips: Set of target IP addresses
            task_id: Optional task ID (auto-generated if not provided)

        Returns:
            Task ID for tracking optimization progress
        """

        if not self.enable_optimization:
            LOG.warning("Evolutionary optimization is disabled")
            return None

        # Generate task ID if not provided
        if not task_id:
            task_id = f"opt_{int(time.time())}_{hash(tuple(sorted(domains)))}"

        # Check if optimization is already running for these domains
        for existing_task in self.optimization_tasks.values():
            if existing_task.status == "running" and set(existing_task.domains) == set(domains):
                LOG.info(f"Optimization already running for domains: {domains}")
                return existing_task.task_id

        # Create optimization task
        task = OptimizationTask(
            task_id=task_id,
            domains=domains,
            target_ips=target_ips,
            status="pending",
            start_time=None,
            result=None,
            error=None,
        )

        self.optimization_tasks[task_id] = task

        # Start background optimization using BackgroundTaskManager
        try:
            config = BackgroundTaskConfig(
                name=f"evolutionary_optimization_{task_id}",
                coroutine_func=self._run_background_optimization,
                args=(task_id,),
                restart_on_error=False,  # Don't restart optimization tasks
            )

            success = AsyncOperationWrapper.schedule_background_task(config)
            if success:
                LOG.info(f"Started background optimization task {task_id} for domains: {domains}")
            else:
                raise RuntimeError("Failed to schedule background task")

            return task_id

        except Exception as e:
            LOG.error(f"Failed to start background optimization: {e}")
            task.status = "failed"
            task.error = str(e)
            return task_id

    async def _run_background_optimization(self, task_id: str):
        """Run evolutionary optimization in background."""

        task = self.optimization_tasks.get(task_id)
        if not task:
            LOG.error(f"Optimization task {task_id} not found")
            return

        try:
            task.status = "running"
            task.start_time = datetime.now()

            LOG.info(f"Running evolutionary optimization for task {task_id}")

            # Prepare data for evolutionary search
            domains = task.domains
            target_ips = task.target_ips

            # Create DNS cache (simplified)
            dns_cache = {}
            for domain in domains:
                # Use first available IP for each domain
                if target_ips:
                    dns_cache[domain] = list(target_ips)[0]

            # Create fingerprint dict (simplified)
            fingerprint_dict = {
                domain: {"dpi_type": "generic", "confidence": 0.5} for domain in domains
            }

            # Run evolutionary optimization
            start_time = time.time()

            result = await self.evolutionary_searcher.run(
                domains=domains,
                ips=target_ips,
                dns_cache=dns_cache,
                fingerprint_dict=fingerprint_dict,
            )

            optimization_time = time.time() - start_time

            # Create optimization result
            optimization_result = OptimizationResult(
                best_strategy=result.get("best_strategy", {}),
                fitness_score=result.get("best_fitness", 0.0),
                generations_run=self.generations,
                optimization_time_seconds=optimization_time,
                fitness_history=result.get("fitness_history", []),
                target_domains=domains,
                timestamp=datetime.now(),
            )

            # Store result
            task.result = optimization_result
            task.status = "completed"

            # Cache result for domains
            for domain in domains:
                self.optimization_results[domain] = optimization_result

            LOG.info(
                f"Evolutionary optimization completed for task {task_id}. "
                f"Best fitness: {optimization_result.fitness_score:.2f}, "
                f"Time: {optimization_time:.1f}s"
            )

        except Exception as e:
            LOG.error(f"Evolutionary optimization failed for task {task_id}: {e}")
            task.status = "failed"
            task.error = str(e)

    def get_optimization_result(self, domain: str) -> Optional[OptimizationResult]:
        """Get cached optimization result for a domain."""

        result = self.optimization_results.get(domain)
        if result:
            # Check if result is still fresh
            age = (datetime.now() - result.timestamp).total_seconds()
            if age < self.results_cache_ttl:
                return result
            else:
                # Remove stale result
                del self.optimization_results[domain]

        return None

    def get_optimized_strategy(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get optimized strategy for a domain if available."""

        result = self.get_optimization_result(domain)
        if result and result.best_strategy:
            return result.best_strategy

        return None

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of optimization task."""

        task = self.optimization_tasks.get(task_id)
        if not task:
            return None

        status_info = {
            "task_id": task.task_id,
            "domains": task.domains,
            "status": task.status,
            "start_time": task.start_time.isoformat() if task.start_time else None,
            "error": task.error,
        }

        if task.result:
            status_info.update(
                {
                    "fitness_score": task.result.fitness_score,
                    "optimization_time": task.result.optimization_time_seconds,
                    "generations": task.result.generations_run,
                }
            )

        return status_info

    def list_active_optimizations(self) -> List[Dict[str, Any]]:
        """List all active optimization tasks."""

        active_tasks = []
        for task in self.optimization_tasks.values():
            if task.status in ["pending", "running"]:
                active_tasks.append(self.get_task_status(task.task_id))

        return active_tasks

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics."""

        stats = {
            "enabled": self.enable_optimization,
            "total_tasks": len(self.optimization_tasks),
            "active_tasks": len(
                [t for t in self.optimization_tasks.values() if t.status in ["pending", "running"]]
            ),
            "completed_tasks": len(
                [t for t in self.optimization_tasks.values() if t.status == "completed"]
            ),
            "failed_tasks": len(
                [t for t in self.optimization_tasks.values() if t.status == "failed"]
            ),
            "cached_results": len(self.optimization_results),
            "background_tasks": len(self.background_tasks),
            "configuration": {
                "population_size": self.population_size,
                "generations": self.generations,
                "mutation_rate": self.mutation_rate,
                "elite_size": self.elite_size,
            },
        }

        return stats

    def cleanup_old_tasks(self, max_age_hours: int = 24):
        """Clean up old completed/failed tasks."""

        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

        tasks_to_remove = []
        for task_id, task in self.optimization_tasks.items():
            if (
                task.status in ["completed", "failed"]
                and task.start_time
                and task.start_time < cutoff_time
            ):
                tasks_to_remove.append(task_id)

        for task_id in tasks_to_remove:
            del self.optimization_tasks[task_id]

        if tasks_to_remove:
            LOG.info(f"Cleaned up {len(tasks_to_remove)} old optimization tasks")

    def suggest_optimization_for_domains(self, domains: List[str]) -> bool:
        """
        Check if domains would benefit from optimization and suggest it.

        Returns:
            True if optimization is recommended, False otherwise
        """

        if not self.enable_optimization:
            return False

        # Check if we already have recent optimization results
        for domain in domains:
            result = self.get_optimization_result(domain)
            if result:
                # We have recent results, no need to optimize again
                return False

        # Check if optimization is already running
        for task in self.optimization_tasks.values():
            if task.status in ["pending", "running"] and any(
                domain in task.domains for domain in domains
            ):
                return False

        # Optimization would be beneficial
        return True


# Simplified implementations for integration


class SimplifiedStrategyGenerator:
    """Simplified strategy generator for evolutionary optimization."""

    def generate_strategies(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate diverse attack strategies."""

        strategies = []

        # Basic strategy templates
        strategy_templates = [
            {"name": "tcp_window_scaling", "params": {"window_scale": 2}},
            {"name": "tcp_multisplit", "params": {"split_count": 3}},
            {"name": "badsum_race", "params": {"delay_ms": 10}},
            {"name": "low_ttl_poisoning", "params": {"ttl": 8}},
            {
                "name": "tcp_timestamp_manipulation",
                "params": {"timestamp_offset": 1000},
            },
            {"name": "urgent_pointer_manipulation", "params": {"urgent_size": 4}},
            {"name": "tcp_options_padding", "params": {"padding_size": 16}},
            {"name": "md5sig_fooling", "params": {"split_pos": 3}},
        ]

        # Generate strategies with parameter variations
        for i in range(count):
            template = strategy_templates[i % len(strategy_templates)]
            strategy = template.copy()

            # Add parameter variations
            if "window_scale" in strategy["params"]:
                strategy["params"]["window_scale"] = random.choice([1, 2, 4, 6, 8])
            if "split_count" in strategy["params"]:
                strategy["params"]["split_count"] = random.choice([2, 3, 4, 5])
            if "delay_ms" in strategy["params"]:
                strategy["params"]["delay_ms"] = random.choice([5, 10, 20, 50])
            if "ttl" in strategy["params"]:
                strategy["params"]["ttl"] = random.choice([1, 4, 8, 16])

            strategies.append(strategy)

        return strategies


# Global instance for easy access
_global_evolutionary_integrator = None


def get_evolutionary_integrator() -> EvolutionaryOptimizationIntegrator:
    """Get global evolutionary optimization integrator instance."""
    global _global_evolutionary_integrator
    if _global_evolutionary_integrator is None:
        _global_evolutionary_integrator = EvolutionaryOptimizationIntegrator()
    return _global_evolutionary_integrator
