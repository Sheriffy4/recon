# recon/ml/evolutionary_search.py
import asyncio
import random
import logging
import copy
import time
from typing import List, Dict, Any, Tuple, Optional, Set

# >>> ИЗМЕНЕНИЕ: Заменяем относительные импорты на абсолютные <<<
from core.interfaces import IEvolutionarySearcher, IAttackAdapter, IStrategyGenerator
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.zapret import synth
from core.metrics import BypassQualityMetrics
import config # <-- Этот импорт нужно будет проверить, возможно, `from . import config` или `from recon import config`

LOG = logging.getLogger("EvolutionarySearcher")


class EvolutionarySearcher(IEvolutionarySearcher): # <<< ИЗМЕНЕНИЕ: Реализуем интерфейс
    """
    Использует генетический алгоритм для "эволюционного" поиска
    оптимальной многоступенчатой стратегии обхода DPI.
    """

    # >>> НАЧАЛО ИЗМЕНЕНИЯ: Полностью переработанный конструктор <<<
    def __init__(
        self,
        attack_adapter: IAttackAdapter,
        strategy_generator: IStrategyGenerator,
        population_size: int = 20,
        generations: int = 5,
        mutation_rate: float = 0.1,
        elite_size: int = 2,
    ):
        """
        Конструктор теперь принимает СЕРВИСЫ через DI.
        Данные для запуска (домены, IP) будут передаваться в метод run().
        """
        self.attack_adapter = attack_adapter
        self.strategy_generator = strategy_generator # Используем внедренный генератор

        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.elite_size = elite_size

        self.population: List[Dict] = []
        self.best_strategy_so_far: Dict = {"fitness": -9999}
        self.semaphore = asyncio.Semaphore(10)
        self.fitness_cache = {}
        self.cache_ttl = 300
    # >>> КОНЕЦ ИЗМЕНЕНИЯ <<<

    def _create_random_stage(self) -> Dict:
        """Создает случайную стадию атаки."""
        tech_type = random.choice(list(config.TECH_LIBRARY.keys()))
        # --- НАЧАЛО ИЗМЕНЕНИЯ ---
        # Используем 'name' вместо 'type' для консистентности
        task = {"name": tech_type, "params": {}}
        base_params = config.TECH_LIBRARY[tech_type][0].get("params", {})
        task["params"].update(base_params)
        # --- КОНЕЦ ИЗМЕНЕНИЯ ---

        # Добавляем случайную задержку для "гоночных" атак
        if "race" in tech_type:
            task["params"]["delay_ms"] = random.randint(5, 50)

        return task

    def _create_initial_population(self):
        """
        Создает начальную популяцию, используя внедренный IStrategyGenerator.
        """
        # Генерируем половину популяции с помощью умного генератора
        # Теперь мы не создаем генератор, а используем тот, что был внедрен
        seed_strategies = self.strategy_generator.generate_strategies(
            count=self.population_size // 2
        )

        for task in seed_strategies:
            if task.get("name") == "adaptive_multi_layer":
                stages = []
                if "layer1" in task.get("params", {}):
                    stages.append({"name": task["params"]["layer1"], "params": {}})
                if "layer2" in task.get("params", {}):
                    stages.append({"name": task["params"]["layer2"], "params": {}})
                if stages:
                    chromosome = {"strategy": {"type": "dynamic_combo", "stages": stages}, "fitness": 0.0}
                    self.population.append(chromosome)
            else:
                chromosome = {"strategy": {"type": "dynamic_combo", "stages": [task]}, "fitness": 0.0}
                self.population.append(chromosome)

        # Дополняем популяцию случайными стратегиями
        while len(self.population) < self.population_size:
            num_stages = random.randint(2, 4)
            stages = [self._create_random_stage() for _ in range(num_stages)]
            chromosome = {"strategy": {"type": "dynamic_combo", "stages": stages}, "fitness": 0.0}
            self.population.append(chromosome)

        LOG.info(f"Создана начальная популяция из {len(self.population)} стратегий.")

    async def _calculate_fitness(self, chromosome: Dict, domains: List[str], dns_cache: Dict[str, str]) -> float:
        """
        Оценивает приспособленность. Теперь принимает домены и dns_cache как аргументы.
        """
        async with self.semaphore:
            strategy_task = chromosome["strategy"]
            attack_name = strategy_task.get("type")
            if not attack_name: return -1000.0

            strategy_key = self._create_strategy_cache_key(strategy_task)
            cached_result = self._get_cached_fitness(strategy_key)
            if cached_result is not None:
                return cached_result

            target_domain = random.choice(domains) if domains else "example.com"
            target_ip = dns_cache.get(target_domain)
            if not target_ip: return -1000.0

            context = AttackContext(
                dst_ip=target_ip,
                dst_port=443,
                domain=target_domain,
                payload=b"GET / HTTP/1.1\r\n\r\n",
                params={"stages": strategy_task.get("stages", [])},
                debug=True,
            )

            try:
                attack_result = await asyncio.wait_for(
                    self.attack_adapter.execute_attack_by_name(attack_name, context),
                    timeout=15.0,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                fitness = -5000.0
                self._cache_fitness(strategy_key, fitness)
                return fitness
            except Exception as e:
                LOG.error(f"Непредвиденная ошибка в _calculate_fitness: {e}")
                fitness = -10000.0
                self._cache_fitness(strategy_key, fitness)
                return fitness

            fitness = self._calculate_fitness_with_quality_metrics(
                attack_result, strategy_task, target_domain
            )
            self._cache_fitness(strategy_key, fitness)
            return fitness

    def _calculate_fitness_with_quality_metrics(
        self, attack_result, strategy_task: Dict, target_domain: str
    ) -> float:
        """
        Рассчитывает фитнес с использованием BypassQualityMetrics.

        Args:
            attack_result: Результат выполнения атаки
            strategy_task: Задача стратегии
            target_domain: Целевой домен

        Returns:
            Значение фитнеса
        """
        from core.metrics import BypassQualityMetrics

        quality_metrics = BypassQualityMetrics()

        # Проверяем эффективность
        is_effective = False
        if (
            attack_result
            and attack_result.metadata
            and "bypass_results" in attack_result.metadata
        ):
            is_effective = attack_result.metadata["bypass_results"].get(
                "bypass_effective", False
            )

        if not is_effective:
            # Стратегия неэффективна - возвращаем отрицательный фитнес
            connection_penalty = 0 if attack_result.connection_established else 200
            return -500.0 - connection_penalty

        # Стратегия эффективна - используем BypassQualityMetrics
        latency_ms = (
            attack_result.latency_ms if attack_result.latency_ms > 0 else 5000.0
        )
        rtt_seconds = (
            latency_ms / 1000.0
        )  # Конвертируем в секунды для BypassQualityMetrics

        # Создаем результат в формате, ожидаемом BypassQualityMetrics
        result_for_metrics = {
            "rtt": rtt_seconds,
            "task": strategy_task,
        }

        # Получаем оценки качества
        quality_scores = quality_metrics.calculate_score(result_for_metrics)

        # Извлекаем численные значения
        try:
            speed_score = float(quality_scores["speed"])
            complexity_score = float(quality_scores["complexity"])
            total_score = float(quality_scores["total_score"])
        except (ValueError, KeyError):
            # Fallback на старую логику при ошибке
            speed_score = 0.5
            complexity_score = 0.5
            total_score = 0.5

        # Масштабируем оценку в диапазон фитнеса (0-1000)
        base_fitness = total_score * 1000.0

        # Дополнительные бонусы и штрафы
        bonuses = 0.0

        # Бонус за стабильность
        if attack_result.metadata and "bypass_results" in attack_result.metadata:
            baseline_success = (
                attack_result.metadata["bypass_results"]
                .get("baseline", {})
                .get("success", False)
            )
            if baseline_success:
                bonuses += 100.0  # Бонус за работу на незаблокированном сайте

        # Бонус за низкую задержку
        if latency_ms < 200:
            bonuses += 50.0
        elif latency_ms < 500:
            bonuses += 25.0

        # Штраф за очень высокую задержку
        latency_penalty = 0.0
        if latency_ms > 2000:
            latency_penalty = (latency_ms - 2000) / 100.0

        # Штраф за сложность (количество стадий)
        complexity_penalty = len(strategy_task.get("stages", [])) * 5.0

        final_fitness = base_fitness + bonuses - latency_penalty - complexity_penalty

        # Дополнительная информация для отладки
        LOG.debug(
            f"Качественные метрики - Скорость: {speed_score:.2f}, "
            f"Сложность: {complexity_score:.2f}, Общая оценка: {total_score:.2f}, "
            f"Финальный фитнес: {final_fitness:.2f}"
        )

        return final_fitness

    def _selection(self) -> List[Dict]:
        """Выбирает родительские особи для следующего поколения."""
        # Сортируем популяцию по приспособленности
        self.population.sort(key=lambda x: x["fitness"], reverse=True)

        # Элитизм: лучшие особи переходят напрямую
        parents = self.population[: self.elite_size]

        # Турнирный отбор для остальных
        for _ in range(self.population_size - self.elite_size):
            tournament = random.sample(self.population, k=3)
            winner = max(tournament, key=lambda x: x["fitness"])
            parents.append(winner)

        return parents

    def _crossover(self, parent1: Dict, parent2: Dict) -> Dict:
        """Создает потомка путем скрещивания двух родителей."""
        p1_stages = parent1["strategy"]["stages"]
        p2_stages = parent2["strategy"]["stages"]

        # Простое одноточечное скрещивание
        if len(p1_stages) > 1 and len(p2_stages) > 1:
            crossover_point = random.randint(1, min(len(p1_stages), len(p2_stages)) - 1)
            child_stages = p1_stages[:crossover_point] + p2_stages[crossover_point:]
        else:
            child_stages = p1_stages if len(p1_stages) > len(p2_stages) else p2_stages

        return {
            "strategy": {"type": "dynamic_combo", "stages": child_stages},
            "fitness": 0.0,
        }

    def _mutation(self, chromosome: Dict):
        """Применяет случайные мутации к хромосоме."""
        if random.random() < self.mutation_rate:
            stages = chromosome["strategy"]["stages"]
            if not stages:
                return

            mutation_type = random.randint(1, 4)

            # 1: Изменить параметр в стадии
            if mutation_type == 1:
                stage_to_mutate = random.choice(stages)
                if "params" in stage_to_mutate:
                    if "ttl" in stage_to_mutate["params"]:
                        stage_to_mutate["params"]["ttl"] = random.choice([2, 3, 5, 10])
                    if "split_pos" in stage_to_mutate["params"]:
                        stage_to_mutate["params"]["split_pos"] = random.choice(
                            [1, 3, 5, "midsld"]
                        )

            # 2: Добавить новую стадию
            elif mutation_type == 2 and len(stages) < 5:
                stages.insert(
                    random.randint(0, len(stages)), self._create_random_stage()
                )

            # 3: Удалить стадию
            elif mutation_type == 3 and len(stages) > 1:
                stages.pop(random.randint(0, len(stages) - 1))

            # 4: Поменять стадии местами
            elif mutation_type == 4 and len(stages) > 1:
                idx1, idx2 = random.sample(range(len(stages)), 2)
                stages[idx1], stages[idx2] = stages[idx2], stages[idx1]

    async def run(
        self,
        domains: List[str],
        ips: Set[str],
        dns_cache: Dict[str, str],
        fingerprint_dict: Dict[str, Any]
    ) -> Dict:
        """
        Запускает полный цикл эволюционного поиска.
        Теперь принимает данные для запуска как аргументы.
        """
        # Сбрасываем состояние перед новым запуском
        self.population = []
        self.best_strategy_so_far = {"fitness": -9999}

        # Создаем начальную популяцию
        self._create_initial_population()

        fitness_history = []

        for gen in range(self.generations):
            LOG.info(f"--- Поколение {gen + 1}/{self.generations} ---")

            # Передаем данные в _calculate_fitness
            tasks = [self._calculate_fitness(chromo, domains, dns_cache) for chromo in self.population]
            fitness_scores = await asyncio.gather(*tasks)

            for i, score in enumerate(fitness_scores):
                self.population[i]["fitness"] = score

            parents = self._selection()

            current_best = self.population[0]
            if current_best["fitness"] > self.best_strategy_so_far["fitness"]:
                self.best_strategy_so_far = copy.deepcopy(current_best)

            avg_fitness = sum(s for s in fitness_scores if s is not None) / len(fitness_scores)
            best_fitness_in_gen = current_best["fitness"]
            fitness_history.append({"gen": gen + 1, "best": best_fitness_in_gen, "avg": avg_fitness})

            LOG.info(
                f"Лучший фитнес в поколении: {best_fitness_in_gen:.2f}. Средний: {avg_fitness:.2f}. Глобально лучший: {self.best_strategy_so_far['fitness']:.2f}"
            )

            next_generation = parents[: self.elite_size]
            while len(next_generation) < self.population_size:
                p1, p2 = random.sample(parents, 2)
                child = self._crossover(p1, p2)
                self._mutation(child)
                next_generation.append(child)

            self.population = next_generation

        LOG.info("Эволюционный поиск завершен.")

        # --- НОВОЕ: Выводим итоговую статистику ---
        print("\n--- Эволюция Фитнеса ---")
        for record in fitness_history:
            print(
                f"Поколение {record['gen']}: Лучший = {record['best']:.2f}, Средний = {record['avg']:.2f}"
            )
        # ------------------------------------

        return self.best_strategy_so_far

    def _get_random_domain(self) -> str:
        """
        Получает случайно выбранный домен для тестирования.
        Обеспечивает разнообразие тестирования через случайный выбор.
        """
        if not self.domains:
            return "example.com"

        return random.choice(self.domains)

    def _create_strategy_cache_key(self, strategy_task: Dict[str, Any]) -> str:
        """
        Создает ключ для кэширования результатов фитнеса стратегии.
        """
        try:
            # Используем тип стратегии и стадии для создания ключа
            strategy_type = strategy_task.get("type", "unknown")
            stages = strategy_task.get("stages", [])

            # Создаем компактное представление стадий
            stages_key = []
            for stage in stages:
                if isinstance(stage, dict):
                    stage_name = stage.get("name", "unknown")
                    # Включаем основные параметры, но не все детали
                    stage_params = stage.get("params", {})
                    key_params = {
                        k: v
                        for k, v in stage_params.items()
                        if k in ["segments", "split_position", "fake_packets"]
                    }
                    stages_key.append(
                        f"{stage_name}:{hash(str(sorted(key_params.items())))}"
                    )
                else:
                    stages_key.append(str(stage))

            cache_key = f"{strategy_type}:{'|'.join(stages_key)}"
            return cache_key[:100]  # Ограничиваем длину ключа

        except Exception as e:
            LOG.error(f"Error creating cache key: {e}")
            return f"error_{random.randint(0, 9999)}"

    def _get_cached_fitness(self, strategy_key: str) -> float:
        """
        Получает кэшированный результат фитнеса, если он еще актуален.
        Улучшенная версия с более эффективной проверкой TTL.
        """
        try:
            if strategy_key in self.fitness_cache:
                cached_data = self.fitness_cache[strategy_key]
                timestamp = cached_data.get("timestamp", 0)
                fitness = cached_data.get("fitness", None)
                hit_count = cached_data.get("hit_count", 0)

                # Проверяем, не истек ли TTL
                current_time = time.time()
                if current_time - timestamp < self.cache_ttl and fitness is not None:
                    # Увеличиваем счетчик попаданий для статистики
                    cached_data["hit_count"] = hit_count + 1
                    cached_data["last_access"] = current_time
                    return fitness
                else:
                    # Удаляем устаревший результат
                    del self.fitness_cache[strategy_key]

            return None

        except Exception as e:
            LOG.error(f"Error getting cached fitness: {e}")
            return None

    def _cache_fitness(self, strategy_key: str, fitness: float):
        """
        Кэширует результат фитнеса с временной меткой.
        Улучшенная версия с более эффективным управлением памятью.
        """
        try:
            current_time = time.time()

            self.fitness_cache[strategy_key] = {
                "fitness": fitness,
                "timestamp": current_time,
                "last_access": current_time,
                "hit_count": 0,
            }

            # Более эффективное управление размером кэша
            if len(self.fitness_cache) > 1000:
                self._cleanup_cache()

        except Exception as e:
            LOG.error(f"Error caching fitness: {e}")

    def _cleanup_cache(self):
        """
        Очищает кэш от старых и редко используемых записей.
        """
        try:
            current_time = time.time()

            # Удаляем записи старше TTL
            expired_keys = []
            for key, data in self.fitness_cache.items():
                if current_time - data.get("timestamp", 0) > self.cache_ttl:
                    expired_keys.append(key)

            for key in expired_keys:
                del self.fitness_cache[key]

            # Если кэш все еще слишком большой, удаляем редко используемые записи
            if len(self.fitness_cache) > 800:
                # Сортируем по частоте использования и времени последнего доступа
                sorted_items = sorted(
                    self.fitness_cache.items(),
                    key=lambda x: (
                        x[1].get("hit_count", 0),
                        x[1].get("last_access", 0),
                    ),
                )

                # Удаляем 200 наименее используемых записей
                for key, _ in sorted_items[:200]:
                    del self.fitness_cache[key]

            LOG.debug(
                f"Cache cleanup completed. Current size: {len(self.fitness_cache)}"
            )

        except Exception as e:
            LOG.error(f"Error during cache cleanup: {e}")

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Возвращает статистику использования кэша.
        """
        try:
            total_entries = len(self.fitness_cache)
            total_hits = sum(
                data.get("hit_count", 0) for data in self.fitness_cache.values()
            )

            if total_entries > 0:
                avg_hits = total_hits / total_entries
                current_time = time.time()
                fresh_entries = sum(
                    1
                    for data in self.fitness_cache.values()
                    if current_time - data.get("timestamp", 0) < self.cache_ttl / 2
                )
            else:
                avg_hits = 0
                fresh_entries = 0

            return {
                "total_entries": total_entries,
                "total_hits": total_hits,
                "average_hits_per_entry": avg_hits,
                "fresh_entries": fresh_entries,
                "cache_ttl": self.cache_ttl,
            }

        except Exception as e:
            LOG.error(f"Error getting cache stats: {e}")
            return {"error": str(e)}

    # Interface methods required by IEvolutionarySearcher
    def search_optimal_strategies(self, domain: str, generations: int = 10) -> list:
        """Search for optimal strategies using evolutionary algorithm."""
        try:
            # Create a simple DNS cache for the domain
            dns_cache = {domain: domain}  # Simplified for interface compatibility
            
            # Run the evolutionary search
            result = asyncio.run(self.run([domain], dns_cache, generations))
            
            # Extract strategies from the result
            if result and "strategy" in result:
                return [result["strategy"]]
            else:
                return []
                
        except Exception as e:
            LOG.error(f"Error in search_optimal_strategies: {e}")
            return []
    
    def get_search_results(self) -> Dict[str, Any]:
        """Get results from evolutionary search."""
        return {
            "best_strategy": self.best_strategy_so_far,
            "population_size": self.population_size,
            "generations": self.generations,
            "cache_stats": self.get_cache_stats()
        }
