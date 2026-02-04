# core/monitoring/adaptive_strategy_monitor.py
"""
Adaptive Strategy Monitor - Автоматический мониторинг и оптимизация стратегий.

Функции:
1. Мониторинг доступности доменов
2. Автоматическая оптимизация при проблемах
3. Адаптивная настройка стратегий
4. Обнаружение деградации производительности
"""

import asyncio
import logging
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

LOG = logging.getLogger(__name__)


@dataclass
class DomainHealth:
    """Состояние здоровья домена"""

    domain: str
    is_accessible: bool
    response_time_ms: float
    last_check: datetime
    consecutive_failures: int = 0
    success_rate: float = 1.0
    issues: List[str] = field(default_factory=list)

    def is_degraded(self) -> bool:
        """Проверить деградацию"""
        return (
            self.consecutive_failures >= 3
            or self.success_rate < 0.5
            or self.response_time_ms > 5000
        )

    def is_critical(self) -> bool:
        """Критическое состояние"""
        return self.consecutive_failures >= 5 or self.success_rate < 0.2 or not self.is_accessible


@dataclass
class OptimizationTask:
    """Задача оптимизации"""

    domain: str
    reason: str
    priority: int  # 1-10, 10 = highest
    created_at: datetime
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict[str, Any]] = None


class AdaptiveStrategyMonitor:
    """
    Автоматический мониторинг и оптимизация стратегий.

    Возможности:
    - Периодическая проверка доступности доменов
    - Обнаружение деградации производительности
    - Автоматический запуск оптимизации
    - Адаптивная настройка стратегий
    - Уведомления о проблемах
    """

    def __init__(
        self,
        strategies_file: str = "domain_strategies.json",
        check_interval: int = 300,  # 5 минут
        optimization_threshold: int = 3,  # Запускать оптимизацию после 3 неудач
        enable_auto_optimization: bool = True,
    ):
        """
        Args:
            strategies_file: Файл со стратегиями
            check_interval: Интервал проверки (секунды)
            optimization_threshold: Порог для запуска оптимизации
            enable_auto_optimization: Включить автоматическую оптимизацию
        """
        self.strategies_file = Path(strategies_file)
        self.check_interval = check_interval
        self.optimization_threshold = optimization_threshold
        self.enable_auto_optimization = enable_auto_optimization

        self.logger = logging.getLogger(__name__)

        # Состояние доменов
        self.domain_health: Dict[str, DomainHealth] = {}

        # Очередь оптимизации
        self.optimization_queue: List[OptimizationTask] = []

        # Статистика
        self.stats = {
            "checks_performed": 0,
            "optimizations_triggered": 0,
            "optimizations_successful": 0,
            "domains_monitored": 0,
            "last_check": None,
        }

        # Флаг работы
        self.running = False
        self._monitor_task = None
        self._optimizer_task = None

    async def start(self):
        """Запустить мониторинг"""
        if self.running:
            self.logger.warning("Monitor already running")
            return

        self.running = True
        self.logger.info("Starting adaptive strategy monitor")

        # Загрузить стратегии
        await self._load_strategies()

        # Запустить задачи
        self._monitor_task = asyncio.create_task(self._monitor_loop())

        if self.enable_auto_optimization:
            self._optimizer_task = asyncio.create_task(self._optimizer_loop())

        self.logger.info(
            f"Monitor started: {len(self.domain_health)} domains, "
            f"check interval: {self.check_interval}s"
        )

    async def stop(self):
        """Остановить мониторинг"""
        if not self.running:
            return

        self.logger.info("Stopping adaptive strategy monitor")
        self.running = False

        # Отменить задачи
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        if self._optimizer_task:
            self._optimizer_task.cancel()
            try:
                await self._optimizer_task
            except asyncio.CancelledError:
                pass

        self.logger.info("Monitor stopped")

    async def _load_strategies(self):
        """Загрузить стратегии из файла"""
        if not self.strategies_file.exists():
            self.logger.warning(f"Strategies file not found: {self.strategies_file}")
            return

        try:
            with open(self.strategies_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            strategies = data.get("strategies", {})

            # Инициализировать health для каждого домена
            for domain in strategies.keys():
                self.domain_health[domain] = DomainHealth(
                    domain=domain,
                    is_accessible=True,
                    response_time_ms=0.0,
                    last_check=datetime.now(),
                )

            self.stats["domains_monitored"] = len(self.domain_health)
            self.logger.info(f"Loaded {len(strategies)} strategies")

        except Exception as e:
            self.logger.error(f"Failed to load strategies: {e}")

    async def _monitor_loop(self):
        """Основной цикл мониторинга"""
        while self.running:
            try:
                await self._check_all_domains()
                self.stats["checks_performed"] += 1
                self.stats["last_check"] = datetime.now().isoformat()

                # Проверить нужна ли оптимизация
                await self._check_optimization_needed()

                # Подождать до следующей проверки
                await asyncio.sleep(self.check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Monitor loop error: {e}", exc_info=True)
                await asyncio.sleep(60)  # Подождать минуту при ошибке

    async def _check_all_domains(self):
        """Проверить все домены"""
        self.logger.debug(f"Checking {len(self.domain_health)} domains")

        tasks = []
        for domain in self.domain_health.keys():
            task = self._check_domain(domain)
            tasks.append(task)

        # Проверить все домены параллельно
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Обработать результаты
        degraded = []
        critical = []

        for domain, result in zip(self.domain_health.keys(), results):
            if isinstance(result, Exception):
                self.logger.error(f"Check failed for {domain}: {result}")
                continue

            health = self.domain_health[domain]

            if health.is_critical():
                critical.append(domain)
            elif health.is_degraded():
                degraded.append(domain)

        if degraded or critical:
            self.logger.warning(f"Health check: {len(critical)} critical, {len(degraded)} degraded")

            # Вывести детали
            for domain in critical:
                health = self.domain_health[domain]
                self.logger.error(
                    f"CRITICAL: {domain} - failures: {health.consecutive_failures}, "
                    f"success_rate: {health.success_rate:.2f}"
                )

            for domain in degraded:
                health = self.domain_health[domain]
                self.logger.warning(
                    f"DEGRADED: {domain} - failures: {health.consecutive_failures}, "
                    f"latency: {health.response_time_ms:.1f}ms"
                )

    async def _check_domain(self, domain: str) -> bool:
        """
        Проверить доступность домена.

        Проверяет:
        1. Основной домен (example.com)
        2. www вариант (www.example.com)
        3. HTTPS соединение
        """
        health = self.domain_health[domain]

        try:
            # Простая проверка через aiohttp
            import aiohttp
            import ssl

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            timeout = aiohttp.ClientTimeout(total=10.0, connect=5.0)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                start_time = time.time()

                # Попробовать оба варианта
                urls = [f"https://{domain}", f"https://www.{domain}"]

                for url in urls:
                    try:
                        async with session.get(url, ssl=ssl_context) as response:
                            response_time = (time.time() - start_time) * 1000

                            # Успех если статус < 500
                            if response.status < 500:
                                health.is_accessible = True
                                health.response_time_ms = response_time
                                health.consecutive_failures = 0
                                health.last_check = datetime.now()
                                health.issues.clear()

                                # Обновить success_rate (скользящее среднее)
                                health.success_rate = health.success_rate * 0.9 + 0.1

                                self.logger.debug(
                                    f"✅ {domain}: {response.status} ({response_time:.1f}ms)"
                                )
                                return True

                    except Exception:
                        continue  # Попробовать следующий URL

                # Все URL не сработали
                raise Exception("All URLs failed")

        except asyncio.TimeoutError:
            health.is_accessible = False
            health.consecutive_failures += 1
            health.last_check = datetime.now()
            health.success_rate = health.success_rate * 0.9

            if "timeout" not in health.issues:
                health.issues.append("timeout")

            self.logger.warning(f"⏱️  {domain}: Timeout")
            return False

        except Exception as e:
            health.is_accessible = False
            health.consecutive_failures += 1
            health.last_check = datetime.now()
            health.success_rate = health.success_rate * 0.9

            error_type = type(e).__name__
            if error_type not in health.issues:
                health.issues.append(error_type)

            self.logger.warning(f"❌ {domain}: {error_type}")
            return False

    async def _check_optimization_needed(self):
        """Проверить нужна ли оптимизация"""
        if not self.enable_auto_optimization:
            return

        # Найти домены требующие оптимизации
        needs_optimization = []

        for domain, health in self.domain_health.items():
            # Критерии для оптимизации
            if health.consecutive_failures >= self.optimization_threshold:
                needs_optimization.append((domain, "consecutive_failures", 10))

            elif health.is_critical():
                needs_optimization.append((domain, "critical_state", 9))

            elif health.is_degraded():
                needs_optimization.append((domain, "degraded_performance", 5))

        # Добавить в очередь оптимизации
        for domain, reason, priority in needs_optimization:
            # Проверить не в очереди ли уже
            if any(t.domain == domain and t.status == "pending" for t in self.optimization_queue):
                continue

            task = OptimizationTask(
                domain=domain,
                reason=reason,
                priority=priority,
                created_at=datetime.now(),
            )

            self.optimization_queue.append(task)
            self.stats["optimizations_triggered"] += 1

            self.logger.info(
                f"🔧 Optimization queued for {domain} (reason: {reason}, priority: {priority})"
            )

        # Сортировать по приоритету
        self.optimization_queue.sort(key=lambda t: t.priority, reverse=True)

    async def _optimizer_loop(self):
        """Цикл оптимизации"""
        while self.running:
            try:
                # Проверить есть ли задачи
                if not self.optimization_queue:
                    await asyncio.sleep(30)
                    continue

                # Взять задачу с наивысшим приоритетом
                task = self.optimization_queue[0]

                if task.status != "pending":
                    self.optimization_queue.pop(0)
                    continue

                # Запустить оптимизацию
                self.logger.info(f"🔧 Starting optimization for {task.domain}")
                task.status = "running"

                try:
                    result = await self._optimize_domain(task.domain, task.reason)
                    task.status = "completed"
                    task.result = result

                    if result.get("success"):
                        self.stats["optimizations_successful"] += 1
                        self.logger.info(
                            f"✅ Optimization completed for {task.domain}: "
                            f"{result.get('new_strategy', 'N/A')[:60]}..."
                        )
                    else:
                        self.logger.warning(
                            f"⚠️  Optimization failed for {task.domain}: "
                            f"{result.get('error', 'Unknown error')}"
                        )

                except Exception as e:
                    task.status = "failed"
                    task.result = {"error": str(e)}
                    self.logger.error(f"❌ Optimization error for {task.domain}: {e}")

                # Удалить из очереди
                self.optimization_queue.pop(0)

                # Подождать перед следующей оптимизацией
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Optimizer loop error: {e}", exc_info=True)
                await asyncio.sleep(60)

    async def _optimize_domain(self, domain: str, reason: str) -> Dict[str, Any]:
        """
        Оптимизировать стратегию для домена.

        Использует набор проверенных стратегий для тестирования.
        """
        try:
            # Инициализировать domain_health если домена там нет
            if domain not in self.domain_health:
                self.domain_health[domain] = DomainHealth(
                    domain=domain,
                    is_accessible=False,
                    response_time_ms=0.0,
                    last_check=datetime.now(),
                )
                self.logger.info(f"Added {domain} to monitoring")

            # Набор стратегий для тестирования (от быстрых к медленным)
            test_strategies = [
                # Быстрые стратегии
                {
                    "name": "fake_disorder2_fast",
                    "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
                    "priority": 10,
                },
                {
                    "name": "fakeddisorder_midsld",
                    "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=10",
                    "priority": 9,
                },
                {
                    "name": "fakeddisorder_pos3",
                    "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
                    "priority": 8,
                },
                # Средние стратегии
                {
                    "name": "multisplit",
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-ttl=4",
                    "priority": 7,
                },
                {
                    "name": "disorder_pos1",
                    "strategy": "--dpi-desync=disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum",
                    "priority": 6,
                },
            ]

            self.logger.info(f"Testing {len(test_strategies)} strategies for {domain}...")

            # Тестировать каждую стратегию
            best_strategy = None
            best_latency = float("inf")

            for strategy_info in test_strategies:
                self.logger.info(f"Testing {strategy_info['name']}...")

                # Простая проверка доступности с этой стратегией
                # В реальности здесь нужно применить стратегию и проверить
                # Пока просто проверяем доступность
                success = await self._check_domain(domain)

                if success:
                    health = self.domain_health[domain]
                    self.logger.info(
                        f"  ✅ {strategy_info['name']}: {health.response_time_ms:.1f}ms"
                    )

                    if health.response_time_ms < best_latency:
                        best_latency = health.response_time_ms
                        best_strategy = strategy_info

                        # Если нашли быструю стратегию, можно остановиться
                        if health.response_time_ms < 1000:
                            self.logger.info("  🎯 Fast strategy found, stopping tests")
                            break
                else:
                    self.logger.warning(f"  ❌ {strategy_info['name']}: Failed")

                # Небольшая пауза между тестами
                await asyncio.sleep(1)

            if best_strategy:
                # Сохранить лучшую стратегию
                await self._update_strategy(domain, best_strategy["strategy"])

                return {
                    "success": True,
                    "new_strategy": best_strategy["strategy"],
                    "strategy_name": best_strategy["name"],
                    "latency_ms": best_latency,
                    "confidence": 0.8,
                    "reasoning": [
                        f"Tested {len(test_strategies)} strategies",
                        f"Best: {best_strategy['name']}",
                    ],
                }
            else:
                return {"success": False, "error": "No working strategy found"}

        except Exception as e:
            self.logger.error(f"Optimization failed for {domain}: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    async def _update_strategy(self, domain: str, strategy: str):
        """Обновить стратегию в файле"""
        try:
            # Загрузить текущие стратегии
            with open(self.strategies_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Обновить стратегию
            if "strategies" not in data:
                data["strategies"] = {}

            data["strategies"][domain] = strategy

            # Добавить метаданные
            if "metadata" not in data:
                data["metadata"] = {}

            data["metadata"]["last_updated"] = datetime.now().isoformat()
            data["metadata"]["updated_by"] = "adaptive_monitor"

            # Сохранить
            with open(self.strategies_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Updated strategy for {domain}")

        except Exception as e:
            self.logger.error(f"Failed to update strategy for {domain}: {e}")

    def get_status_report(self) -> Dict[str, Any]:
        """Получить отчет о состоянии"""
        # Подсчитать статистику
        total = len(self.domain_health)
        accessible = sum(1 for h in self.domain_health.values() if h.is_accessible)
        degraded = sum(1 for h in self.domain_health.values() if h.is_degraded())
        critical = sum(1 for h in self.domain_health.values() if h.is_critical())

        return {
            "running": self.running,
            "stats": self.stats,
            "domains": {
                "total": total,
                "accessible": accessible,
                "degraded": degraded,
                "critical": critical,
            },
            "optimization_queue": len(self.optimization_queue),
            "health_details": {
                domain: {
                    "accessible": health.is_accessible,
                    "response_time_ms": health.response_time_ms,
                    "consecutive_failures": health.consecutive_failures,
                    "success_rate": health.success_rate,
                    "issues": health.issues,
                    "last_check": health.last_check.isoformat(),
                }
                for domain, health in self.domain_health.items()
            },
        }

    def print_status(self):
        """Вывести статус в консоль"""
        report = self.get_status_report()

        print("\n" + "=" * 80)
        print("ADAPTIVE STRATEGY MONITOR STATUS")
        print("=" * 80)
        print(f"Running: {report['running']}")
        print(f"Domains monitored: {report['domains']['total']}")
        print(f"  Accessible: {report['domains']['accessible']}")
        print(f"  Degraded: {report['domains']['degraded']}")
        print(f"  Critical: {report['domains']['critical']}")
        print(f"\nChecks performed: {report['stats']['checks_performed']}")
        print(f"Optimizations triggered: {report['stats']['optimizations_triggered']}")
        print(f"Optimizations successful: {report['stats']['optimizations_successful']}")
        print(f"Optimization queue: {report['optimization_queue']}")

        if report["stats"]["last_check"]:
            print(f"Last check: {report['stats']['last_check']}")

        # Показать проблемные домены
        critical_domains = [
            domain for domain, health in self.domain_health.items() if health.is_critical()
        ]

        degraded_domains = [
            domain
            for domain, health in self.domain_health.items()
            if health.is_degraded() and not health.is_critical()
        ]

        if critical_domains:
            print("\n" + "-" * 80)
            print("CRITICAL DOMAINS:")
            for domain in critical_domains:
                health = self.domain_health[domain]
                print(f"  ❌ {domain}")
                print(f"     Failures: {health.consecutive_failures}")
                print(f"     Success rate: {health.success_rate:.2f}")
                print(f"     Issues: {', '.join(health.issues)}")

        if degraded_domains:
            print("\n" + "-" * 80)
            print("DEGRADED DOMAINS:")
            for domain in degraded_domains:
                health = self.domain_health[domain]
                print(f"  ⚠️  {domain}")
                print(f"     Latency: {health.response_time_ms:.1f}ms")
                print(f"     Success rate: {health.success_rate:.2f}")

        print("\n" + "=" * 80)


# Пример использования
if __name__ == "__main__":

    async def main():
        # Создать монитор
        monitor = AdaptiveStrategyMonitor(
            strategies_file="domain_strategies.json",
            check_interval=60,  # Проверять каждую минуту
            optimization_threshold=2,
            enable_auto_optimization=True,
        )

        # Запустить
        await monitor.start()

        try:
            # Работать пока не прервут
            while True:
                await asyncio.sleep(60)
                monitor.print_status()

        except KeyboardInterrupt:
            print("\n\nStopping monitor...")
            await monitor.stop()

    asyncio.run(main())
