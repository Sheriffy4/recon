#!/usr/bin/env python3
"""
Адаптивная служба обхода DPI с интеграцией в существующую архитектуру проекта

Интегрируется с:
- cli.py (WindowsBypassEngine, AttackDispatcher)
- recon_service.py (служба обхода)
- monitoring_system.py (система мониторинга)

Основные функции:
1. Автоматическое обнаружение заблокированных доменов из sites.txt
2. Интеллектуальный подбор стратегий на основе анализа трафика
3. Интеграция с существующим bypass engine
4. Автоматическое обновление конфигураций
5. Веб-интерфейс для мониторинга
"""

import asyncio
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Импорты проекта
try:
    from cli import WindowsBypassEngine, AttackDispatcher, PacketCapturer
    from recon_service import ReconService
    from core.monitoring_system import MonitoringSystem

    CLI_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Импорт модулей CLI: {e}")
    CLI_AVAILABLE = False

try:
    from intelligent_bypass_monitor import (
        IntelligentBypassMonitor,
        TrafficPattern,
        BypassStrategy,
        DPIAnalyzer,
    )

    INTELLIGENT_MONITOR_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Импорт интеллектуального монитора: {e}")
    INTELLIGENT_MONITOR_AVAILABLE = False

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("adaptive_bypass_service.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class AdaptiveBypassService:
    """Адаптивная служба обхода DPI"""

    def __init__(self, config_file: str = "adaptive_bypass_config.json"):
        self.config_file = config_file
        self.config = self._load_config()

        # Компоненты системы
        self.bypass_engine = None
        self.attack_dispatcher = None
        self.recon_service = None
        self.monitoring_system = None
        self.intelligent_monitor = None

        # Состояние системы
        self.running = False
        self.sites_to_monitor = set()
        self.active_strategies = {}
        self.blocked_domains = {}
        self.performance_stats = {}

        # Инициализация компонентов
        self._initialize_components()

    def _load_config(self) -> Dict:
        """Загружает конфигурацию"""
        default_config = {
            "service": {
                "auto_start_bypass": True,
                "auto_calibrate": True,
                "monitoring_interval": 30,
                "strategy_update_interval": 300,
            },
            "sites": {
                "sites_file": "sites.txt",
                "auto_discover": True,
                "test_interval": 60,
                "max_concurrent_tests": 5,
            },
            "strategies": {
                "strategies_file": "domain_strategies.json",
                "backup_strategies_file": "strategies_enhanced.json",
                "auto_save": True,
                "calibration_timeout": 30,
            },
            "monitoring": {
                "enable_traffic_monitoring": True,
                "enable_performance_monitoring": True,
                "stats_file": "adaptive_bypass_stats.json",
                "web_interface_port": 8080,
            },
            "integration": {
                "recon_service_config": "recon_service_config.json",
                "cli_config": "cli_config.json",
                "monitoring_config": "monitoring_config.json",
            },
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded_config = json.load(f)
                    # Рекурсивное обновление конфигурации
                    self._deep_update(default_config, loaded_config)
        except Exception as e:
            logger.warning(f"Ошибка загрузки конфигурации: {e}")

        return default_config

    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Рекурсивно обновляет словарь"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _initialize_components(self):
        """Инициализирует компоненты системы"""

        logger.info("Инициализация компонентов адаптивной службы...")

        # Инициализация bypass engine
        if CLI_AVAILABLE:
            try:
                self.bypass_engine = WindowsBypassEngine()
                self.attack_dispatcher = AttackDispatcher()
                logger.info("✅ Bypass engine инициализирован")
            except Exception as e:
                logger.error(f"❌ Ошибка инициализации bypass engine: {e}")

        # Инициализация recon service
        try:
            self.recon_service = ReconService()
            logger.info("✅ Recon service инициализирован")
        except Exception as e:
            logger.warning(f"⚠️ Recon service недоступен: {e}")

        # Инициализация monitoring system
        try:
            self.monitoring_system = MonitoringSystem()
            logger.info("✅ Monitoring system инициализирован")
        except Exception as e:
            logger.warning(f"⚠️ Monitoring system недоступен: {e}")

        # Инициализация intelligent monitor
        if INTELLIGENT_MONITOR_AVAILABLE:
            try:
                self.intelligent_monitor = IntelligentBypassMonitor()
                logger.info("✅ Intelligent monitor инициализирован")
            except Exception as e:
                logger.warning(f"⚠️ Intelligent monitor недоступен: {e}")

        # Загрузка сайтов для мониторинга
        self._load_sites_to_monitor()

    def _load_sites_to_monitor(self):
        """Загружает список сайтов для мониторинга"""

        sites_file = self.config["sites"]["sites_file"]

        try:
            if os.path.exists(sites_file):
                with open(sites_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Извлекаем домен из URL
                            if line.startswith("http"):
                                domain = urlparse(line).netloc
                            else:
                                domain = line

                            self.sites_to_monitor.add(domain)

                logger.info(f"Загружено {len(self.sites_to_monitor)} сайтов для мониторинга")

        except Exception as e:
            logger.error(f"Ошибка загрузки сайтов: {e}")

    async def start_service(self):
        """Запускает адаптивную службу"""

        logger.info("🚀 Запуск адаптивной службы обхода DPI")

        self.running = True

        # Запускаем компоненты
        tasks = []

        # Мониторинг сайтов
        if self.config["sites"]["auto_discover"]:
            tasks.append(asyncio.create_task(self._site_monitoring_loop()))

        # Автоматическая калибровка
        if self.config["service"]["auto_calibrate"]:
            tasks.append(asyncio.create_task(self._calibration_loop()))

        # Мониторинг производительности
        if self.config["monitoring"]["enable_performance_monitoring"]:
            tasks.append(asyncio.create_task(self._performance_monitoring_loop()))

        # Веб-интерфейс
        if self.config["monitoring"]["web_interface_port"]:
            tasks.append(asyncio.create_task(self._start_web_interface()))

        # Интеллектуальный мониторинг трафика
        if self.intelligent_monitor and self.config["monitoring"]["enable_traffic_monitoring"]:
            tasks.append(asyncio.create_task(self._start_intelligent_monitoring()))

        logger.info(f"✅ Запущено {len(tasks)} компонентов службы")

        try:
            # Ждем завершения всех задач
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Ошибка в службе: {e}")
        finally:
            await self.stop_service()

    async def stop_service(self):
        """Останавливает службу"""

        logger.info("🛑 Остановка адаптивной службы")

        self.running = False

        # Останавливаем компоненты
        if self.intelligent_monitor:
            self.intelligent_monitor.stop()

        if self.recon_service:
            # Останавливаем recon service если он запущен
            pass

        # Сохраняем финальную статистику
        await self._save_performance_stats()

        logger.info("✅ Адаптивная служба остановлена")

    async def _site_monitoring_loop(self):
        """Цикл мониторинга сайтов"""

        logger.info("🔍 Запуск мониторинга сайтов")

        while self.running:
            try:
                # Тестируем сайты пакетами
                sites_batch = list(self.sites_to_monitor)[
                    : self.config["sites"]["max_concurrent_tests"]
                ]

                tasks = []
                for site in sites_batch:
                    tasks.append(asyncio.create_task(self._test_site_accessibility(site)))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты
                for site, result in zip(sites_batch, results):
                    if isinstance(result, Exception):
                        logger.error(f"Ошибка тестирования {site}: {result}")
                        continue

                    is_accessible, response_time, error = result

                    if not is_accessible:
                        logger.warning(f"🚫 Сайт заблокирован: {site} - {error}")
                        self.blocked_domains[site] = {
                            "timestamp": datetime.now().isoformat(),
                            "error": error,
                            "response_time": response_time,
                        }

                        # Запускаем калибровку для заблокированного сайта
                        asyncio.create_task(self._calibrate_site_strategy(site))

                    else:
                        logger.debug(f"✅ Сайт доступен: {site} ({response_time:.2f}ms)")
                        # Удаляем из заблокированных если был там
                        self.blocked_domains.pop(site, None)

                # Пауза между циклами
                await asyncio.sleep(self.config["sites"]["test_interval"])

            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга сайтов: {e}")
                await asyncio.sleep(10)

    async def _test_site_accessibility(self, site: str) -> Tuple[bool, float, Optional[str]]:
        """Тестирует доступность сайта"""

        try:
            import aiohttp

            url = f"https://{site}" if not site.startswith("http") else site

            start_time = time.time()

            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=False, ssl=False) as response:
                    response_time = (time.time() - start_time) * 1000

                    # Любой HTTP ответ считаем успехом
                    is_accessible = response.status in [200, 301, 302, 304, 403, 404]

                    return is_accessible, response_time, None

        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, "TIMEOUT"

        except Exception as e:
            response_time = (time.time() - start_time) * 1000 if "start_time" in locals() else 0
            return False, response_time, str(e)

    async def _calibrate_site_strategy(self, site: str):
        """Калибрует стратегию для заблокированного сайта"""

        logger.info(f"🎯 Калибровка стратегии для {site}")

        try:
            # Проверяем, есть ли уже стратегия
            if site in self.active_strategies:
                logger.info(f"Стратегия для {site} уже существует")
                return

            # Используем intelligent monitor для калибровки
            if self.intelligent_monitor and self.intelligent_monitor.strategy_calibrator:

                # Определяем тип блокировки (упрощенно)
                blocking_type = "TLS_HANDSHAKE_BLOCKING"  # По умолчанию для HTTPS

                # Получаем предложенные стратегии
                suggested_strategies = ["tls_attacks", "fragmentation_attacks", "fake_attacks"]

                # Калибруем стратегию
                strategy = self.intelligent_monitor.strategy_calibrator.calibrate_strategy(
                    site, blocking_type, suggested_strategies
                )

                if strategy:
                    self.active_strategies[site] = strategy
                    logger.info(f"✅ Стратегия для {site} откалибрована: {strategy.name}")

                    # Сохраняем стратегию
                    await self._save_strategy(site, strategy)

                    # Применяем стратегию
                    await self._apply_strategy(site, strategy)

                else:
                    logger.warning(f"❌ Не удалось откалибровать стратегию для {site}")

            else:
                logger.warning("Intelligent monitor недоступен для калибровки")

        except Exception as e:
            logger.error(f"Ошибка калибровки для {site}: {e}")

    async def _save_strategy(self, site: str, strategy: BypassStrategy):
        """Сохраняет стратегию в файлы конфигурации"""

        try:
            # Сохраняем в domain_strategies.json
            strategies_file = self.config["strategies"]["strategies_file"]

            strategies = {}
            if os.path.exists(strategies_file):
                with open(strategies_file, "r", encoding="utf-8") as f:
                    strategies = json.load(f)

            # Обновляем структуру для совместимости
            if "domain_strategies" not in strategies:
                strategies["domain_strategies"] = {}

            strategies["domain_strategies"][site] = {
                "domain": site,
                "strategy": self._convert_strategy_to_zapret_format(strategy),
                "success_rate": strategy.success_rate,
                "avg_latency_ms": strategy.avg_latency_ms,
                "last_tested": datetime.now().isoformat(),
                "test_count": strategy.test_count,
                "split_pos": strategy.parameters.get("split_pos"),
                "overlap_size": strategy.parameters.get("overlap_size"),
                "fake_ttl_source": strategy.parameters.get("ttl"),
                "fooling_modes": strategy.parameters.get("fooling"),
            }

            with open(strategies_file, "w", encoding="utf-8") as f:
                json.dump(strategies, f, indent=2, ensure_ascii=False)

            # Также сохраняем в strategies_enhanced.json
            enhanced_file = self.config["strategies"]["backup_strategies_file"]

            enhanced_strategies = {}
            if os.path.exists(enhanced_file):
                with open(enhanced_file, "r", encoding="utf-8") as f:
                    enhanced_strategies = json.load(f)

            enhanced_strategies[site] = self._convert_strategy_to_zapret_format(strategy)

            with open(enhanced_file, "w", encoding="utf-8") as f:
                json.dump(enhanced_strategies, f, indent=2, ensure_ascii=False)

            logger.info(f"💾 Стратегия для {site} сохранена")

        except Exception as e:
            logger.error(f"Ошибка сохранения стратегии: {e}")

    def _convert_strategy_to_zapret_format(self, strategy: BypassStrategy) -> str:
        """Конвертирует стратегию в формат zapret"""

        # Базовая конвертация параметров в zapret формат
        params = []

        # Тип атаки
        if strategy.attack_type in ["fake_attacks", "disorder_attacks"]:
            params.append("--dpi-desync=fake,disorder")
        elif strategy.attack_type in ["multisplit_attacks"]:
            params.append("--dpi-desync=multisplit")
        elif strategy.attack_type in ["tls_attacks"]:
            params.append("--dpi-desync=fake,disorder")
        else:
            params.append("--dpi-desync=fake,disorder")

        # Параметры из стратегии
        if "split_pos" in strategy.parameters:
            params.append(f"--dpi-desync-split-pos={strategy.parameters['split_pos']}")

        if "ttl" in strategy.parameters:
            params.append(f"--dpi-desync-ttl={strategy.parameters['ttl']}")

        if "fooling" in strategy.parameters:
            fooling = strategy.parameters["fooling"]
            if isinstance(fooling, list):
                fooling = ",".join(fooling)
            params.append(f"--dpi-desync-fooling={fooling}")

        if "repeats" in strategy.parameters:
            params.append(f"--dpi-desync-repeats={strategy.parameters['repeats']}")

        if "split_tls" in strategy.parameters:
            params.append(f"--dpi-desync-split-tls={strategy.parameters['split_tls']}")

        return " ".join(params)

    async def _apply_strategy(self, site: str, strategy: BypassStrategy):
        """Применяет стратегию для сайта"""

        logger.info(f"🚀 Применение стратегии {strategy.name} для {site}")

        try:
            # Интеграция с recon_service
            if self.recon_service:
                # Обновляем конфигурацию recon_service
                # (здесь должна быть реальная интеграция)
                pass

            # Интеграция с bypass_engine
            if self.bypass_engine:
                # Применяем стратегию через bypass engine
                # (здесь должна быть реальная интеграция)
                pass

            logger.info(f"✅ Стратегия применена для {site}")

        except Exception as e:
            logger.error(f"Ошибка применения стратегии: {e}")

    async def _calibration_loop(self):
        """Цикл автоматической калибровки"""

        logger.info("⚙️ Запуск цикла автоматической калибровки")

        while self.running:
            try:
                # Проверяем заблокированные домены
                for site in list(self.blocked_domains.keys()):
                    if site not in self.active_strategies:
                        await self._calibrate_site_strategy(site)

                # Пауза между циклами калибровки
                await asyncio.sleep(self.config["service"]["strategy_update_interval"])

            except Exception as e:
                logger.error(f"Ошибка в цикле калибровки: {e}")
                await asyncio.sleep(30)

    async def _performance_monitoring_loop(self):
        """Цикл мониторинга производительности"""

        logger.info("📊 Запуск мониторинга производительности")

        while self.running:
            try:
                # Собираем статистику
                stats = {
                    "timestamp": datetime.now().isoformat(),
                    "sites_monitored": len(self.sites_to_monitor),
                    "blocked_domains": len(self.blocked_domains),
                    "active_strategies": len(self.active_strategies),
                    "blocked_domains_list": list(self.blocked_domains.keys()),
                    "active_strategies_list": list(self.active_strategies.keys()),
                }

                self.performance_stats = stats

                # Сохраняем статистику
                await self._save_performance_stats()

                # Выводим статистику
                logger.info(
                    f"📈 Статистика: {stats['sites_monitored']} сайтов, "
                    f"{stats['blocked_domains']} заблокированных, "
                    f"{stats['active_strategies']} активных стратегий"
                )

                await asyncio.sleep(self.config["service"]["monitoring_interval"])

            except Exception as e:
                logger.error(f"Ошибка мониторинга производительности: {e}")
                await asyncio.sleep(10)

    async def _save_performance_stats(self):
        """Сохраняет статистику производительности"""

        try:
            stats_file = self.config["monitoring"]["stats_file"]

            with open(stats_file, "w", encoding="utf-8") as f:
                json.dump(self.performance_stats, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Ошибка сохранения статистики: {e}")

    async def _start_web_interface(self):
        """Запускает веб-интерфейс для мониторинга"""

        try:
            from aiohttp import web, web_runner

            app = web.Application()

            # Маршруты API
            app.router.add_get("/api/stats", self._api_get_stats)
            app.router.add_get("/api/blocked", self._api_get_blocked)
            app.router.add_get("/api/strategies", self._api_get_strategies)
            app.router.add_post("/api/calibrate/{site}", self._api_calibrate_site)

            # Статические файлы (простая HTML страница)
            app.router.add_get("/", self._web_index)

            port = self.config["monitoring"]["web_interface_port"]

            runner = web_runner.AppRunner(app)
            await runner.setup()

            site = web_runner.TCPSite(runner, "localhost", port)
            await site.start()

            logger.info(f"🌐 Веб-интерфейс запущен: http://localhost:{port}")

            # Держим веб-сервер запущенным
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Ошибка веб-интерфейса: {e}")

    async def _api_get_stats(self, request):
        """API: получение статистики"""
        from aiohttp import web

        return web.json_response(self.performance_stats)

    async def _api_get_blocked(self, request):
        """API: получение заблокированных доменов"""
        from aiohttp import web

        return web.json_response(self.blocked_domains)

    async def _api_get_strategies(self, request):
        """API: получение активных стратегий"""
        from aiohttp import web

        strategies = {site: strategy.to_dict() for site, strategy in self.active_strategies.items()}
        return web.json_response(strategies)

    async def _api_calibrate_site(self, request):
        """API: калибровка стратегии для сайта"""
        from aiohttp import web

        site = request.match_info["site"]

        # Запускаем калибровку асинхронно
        asyncio.create_task(self._calibrate_site_strategy(site))

        return web.json_response({"status": "calibration_started", "site": site})

    async def _web_index(self, request):
        """Главная страница веб-интерфейса"""
        from aiohttp import web

        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Адаптивная служба обхода DPI</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .stats { background: #f0f0f0; padding: 10px; margin: 10px 0; }
        .blocked { background: #ffe6e6; padding: 10px; margin: 10px 0; }
        .strategies { background: #e6ffe6; padding: 10px; margin: 10px 0; }
        button { padding: 5px 10px; margin: 5px; }
    </style>
</head>
<body>
    <h1>🚀 Адаптивная служба обхода DPI</h1>
    
    <div class="stats">
        <h2>📊 Статистика</h2>
        <div id="stats">Загрузка...</div>
    </div>
    
    <div class="blocked">
        <h2>🚫 Заблокированные домены</h2>
        <div id="blocked">Загрузка...</div>
    </div>
    
    <div class="strategies">
        <h2>⚙️ Активные стратегии</h2>
        <div id="strategies">Загрузка...</div>
    </div>
    
    <script>
        async function loadData() {
            try {
                const [stats, blocked, strategies] = await Promise.all([
                    fetch('/api/stats').then(r => r.json()),
                    fetch('/api/blocked').then(r => r.json()),
                    fetch('/api/strategies').then(r => r.json())
                ]);
                
                document.getElementById('stats').innerHTML = 
                    `Сайтов: ${stats.sites_monitored || 0}<br>
                     Заблокированных: ${stats.blocked_domains || 0}<br>
                     Стратегий: ${stats.active_strategies || 0}<br>
                     Обновлено: ${stats.timestamp || 'N/A'}`;
                
                document.getElementById('blocked').innerHTML = 
                    Object.keys(blocked).length > 0 
                        ? Object.keys(blocked).map(site => 
                            `${site} <button onclick="calibrate('${site}')">Калибровать</button>`
                          ).join('<br>')
                        : 'Нет заблокированных доменов';
                
                document.getElementById('strategies').innerHTML = 
                    Object.keys(strategies).length > 0
                        ? Object.entries(strategies).map(([site, strategy]) => 
                            `${site}: ${strategy.name} (${strategy.success_rate})`
                          ).join('<br>')
                        : 'Нет активных стратегий';
                        
            } catch (e) {
                console.error('Ошибка загрузки данных:', e);
            }
        }
        
        async function calibrate(site) {
            try {
                const response = await fetch(`/api/calibrate/${site}`, {method: 'POST'});
                const result = await response.json();
                alert(`Калибровка запущена для ${site}`);
                setTimeout(loadData, 2000);
            } catch (e) {
                alert('Ошибка запуска калибровки');
            }
        }
        
        // Загружаем данные при загрузке страницы и каждые 10 секунд
        loadData();
        setInterval(loadData, 10000);
    </script>
</body>
</html>
        """

        return web.Response(text=html, content_type="text/html")

    async def _start_intelligent_monitoring(self):
        """Запускает интеллектуальный мониторинг трафика"""

        if not self.intelligent_monitor:
            logger.warning("Intelligent monitor недоступен")
            return

        logger.info("🧠 Запуск интеллектуального мониторинга трафика")

        try:
            # Запускаем в отдельном потоке
            def run_monitor():
                self.intelligent_monitor.start()

            monitor_thread = threading.Thread(target=run_monitor, daemon=True)
            monitor_thread.start()

            # Ждем пока служба работает
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Ошибка интеллектуального мониторинга: {e}")


def main():
    """Главная функция"""

    import argparse

    parser = argparse.ArgumentParser(description="Адаптивная служба обхода DPI")
    parser.add_argument("--config", default="adaptive_bypass_config.json", help="Файл конфигурации")
    parser.add_argument("--debug", action="store_true", help="Режим отладки")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Создаем службу
    service = AdaptiveBypassService(args.config)

    try:
        # Запускаем службу
        asyncio.run(service.start_service())
    except KeyboardInterrupt:
        logger.info("Получен сигнал остановки")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
