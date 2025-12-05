#!/usr/bin/env python3
"""
Online Analysis Demo

Демонстрирует использование системы онлайн анализа трафика
и адаптивной генерации стратегий.
"""

import asyncio
import logging
import time
import signal
import sys
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.monitoring import (
    EnhancedMonitoringSystem,
    create_enhanced_monitoring_system,
    BlockingEvent,
    BlockingType
)


class OnlineAnalysisDemo:
    """Демонстрация онлайн анализа"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring_system = None
        self.running = False
        
        # Настраиваем логирование
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    async def run_demo(self):
        """Запускает демонстрацию"""
        self.logger.info("Starting Online Analysis Demo")
        
        try:
            # Создаем расширенную систему мониторинга
            self.monitoring_system = create_enhanced_monitoring_system()
            
            # Запускаем систему
            await self.monitoring_system.start()
            
            # Добавляем тестовые домены
            test_domains = [
                'x.com',
                'instagram.com', 
                'youtube.com',
                'abs-0.twimg.com'
            ]
            
            for domain in test_domains:
                self.monitoring_system.add_site(domain, enable_online_monitoring=True)
                self.logger.info(f"Added {domain} to monitoring")
            
            self.running = True
            
            # Демонстрируем различные функции
            await self._demo_monitoring_features()
            
            # Основной цикл демонстрации
            await self._main_demo_loop()
            
        except KeyboardInterrupt:
            self.logger.info("Demo interrupted by user")
        except Exception as e:
            self.logger.error(f"Error in demo: {e}")
        finally:
            await self._cleanup()
    
    async def _demo_monitoring_features(self):
        """Демонстрирует функции мониторинга"""
        self.logger.info("=== Demonstrating Monitoring Features ===")
        
        # Ждем немного для инициализации
        await asyncio.sleep(5)
        
        # Показываем статус системы
        status = self.monitoring_system.get_comprehensive_status()
        self.logger.info(f"System status: {self.monitoring_system.get_health_summary()}")
        
        # Показываем онлайн анализ статистику
        if self.monitoring_system.online_analysis:
            online_stats = self.monitoring_system.online_analysis.get_comprehensive_stats()
            self.logger.info(f"Online analysis stats: {online_stats['online_analysis_metrics']}")
        
        # Демонстрируем принудительное переключение стратегии
        self.logger.info("Demonstrating manual strategy switching...")
        
        # Создаем тестовую стратегию (в реальности она была бы сгенерирована)
        if self.monitoring_system.online_analysis:
            # Получаем доступные стратегии из кэша
            strategy_cache = self.monitoring_system.online_analysis.strategy_generator.strategy_cache
            if strategy_cache:
                strategy_id = list(strategy_cache.keys())[0]
                success = self.monitoring_system.force_strategy_switch('x.com', strategy_id)
                self.logger.info(f"Manual strategy switch result: {success}")
    
    async def _main_demo_loop(self):
        """Основной цикл демонстрации"""
        self.logger.info("=== Starting Main Demo Loop ===")
        self.logger.info("Monitoring traffic and demonstrating adaptive features...")
        self.logger.info("Press Ctrl+C to stop the demo")
        
        loop_count = 0
        
        while self.running:
            try:
                loop_count += 1
                
                # Каждые 30 секунд показываем статистику
                if loop_count % 30 == 0:
                    await self._show_periodic_stats()
                
                # Каждые 60 секунд показываем недавние события
                if loop_count % 60 == 0:
                    await self._show_recent_events()
                
                # Каждые 120 секунд экспортируем метрики
                if loop_count % 120 == 0:
                    await self._export_demo_metrics()
                
                await asyncio.sleep(1)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error in demo loop: {e}")
                await asyncio.sleep(5)
    
    async def _show_periodic_stats(self):
        """Показывает периодическую статистику"""
        self.logger.info("=== Periodic Stats Update ===")
        
        # Общий статус
        health_summary = self.monitoring_system.get_health_summary()
        self.logger.info(f"Health: {health_summary}")
        
        # Онлайн анализ метрики
        if self.monitoring_system.online_analysis:
            stats = self.monitoring_system.online_analysis.get_comprehensive_stats()
            metrics = stats.get('online_analysis_metrics', {})
            
            self.logger.info(
                f"Online Analysis: "
                f"Blocks={metrics.get('blocking_events_detected', 0)}, "
                f"Strategies={metrics.get('strategies_generated', 0)}, "
                f"Success Rate={metrics.get('avg_bypass_success_rate', 0.0):.2%}"
            )
    
    async def _show_recent_events(self):
        """Показывает недавние события"""
        self.logger.info("=== Recent Events ===")
        
        events = self.monitoring_system.get_recent_events(60)  # Последние 60 секунд
        
        if not events:
            self.logger.info("No recent events")
            return
        
        for event in events[:5]:  # Показываем только последние 5
            event_time = time.strftime('%H:%M:%S', time.localtime(event['timestamp']))
            self.logger.info(
                f"[{event_time}] {event['type']}: {event['domain']} - "
                f"{event.get('details', {})}"
            )
    
    async def _export_demo_metrics(self):
        """Экспортирует метрики демонстрации"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f"online_analysis_demo_metrics_{timestamp}.json"
        
        self.monitoring_system.export_metrics(filename)
        self.logger.info(f"Metrics exported to {filename}")
    
    async def _simulate_blocking_event(self):
        """Симулирует событие блокировки для демонстрации"""
        if not self.monitoring_system.online_analysis:
            return
        
        # Создаем тестовое событие блокировки
        from core.monitoring.real_time_traffic_analyzer import ConnectionAttempt
        
        test_connection = ConnectionAttempt(
            domain='test.example.com',
            ip='1.2.3.4',
            port=443,
            start_time=time.time(),
            end_time=time.time() + 5,
            success=False,
            rst_received=True
        )
        
        blocking_event = BlockingEvent(
            timestamp=time.time(),
            domain='test.example.com',
            ip='1.2.3.4',
            port=443,
            blocking_type=BlockingType.TCP_RST_BLOCKING,
            details={
                'connection_duration': 5.0,
                'packets_sent': 3,
                'packets_received': 0,
                'rst_received': True
            },
            confidence=0.8,
            connection_attempt=test_connection
        )
        
        # Отправляем событие в систему
        self.monitoring_system.online_analysis._on_blocking_detected(blocking_event)
        self.logger.info("Simulated blocking event sent to system")
    
    async def _cleanup(self):
        """Очищает ресурсы"""
        self.logger.info("Cleaning up demo resources...")
        
        if self.monitoring_system:
            await self.monitoring_system.stop()
        
        self.logger.info("Demo cleanup completed")
    
    def signal_handler(self, signum, frame):
        """Обработчик сигналов"""
        self.logger.info(f"Received signal {signum}, stopping demo...")
        self.running = False


async def main():
    """Главная функция демонстрации"""
    demo = OnlineAnalysisDemo()
    
    # Настраиваем обработчик сигналов
    signal.signal(signal.SIGINT, demo.signal_handler)
    signal.signal(signal.SIGTERM, demo.signal_handler)
    
    await demo.run_demo()


if __name__ == '__main__':
    print("Online Analysis Demo")
    print("===================")
    print("This demo shows the online traffic analysis and adaptive strategy generation system.")
    print("The system will monitor traffic in real-time and automatically generate strategies")
    print("to bypass detected blockings.")
    print()
    print("Note: This demo requires PyDivert for traffic capture on Windows.")
    print("      On other systems, some features may be limited.")
    print()
    print("Starting demo...")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nDemo stopped by user")
    except Exception as e:
        print(f"Demo failed: {e}")
        sys.exit(1)