# recon/recon_service.py - Служба обхода DPI с поддержкой стратегий по доменам

import os
import sys
import json
import logging
import time
import signal
from pathlib import Path
from typing import Dict, Set, Optional
from urllib.parse import urlparse

# Добавляем путь к проекту
if __name__ == "__main__" and __package__ is None:
    recon_dir = Path(__file__).parent
    project_root = recon_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.live import Live
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    class Console:
        def print(self, *args, **kwargs): print(*args)

console = Console() if RICH_AVAILABLE else Console()

class DPIBypassService:
    """Служба обхода DPI с поддержкой стратегий по доменам."""
    
    def __init__(self):
        self.running = False
        self.domain_strategies: Dict[str, str] = {}
        self.monitored_domains: Set[str] = set()
        self.bypass_engine = None
        self.logger = self.setup_logging()
        
        # Настройка обработчиков сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self) -> logging.Logger:
        """Настраивает логирование."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        return logging.getLogger("ReconService")
    
    def signal_handler(self, signum, frame):
        """Обработчик сигналов для graceful shutdown."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def load_strategies(self) -> bool:
        """Загружает стратегии из файлов конфигурации."""
        strategies_loaded = 0
        
        # 1. Пытаемся загрузить из нового формата (domain_strategies.json)
        domain_strategies_file = Path("domain_strategies.json")
        if domain_strategies_file.exists():
            try:
                with open(domain_strategies_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                domain_strategies = data.get('domain_strategies', {})
                for domain, strategy_data in domain_strategies.items():
                    strategy = strategy_data.get('strategy', '')
                    if strategy:
                        self.domain_strategies[domain] = strategy
                        strategies_loaded += 1
                
                if strategies_loaded > 0:
                    self.logger.info(f"✅ Loaded {strategies_loaded} domain-specific strategies")
                    return True
            except Exception as e:
                self.logger.warning(f"Failed to load domain strategies: {e}")
        
        # 2. Fallback к старому формату (best_strategy.json)
        legacy_file = Path("best_strategy.json")
        if legacy_file.exists():
            try:
                with open(legacy_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                strategy = data.get('strategy', '')
                if strategy:
                    # Используем стратегию для всех доменов
                    self.domain_strategies['default'] = strategy
                    strategies_loaded = 1
                    self.logger.info(f"✅ Loaded legacy strategy for all domains")
                    return True
            except Exception as e:
                self.logger.warning(f"Failed to load legacy strategy: {e}")
        
        return False
    
    def load_domains(self) -> bool:
        """Загружает список доменов для мониторинга."""
        domains_loaded = 0
        
        # Загружаем из sites.txt
        sites_file = Path("sites.txt")
        if sites_file.exists():
            try:
                with open(sites_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Извлекаем домен из URL или используем как есть
                            if line.startswith(('http://', 'https://')):
                                domain = urlparse(line).hostname
                            else:
                                domain = line.split(':')[0]  # Убираем порт если есть
                            
                            if domain:
                                self.monitored_domains.add(domain.lower())
                                domains_loaded += 1
                
                if domains_loaded > 0:
                    self.logger.info(f"✅ Loaded {domains_loaded} domains from sites.txt")
                    return True
            except Exception as e:
                self.logger.warning(f"Failed to load domains: {e}")
        
        # Если нет sites.txt, используем домены из стратегий
        if self.domain_strategies:
            for domain in self.domain_strategies.keys():
                if domain != 'default':
                    self.monitored_domains.add(domain.lower())
                    domains_loaded += 1
            
            if domains_loaded > 0:
                self.logger.info(f"✅ Using {domains_loaded} domains from strategies")
                return True
        
        return False
    
    def get_strategy_for_domain(self, domain: str) -> Optional[str]:
        """Получает стратегию для конкретного домена."""
        domain = domain.lower()
        
        # 1. Ищем точное совпадение
        if domain in self.domain_strategies:
            return self.domain_strategies[domain]
        
        # 2. Ищем по поддомену (например, www.example.com -> example.com)
        for strategy_domain in self.domain_strategies:
            if domain.endswith('.' + strategy_domain):
                return self.domain_strategies[strategy_domain]
        
        # 3. Используем стратегию по умолчанию
        return self.domain_strategies.get('default')
    
    def start_bypass_engine(self):
        """Запускает движок обхода DPI."""
        try:
            from recon.core.bypass_engine import BypassEngine
            
            # Создаем движок обхода без отладки для чистого вывода
            self.bypass_engine = BypassEngine(debug=False)
            
            # Собираем все уникальные стратегии
            unique_strategies = set()
            domain_strategy_map = {}
            
            for domain in self.monitored_domains:
                strategy = self.get_strategy_for_domain(domain)
                if strategy:
                    unique_strategies.add(strategy)
                    domain_strategy_map[domain] = strategy
                    self.logger.info(f"Mapped {domain} -> {strategy}")
            
            if not unique_strategies:
                self.logger.error("❌ No strategies found for any domain")
                return False
            
            # Запускаем движок обхода с первой стратегией
            # (BypassEngine применяет стратегию ко всему трафику на порт 443)
            primary_strategy = next(iter(unique_strategies))
            self.logger.info(f"🚀 Starting BypassEngine with primary strategy: {primary_strategy}")
            
            # Парсим стратегию для BypassEngine
            strategy_config = self.parse_strategy_config(primary_strategy)
            
            # Запускаем движок с конфигурацией
            self.bypass_engine.start_with_config(strategy_config)
            
            self.logger.info("✅ DPI Bypass Engine started successfully")
            self.logger.info(f"🛡️ Protecting {len(self.monitored_domains)} domains with bypass")
            
            return True
        except ImportError as e:
            self.logger.error(f"❌ Failed to import BypassEngine: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Failed to start bypass engine: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    def parse_strategy_config(self, strategy: str) -> dict:
        """Парсит строку стратегии в конфигурацию для BypassEngine."""
        config = {
            'desync_method': 'fake',
            'ttl': 3,
            'split_pos': 3,
            'fooling': 'badsum'
        }
        
        try:
            # Парсим параметры из строки стратегии
            parts = strategy.split()
            
            for i, part in enumerate(parts):
                if part.startswith('--dpi-desync='):
                    methods = part.split('=')[1]
                    config['desync_method'] = methods.split(',')[0]  # Берем первый метод
                
                elif part.startswith('--dpi-desync-ttl='):
                    config['ttl'] = int(part.split('=')[1])
                
                elif part.startswith('--dpi-desync-split-pos='):
                    pos_value = part.split('=')[1]
                    if pos_value.isdigit():
                        config['split_pos'] = int(pos_value)
                    elif ',' in pos_value:
                        # Берем первую позицию из списка
                        config['split_pos'] = int(pos_value.split(',')[0])
                
                elif part.startswith('--dpi-desync-fooling='):
                    fooling = part.split('=')[1]
                    config['fooling'] = fooling.split(',')[0]  # Берем первый метод
                
                elif part.startswith('--dpi-desync-split-count='):
                    config['split_count'] = int(part.split('=')[1])
                
                elif part.startswith('--dpi-desync-split-seqovl='):
                    config['overlap_size'] = int(part.split('=')[1])
            
            self.logger.info(f"Parsed strategy config: {config}")
            return config
            
        except Exception as e:
            self.logger.warning(f"Failed to parse strategy config: {e}, using defaults")
            return config
    
    def stop_bypass_engine(self):
        """Останавливает движок обхода DPI."""
        if self.bypass_engine:
            try:
                self.bypass_engine.stop()
                self.logger.info("🛑 DPI Bypass Engine stopped")
            except Exception as e:
                self.logger.error(f"Error stopping bypass engine: {e}")
        else:
            self.logger.info("🛑 No bypass engine to stop")
    
    def print_status(self):
        """Выводит текущий статус службы."""
        if not RICH_AVAILABLE:
            print(f"Domains: {len(self.monitored_domains)}, Strategies: {len(self.domain_strategies)}")
            return
        
        table = Table(title="🛡️ DPI Bypass Service Status")
        table.add_column("Domain", style="cyan")
        table.add_column("Strategy", style="green")
        table.add_column("Status", justify="center")
        
        for domain in sorted(self.monitored_domains):
            strategy = self.get_strategy_for_domain(domain)
            if strategy:
                # Сокращаем длинные стратегии
                short_strategy = strategy[:50] + "..." if len(strategy) > 50 else strategy
                table.add_row(domain, short_strategy, "✅ Active")
            else:
                table.add_row(domain, "No strategy", "❌ Inactive")
        
        console.print(table)
    
    def run(self):
        """Основной цикл службы."""
        console.print(Panel(
            "[bold cyan]🛡️ Recon DPI Bypass Service[/bold cyan]\n"
            "[dim]Advanced multi-domain bypass with adaptive strategies[/dim]",
            title="Starting Service"
        ))
        
        # Загружаем конфигурацию
        if not self.load_strategies():
            self.logger.error("❌ No strategies found in configuration files")
            console.print("[red]❌ No strategies found. Please run strategy discovery first:[/red]")
            console.print("[yellow]   python cli.py your-domain.com --count 10[/yellow]")
            return False
        
        if not self.load_domains():
            self.logger.error("❌ No domains found for monitoring")
            console.print("[red]❌ No domains found. Please create sites.txt file[/red]")
            return False
        
        # Запускаем движок обхода
        if not self.start_bypass_engine():
            return False
        
        # Показываем статус
        self.print_status()
        
        console.print(Panel(
            f"[bold green]✅ Service Started Successfully[/bold green]\n\n"
            f"Monitoring {len(self.monitored_domains)} domains\n"
            f"Using {len(self.domain_strategies)} strategies\n\n"
            f"[dim]Press Ctrl+C to stop the service[/dim]",
            title="Service Running"
        ))
        
        # Основной цикл
        self.running = True
        try:
            while self.running:
                time.sleep(1)
                # Здесь может быть логика мониторинга и обновления стратегий
        
        except KeyboardInterrupt:
            self.logger.info("Service interrupted by user")
        
        finally:
            self.stop_bypass_engine()
            console.print("[green]✅ Service stopped gracefully[/green]")
        
        return True

def main():
    """Точка входа в службу."""
    service = DPIBypassService()
    
    try:
        success = service.run()
        return 0 if success else 1
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())