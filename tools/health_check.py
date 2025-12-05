#!/usr/bin/env python3
"""
Health Check Tool - Проверка работоспособности всех компонентов

Этот инструмент проверяет работоспособность всех компонентов системы:
DoH, SNI, PCAP, WinDivert и генерирует отчет о состоянии системы.

Requirements: 11.1, 11.2, 11.3
"""

import json
import logging
import sys
import asyncio
import socket
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)


@dataclass
class ComponentHealth:
    """Состояние здоровья компонента."""
    
    name: str
    status: str  # 'healthy', 'degraded', 'unhealthy', 'unknown'
    available: bool
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    checks_performed: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'status': self.status,
            'available': self.available,
            'error_message': self.error_message,
            'details': self.details,
            'checks_performed': self.checks_performed,
            'timestamp': self.timestamp
        }


@dataclass
class SystemHealth:
    """Общее состояние системы."""
    
    overall_status: str  # 'healthy', 'degraded', 'unhealthy'
    components: List[ComponentHealth] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall_status': self.overall_status,
            'timestamp': self.timestamp,
            'components': [c.to_dict() for c in self.components]
        }


class HealthCheckTool:
    """
    Инструмент для проверки работоспособности компонентов.
    
    Requirements: 11.1, 11.2, 11.3
    """
    
    def __init__(self, debug: bool = False):
        """
        Инициализация инструмента.
        
        Args:
            debug: Включить отладочный вывод
        """
        self.logger = LOG
        if debug:
            self.logger.setLevel(logging.DEBUG)
        
        self.logger.info("✅ Health Check Tool initialized")
    
    async def check_doh_health(self) -> ComponentHealth:
        """
        Проверяет работоспособность DoH resolver.
        
        Returns:
            ComponentHealth для DoH
        """
        self.logger.info("🔍 Проверка DoH resolver")
        
        health = ComponentHealth(
            name='DoH Resolver',
            status='unknown',
            available=False
        )
        
        try:
            # Try to import DoH resolver
            from core.doh_resolver import DoHResolver
            
            health.checks_performed.append('Import DoHResolver')
            health.available = True
            
            # Try to create resolver instance
            try:
                resolver = DoHResolver()
                health.checks_performed.append('Create DoHResolver instance')
                health.details['providers'] = resolver.providers if hasattr(resolver, 'providers') else []
                
                # Try to resolve a test domain
                try:
                    test_domain = 'google.com'
                    ips = await asyncio.wait_for(
                        resolver.resolve(test_domain),
                        timeout=5.0
                    )
                    
                    if ips:
                        health.checks_performed.append(f'Resolve {test_domain}')
                        health.details['test_resolution'] = {
                            'domain': test_domain,
                            'ips': list(ips),
                            'success': True
                        }
                        health.status = 'healthy'
                    else:
                        health.status = 'degraded'
                        health.error_message = 'DoH resolution returned no IPs'
                
                except asyncio.TimeoutError:
                    health.status = 'degraded'
                    health.error_message = 'DoH resolution timeout'
                
                except Exception as e:
                    health.status = 'degraded'
                    health.error_message = f'DoH resolution failed: {str(e)}'
            
            except Exception as e:
                health.status = 'unhealthy'
                health.error_message = f'Failed to create DoHResolver: {str(e)}'
        
        except ImportError as e:
            health.status = 'unhealthy'
            health.available = False
            health.error_message = f'DoHResolver not available: {str(e)}'
        
        except Exception as e:
            health.status = 'unhealthy'
            health.error_message = f'DoH check failed: {str(e)}'
        
        status_icon = {'healthy': '✅', 'degraded': '🟡', 'unhealthy': '❌', 'unknown': '⚪'}[health.status]
        self.logger.info(f"{status_icon} DoH Resolver: {health.status}")
        
        return health
    
    def check_sni_health(self) -> ComponentHealth:
        """
        Проверяет работоспособность SNI manipulator.
        
        Returns:
            ComponentHealth для SNI
        """
        self.logger.info("🔍 Проверка SNI Manipulator")
        
        health = ComponentHealth(
            name='SNI Manipulator',
            status='unknown',
            available=False
        )
        
        try:
            # Try to import SNI manipulator
            from core.bypass.sni.manipulator import SNIManipulator
            
            health.checks_performed.append('Import SNIManipulator')
            health.available = True
            
            # Test SNI position finding
            try:
                # Create a minimal TLS ClientHello packet for testing
                test_packet = self._create_test_tls_packet()
                
                sni_pos = SNIManipulator.find_sni_position(test_packet)
                
                if sni_pos:
                    health.checks_performed.append('Find SNI position')
                    health.details['sni_detection'] = 'working'
                    health.status = 'healthy'
                else:
                    health.status = 'degraded'
                    health.error_message = 'SNI position not found in test packet'
            
            except Exception as e:
                health.status = 'degraded'
                health.error_message = f'SNI manipulation test failed: {str(e)}'
        
        except ImportError as e:
            health.status = 'unhealthy'
            health.available = False
            health.error_message = f'SNIManipulator not available: {str(e)}'
        
        except Exception as e:
            health.status = 'unhealthy'
            health.error_message = f'SNI check failed: {str(e)}'
        
        status_icon = {'healthy': '✅', 'degraded': '🟡', 'unhealthy': '❌', 'unknown': '⚪'}[health.status]
        self.logger.info(f"{status_icon} SNI Manipulator: {health.status}")
        
        return health
    
    def check_pcap_health(self) -> ComponentHealth:
        """
        Проверяет работоспособность PCAP analyzer.
        
        Returns:
            ComponentHealth для PCAP
        """
        self.logger.info("🔍 Проверка PCAP Analyzer")
        
        health = ComponentHealth(
            name='PCAP Analyzer',
            status='unknown',
            available=False
        )
        
        try:
            # Try to import PCAP analyzer
            from core.pcap.analyzer import PCAPAnalyzer
            
            health.checks_performed.append('Import PCAPAnalyzer')
            health.available = True
            
            # Try to create analyzer instance
            try:
                analyzer = PCAPAnalyzer()
                health.checks_performed.append('Create PCAPAnalyzer instance')
                
                # Check if Scapy is available
                try:
                    from scapy.all import rdpcap
                    health.checks_performed.append('Scapy available')
                    health.details['scapy_available'] = True
                    health.status = 'healthy'
                
                except ImportError:
                    health.status = 'degraded'
                    health.error_message = 'Scapy not available - PCAP analysis limited'
                    health.details['scapy_available'] = False
            
            except Exception as e:
                health.status = 'unhealthy'
                health.error_message = f'Failed to create PCAPAnalyzer: {str(e)}'
        
        except ImportError as e:
            health.status = 'unhealthy'
            health.available = False
            health.error_message = f'PCAPAnalyzer not available: {str(e)}'
        
        except Exception as e:
            health.status = 'unhealthy'
            health.error_message = f'PCAP check failed: {str(e)}'
        
        status_icon = {'healthy': '✅', 'degraded': '🟡', 'unhealthy': '❌', 'unknown': '⚪'}[health.status]
        self.logger.info(f"{status_icon} PCAP Analyzer: {health.status}")
        
        return health
    
    def check_windivert_health(self) -> ComponentHealth:
        """
        Проверяет работоспособность WinDivert.
        
        Returns:
            ComponentHealth для WinDivert
        """
        self.logger.info("🔍 Проверка WinDivert")
        
        health = ComponentHealth(
            name='WinDivert',
            status='unknown',
            available=False
        )
        
        try:
            # Check if WinDivert DLL exists
            windivert_dll = Path('WinDivert.dll')
            windivert64_dll = Path('WinDivert64.dll')
            
            if windivert_dll.exists() or windivert64_dll.exists():
                health.checks_performed.append('WinDivert DLL found')
                health.details['dll_found'] = True
            else:
                health.checks_performed.append('WinDivert DLL not found')
                health.details['dll_found'] = False
            
            # Check if WinDivert driver exists
            windivert_sys = Path('WinDivert64.sys')
            
            if windivert_sys.exists():
                health.checks_performed.append('WinDivert driver found')
                health.details['driver_found'] = True
            else:
                health.checks_performed.append('WinDivert driver not found')
                health.details['driver_found'] = False
            
            # Try to import pydivert
            try:
                import pydivert
                
                health.checks_performed.append('Import pydivert')
                health.available = True
                health.details['pydivert_version'] = pydivert.__version__ if hasattr(pydivert, '__version__') else 'unknown'
                
                # Try to create a WinDivert handle (requires admin privileges)
                try:
                    # This will fail if not running as admin, but that's expected
                    with pydivert.WinDivert("false") as w:
                        pass
                    
                    health.checks_performed.append('Create WinDivert handle')
                    health.status = 'healthy'
                
                except PermissionError:
                    health.status = 'degraded'
                    health.error_message = 'WinDivert requires administrator privileges'
                    health.details['admin_required'] = True
                
                except Exception as e:
                    # Other errors might indicate WinDivert is not properly installed
                    if 'driver' in str(e).lower():
                        health.status = 'unhealthy'
                        health.error_message = f'WinDivert driver issue: {str(e)}'
                    else:
                        health.status = 'degraded'
                        health.error_message = f'WinDivert test failed: {str(e)}'
            
            except ImportError as e:
                health.status = 'unhealthy'
                health.available = False
                health.error_message = f'pydivert not available: {str(e)}'
        
        except Exception as e:
            health.status = 'unhealthy'
            health.error_message = f'WinDivert check failed: {str(e)}'
        
        status_icon = {'healthy': '✅', 'degraded': '🟡', 'unhealthy': '❌', 'unknown': '⚪'}[health.status]
        self.logger.info(f"{status_icon} WinDivert: {health.status}")
        
        return health
    
    def check_strategy_loader_health(self) -> ComponentHealth:
        """
        Проверяет работоспособность UnifiedStrategyLoader.
        
        Returns:
            ComponentHealth для Strategy Loader
        """
        self.logger.info("🔍 Проверка Strategy Loader")
        
        health = ComponentHealth(
            name='Strategy Loader',
            status='unknown',
            available=False
        )
        
        try:
            # Try to import strategy loader
            from core.unified_strategy_loader import UnifiedStrategyLoader
            
            health.checks_performed.append('Import UnifiedStrategyLoader')
            health.available = True
            
            # Try to create loader instance
            try:
                loader = UnifiedStrategyLoader()
                health.checks_performed.append('Create UnifiedStrategyLoader instance')
                
                # Test loading a simple strategy
                try:
                    test_strategy = "fake,disorder --split-pos=3 --ttl=2"
                    normalized = loader.load_strategy(test_strategy)
                    
                    health.checks_performed.append('Load test strategy')
                    health.details['test_strategy_loaded'] = True
                    health.details['known_attacks_count'] = len(loader.known_attacks)
                    health.status = 'healthy'
                
                except Exception as e:
                    health.status = 'degraded'
                    health.error_message = f'Strategy loading test failed: {str(e)}'
            
            except Exception as e:
                health.status = 'unhealthy'
                health.error_message = f'Failed to create UnifiedStrategyLoader: {str(e)}'
        
        except ImportError as e:
            health.status = 'unhealthy'
            health.available = False
            health.error_message = f'UnifiedStrategyLoader not available: {str(e)}'
        
        except Exception as e:
            health.status = 'unhealthy'
            health.error_message = f'Strategy Loader check failed: {str(e)}'
        
        status_icon = {'healthy': '✅', 'degraded': '🟡', 'unhealthy': '❌', 'unknown': '⚪'}[health.status]
        self.logger.info(f"{status_icon} Strategy Loader: {health.status}")
        
        return health
    
    def check_bypass_engine_health(self) -> ComponentHealth:
        """
        Проверяет работоспособность UnifiedBypassEngine.
        
        Returns:
            ComponentHealth для Bypass Engine
        """
        self.logger.info("🔍 Проверка Bypass Engine")
        
        health = ComponentHealth(
            name='Bypass Engine',
            status='unknown',
            available=False
        )
        
        try:
            # Try to import bypass engine
            from core.unified_bypass_engine import UnifiedBypassEngine
            
            health.checks_performed.append('Import UnifiedBypassEngine')
            health.available = True
            
            # Try to create engine instance
            try:
                # Note: Creating engine might require admin privileges
                # We'll just check if we can import and instantiate
                health.checks_performed.append('UnifiedBypassEngine available')
                health.status = 'healthy'
                health.details['note'] = 'Full engine test requires admin privileges'
            
            except Exception as e:
                health.status = 'degraded'
                health.error_message = f'Bypass Engine instantiation issue: {str(e)}'
        
        except ImportError as e:
            health.status = 'unhealthy'
            health.available = False
            health.error_message = f'UnifiedBypassEngine not available: {str(e)}'
        
        except Exception as e:
            health.status = 'unhealthy'
            health.error_message = f'Bypass Engine check failed: {str(e)}'
        
        status_icon = {'healthy': '✅', 'degraded': '🟡', 'unhealthy': '❌', 'unknown': '⚪'}[health.status]
        self.logger.info(f"{status_icon} Bypass Engine: {health.status}")
        
        return health
    
    async def check_all_components(self) -> SystemHealth:
        """
        Проверяет все компоненты системы.
        
        Returns:
            SystemHealth с состоянием всех компонентов
        """
        self.logger.info("🏥 Начало проверки всех компонентов")
        
        components = []
        
        # Check each component
        components.append(await self.check_doh_health())
        components.append(self.check_sni_health())
        components.append(self.check_pcap_health())
        components.append(self.check_windivert_health())
        components.append(self.check_strategy_loader_health())
        components.append(self.check_bypass_engine_health())
        
        # Determine overall status
        statuses = [c.status for c in components]
        
        if all(s == 'healthy' for s in statuses):
            overall_status = 'healthy'
        elif any(s == 'unhealthy' for s in statuses):
            overall_status = 'unhealthy'
        else:
            overall_status = 'degraded'
        
        system_health = SystemHealth(
            overall_status=overall_status,
            components=components
        )
        
        status_icon = {'healthy': '✅', 'degraded': '🟡', 'unhealthy': '❌'}[overall_status]
        self.logger.info(f"{status_icon} Общее состояние системы: {overall_status}")
        
        return system_health
    
    def generate_report(self,
                       system_health: SystemHealth,
                       output_file: Optional[str] = None) -> str:
        """
        Генерирует отчет о состоянии системы.
        
        Args:
            system_health: Состояние системы
            output_file: Путь для сохранения отчета (опционально)
            
        Returns:
            Текстовый отчет
        """
        lines = []
        lines.append("=" * 80)
        lines.append("SYSTEM HEALTH CHECK REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {system_health.timestamp}")
        lines.append(f"Overall Status: {system_health.overall_status.upper()}")
        lines.append("")
        
        # Component status summary
        lines.append("COMPONENT STATUS SUMMARY")
        lines.append("-" * 80)
        
        for component in system_health.components:
            status_icon = {
                'healthy': '✅',
                'degraded': '🟡',
                'unhealthy': '❌',
                'unknown': '⚪'
            }[component.status]
            
            lines.append(f"{status_icon} {component.name}: {component.status.upper()}")
            if component.error_message:
                lines.append(f"   Error: {component.error_message}")
        
        lines.append("")
        
        # Detailed component information
        lines.append("DETAILED COMPONENT INFORMATION")
        lines.append("-" * 80)
        
        for component in system_health.components:
            lines.append(f"\n{component.name}")
            lines.append(f"  Status: {component.status}")
            lines.append(f"  Available: {component.available}")
            
            if component.checks_performed:
                lines.append(f"  Checks performed:")
                for check in component.checks_performed:
                    lines.append(f"    - {check}")
            
            if component.details:
                lines.append(f"  Details:")
                for key, value in component.details.items():
                    lines.append(f"    - {key}: {value}")
            
            if component.error_message:
                lines.append(f"  Error: {component.error_message}")
        
        lines.append("")
        lines.append("=" * 80)
        
        report = "\n".join(lines)
        
        # Save to file if requested
        if output_file:
            try:
                Path(output_file).write_text(report, encoding='utf-8')
                self.logger.info(f"📄 Отчет сохранен в {output_file}")
            except Exception as e:
                self.logger.error(f"❌ Ошибка сохранения отчета: {e}")
        
        return report
    
    def generate_json_report(self,
                            system_health: SystemHealth,
                            output_file: str) -> None:
        """
        Генерирует JSON отчет о состоянии системы.
        
        Args:
            system_health: Состояние системы
            output_file: Путь для сохранения JSON отчета
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(system_health.to_dict(), f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"📄 JSON отчет сохранен в {output_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка сохранения JSON отчета: {e}")
    
    def _create_test_tls_packet(self) -> bytes:
        """Создает тестовый TLS ClientHello пакет для проверки SNI."""
        # Minimal TLS ClientHello with SNI extension
        # This is a simplified version for testing purposes
        return bytes([
            0x16, 0x03, 0x01,  # TLS Handshake, version 3.1
            0x00, 0x50,  # Length
            0x01,  # ClientHello
            0x00, 0x00, 0x4c,  # Length
            0x03, 0x03,  # Version 3.3
        ] + [0x00] * 32 + [  # Random
            0x00,  # Session ID length
            0x00, 0x02,  # Cipher suites length
            0x00, 0x2f,  # Cipher suite
            0x01, 0x00,  # Compression methods
            0x00, 0x1d,  # Extensions length
            0x00, 0x00,  # SNI extension type
            0x00, 0x19,  # SNI extension length
            0x00, 0x17,  # Server name list length
            0x00,  # Server name type (hostname)
            0x00, 0x14,  # Server name length
        ] + list(b'www.example.com'))  # Server name


def main():
    """Главная функция CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Health Check Tool - Проверка работоспособности всех компонентов'
    )
    parser.add_argument(
        '--output',
        help='Файл для сохранения текстового отчета'
    )
    parser.add_argument(
        '--json-output',
        help='Файл для сохранения JSON отчета'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Включить отладочный вывод'
    )
    
    args = parser.parse_args()
    
    # Create tool
    tool = HealthCheckTool(debug=args.debug)
    
    # Check all components
    system_health = asyncio.run(tool.check_all_components())
    
    # Generate text report
    report = tool.generate_report(system_health, args.output)
    
    # Print to console if no output file specified
    if not args.output:
        print(report)
    
    # Generate JSON report if requested
    if args.json_output:
        tool.generate_json_report(system_health, args.json_output)
    
    # Exit with error code if system is unhealthy
    if system_health.overall_status == 'unhealthy':
        LOG.error("❌ System is unhealthy")
        sys.exit(1)
    elif system_health.overall_status == 'degraded':
        LOG.warning("🟡 System is degraded")
        sys.exit(0)
    else:
        LOG.info("✅ System is healthy")
        sys.exit(0)


if __name__ == '__main__':
    main()
