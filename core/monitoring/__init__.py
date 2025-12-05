"""
Enhanced Monitoring Module

Модуль расширенного мониторинга с онлайн анализом трафика,
адаптивной генерацией стратегий и автоматическим переключением обходов.
"""

from .real_time_traffic_analyzer import (
    RealTimeTrafficAnalyzer,
    BlockingEvent,
    BlockingType,
    TrafficEvent,
    ConnectionAttempt,
    TrafficBuffer,
    DPIPatternDetector,
    NotificationSystem
)

from .adaptive_online_strategy_generator import (
    AdaptiveOnlineStrategyGenerator,
    StrategyCandidate,
    StrategyType,
    ABTestResult,
    ABTestManager,
    OnlineMLPredictor,
    FeedbackSystem
)

from .online_analysis_integration import (
    OnlineAnalysisIntegration,
    OnlineAnalysisMetrics,
    StrategySwitch,
    NotificationManager,
    StrategyOrchestrator
)

from .enhanced_monitoring_system import (
    EnhancedMonitoringSystem,
    create_enhanced_monitoring_system
)

__all__ = [
    # Real-time traffic analysis
    'RealTimeTrafficAnalyzer',
    'BlockingEvent',
    'BlockingType', 
    'TrafficEvent',
    'ConnectionAttempt',
    'TrafficBuffer',
    'DPIPatternDetector',
    'NotificationSystem',
    
    # Adaptive strategy generation
    'AdaptiveOnlineStrategyGenerator',
    'StrategyCandidate',
    'StrategyType',
    'ABTestResult',
    'ABTestManager',
    'OnlineMLPredictor',
    'FeedbackSystem',
    
    # Integration components
    'OnlineAnalysisIntegration',
    'OnlineAnalysisMetrics',
    'StrategySwitch',
    'NotificationManager',
    'StrategyOrchestrator',
    
    # Enhanced monitoring system
    'EnhancedMonitoringSystem',
    'create_enhanced_monitoring_system'
]

# Version info
__version__ = '1.0.0'
__author__ = 'DPI Bypass System'
__description__ = 'Enhanced monitoring with online traffic analysis and adaptive strategy generation'