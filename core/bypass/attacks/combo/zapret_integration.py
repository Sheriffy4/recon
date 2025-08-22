"""
Zapret Integration Module

Provides easy integration of the zapret strategy into the main DPI bypass system.
Includes preset configurations and integration helpers.
"""
import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
try:
    from recon.core.bypass.attacks.combo.zapret_strategy import ZapretStrategy, ZapretConfig, create_zapret_strategy
    from recon.core.bypass.attacks.combo.native_combo_engine import get_global_combo_engine, ComboRule, ComboMode, ComboTiming
    from recon.core.bypass.attacks.base import AttackContext, AttackResult
except ImportError:
    from enum import Enum
    from dataclasses import dataclass
    from typing import Optional, Dict, Any

    class AttackStatus(Enum):
        SUCCESS = 'success'
        FAILED = 'failed'

    @dataclass
    class AttackContext:
        target_host: str
        target_port: int
        source_ip: Optional[str] = None
        source_port: Optional[int] = None
        payload: Optional[bytes] = None

    @dataclass
    class AttackResult:
        success: bool
        status: AttackStatus = AttackStatus.SUCCESS
        technique_used: str = ''
        packets_sent: int = 0
        execution_time_ms: float = 0.0
        details: Optional[Dict[str, Any]] = None
        error_message: Optional[str] = None
LOG = logging.getLogger('ZapretIntegration')
ZAPRET_PRESETS = {'default': {'name': 'Default Zapret (High Effectiveness)', 'description': 'The original highly effective zapret configuration', 'config': {'split_seqovl': 297, 'ttl': 51, 'repeats': 10, 'auto_ttl': True, 'desync_methods': ['fake', 'fakeddisorder'], 'fooling_method': 'md5sig'}}, 'aggressive': {'name': 'Aggressive Zapret', 'description': 'More aggressive configuration for stubborn DPI systems', 'config': {'split_seqovl': 200, 'ttl': 48, 'repeats': 15, 'auto_ttl': True, 'desync_methods': ['fake', 'fakeddisorder'], 'fooling_method': 'md5sig', 'disorder_window': 5, 'inter_packet_delay_ms': 0.01}}, 'conservative': {'name': 'Conservative Zapret', 'description': 'Less aggressive configuration to avoid detection', 'config': {'split_seqovl': 400, 'ttl': 64, 'repeats': 5, 'auto_ttl': False, 'desync_methods': ['fake'], 'fooling_method': 'md5sig', 'inter_packet_delay_ms': 0.1}}, 'fast': {'name': 'Fast Zapret', 'description': 'Optimized for speed with minimal delays', 'config': {'split_seqovl': 297, 'ttl': 51, 'repeats': 3, 'auto_ttl': True, 'desync_methods': ['fake', 'fakeddisorder'], 'fooling_method': 'md5sig', 'inter_packet_delay_ms': 0.0, 'burst_delay_ms': 0.0}}, 'stealth': {'name': 'Stealth Zapret', 'description': 'Designed to avoid DPI detection and analysis', 'config': {'split_seqovl': 350, 'ttl': 55, 'repeats': 7, 'auto_ttl': True, 'desync_methods': ['fake'], 'fooling_method': 'md5sig', 'disorder_window': 2, 'inter_packet_delay_ms': 0.2, 'burst_delay_ms': 2.0}}}

class ZapretIntegration:
    """
    Integration helper for zapret strategy in the main system.

    Provides easy access to preset configurations and integration
    with the native combo engine.
    """

    def __init__(self):
        self.combo_engine = None
        self.registered_presets = {}
        self._initialize_presets()
        LOG.info(f'Zapret integration initialized with {len(ZAPRET_PRESETS)} presets')

    def _initialize_presets(self):
        """Initialize preset configurations in the combo engine."""
        try:
            self.combo_engine = get_global_combo_engine()
            if 'zapret' not in self.combo_engine.attack_registry:
                self.combo_engine.register_attack('zapret', ZapretStrategy)
            for preset_name, preset_info in ZAPRET_PRESETS.items():
                rule_name = f'zapret_{preset_name}'
                combo_rule = ComboRule(name=rule_name, attacks=['zapret'], mode=ComboMode.SEQUENTIAL, timing=ComboTiming.IMMEDIATE, parameters={'zapret': preset_info['config']})
                self.combo_engine.register_combo_rule(combo_rule)
                self.registered_presets[preset_name] = rule_name
                LOG.debug(f'Registered preset: {preset_name} -> {rule_name}')
        except Exception as e:
            LOG.warning(f'Could not initialize combo engine integration: {e}')

    async def execute_preset(self, preset_name: str, context: AttackContext, custom_params: Optional[Dict[str, Any]]=None) -> AttackResult:
        """
        Execute a zapret preset configuration.

        Args:
            preset_name: Name of the preset to execute
            context: Attack execution context
            custom_params: Custom parameters to override preset defaults

        Returns:
            AttackResult from execution
        """
        if preset_name not in ZAPRET_PRESETS:
            available = ', '.join(ZAPRET_PRESETS.keys())
            raise ValueError(f"Unknown preset '{preset_name}'. Available: {available}")
        preset_info = ZAPRET_PRESETS[preset_name]
        LOG.info(f"Executing zapret preset '{preset_name}': {preset_info['description']}")
        if self.combo_engine and preset_name in self.registered_presets:
            try:
                rule_name = self.registered_presets[preset_name]
                result = await self.combo_engine.execute_combo(rule_name, context, custom_params)
                if result.attack_results:
                    return result.attack_results[0]
                else:
                    return AttackResult(success=result.success, technique_used=f'zapret_{preset_name}', execution_time_ms=result.execution_time_ms)
            except Exception as e:
                LOG.warning(f'Combo engine execution failed, falling back to direct execution: {e}')
        config_params = preset_info['config'].copy()
        if custom_params:
            config_params.update(custom_params)
        strategy = create_zapret_strategy(**config_params)
        result = await strategy.execute(context)
        if result.details:
            result.details['preset'] = {'name': preset_name, 'description': preset_info['description']}
        return result

    async def execute_custom(self, context: AttackContext, **config_params) -> AttackResult:
        """
        Execute zapret with custom configuration.

        Args:
            context: Attack execution context
            **config_params: Custom configuration parameters

        Returns:
            AttackResult from execution
        """
        LOG.info(f'Executing custom zapret configuration: {config_params}')
        strategy = create_zapret_strategy(**config_params)
        result = await strategy.execute(context)
        if result.details:
            result.details['custom_config'] = config_params
        return result

    def get_preset_info(self, preset_name: Optional[str]=None) -> Dict[str, Any]:
        """
        Get information about available presets.

        Args:
            preset_name: Specific preset name, or None for all presets

        Returns:
            Preset information dictionary
        """
        if preset_name:
            if preset_name not in ZAPRET_PRESETS:
                raise ValueError(f'Unknown preset: {preset_name}')
            return ZAPRET_PRESETS[preset_name]
        return ZAPRET_PRESETS

    def list_presets(self) -> List[str]:
        """Get list of available preset names."""
        return list(ZAPRET_PRESETS.keys())

    def get_recommended_preset(self, target_type: str='general') -> str:
        """
        Get recommended preset based on target type.

        Args:
            target_type: Type of target ("general", "aggressive_dpi", "stealth", "fast")

        Returns:
            Recommended preset name
        """
        recommendations = {'general': 'default', 'aggressive_dpi': 'aggressive', 'stealth': 'stealth', 'fast': 'fast', 'conservative': 'conservative'}
        return recommendations.get(target_type, 'default')

    async def test_all_presets(self, context: AttackContext, max_concurrent: int=3) -> Dict[str, AttackResult]:
        """
        Test all presets against a target for comparison.

        Args:
            context: Attack execution context
            max_concurrent: Maximum concurrent preset tests

        Returns:
            Dictionary mapping preset names to results
        """
        LOG.info(f'Testing all {len(ZAPRET_PRESETS)} presets against {context.target_host}')
        semaphore = asyncio.Semaphore(max_concurrent)

        async def test_preset(preset_name: str) -> tuple:
            async with semaphore:
                try:
                    result = await self.execute_preset(preset_name, context)
                    return (preset_name, result)
                except Exception as e:
                    LOG.error(f'Preset {preset_name} test failed: {e}')
                    return (preset_name, AttackResult(success=False, technique_used=f'zapret_{preset_name}', error_message=str(e)))
        tasks = [test_preset(name) for name in ZAPRET_PRESETS.keys()]
        results = await asyncio.gather(*tasks)
        result_dict = dict(results)
        successful = sum((1 for r in result_dict.values() if r.success))
        LOG.info(f'Preset testing completed: {successful}/{len(result_dict)} successful')
        return result_dict

    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics."""
        stats = {'available_presets': len(ZAPRET_PRESETS), 'registered_presets': len(self.registered_presets), 'combo_engine_available': self.combo_engine is not None, 'presets': {name: {'description': info['description'], 'config_keys': list(info['config'].keys())} for name, info in ZAPRET_PRESETS.items()}}
        if self.combo_engine:
            engine_stats = self.combo_engine.get_statistics()
            stats['combo_engine_stats'] = engine_stats
        return stats
_global_zapret_integration: Optional[ZapretIntegration] = None

def get_zapret_integration() -> ZapretIntegration:
    """Get or create global zapret integration instance."""
    global _global_zapret_integration
    if _global_zapret_integration is None:
        _global_zapret_integration = ZapretIntegration()
    return _global_zapret_integration

async def execute_zapret_default(context: AttackContext) -> AttackResult:
    """Execute zapret with default (highly effective) configuration."""
    integration = get_zapret_integration()
    return await integration.execute_preset('default', context)

async def execute_zapret_aggressive(context: AttackContext) -> AttackResult:
    """Execute zapret with aggressive configuration."""
    integration = get_zapret_integration()
    return await integration.execute_preset('aggressive', context)

async def execute_zapret_stealth(context: AttackContext) -> AttackResult:
    """Execute zapret with stealth configuration."""
    integration = get_zapret_integration()
    return await integration.execute_preset('stealth', context)

async def execute_zapret_fast(context: AttackContext) -> AttackResult:
    """Execute zapret with fast configuration."""
    integration = get_zapret_integration()
    return await integration.execute_preset('fast', context)

def get_zapret_presets() -> List[str]:
    """Get list of available zapret presets."""
    return list(ZAPRET_PRESETS.keys())

def get_zapret_preset_info(preset_name: str) -> Dict[str, Any]:
    """Get information about a specific zapret preset."""
    if preset_name not in ZAPRET_PRESETS:
        raise ValueError(f'Unknown preset: {preset_name}')
    return ZAPRET_PRESETS[preset_name]