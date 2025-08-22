"""
Dynamic Combo Attack - заглушка для совместимости.

Эта атака представляет собой последовательность других атак,
выполняемых в определенном порядке.
"""
import logging
import asyncio
from typing import Dict, List, Any, Tuple
from recon.core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from recon.core.bypass.attacks.registry import register_attack
from recon.core.integration.attack_adapter import AttackAdapter
LOG = logging.getLogger('DynamicComboAttack')

@register_attack('dynamic_combo')
class DynamicComboAttack(BaseAttack):
    """
    Dynamic Combo Attack - выполняет последовательность атак.

    Эта атака является заглушкой для совместимости с существующим кодом.
    В реальной реализации она должна выполнять последовательность других атак.
    """

    def __init__(self, attack_adapter: AttackAdapter):
        super().__init__()
        self.attack_adapter = attack_adapter

    @property
    def name(self) -> str:
        """Unique name for this attack."""
        return 'dynamic_combo'

    @property
    def category(self) -> str:
        """Attack category."""
        return 'combo'

    @property
    def description(self) -> str:
        """Human-readable description of the attack."""
        return 'Dynamic combination of multiple attacks executed in sequence'

    @property
    def supported_protocols(self) -> List[str]:
        """List of supported protocols."""
        return ['tcp', 'udp', 'http', 'https']

    def _extract_combo_config(self, kwargs: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str, bool, bool]:
        """
        Унифицировано извлекает конфигурацию комбо из разных форматов параметров.

        Возвращает:
            stages: нормализованный список стадий в виде [{ 'name': ..., ...}, ...]
            execution_mode: 'sequential' | 'parallel'
            stop_on_failure: True/False
            propagate_context: True/False
        """
        sources: List[Any] = []
        sources.append(kwargs if isinstance(kwargs, dict) else {})
        sources.append(kwargs.get('params') or {} if isinstance(kwargs, dict) else {})
        sp = kwargs.get('strategy_params') if isinstance(kwargs, dict) else None
        if isinstance(sp, dict):
            sources.append(sp)
            if isinstance(sp.get('params'), dict):
                sources.append(sp['params'])
            if isinstance(sp.get('combo'), dict):
                sources.append(sp['combo'])
        stages_raw: Any = None
        for src in sources:
            if isinstance(src, list):
                stages_raw = src
                break
            if isinstance(src, dict):
                for key in ('stages', 'steps', 'sequence', 'techniques'):
                    if key in src:
                        stages_raw = src.get(key)
                        if stages_raw:
                            break
            if stages_raw:
                break
        stages: List[Dict[str, Any]] = []
        if isinstance(stages_raw, list):
            for item in stages_raw:
                if isinstance(item, str):
                    stages.append({'name': item})
                elif isinstance(item, dict):
                    if 'name' not in item:
                        if 'type' in item:
                            tmp = dict(item)
                            tmp['name'] = tmp.get('type')
                            stages.append(tmp)
                        elif 'attack' in item:
                            tmp = dict(item)
                            tmp['name'] = tmp.get('attack')
                            stages.append(tmp)
                        else:
                            continue
                    else:
                        stages.append(dict(item))
        execution_mode = 'sequential'
        for src in sources:
            if isinstance(src, dict):
                if 'execution_mode' in src and src['execution_mode']:
                    execution_mode = str(src['execution_mode']).lower()
                elif 'mode' in src and src['mode']:
                    execution_mode = str(src['mode']).lower()
        if execution_mode not in ('sequential', 'parallel'):
            execution_mode = 'sequential'
        stop_on_failure = False
        for src in sources:
            if isinstance(src, dict):
                if 'stop_on_failure' in src:
                    stop_on_failure = bool(src['stop_on_failure'])
                elif 'fail_fast' in src:
                    stop_on_failure = bool(src['fail_fast'])
        propagate_context = True
        for src in sources:
            if isinstance(src, dict) and 'propagate_context' in src:
                propagate_context = bool(src['propagate_context'])
        return (stages, execution_mode, stop_on_failure, propagate_context)

    async def execute(self, context: AttackContext, **kwargs) -> AttackResult:
        """
        Выполняет последовательность атак (стадий).
        Поддерживает параметры, переданные как:
        - прямые kwargs: stages=..., params={'execution_mode': ...}
        - вложенные: strategy_params={'stages': ..., 'execution_mode': ...}
        - алиасы: steps/sequence/techniques
        """
        try:
            stages, execution_mode, stop_on_failure, propagate_context = self._extract_combo_config(kwargs)
        except Exception as e:
            self.logger.exception('Failed to parse dynamic combo params')
            return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message=f'Invalid combo params: {e}')
        if not stages:
            return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='No stages defined for dynamic combo attack')
        stage_names = [s.get('name') for s in stages if isinstance(s.get('name'), str)]
        self.logger.info(f'Executing {len(stages)}-stage combo in {execution_mode} mode: {stage_names}')
        try:
            current_context = context.copy()
        except Exception:
            current_context = context
        all_segments: List[Any] = []
        total_latency: float = 0.0
        total_packets_sent: int = 0
        errors: List[str] = []

        async def run_stage(idx: int, stage_task: Dict[str, Any], stage_ctx: AttackContext):
            stage_name = stage_task.get('name') or stage_task.get('type') or 'unknown'
            stage_params = dict(stage_task)
            stage_params.setdefault('name', stage_name)
            stage_params.setdefault('_combo', {'index': idx, 'total': len(stages)})
            self.logger.debug(f"  Stage {idx + 1}/{len(stages)}: '{stage_name}' -> params: { {k: v for k, v in stage_params.items() if k != '_combo'}}")
            try:
                res = await self.attack_adapter.execute_attack_by_name(attack_name=stage_name, context=stage_ctx, strategy_params=stage_params)
                return (res, stage_name)
            except Exception as e:
                self.logger.exception(f"Stage {idx + 1} '{stage_name}' raised an exception")
                return (AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=0.0), stage_name)
        if execution_mode == 'parallel':
            ctx_list: List[AttackContext] = []
            for _ in stages:
                try:
                    ctx_list.append(context.copy())
                except Exception:
                    ctx_list.append(context)
            tasks = [run_stage(i, s, ctx_list[i]) for i, s in enumerate(stages)]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            for i, item in enumerate(results):
                stage_result, stage_name = item
                total_latency += getattr(stage_result, 'latency_ms', 0.0) or 0.0
                ps = getattr(stage_result, 'packets_sent', None)
                if isinstance(ps, int) and ps >= 0:
                    total_packets_sent += ps
                else:
                    segs = getattr(stage_result, 'segments', None) or []
                    total_packets_sent += len(segs)
                if getattr(stage_result, 'status', None) != AttackStatus.SUCCESS:
                    emsg = getattr(stage_result, 'error_message', None) or f"Stage '{stage_name}' failed with status {getattr(stage_result, 'status', None)}"
                    errors.append(f'[{i + 1}:{stage_name}] {emsg}')
                segs = getattr(stage_result, 'segments', None) or []
                if segs:
                    all_segments.extend(segs)
        else:
            for i, stage_task in enumerate(stages):
                stage_result, stage_name = await run_stage(i, stage_task, current_context)
                total_latency += getattr(stage_result, 'latency_ms', 0.0) or 0.0
                ps = getattr(stage_result, 'packets_sent', None)
                if isinstance(ps, int) and ps >= 0:
                    total_packets_sent += ps
                else:
                    segs_tmp = getattr(stage_result, 'segments', None) or []
                    total_packets_sent += len(segs_tmp)
                if getattr(stage_result, 'status', None) != AttackStatus.SUCCESS:
                    emsg = getattr(stage_result, 'error_message', '') or f"Stage '{stage_name}' failed"
                    self.logger.warning(f"Stage {i + 1} '{stage_name}' failed: {emsg}")
                    errors.append(f'[{i + 1}:{stage_name}] {emsg}')
                    if stop_on_failure:
                        break
                segs_tmp = getattr(stage_result, 'segments', None) or []
                if segs_tmp:
                    all_segments.extend(segs_tmp)
                if propagate_context:
                    next_ctx = getattr(stage_result, 'context', None)
                    if next_ctx is not None:
                        current_context = next_ctx
        if not all_segments:
            error_text = '; '.join(errors) if errors else 'Combo attack produced no segments.'
            return AttackResult(status=AttackStatus.ERROR, error_message=error_text, latency_ms=total_latency, packets_sent=total_packets_sent, technique_used='dynamic_combo')
        technique_used = 'dynamic_combo:' + ','.join(stage_names) if stage_names else 'dynamic_combo'
        return AttackResult(status=AttackStatus.SUCCESS, technique_used=technique_used, segments=all_segments, packets_sent=total_packets_sent, latency_ms=total_latency)

    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Валидирует параметры атаки.

        Args:
            params: Параметры для валидации. Поддерживаются старый и новый форматы:
                - {"stages": [...]}
                - {"params": {"stages": [...]}}
                - {"strategy_params": {"stages": [...]}}
                - а также алиасы steps/sequence/techniques и список строк.

        Returns:
            True если параметры валидны
        """
        if not isinstance(params, (dict, list)):
            return False
        wrapped = {'strategy_params': params} if not isinstance(params, dict) else params
        try:
            stages, _, _, _ = self._extract_combo_config(wrapped)
        except Exception:
            return False
        if not isinstance(stages, list) or not stages:
            return False
        for stage in stages:
            if isinstance(stage, dict):
                if 'name' not in stage and 'type' not in stage and ('attack' not in stage):
                    return False
            elif isinstance(stage, str):
                continue
            else:
                return False
        return True

    def get_required_params(self) -> List[str]:
        """Возвращает список обязательных параметров."""
        return ['stages']

    def get_optional_params(self) -> List[str]:
        """Возвращает список опциональных параметров."""
        return ['execution_mode', 'stop_on_failure', 'propagate_context']