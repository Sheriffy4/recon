import logging
import copy
from typing import List, Dict, Any, Optional
from recon import config
from recon.core.storage import Storage
from recon.ml.strategy_predictor import StrategyPredictor
from recon.core.bypass.attacks.registry import AttackRegistry
from recon.core.integration.attack_adapter import AttackAdapter
from typing import TYPE_CHECKING
from typing_extensions import Protocol
LOG = logging.getLogger('AdaptivePlanner')

class AdaptivePlanner:
    """
    Генерирует план тестирования, используя иерархию атак,
    контекст DPI и динамическую генерацию комбинаций на основе истории неудач.
    """

    def __init__(self, store: Storage, predictor: StrategyPredictor):
        self.store = store
        self.predictor = predictor
        self.attack_adapter = AttackAdapter()
        self.attack_registry = AttackRegistry()
        self._default_params_cache = {}

    def _get_attack_default_params(self, attack_name: str) -> Dict[str, Any]:
        """Получает параметры по умолчанию для атаки из реестра."""
        if attack_name in self._default_params_cache:
            return self._default_params_cache[attack_name].copy()
        try:
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            if attack_info:
                attack = self.attack_registry.create(attack_name)
                if attack and hasattr(attack, 'get_default_params'):
                    params = attack.get_default_params()
                else:
                    params = {}
            else:
                params = config.TECH_LIBRARY.get(attack_name, [{}])[0].get('params', {})
            self._default_params_cache[attack_name] = params
            return params.copy()
        except Exception as e:
            LOG.warning(f'Failed to get default params for {attack_name}: {e}')
            return config.TECH_LIBRARY.get(attack_name, [{}])[0].get('params', {})

    def _create_logical_combo(self, race_tech: Optional[str], delivery_tech: str, fooling_techs: List[str], params: Dict, context: Optional[Dict]=None) -> Optional[Dict]:
        """
        Собирает максимально эффективную многоступенчатую атаку из компонентов.

        Args:
            race_tech: Техника "гонки" для отвлечения DPI (опционально)
            delivery_tech: Основная техника доставки payload
            fooling_techs: Дополнительные техники обмана
            params: Параметры для настройки атак
            context: Контекст DPI для адаптации параметров
        """
        stages = []
        if delivery_tech not in config.SEGMENTATION_TECHS + config.OBFUSCATION_TECHS:
            LOG.warning(f'Invalid delivery technique: {delivery_tech}')
            return None
        if race_tech:
            if race_tech not in config.RACE_TECHS:
                LOG.warning(f'Invalid race technique: {race_tech}')
                race_tech = None
            else:
                race_params = self._get_attack_default_params(race_tech)
                if context and context.get('active_dpi'):
                    race_params['ttl'] = params.get('ttl', 1)
                    race_params['delay_ms'] = params.get('race_delay', 5)
                else:
                    race_params['ttl'] = params.get('ttl', 3)
                    race_params['delay_ms'] = params.get('race_delay', 10)
                stage = {'type': race_tech, 'params': race_params}
                stages.append(stage)
                LOG.debug(f'Added race stage: {race_tech} with params {race_params}')
        pre_delivery_fooling = ['ttl_manipulation', 'badseq_fooling']
        for fool_tech in fooling_techs:
            if fool_tech in pre_delivery_fooling and fool_tech in config.TECH_LIBRARY:
                fool_params = self._get_attack_default_params(fool_tech)
                stage = {'type': fool_tech, 'params': fool_params}
                stages.append(stage)
                LOG.debug(f'Added pre-delivery fooling: {fool_tech}')
        delivery_params = self._get_attack_default_params(delivery_tech)
        if delivery_tech in config.SEGMENTATION_TECHS:
            if 'split_pos' in params:
                delivery_params['split_pos'] = params['split_pos']
            elif context and context.get('sni_filtering'):
                delivery_params['split_pos'] = 'midsld'
            if 'positions' in params:
                delivery_params['positions'] = params['positions']
            elif delivery_tech in ['tcp_multisplit', 'tcp_multidisorder']:
                if context and context.get('deep_inspection'):
                    delivery_params['positions'] = [1, 3, 5, 10, 20]
                else:
                    delivery_params['positions'] = [1, 3, 10]
            if delivery_tech == 'tcp_seqovl' and 'overlap_size' in params:
                delivery_params['overlap_size'] = params['overlap_size']
        elif delivery_tech in config.OBFUSCATION_TECHS:
            if delivery_tech == 'payload_encryption' and 'key' in params:
                delivery_params['key'] = params['key']
            elif delivery_tech == 'noise_injection' and 'noise_ratio' in params:
                delivery_params['noise_ratio'] = params['noise_ratio']
        stage = {'type': delivery_tech, 'params': delivery_params}
        stages.append(stage)
        LOG.debug(f'Added delivery stage: {delivery_tech} with params {delivery_params}')
        post_delivery_fooling = ['badsum_fooling', 'md5sig_fooling']
        for fool_tech in fooling_techs:
            if fool_tech in post_delivery_fooling and fool_tech in config.TECH_LIBRARY:
                fool_params = self._get_attack_default_params(fool_tech)
                stage = {'type': fool_tech, 'params': fool_params}
                stages.append(stage)
                LOG.debug(f'Added post-delivery fooling: {fool_tech}')
        combo = {'type': 'combo_strategy', 'name': f"dynamic_combo_{race_tech or 'no_race'}_{delivery_tech}", 'params': {'stages': stages, 'execution_mode': 'sequential', 'stop_on_success': False}}
        LOG.info(f"Created logical combo with {len(stages)} stages: {[s['type'] for s in stages]}")
        return combo

    def _analyze_dpi_context(self, fp: 'Fingerprint', history: List[Dict]) -> Dict[str, Any]:
        """Анализирует контекст DPI на основе fingerprint и истории."""
        context = {'active_dpi': False, 'sni_filtering': False, 'deep_inspection': False, 'stateful_tracking': False, 'protocol_validation': False}
        session_failures = getattr(fp, 'session_history', {})
        if session_failures.get('FAKE_RST_DETECTED', 0) > 0:
            context['active_dpi'] = True
        if any((h.get('result') == 'INVALID_PARAMS' and 'sni' in h.get('technique', '') for h in history)):
            context['sni_filtering'] = True
        complex_timeouts = sum((1 for h in history if h.get('result') == 'TIMEOUT' and h.get('technique') in config.OBFUSCATION_TECHS))
        if complex_timeouts >= 2:
            context['deep_inspection'] = True
        if session_failures.get('TIMEOUT', 0) > 3:
            context['stateful_tracking'] = True
        protocol_errors = sum((1 for h in history if 'PROTOCOL' in h.get('result', '') or 'INVALID' in h.get('result', '')))
        if protocol_errors >= 2:
            context['protocol_validation'] = True
        LOG.debug(f'DPI context analysis: {context}')
        return context

    def _generate_dynamic_combos(self, fp: 'Fingerprint', history: List[Dict]) -> List[Dict[str, Any]]:
        """
        Генерирует максимально эффективные многоступенчатые атаки на основе анализа.
        """
        from recon.core.fingerprint import Fingerprint
        combos = []
        session_failures = getattr(fp, 'session_history', {})
        ml_predictions = self.predictor.predict(fp.to_dict()) if hasattr(fp, 'to_dict') else []
        dpi_context = self._analyze_dpi_context(fp, history)
        if dpi_context['active_dpi']:
            LOG.info("💡 Тактика: 'Шок и трепет' (против активного DPI)")
            combo = self._create_logical_combo(race_tech='md5sig_race', delivery_tech='tcp_multidisorder', fooling_techs=['md5sig_fooling', 'badsum_fooling'], params={'ttl': 1, 'positions': [1, 3, 5, 10, 50], 'race_delay': 3}, context=dpi_context)
            if combo:
                combos.append(combo)
            combo = self._create_logical_combo(race_tech='badsum_race', delivery_tech='tcp_seqovl', fooling_techs=['ttl_manipulation'], params={'ttl': 2, 'split_pos': 3, 'overlap_size': 312}, context=dpi_context)
            if combo:
                combos.append(combo)
        elif dpi_context['stateful_tracking']:
            LOG.info("💡 Тактика: 'Скрытное проникновение' (против stateful DPI)")
            obfuscation_tech = next((p[0] for p in ml_predictions if p[0] in config.OBFUSCATION_TECHS), 'payload_obfuscation')
            segmentation_tech = next((p[0] for p in ml_predictions if p[0] in config.SEGMENTATION_TECHS), 'tcp_fakeddisorder')
            combo = self._create_logical_combo(race_tech=None, delivery_tech=obfuscation_tech, fooling_techs=[], params={'split_pos': 'midsld' if dpi_context['sni_filtering'] else 5}, context=dpi_context)
            if combo:
                combo['params']['stages'].append({'type': segmentation_tech, 'params': self._get_attack_default_params(segmentation_tech)})
                combos.append(combo)
        elif dpi_context['protocol_validation']:
            LOG.info("💡 Тактика: 'Протокольная мимикрия' (против строгой валидации)")
            combo = self._create_logical_combo(race_tech=None, delivery_tech='tlsrec_split', fooling_techs=[], params={'split_pos': 5}, context=dpi_context)
            if combo:
                combos.append(combo)
            combo = self._create_logical_combo(race_tech=None, delivery_tech='grease_injection', fooling_techs=[], params={'grease_count': 3}, context=dpi_context)
            if combo:
                combos.append(combo)
        else:
            LOG.info("💡 Тактика: 'Адаптивная разведка' (на основе ML)")
            if len(ml_predictions) >= 2:
                tech1, conf1 = ml_predictions[0]
                tech2, conf2 = ml_predictions[1] if len(ml_predictions) > 1 else (None, 0)
                race_tech = None
                delivery_tech = None
                fooling_techs = []
                if tech1 in config.RACE_TECHS and conf1 > 0.7:
                    race_tech = tech1
                    delivery_tech = tech2 if tech2 in config.SEGMENTATION_TECHS else 'tcp_fakeddisorder'
                elif tech2 in config.RACE_TECHS and conf2 > 0.6:
                    race_tech = tech2
                    delivery_tech = tech1 if tech1 in config.SEGMENTATION_TECHS else 'tcp_multisplit'
                else:
                    delivery_tech = tech1 if tech1 in config.SEGMENTATION_TECHS + config.OBFUSCATION_TECHS else 'tcp_fakeddisorder'
                available_fooling = [t for t in config.TECH_LIBRARY if 'fooling' in t and t not in [race_tech, delivery_tech]]
                if available_fooling and conf1 + conf2 < 1.5:
                    fooling_techs = available_fooling[:2]
                combo = self._create_logical_combo(race_tech=race_tech, delivery_tech=delivery_tech, fooling_techs=fooling_techs, params={'ttl': 3, 'split_pos': 'midsld', 'race_delay': 10}, context=dpi_context)
                if combo:
                    combos.append(combo)
        if not combos:
            LOG.warning('No combos generated, using fallback')
            fallback = self._create_logical_combo(race_tech='badsum_race', delivery_tech='tcp_fakeddisorder', fooling_techs=['badsum_fooling'], params={'ttl': 2, 'split_pos': 3}, context=dpi_context)
            if fallback:
                combos.append(fallback)
        combos = combos[:config.MAX_TESTS_PER_LEVEL]
        LOG.info(f'Generated {len(combos)} dynamic combos')
        for i, combo in enumerate(combos):
            stages_info = [s['type'] for s in combo['params']['stages']]
            LOG.debug(f'Combo {i + 1}: {stages_info}')
        return combos

    def generate_plan(self, fp: 'Fingerprint', level: int, history: List[Dict], full_scan: bool=False) -> List[Dict[str, Any]]:
        """
        Генерирует план для определенного уровня иерархии или для полного сканирования.
        """
        from recon.core.fingerprint import Fingerprint
        if full_scan:
            plan = []
            for tech_name, tech_configs in config.TECH_LIBRARY.items():
                if tech_configs:
                    plan.append(tech_configs[0])
            LOG.info(f'Full scan mode: planning to test all {len(plan)} techniques.')
            return plan
        plan = []
        if level == 7:
            techs_at_level = self._generate_dynamic_combos(fp, history)
        else:
            tech_names_at_level = config.ATTACK_HIERARCHY.get(level, [])
            techs_at_level = []
            for tech_name in tech_names_at_level:
                if tech_name in config.TECH_LIBRARY:
                    tech_config = config.TECH_LIBRARY[tech_name][0].copy()
                    default_params = self._get_attack_default_params(tech_name)
                    if 'params' not in tech_config:
                        tech_config['params'] = {}
                    for key, value in default_params.items():
                        if key not in tech_config['params']:
                            tech_config['params'][key] = value
                    techs_at_level.append(tech_config)
        plan.extend(techs_at_level)
        unique_plan = []
        seen = set()
        for item in plan:
            if 'stages' in item.get('params', {}):
                item_key = (item['type'], tuple((s['type'] for s in item['params']['stages'])))
            else:
                params = item.get('params', {})
                try:
                    item_key = (item['type'], tuple(sorted(params.items())))
                except TypeError:
                    item_key = (item['type'], repr(params))
            if item_key not in seen:
                unique_plan.append(item)
                seen.add(item_key)
        return unique_plan[:config.MAX_TESTS_PER_LEVEL]