"""Strategy adaptation and translation for hybrid engine."""

import re
import logging
from typing import Dict, Any, Optional, List, Union
from core.bypass.attacks.alias_map import normalize_attack_name


class StrategyAdapter:
    """
    Handles strategy translation and adaptation.
    Converts between different strategy formats.
    """

    def __init__(self, parser):
        self.parser = parser
        self.logger = logging.getLogger(self.__class__.__name__)

    def translate_zapret_to_task(self, params: Dict) -> Optional[Dict]:
        """
        Translate zapret parameters to engine task.

        Args:
            params: Zapret-style parameters dictionary

        Returns:
            Engine task dictionary or None if translation fails
        """
        desync = [normalize_attack_name(d) for d in params.get('dpi_desync', [])]
        fooling = [normalize_attack_name(f) for f in params.get('dpi_desync_fooling', [])]

        # Determine task type with new priority logic
        task_type = self._determine_task_type(desync, fooling, params)

        if task_type == 'none':
            # This can happen if only unsupported flags are present
            return None

        task_params = self._build_task_params(params, task_type, desync, fooling)

        return {'type': task_type, 'params': task_params}

    def _determine_task_type(self, desync: List[str], fooling: List[str],
                            params: Dict) -> str:
        """
        Determine task type from desync methods.
        QUIC fragmentation now has the highest priority.
        """
        # Priority 1: QUIC fragmentation
        qfrag = params.get('quic_frag') or params.get('quic_fragment')
        if qfrag:
            return 'quic_fragmentation'

        # If no desync methods, no further processing needed
        if not desync:
            return 'none'

        # Priority 2: Fakeddisorder family
        if 'fakeddisorder' in desync or 'desync' in desync:
            return 'fakeddisorder'
        elif 'disorder' in desync or 'disorder2' in desync:
            return 'fakeddisorder'

        # Priority 3: Multi-techniques
        elif 'multidisorder' in desync:
            return 'multidisorder'
        elif 'multisplit' in desync:
            return 'multisplit'

        # Priority 4: Sequence overlap
        elif params.get('dpi_desync_split_seqovl'):
            # Ensure it's not just a parameter for fakeddisorder
            has_faked = any(x in desync for x in ['fakeddisorder', 'desync', 'disorder'])
            if not has_faked:
                return 'seqovl'

        # Priority 5: Fake with fooling (races) or standalone fake
        elif 'fake' in desync:
            if 'badsum' in fooling:
                return 'badsum_race'
            elif 'md5sig' in fooling:
                return 'md5sig_race'
            else:
                return 'fake'

        # Priority 6: Simple split
        elif 'split' in desync:
            return 'simple_fragment'

        return 'none'

    def _build_task_params(self, params: Dict, task_type: str,
                          desync: List[str], fooling: List[str]) -> Dict:
        """Build task parameters based on type."""
        task_params = {}

        # Handle QUIC fragmentation params
        if task_type == 'quic_fragmentation':
            qfrag = params.get('quic_frag') or params.get('quic_fragment')
            try:
                # Handle zapret's format: "size[:count]"
                if isinstance(qfrag, str) and ':' in qfrag:
                    size_str, count_str = qfrag.split(':', 1)
                    task_params['fragment_size'] = int(size_str)
                    task_params['fragment_count'] = int(count_str)
                else:
                    task_params['fragment_size'] = int(qfrag)
            except (ValueError, TypeError):
                task_params['fragment_size'] = 120 # default
            task_params['add_version_negotiation'] = bool(params.get('quic_vn'))
            return task_params

        # Handle split positions
        if task_type in ['fakeddisorder', 'multidisorder', 'multisplit', 'seqovl']:
            split_pos_raw = params.get('dpi_desync_split_pos', [])
            if any(p.get('type') == 'midsld' for p in split_pos_raw):
                task_params['split_pos'] = 'midsld'
            else:
                positions = [p['value'] for p in split_pos_raw
                           if p.get('type') == 'absolute']
                if task_type == 'fakeddisorder':
                    task_params['split_pos'] = positions[0] if positions else 76
                else:
                    # Generate positions for multi-techniques
                    count = params.get('dpi_desync_split_count')
                    if not positions and isinstance(count, int) and count > 1:
                        base, gap = 6, max(4, 120 // min(count, 10))
                        positions = [base + i * gap for i in range(count)]
                    task_params['positions'] = positions if positions else [1, 5, 10]

        # Handle TTL
        if params.get('dpi_desync_ttl') is not None:
            task_params['ttl'] = int(params.get('dpi_desync_ttl'))
        if params.get('dpi_desync_autottl') is not None:
            task_params['autottl'] = int(params.get('dpi_desync_autottl'))

        # Handle overlap
        if params.get('dpi_desync_split_seqovl'):
            task_params['overlap_size'] = params.get('dpi_desync_split_seqovl')

        # Handle fooling
        if fooling:
            task_params['fooling'] = fooling

        # Apply defaults for specific techniques
        if task_type == 'fakeddisorder':
            task_params.setdefault('ttl', 1)
            task_params.setdefault('split_pos', 76)
            task_params.setdefault('overlap_size', 336)

        return task_params

    def ensure_engine_task(self, strategy: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Ensure strategy is in engine task format.

        Args:
            strategy: Strategy in various formats (string, dict, etc.)

        Returns:
            Normalized engine task dictionary
        """
        if isinstance(strategy, dict):
            # Already in dict format, just normalize
            t = (strategy.get('type') or strategy.get('name') or '').strip().lower()
            if not t:
                return None
            ntp = normalize_attack_name(t)
            if ntp == 'desync':
                ntp = 'fakeddisorder'
            return {'type': ntp, 'params': strategy.get('params', {}) or {}}

        s = str(strategy).strip()

        # Try zapret CLI format (covers --dpi-desync, --quic-frag etc.)
        if s.startswith('--'):
            try:
                parsed_params = self.parser.parse(s)
                return self.translate_zapret_to_task(parsed_params)
            except Exception as e:
                self.logger.debug(f"Failed to parse zapret strategy '{s}': {e}")
                pass

        # Try simple DSL format: func(key=value, ...)
        match = re.match(r'(\w+)\((.*)\)', s)
        if match:
            func_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = self._parse_dsl_params(params_str)
            ntp = normalize_attack_name(func_name)
            if ntp == 'desync':
                ntp = 'fakeddisorder'
            return {'type': ntp, 'params': params}

        # Try fallback interpretation (legacy)
        try:
            from core.strategy_interpreter import interpret_strategy
            ps = interpret_strategy(s) or {}
            tp = ps.get('type')
            if tp:
                ntp = normalize_attack_name(tp)
                if ntp == 'desync':
                    ntp = 'fakeddisorder'
                return {'type': ntp, 'params': ps.get('params', {})}
        except Exception:
            pass

        # Final fallback for simple strategy names like "fakeddisorder"
        if re.match(r'^\w+$', s):
            return {'type': normalize_attack_name(s), 'params': {}}

        return None

    def _parse_dsl_params(self, params_str: str) -> Dict:
        """Parse DSL-style parameters."""
        params = {}
        if not params_str:
            return params

        try:
            for part in params_str.split(','):
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    if value.isdigit():
                        params[key] = int(value)
                    elif value.lower() == 'true':
                        params[key] = True
                    elif value.lower() == 'false':
                        params[key] = False
                    else:
                        params[key] = value.strip('\'"')
        except Exception:
            pass

        return params

    def task_to_str(self, task: Dict[str, Any]) -> str:
        """Convert task dictionary to readable string."""
        try:
            t = task.get('type') or task.get('name') or 'unknown'
            p = task.get('params', {})
            pairs = []
            for k, v in sorted(p.items(), key=lambda kv: kv[0]):
                try:
                    pairs.append(f"{k}={v}")
                except Exception:
                    pairs.append(f"{k}=<obj>")
            return f"{t}({', '.join(pairs)})"
        except Exception:
            return str(task)
