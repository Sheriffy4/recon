# recon/core/bypass/strategies/parser.py
"""
Unified Strategy Parser

Combines the universal parsing capabilities with detailed attack mappings.
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)


@dataclass
class StrategyParameter:
    """Strategy parameter with type and metadata."""

    name: str
    value: Any
    type: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedStrategy:
    """Parsed strategy with structured data."""

    name: str
    attack_types: List[str]
    parameters: Dict[str, StrategyParameter]
    raw_string: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class UnifiedStrategyParser:
    """
    Универсальный парсер стратегий, который преобразует различные форматы
    в единую, исполняемую "задачу" для движка.
    """

    # --- ЕДИНЫЙ ИСТОЧНИК ИСТИНЫ ---
    # Карта, связывающая параметры zapret с внутренними именами атак и их параметрами.
    ZAPRET_TO_ATTACK_MAP = {
        # Техники сегментации
        "fakeddisorder": {"attack_name": "tcp_fakeddisorder", "param_mapping": {"dpi_desync_split_pos": "split_pos"}},
        "multisplit": {"attack_name": "tcp_multisplit", "param_mapping": {"dpi_desync_split_count": "split_count", "dpi_desync_split_seqovl": "overlap_size"}},
        "multidisorder": {"attack_name": "tcp_multidisorder", "param_mapping": {"dpi_desync_split_count": "split_count"}},
        "seqovl": {"attack_name": "tcp_seqovl", "param_mapping": {"dpi_desync_split_pos": "split_pos", "dpi_desync_split_seqovl": "overlap_size"}},
        "split2": {"attack_name": "tcp_split", "param_mapping": {"dpi_desync_split_pos": "split_pos"}},
        "tlsrec": {"attack_name": "tls_record_splitting", "param_mapping": {"tlsrec": "split_pos"}},
        
        # Техники "гонки" и обмана (Fooling)
        "fake": {"attack_name": "ttl_fake_race", "param_mapping": {"dpi_desync_ttl": "ttl", "dpi_desync_repeats": "repeats"}},
        "badsum": {"attack_name": "badsum_fooling"},
        "badseq": {"attack_name": "badseq_fooling"},
        "md5sig": {"attack_name": "md5sig_fooling"},
        
        # HTTP-модификаторы
        "hostcase": {"attack_name": "http_header_case"},
        "methodspace": {"attack_name": "http_method_space"},
        "unixeol": {"attack_name": "http_unix_eol"},
        "hostpad": {"attack_name": "http_host_padding"},
    }

    def __init__(self):
        self.logger = LOG
        self.patterns = {
            "zapret": re.compile(r"--([a-zA-Z0-9-]+)(?:=([^\s]+))?"),
            "json": re.compile(r"^\s*\{.*\}\s*$", re.DOTALL),
        }

    def parse(self, strategy_string: str) -> Optional[Dict[str, Any]]:
        """
        Главный метод. Парсит строку и СРАЗУ возвращает готовую "задачу" для движка.
        """
        strategy_string = strategy_string.strip()

        if self.patterns["zapret"].search(strategy_string):
            raw_params = self._parse_zapret_raw(strategy_string)
            return self._translate_parsed_to_engine_task(raw_params)
        elif self.patterns["json"].match(strategy_string):
            return self._parse_json(strategy_string)
        elif self.patterns["simple"].match(strategy_string):
            return self._parse_simple(strategy_string)
        else:
            # Fallback для простого имени атаки (например, "tcp_timing")
            return {"type": strategy_string, "name": strategy_string, "params": {}}

    def _parse_zapret_raw(self, strategy_string: str) -> Dict[str, Any]:
        """Вспомогательная функция: парсит zapret-строку в сырой словарь."""
        raw_params = {}
        for match in self.patterns["zapret"].finditer(strategy_string):
            param_name = match.group(1)
            param_value = match.group(2) if match.group(2) is not None else True
            
            if param_name in ["dpi-desync", "dpi-desync-fooling"]:
                raw_params[param_name] = str(param_value).split(',')
            else:
                raw_params[param_name] = self._parse_value(str(param_value))
        return raw_params

    def _translate_parsed_to_engine_task(self, parsed_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Центральный метод-транслятор. Преобразует сырой словарь в исполняемую задачу.
        """
        if not parsed_params: return None
        self.logger.debug(f"Translating raw params to engine task: {parsed_params}")

        stages = []
        # Собираем все возможные техники из разных флагов
        all_techniques = parsed_params.get('dpi-desync', []) + parsed_params.get('dpi-desync-fooling', [])
        for key in ["hostcase", "methodspace", "unixeol", "hostpad", "tlsrec"]:
            if key in parsed_params:
                all_techniques.append(key)

        for technique in set(all_techniques): # Используем set для удаления дубликатов
            if technique in self.ZAPRET_TO_ATTACK_MAP:
                mapping = self.ZAPRET_TO_ATTACK_MAP[technique]
                stage_params = {}
                # Применяем маппинг параметров
                for zapret_param, engine_param in mapping.get("param_mapping", {}).items():
                    if zapret_param in parsed_params:
                        stage_params[engine_param] = parsed_params[zapret_param]
                
                stages.append({"type": mapping["attack_name"], "name": mapping["attack_name"], "params": stage_params})

        if not stages:
            self.logger.warning("No recognized techniques found in the strategy.")
            return None

        if len(stages) == 1:
            final_task = stages[0]
            self.logger.info(f"Translated to a single-stage task: {final_task}")
            return final_task
        else:
            final_task = {
                "type": "dynamic_combo",
                "name": "dynamic_combo",
                "stages": stages,
                "params": {"execution_mode": "sequential"}
            }
            stage_names = [s['type'] for s in stages]
            self.logger.info(f"Translated to a multi-stage combo task: {stage_names}")
            return final_task

    def _parse_value(self, value: str) -> Any:
        """Пытается преобразовать строковое значение в правильный тип."""
        if not value: return None
        if value.lower() in ["true", "yes"]: return True
        if value.lower() in ["false", "no"]: return False
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value # Возвращаем как строку


# Aliases for compatibility
StrategyParser = UnifiedStrategyParser
ZapretStrategyParser = UnifiedStrategyParser
