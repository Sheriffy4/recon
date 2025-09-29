# Файл: core/strategy_interpreter.py (Полная замена)

"""
Enhanced Strategy Interpreter for Zapret-style DPI bypass strategies.
CRITICAL FIXES APPLIED: Integrates FixedStrategyInterpreter for correct parsing.
This module acts as a smart dispatcher, using the new fixed parser for complex
strategies and falling back to a legacy parser for simple, known cases.
"""

import re
import logging
from typing import Dict, Any, List, Optional

# CRITICAL IMPORT: Пытаемся импортировать исправленный парсер.
# Если он недоступен, система будет работать в режиме обратной совместимости.
try:
    from .strategy_interpreter_fixed import get_fixed_interpreter, ZapretStrategy
    FIXED_INTERPRETER_AVAILABLE = True
    _fixed_interpreter = get_fixed_interpreter()
    logging.getLogger(__name__).info("FixedStrategyInterpreter loaded successfully - critical fixes available.")
except ImportError as e:
    FIXED_INTERPRETER_AVAILABLE = False
    _fixed_interpreter = None
    logging.getLogger(__name__).warning(f"FixedStrategyInterpreter not available: {e} - using legacy parser only.")

LOG = logging.getLogger("strategy_interpreter")


# --- Класс старого парсера (для обратной совместимости) ---
# Этот класс содержит упрощенную старую логику и используется только как fallback.
class LegacyInterpreter:
    def __init__(self):
        self.logger = logging.getLogger("strategy_interpreter.legacy")

    def parse_zapret_strategy(self, strategy_string: str) -> Dict[str, Any]:
        """Упрощенный парсинг CLI-строк в стиле zapret."""
        params = {'desync_methods': [], 'fooling_methods': []}
        
        desync_match = re.search(r"--dpi-desync=([^\s]+)", strategy_string)
        if desync_match:
            params['desync_methods'] = desync_match.group(1).split(',')
        
        fooling_match = re.search(r"--dpi-desync-fooling=([^\s]+)", strategy_string)
        if fooling_match:
            params['fooling_methods'] = fooling_match.group(1).split(',')
            
        ttl_match = re.search(r"--dpi-desync-ttl=(\d+)", strategy_string)
        if ttl_match:
            params['ttl'] = int(ttl_match.group(1))

        split_pos_match = re.search(r"--dpi-desync-split-pos=([\d,midsld]+)", strategy_string)
        if split_pos_match:
            # Старый парсер мог возвращать список, берем первый элемент
            positions = [p for p in split_pos_match.group(1).split(',') if p.strip()]
            params['split_pos'] = int(positions[0]) if positions and positions[0].isdigit() else positions[0]

        seqovl_match = re.search(r"--dpi-desync-split-seqovl=(\d+)", strategy_string)
        if seqovl_match:
            params['split_seqovl'] = int(seqovl_match.group(1))
            
        return params

    def convert_to_engine_task(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Упрощенная конвертация в задачу для движка."""
        task_type = "fakeddisorder"  # Старый парсер почти всегда выдавал это
        if 'multisplit' in parsed.get('desync_methods', []):
            task_type = 'multisplit'

        params = {
            "ttl": parsed.get('ttl', 64),
            "split_pos": parsed.get('split_pos', 3),
            "fooling": parsed.get('fooling_methods', []),
            "overlap_size": parsed.get('split_seqovl')
        }
        # Удаляем None значения
        params = {k: v for k, v in params.items() if v is not None}
        
        return {"type": task_type, "params": params}


# --- Основная логика ---

def _should_use_fixed_parser(strategy_str: str) -> bool:
    """
    Определяет, нужно ли использовать новый, исправленный парсер.
    Новый парсер используется для сложных случаев, которые старый обрабатывает неверно.
    """
    if not FIXED_INTERPRETER_AVAILABLE:
        LOG.debug("Fixed parser not available, using legacy.")
        return False
    
    # Проверяем формат func(key=value), который старый парсер не понимает
    if re.match(r'\w+\(.*\)', strategy_str.strip()):
        LOG.debug("DSL format detected, using fixed parser.")
        return True
        
    # Проверяем на наличие сложных случаев
    if "autottl" in strategy_str:
        LOG.debug("autottl detected, using fixed parser.")
        return True
    if re.search(r'fooling=\[[^\]]+\]', strategy_str): # fooling=['badsum']
        LOG.debug("List-style fooling detected, using fixed parser.")
        return True
    if re.search(r'fooling=[^,\s]+,[^,\s]+', strategy_str): # fooling=badsum,md5sig
        LOG.debug("Multiple fooling methods detected, using fixed parser.")
        return True
        
    # По умолчанию используем новый парсер, если он доступен, т.к. он надежнее
    return True

def interpret_strategy(strategy_str: str) -> Optional[Dict[str, Any]]:
    """
    Главная функция для интерпретации стратегий.
    Сначала пытается использовать новый, исправленный парсер.
    Если он недоступен или не справляется, использует старый.
    """
    if not strategy_str or not isinstance(strategy_str, str):
        LOG.error("Empty or invalid strategy string provided.")
        return None

    LOG.info(f"Interpreting strategy: {strategy_str}")

    # Сначала пытаемся использовать новый, надежный парсер
    if _should_use_fixed_parser(strategy_str):
        try:
            # Используем функцию interpret_strategy из исправленного модуля
            from .strategy_interpreter_fixed import interpret_strategy as fixed_interpret
            result = fixed_interpret(strategy_str)
            
            if result and "error" not in result:
                result['_parser_used'] = 'fixed'
                result['_original_strategy'] = strategy_str
                LOG.info(f"Fixed parser result: {result}")
                return result
            else:
                LOG.warning("Fixed parser returned an error or empty result, falling back to legacy.")
        except Exception as e:
            LOG.error(f"FixedStrategyInterpreter failed with exception: {e}, falling back to legacy.")

    # Если новый парсер не справился или недоступен, используем старый
    LOG.warning("Using legacy interpreter as a fallback.")
    try:
        legacy_interpreter = LegacyInterpreter()
        parsed = legacy_interpreter.parse_zapret_strategy(strategy_str)
        result = legacy_interpreter.convert_to_engine_task(parsed)
        
        result['_parser_used'] = 'legacy'
        result['_original_strategy'] = strategy_str
        LOG.info(f"Legacy parser result: {result}")
        return result
    except Exception as e:
        LOG.error(f"Legacy strategy interpretation failed: {e}")
        return {"error": f"Failed to interpret strategy with all parsers: {e}"}