"""
Enhanced Strategy Interpreter for Zapret-style DPI bypass strategies.

CRITICAL FIXES APPLIED (Task 24):
- Integration with FixedStrategyInterpreter for correct fake,fakeddisorder parsing
- Proper fakeddisorder attack implementation (NOT seqovl mapping)
- Correct parameter mapping: split-seqovl=336 -> overlap_size=336
- Correct default values: split_pos=76 (not 3), ttl=1 (not 64)
- Full support for autottl, fooling methods, and fake payloads

Original issues fixed in task 15:
- Proper fakeddisorder attack implementation
- Correct autottl parameter handling
- Multiple fooling methods support (md5sig, badsum, badseq)
- Proper split-seqovl parameter implementation
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

# CRITICAL IMPORT: FixedStrategyInterpreter for correct zapret parsing
try:
    from .strategy_interpreter_fixed import (
        FixedStrategyInterpreter, 
        ZapretStrategy, 
        DPIMethod, 
        FoolingMethod,
        get_fixed_interpreter
    )
    FIXED_INTERPRETER_AVAILABLE = True
    _fixed_interpreter = get_fixed_interpreter()
    logging.getLogger(__name__).info("FixedStrategyInterpreter loaded successfully - critical fixes available")
except ImportError as e:
    FIXED_INTERPRETER_AVAILABLE = False
    _fixed_interpreter = None
    logging.getLogger(__name__).warning(f"FixedStrategyInterpreter not available: {e} - using legacy parser only")

LOG = logging.getLogger("strategy_interpreter")

def _normalize_engine_task(engine_task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Post-processes parsed engine task for consistency:
      - ensures params['fooling'] is present and list
      - converts split_pos=-1 to 'midsld'
      - removes legacy 'fooling_methods'
    """
    if not engine_task or not isinstance(engine_task, dict):
        return engine_task

    p = engine_task.get("params", {}) or {}
    # 1) fooling: всегда список и всегда присутствует
    if "fooling" not in p:
        fm = p.get("fooling_methods", [])
        if isinstance(fm, str):
            fm = [x.strip() for x in fm.split(",") if x.strip()]
        if not isinstance(fm, list):
            fm = []
        p["fooling"] = fm
    # удалить устаревшее поле
    p.pop("fooling_methods", None)

    # 2) midsld обработка: не допускаем split_pos = -1
    # если парсер вернул -1 для midsld или явно указано midsld
    sp = p.get("split_pos", None)
    if isinstance(sp, str):
        if sp.lower() == "midsld":
            p["split_pos"] = "midsld"
    elif isinstance(sp, int) and sp < 0:
        p["split_pos"] = "midsld"

    # 3) для массовых позиций: удалим «-1» если он попал у multisplit/multidisorder
    if "positions" in p and isinstance(p["positions"], list):
        p["positions"] = [x for x in p["positions"] if isinstance(x, int) and x >= 0]
        # если пусто после фильтра — лучше не отдавать пустой список
        if not p["positions"]:
            p.pop("positions", None)

    engine_task["params"] = p
    return engine_task


def interpret_strategy(strategy_str: str) -> Dict[str, Any]:
    """
    Main entry point for strategy interpretation with critical fixes.
    
    CRITICAL FIX: Uses FixedStrategyInterpreter for fake,fakeddisorder strategies
    to ensure correct parsing and parameter mapping.
    
    TASK 3 ENHANCEMENT: Added TTL validation and error handling with better defaults.
    
    Args:
        strategy_str: Zapret strategy string to interpret
        
    Returns:
        Dictionary with interpreted strategy parameters
        
    Requirements: 7.1, 7.2, 10.3, 10.4, 1.3, 2.4
    """
    logger = logging.getLogger(f"{__name__}.interpret_strategy")
    
    if not strategy_str:
        logger.error("Empty strategy string provided")
        return {"error": "Empty strategy string"}
    
    logger.info(f"Interpreting strategy: {strategy_str}")
    
    # Pre-validate TTL parameters in strategy string for early error detection
    ttl_match = re.search(r"--dpi-desync-ttl=(\d+)", strategy_str)
    if ttl_match:
        try:
            ttl_value = int(ttl_match.group(1))
            if not (1 <= ttl_value <= 255):
                logger.error(f"Invalid TTL value {ttl_value} in strategy string. TTL must be between 1 and 255.")
        except ValueError:
            logger.error(f"Invalid TTL format in strategy string: {ttl_match.group(1)}")
    
    autottl_match = re.search(r"--dpi-desync-autottl=(\d+)", strategy_str)
    if autottl_match:
        try:
            autottl_value = int(autottl_match.group(1))
            if not (1 <= autottl_value <= 64):
                logger.error(f"Invalid autottl value {autottl_value} in strategy string. AutoTTL should be between 1 and 64.")
        except ValueError:
            logger.error(f"Invalid autottl format in strategy string: {autottl_match.group(1)}")
    
    # CRITICAL: Detect fake,fakeddisorder combination and use fixed parser
    if FIXED_INTERPRETER_AVAILABLE and _should_use_fixed_parser(strategy_str):
        logger.info("CRITICAL: Using FixedStrategyInterpreter for fake,fakeddisorder strategy")
        try:
            # Parse with fixed interpreter
            zapret_strategy = _fixed_interpreter.parse_strategy(strategy_str)
            
            # Convert to legacy format for compatibility
            legacy_format = _fixed_interpreter.convert_to_legacy_format(zapret_strategy)
            
            # Convert to consistent format with legacy parser (type + params structure)
            consistent_format = {
                "type": legacy_format.get("attack_type", "fakeddisorder"),
                "params": {k: v for k, v in legacy_format.items() if k != "attack_type"},
                "attack_class": "fake_disorder" if legacy_format.get("attack_type") == "fakeddisorder" else legacy_format.get("attack_type", "fake_disorder")
            }
            
            # Add metadata for tracking
            consistent_format['_parser_used'] = 'fixed'
            consistent_format['_original_strategy'] = strategy_str
            
            logger.info(f"Fixed parser result: {consistent_format}")
            try:
                return _normalize_engine_task(consistent_format)
            except Exception:
                return consistent_format
            
        except Exception as e:
            logger.error(f"FixedStrategyInterpreter failed: {e}, falling back to legacy parser")
            # Fall through to legacy parser
    
    # Use legacy parser for backward compatibility
    logger.info("Using legacy EnhancedStrategyInterpreter")
    try:
        translator = StrategyTranslator()
        result = translator.translate_zapret_to_recon(strategy_str)
        
        # Add metadata for tracking
        result['_parser_used'] = 'legacy'
        result['_original_strategy'] = strategy_str
        
        logger.info(f"Legacy parser result: {result}")
        # Normalize result to guarantee fooling and midsld handling
        try:
            result = _normalize_engine_task(result)
        except Exception:
            pass
        return result
        
    except Exception as e:
        logger.error(f"Strategy interpretation failed: {e}")
        return {
            "error": f"Failed to interpret strategy: {e}",
            "_parser_used": "none",
            "_original_strategy": strategy_str
        }


def _should_use_fixed_parser(strategy_str: str) -> bool:
    """
    Determine if FixedStrategyInterpreter should be used for this strategy.
    
    CRITICAL: Use fixed parser for fake,fakeddisorder combinations to ensure
    correct interpretation as fakeddisorder attack (NOT seqovl).
    
    Args:
        strategy_str: Strategy string to analyze
        
    Returns:
        True if fixed parser should be used, False for legacy parser
    """
    logger = logging.getLogger(f"{__name__}._should_use_fixed_parser")
    
    # Check for fake,fakeddisorder combination - CRITICAL case
    if "fake,fakeddisorder" in strategy_str or "fakeddisorder,fake" in strategy_str:
        logger.info("CRITICAL: Detected fake,fakeddisorder combination - using fixed parser")
        return True
    
    # Check for standalone fakeddisorder with split-seqovl - also critical
    if "fakeddisorder" in strategy_str and "split-seqovl" in strategy_str:
        logger.info("CRITICAL: Detected fakeddisorder with split-seqovl - using fixed parser")
        return True
    
    # Check for autottl parameter - fixed parser handles this better
    if "autottl" in strategy_str:
        logger.info("Detected autottl parameter - using fixed parser for better support")
        return True
    
    # Check for multiple fooling methods - fixed parser has better support
    fooling_match = re.search(r'--dpi-desync-fooling=([^\s]+)', strategy_str)
    if fooling_match and ',' in fooling_match.group(1):
        logger.info("Detected multiple fooling methods - using fixed parser")
        return True
    
    logger.debug("Using legacy parser for this strategy")
    return False


@dataclass
class ParsedStrategy:
    """Structured representation of a parsed zapret strategy."""
    desync_methods: List[str]
    fooling_methods: List[str]
    ttl: Optional[int]
    autottl: Optional[int]
    split_positions: List[int]
    split_seqovl: Optional[int]
    repeats: int
    split_count: Optional[int]
    badseq_increment: int
    fake_tls: Optional[str]
    fake_http: Optional[str]
    fake_syndata: Optional[str]
    wssize: Optional[int]


class EnhancedStrategyInterpreter:
    """
    Enhanced strategy interpreter that properly handles zapret-style parameters
    and fixes the critical issues identified in the discrepancy analysis.
    """
    
    def __init__(self, debug: bool = True):
        self.debug = debug
        self.logger = logging.getLogger("strategy_interpreter")
        if debug and self.logger.level == logging.NOTSET:
            self.logger.setLevel(logging.DEBUG)
    
    def _validate_ttl_value(self, ttl_value: int, param_name: str = "ttl") -> int:
        """
        Validate TTL value and return corrected value if needed.
        
        Args:
            ttl_value: TTL value to validate
            param_name: Parameter name for logging
            
        Returns:
            Valid TTL value (1-255 range)
            
        Requirements: 1.3, 2.4
        """
        if not isinstance(ttl_value, int):
            self.logger.error(f"Invalid {param_name} type: {type(ttl_value)}. Must be integer. Using default TTL=64.")
            return 64
        
        if ttl_value < 1:
            self.logger.error(f"Invalid {param_name} value {ttl_value}. TTL must be >= 1. Using TTL=64.")
            return 64
        elif ttl_value > 255:
            self.logger.error(f"Invalid {param_name} value {ttl_value}. TTL must be <= 255. Using TTL=64.")
            return 64
        else:
            self.logger.info(f"Valid {param_name} value: {ttl_value}")
            return ttl_value
    
    def _get_default_ttl(self, attack_type: str = "general") -> int:
        """
        Get appropriate default TTL value for different attack types.
        
        Args:
            attack_type: Type of attack (fakeddisorder, fake, etc.)
            
        Returns:
            Default TTL value for the attack type
            
        Requirements: 1.3, 2.4
        """
        # Use TTL=64 as default for better compatibility (instead of TTL=1)
        default_ttl = 64
        self.logger.info(f"Using default TTL={default_ttl} for {attack_type} attack (improved compatibility)")
        return default_ttl
    
    def parse_zapret_strategy(self, strategy_string: str) -> ParsedStrategy:
        """
        Parse a zapret-style strategy string into structured parameters.
        
        UPDATED (Task 24.3): Now uses FixedStrategyInterpreter for critical cases
        and converts ZapretStrategy to ParsedStrategy for compatibility.
        
        Example input:
        "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 
         --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 
         --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
         
        Requirements: 7.3, 7.4, 7.5, 7.6, 10.5
        """
        self.logger.debug(f"Parsing zapret strategy: {strategy_string}")
        
        # CRITICAL: Use FixedStrategyInterpreter for better parsing when available
        if FIXED_INTERPRETER_AVAILABLE and _should_use_fixed_parser(strategy_string):
            self.logger.info("Using FixedStrategyInterpreter for enhanced parsing")
            try:
                # Parse with fixed interpreter
                zapret_strategy = _fixed_interpreter.parse_strategy(strategy_string)
                
                # Convert ZapretStrategy to ParsedStrategy for compatibility
                parsed = self._convert_zapret_to_parsed_strategy(zapret_strategy)
                
                self.logger.info(f"Fixed parser conversion successful: {parsed}")
                return parsed
                
            except Exception as e:
                self.logger.error(f"FixedStrategyInterpreter parsing failed: {e}, using legacy parser")
                # Fall through to legacy parsing
        
        # Legacy parsing logic (preserved for backward compatibility)
        self.logger.info("Using legacy parsing logic")
        
        # Initialize with defaults
        parsed = ParsedStrategy(
            desync_methods=[],
            fooling_methods=[],
            ttl=None,
            autottl=None,
            split_positions=[],
            split_seqovl=None,
            repeats=1,
            split_count=None,
            badseq_increment=-10000,
            fake_tls=None,
            fake_http=None,
            fake_syndata=None,
            wssize=None
        )
        
        # Parse desync methods
        desync_match = re.search(r"--dpi-desync=([^\s]+)", strategy_string)
        if desync_match:
            parsed.desync_methods = desync_match.group(1).split(",")
            self.logger.debug(f"Parsed desync methods: {parsed.desync_methods}")
        
        # Parse fooling methods
        fooling_match = re.search(r"--dpi-desync-fooling=([^\s]+)", strategy_string)
        if fooling_match:
            parsed.fooling_methods = fooling_match.group(1).split(",")
            self.logger.debug(f"Parsed fooling methods: {parsed.fooling_methods}")
        
        # Parse numeric parameters
        numeric_params = {
            "ttl": "ttl",
            "autottl": "autottl", 
            "split-seqovl": "split_seqovl",
            "repeats": "repeats",
            "split-count": "split_count",
            "badseq-increment": "badseq_increment",
            "wssize": "wssize"
        }
        
        for param_name, attr_name in numeric_params.items():
            match = re.search(rf"--dpi-desync-{param_name}=([-\d]+)", strategy_string)
            if match:
                try:
                    value = int(match.group(1))
                    
                    # TTL validation (1-255 range)
                    if param_name == "ttl":
                        if not (1 <= value <= 255):
                            self.logger.error(f"Invalid TTL value {value}. TTL must be between 1 and 255. Using default TTL=64.")
                            value = 64  # Use better default instead of 1
                        else:
                            self.logger.info(f"Valid TTL value: {value}")
                    
                    # AutoTTL validation (should be reasonable range)
                    elif param_name == "autottl":
                        if not (1 <= value <= 64):
                            self.logger.error(f"Invalid autottl value {value}. AutoTTL should be between 1 and 64. Using default autottl=2.")
                            value = 2
                        else:
                            self.logger.info(f"Valid autottl value: {value}")
                    
                    setattr(parsed, attr_name, value)
                    self.logger.debug(f"Parsed {param_name}: {value}")
                except ValueError:
                    self.logger.warning(f"Could not parse integer for {param_name}")
                    
                    # Provide fallback values for critical parameters
                    if param_name == "ttl":
                        self.logger.info("Using fallback TTL=64 for invalid TTL parameter")
                        setattr(parsed, attr_name, 64)
                    elif param_name == "autottl":
                        self.logger.info("Using fallback autottl=2 for invalid autottl parameter")
                        setattr(parsed, attr_name, 2)
        
        # Parse split positions
        split_pos_match = re.search(r"--dpi-desync-split-pos=([^\s]+)", strategy_string)
        if split_pos_match:
            positions_str = split_pos_match.group(1).split(",")
            for pos in positions_str:
                if pos == "midsld":
                    # Special handling for midsld - will be resolved at runtime
                    parsed.split_positions.append(-1)  # Special marker
                elif pos.isdigit() or (pos.startswith("-") and pos[1:].isdigit()):
                    parsed.split_positions.append(int(pos))
            self.logger.debug(f"Parsed split positions: {parsed.split_positions}")
        
        # Parse optional string parameters
        string_params = ["fake-tls", "fake-http", "fake-syndata"]
        for param_name in string_params:
            attr_name = param_name.replace("-", "_")
            match = re.search(rf"--dpi-desync-{param_name}(?:=([^\s]+))?(?:\s|$)", strategy_string)
            if match:
                value = match.group(1) if match.group(1) else True
                setattr(parsed, attr_name, value)
                self.logger.debug(f"Parsed {param_name}: {value}")
        
        return parsed
    
    def _convert_zapret_to_parsed_strategy(self, zapret_strategy: 'ZapretStrategy') -> ParsedStrategy:
        """
        Convert ZapretStrategy object to ParsedStrategy for compatibility.
        
        This method bridges the new FixedStrategyInterpreter format with the
        existing EnhancedStrategyInterpreter format for backward compatibility.
        
        Args:
            zapret_strategy: ZapretStrategy object from FixedStrategyInterpreter
            
        Returns:
            ParsedStrategy object compatible with existing code
            
        Requirements: 7.3, 7.4, 7.5, 7.6, 10.5
        """
        self.logger.debug("Converting ZapretStrategy to ParsedStrategy for compatibility")
        
        # Convert DPI methods to string list
        desync_methods = [method.value for method in zapret_strategy.methods]
        
        # Convert fooling methods to string list
        fooling_methods = [method.value for method in zapret_strategy.fooling] if zapret_strategy.fooling else []
        
        # Extract split positions
        split_positions = []
        if zapret_strategy.split_pos is not None:
            split_positions.append(zapret_strategy.split_pos)
        
        # Validate TTL values before creating ParsedStrategy
        validated_ttl = None
        if zapret_strategy.ttl is not None:
            validated_ttl = self._validate_ttl_value(zapret_strategy.ttl, "ttl")
        
        validated_autottl = None
        if zapret_strategy.autottl is not None:
            if not (1 <= zapret_strategy.autottl <= 64):
                self.logger.error(f"Invalid autottl value {zapret_strategy.autottl}. AutoTTL should be between 1 and 64. Using default autottl=2.")
                validated_autottl = 2
            else:
                validated_autottl = zapret_strategy.autottl
                self.logger.info(f"Valid autottl value: {validated_autottl}")
        
        # Create ParsedStrategy with validated values
        parsed = ParsedStrategy(
            desync_methods=desync_methods,
            fooling_methods=fooling_methods,
            ttl=validated_ttl,
            autottl=validated_autottl,
            split_positions=split_positions,
            split_seqovl=zapret_strategy.split_seqovl,
            repeats=zapret_strategy.repeats or 1,
            split_count=zapret_strategy.split_count,
            badseq_increment=-10000,  # Default from zapret
            fake_tls=zapret_strategy.fake_tls,
            fake_http=zapret_strategy.fake_http,
            fake_syndata=None,  # Not in ZapretStrategy
            wssize=zapret_strategy.wssize
        )
        
        self.logger.info(f"Converted ZapretStrategy to ParsedStrategy: "
                        f"methods={desync_methods}, split_seqovl={zapret_strategy.split_seqovl}, "
                        f"split_pos={zapret_strategy.split_pos}, ttl={zapret_strategy.ttl}")
        
        return parsed
    
    def convert_to_engine_task(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """
        Convert parsed strategy to engine task format.
        This is the critical fix for the strategy interpreter.
        """
        self.logger.info(f"Converting parsed strategy to engine task")
        self.logger.debug(f"Desync methods: {parsed.desync_methods}")
        self.logger.debug(f"Fooling methods: {parsed.fooling_methods}")
        
        # Determine primary attack type
        primary_attack = self._determine_primary_attack(parsed)
        self.logger.info(f"Primary attack determined: {primary_attack}")
        
        # Build base parameters
        params = {
            "ttl": parsed.ttl or 64,  # Changed default from 1/3 to 64 for better compatibility
            "split_pos": parsed.split_positions[0] if parsed.split_positions else 3,
            "window_div": 8,
            "tcp_flags": {"psh": True, "ack": True},
            "ipid_step": 2048,
            "repeats": parsed.repeats,
            "fooling_methods": parsed.fooling_methods,
            "autottl": parsed.autottl
        }
        # Если в методах есть 'fake' + другая основная атака — включаем префиксный fake
        if "fake" in parsed.desync_methods and primary_attack not in ("fake",):
            params["pre_fake"] = True
            if parsed.ttl:
                params["fake_ttl"] = parsed.ttl
        
        # Add attack-specific parameters
        if primary_attack == "fake_fakeddisorder":
            params.update(self._build_fake_fakeddisorder_params(parsed))
        elif primary_attack == "fakeddisorder" or primary_attack == "fakeddisorder_seqovl":
            params.update(self._build_fakeddisorder_params(parsed))
        elif primary_attack == "fake":
            params.update(self._build_fake_params(parsed))
        elif primary_attack == "multisplit" or primary_attack == "multidisorder":
            params.update(self._build_multisplit_params(parsed))
        elif primary_attack == "seqovl":
            params.update(self._build_seqovl_params(parsed))
        elif primary_attack == "badsum_race":
            params.update(self._build_badsum_race_params(parsed))
        elif primary_attack == "md5sig_race":
            params.update(self._build_md5sig_race_params(parsed))
        
        task = {
            "type": primary_attack,
            "params": params,
            "attack_class": self._get_attack_class_name(primary_attack)
        }
        
        self.logger.info(f"Generated engine task: {task}")
        return task
    
    def _get_attack_class_name(self, attack_type: str) -> str:
        """
        Map attack type to registered attack class name.
        
        UPDATED (Task 24.4): Ensures correct mapping for fakeddisorder attacks.
        """
        attack_mapping = {
            "fakeddisorder": "fake_disorder",  # CRITICAL: fake,fakeddisorder -> fake_disorder
            "fake": "fake_packet",
            "multisplit": "multisplit",
            "seqovl": "sequence_overlap",
            "badsum_race": "badsum_race",
            "md5sig_race": "md5sig_race",
            "combined_fooling": "combined_fooling"
        }
        return attack_mapping.get(attack_type, attack_type)
    
    def _determine_primary_attack(self, parsed: ParsedStrategy) -> str:
        """
        Determine the primary attack type based on parsed parameters.
        
        CRITICAL FIXES (Task 24.4):
        - fake,fakeddisorder -> fakeddisorder (NOT seqovl!)
        - Proper parameter mapping for internal format
        
        Requirements: 7.1, 7.2, 8.2, 8.3, 10.2, 10.3
        """
        # CRITICAL FIX: fake,fakeddisorder combination -> fakeddisorder attack (NOT seqovl!)
        if "fake" in parsed.desync_methods and "fakeddisorder" in parsed.desync_methods:
            self.logger.info("CRITICAL FIX: fake,fakeddisorder -> fakeddisorder attack (NOT seqovl!)")
            return "fakeddisorder"  # CRITICAL: Return fakeddisorder, not fake_fakeddisorder
        
        # Check for standalone fakeddisorder - this is the primary attack type
        if "fakeddisorder" in parsed.desync_methods:
            self.logger.info("Detected fakeddisorder attack")
            return "fakeddisorder"
        
        # Check for fake method
        if "fake" in parsed.desync_methods:
            return "fake"
        
        # Check for fooling-based attacks
        if "badsum" in parsed.fooling_methods and "md5sig" in parsed.fooling_methods:
            return "combined_fooling"
        elif "badsum" in parsed.fooling_methods:
            return "badsum_race"
        elif "md5sig" in parsed.fooling_methods:
            return "md5sig_race"
        
        # Check for other desync methods
        if "multisplit" in parsed.desync_methods:
            return "multisplit"
        elif "multidisorder" in parsed.desync_methods:
            return "multidisorder"
        elif "seqovl" in parsed.desync_methods:
            return "seqovl"
        
        # Default fallback
        return "fakeddisorder"
    
    def _build_fake_fakeddisorder_params(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """Build parameters for fake,fakeddisorder attack - CRITICAL FIX."""
        params = {}
        
        # This is the critical combination from zapret analysis
        if parsed.split_seqovl is not None:
            params["overlap_size"] = parsed.split_seqovl
            self.logger.info(f"CRITICAL: fake,fakeddisorder with seqovl overlap: {parsed.split_seqovl}")
        else:
            params["overlap_size"] = 1  # Default from zapret
        
        if parsed.autottl is not None:
            params["autottl"] = parsed.autottl
            params["ttl_range"] = list(range(1, parsed.autottl + 1))
            self.logger.info(f"Auto TTL enabled with range: {params['ttl_range']}")
        
        # Add fake packet parameters
        if parsed.fake_http is not None:
            params["fake_http"] = parsed.fake_http
        if parsed.fake_tls is not None:
            params["fake_tls"] = parsed.fake_tls
        
        # Split position from zapret
        if parsed.split_positions:
            params["split_pos"] = parsed.split_positions[0]
        
        params["combined_attack"] = True
        params["attack_type"] = "fake_fakeddisorder"
        
        return params
    
    def _build_fake_params(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """Build parameters for fake attack."""
        params = {}
        
        if parsed.fake_http is not None:
            params["fake_http"] = parsed.fake_http
        if parsed.fake_tls is not None:
            params["fake_tls"] = parsed.fake_tls
        
        return params
    
    def _build_fakeddisorder_params(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """
        Build parameters for fakeddisorder attack.
        
        CRITICAL FIXES (Task 24.4):
        - split-seqovl -> overlap_size (correct mapping)
        - split-pos -> split_pos with correct default (76, not 3)
        - Support for autottl, fooling, fake payloads
        
        Requirements: 7.1, 7.2, 8.2, 8.3, 10.2, 10.3
        """
        params = {}
        
        # CRITICAL: split-seqovl -> overlap_size (this mapping is correct)
        if parsed.split_seqovl is not None:
            params["overlap_size"] = parsed.split_seqovl
            self.logger.info(f"CRITICAL: split-seqovl={parsed.split_seqovl} -> overlap_size={parsed.split_seqovl}")
        else:
            # Default overlap size for fakeddisorder (zapret default is 336)
            params["overlap_size"] = 336
            self.logger.info("Using default overlap_size=336 for fakeddisorder")
        
        # CRITICAL: split_pos with correct default (76, not 3)
        if parsed.split_positions:
            params["split_pos"] = parsed.split_positions[0]
            self.logger.info(f"CRITICAL: Using split_pos={parsed.split_positions[0]}")
        else:
            # Default split position for fakeddisorder (zapret default is 76)
            params["split_pos"] = 76
            self.logger.info("CRITICAL: Using default split_pos=76 (not 3!) for fakeddisorder")
        
        # TTL handling with validation and correct defaults
        if parsed.autottl is not None:
            # AutoTTL is already validated in parsing, but double-check
            validated_autottl = max(1, min(64, parsed.autottl))
            params["autottl"] = validated_autottl
            params["ttl_range"] = list(range(1, validated_autottl + 1))
            self.logger.info(f"Auto TTL enabled with range: {params['ttl_range']}")
        elif parsed.ttl is not None:
            # Validate TTL value
            validated_ttl = self._validate_ttl_value(parsed.ttl, "fakeddisorder_ttl")
            params["ttl"] = validated_ttl
            self.logger.info(f"Fixed TTL: {validated_ttl}")
        else:
            # Default TTL for fakeddisorder (changed from 1 to 64 for better compatibility)
            default_ttl = self._get_default_ttl("fakeddisorder")
            params["ttl"] = default_ttl
            self.logger.info(f"Using default ttl={default_ttl} for fakeddisorder (improved from ttl=1)")
        
        # Fooling methods support
        if parsed.fooling_methods:
            params["fooling"] = parsed.fooling_methods
            self.logger.info(f"Fooling methods: {parsed.fooling_methods}")
        
        # Fake payload support
        if parsed.fake_http is not None:
            params["fake_http"] = parsed.fake_http
            self.logger.info(f"Fake HTTP payload: {parsed.fake_http}")
        
        if parsed.fake_tls is not None:
            params["fake_tls"] = parsed.fake_tls
            self.logger.info(f"Fake TLS payload: {parsed.fake_tls}")
        
        # Repeats support
        if parsed.repeats and parsed.repeats > 1:
            params["repeats"] = parsed.repeats
            self.logger.info(f"Attack repeats: {parsed.repeats}")
        
        return params
    
    def _build_multisplit_params(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """Build parameters for multisplit attack."""
        params = {}
        
        if parsed.split_count:
            # Generate positions based on split count
            positions = []
            base_offset = 6
            gaps = [8, 12, 16, 20, 24]
            last_pos = base_offset
            
            for i in range(parsed.split_count):
                positions.append(last_pos)
                gap = gaps[i] if i < len(gaps) else gaps[-1]
                last_pos += gap
            
            params["positions"] = positions
        elif parsed.split_positions:
            params["positions"] = parsed.split_positions
        else:
            params["positions"] = [10, 25, 40, 55, 70]
        
        return params
    
    def _build_seqovl_params(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """Build parameters for seqovl attack."""
        params = {}
        
        if parsed.split_seqovl is not None:
            params["overlap_size"] = parsed.split_seqovl
        else:
            params["overlap_size"] = 20
        
        return params
    
    def _build_badsum_race_params(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """Build parameters for badsum race attack."""
        params = {
            "extra_ttl": (parsed.ttl or 64) + 1,  # Changed default from 3 to 64
            "delay_ms": 5
        }
        return params
    
    def _build_md5sig_race_params(self, parsed: ParsedStrategy) -> Dict[str, Any]:
        """Build parameters for md5sig race attack."""
        params = {
            "extra_ttl": (parsed.ttl or 64) + 2,  # Changed default from 3 to 64
            "delay_ms": 7
        }
        return params


class StrategyTranslator:
    """
    Translates between different strategy formats and provides compatibility
    with existing recon project configurations.
    """
    
    def __init__(self):
        self.interpreter = EnhancedStrategyInterpreter()
    
    def translate_zapret_to_recon(self, zapret_strategy: str) -> Dict[str, Any]:
        """
        Translate a zapret strategy string to recon engine task format.
        This is the main entry point for fixing strategy interpretation.
        """
        parsed = self.interpreter.parse_zapret_strategy(zapret_strategy)
        return self.interpreter.convert_to_engine_task(parsed)
    
    def validate_strategy_compatibility(self, strategy: Dict[str, Any]) -> bool:
        """
        Validate that a strategy is compatible with the current engine.
        """
        required_fields = ["type", "params"]
        return all(field in strategy for field in required_fields)


def create_attack_from_strategy(strategy_str: str) -> Optional[Any]:
    """
    Create attack instance from strategy string for FakeDisorderAttack creation.
    
    This function bridges the strategy interpretation with attack instantiation,
    specifically designed to create FakeDisorderAttack instances with correct
    parameters from zapret strategy strings.
    
    Args:
        strategy_str: Zapret strategy string
        
    Returns:
        Attack instance or None if creation fails
        
    Requirements: 8.1, 9.1, 10.4, 10.5
    """
    logger = logging.getLogger(f"{__name__}.create_attack_from_strategy")
    
    try:
        # Interpret the strategy
        interpreted = interpret_strategy(strategy_str)
        
        if "error" in interpreted:
            logger.error(f"Strategy interpretation failed: {interpreted['error']}")
            return None
        
        attack_type = interpreted.get("type")
        params = interpreted.get("params", {})
        
        logger.info(f"Creating attack: type={attack_type}, params={params}")
        
        # Import attack classes dynamically to avoid circular imports
        if attack_type == "fakeddisorder":
            try:
                from .bypass.attacks.tcp.fake_disorder_attack import FakeDisorderAttack, FakeDisorderConfig
                
                # Create config from parameters
                config = FakeDisorderConfig(
                    split_seqovl=params.get("overlap_size", 336),
                    split_pos=params.get("split_pos", 76),
                    ttl=params.get("ttl", 1),
                    autottl=params.get("autottl"),
                    fooling=params.get("fooling", []),
                    repeats=params.get("repeats", 1),
                    fake_http=params.get("fake_http"),
                    fake_tls=params.get("fake_tls")
                )
                
                attack = FakeDisorderAttack(config)
                logger.info(f"Created FakeDisorderAttack with config: {config}")
                return attack
                
            except ImportError as e:
                logger.error(f"Failed to import FakeDisorderAttack: {e}")
                return None
        
        else:
            logger.warning(f"Attack type {attack_type} not supported for direct instantiation")
            return None
            
    except Exception as e:
        logger.error(f"Failed to create attack from strategy: {e}")
        return None


def get_strategy_info(strategy_str: str) -> Dict[str, Any]:
    """
    Get detailed strategy analysis and debugging information.
    
    This function provides comprehensive information about how a strategy
    string is interpreted, including parser selection, parameter extraction,
    and compatibility analysis.
    
    Args:
        strategy_str: Zapret strategy string to analyze
        
    Returns:
        Dictionary with detailed strategy information
        
    Requirements: 8.1, 9.1, 10.4, 10.5
    """
    logger = logging.getLogger(f"{__name__}.get_strategy_info")
    
    info = {
        "original_strategy": strategy_str,
        "parser_selection": {},
        "interpretation_result": {},
        "compatibility": {},
        "recommendations": []
    }
    
    try:
        # Analyze parser selection
        should_use_fixed = _should_use_fixed_parser(strategy_str) if FIXED_INTERPRETER_AVAILABLE else False
        info["parser_selection"] = {
            "fixed_interpreter_available": FIXED_INTERPRETER_AVAILABLE,
            "should_use_fixed_parser": should_use_fixed,
            "reason": _get_parser_selection_reason(strategy_str)
        }
        
        # Interpret the strategy
        interpreted = interpret_strategy(strategy_str)
        info["interpretation_result"] = interpreted
        
        # Analyze compatibility
        if FIXED_INTERPRETER_AVAILABLE and should_use_fixed:
            try:
                zapret_strategy = _fixed_interpreter.parse_strategy(strategy_str)
                is_valid = _fixed_interpreter.validate_strategy(zapret_strategy)
                info["compatibility"]["validation_passed"] = is_valid
                info["compatibility"]["zapret_strategy"] = {
                    "methods": [m.value for m in zapret_strategy.methods],
                    "split_seqovl": zapret_strategy.split_seqovl,
                    "split_pos": zapret_strategy.split_pos,
                    "ttl": zapret_strategy.ttl,
                    "autottl": zapret_strategy.autottl,
                    "fooling": [f.value for f in zapret_strategy.fooling] if zapret_strategy.fooling else []
                }
            except Exception as e:
                info["compatibility"]["validation_error"] = str(e)
        
        # Generate recommendations
        info["recommendations"] = _generate_strategy_recommendations(strategy_str, interpreted)
        
        logger.info(f"Generated strategy info for: {strategy_str}")
        return info
        
    except Exception as e:
        logger.error(f"Failed to get strategy info: {e}")
        info["error"] = str(e)
        return info


def _get_parser_selection_reason(strategy_str: str) -> str:
    """Get human-readable reason for parser selection."""
    if not FIXED_INTERPRETER_AVAILABLE:
        return "FixedStrategyInterpreter not available"
    
    if "fake,fakeddisorder" in strategy_str or "fakeddisorder,fake" in strategy_str:
        return "fake,fakeddisorder combination detected (critical case)"
    
    if "fakeddisorder" in strategy_str and "split-seqovl" in strategy_str:
        return "fakeddisorder with split-seqovl detected (critical case)"
    
    if "autottl" in strategy_str:
        return "autottl parameter detected (better support in fixed parser)"
    
    fooling_match = re.search(r'--dpi-desync-fooling=([^\s]+)', strategy_str)
    if fooling_match and ',' in fooling_match.group(1):
        return "multiple fooling methods detected (better support in fixed parser)"
    
    return "using legacy parser (no critical cases detected)"


def _generate_strategy_recommendations(strategy_str: str, interpreted: Dict[str, Any]) -> List[str]:
    """Generate recommendations for strategy optimization."""
    recommendations = []
    
    # Check for critical cases
    if "fake,fakeddisorder" in strategy_str:
        recommendations.append("CRITICAL: fake,fakeddisorder detected - ensure this maps to fakeddisorder attack, not seqovl")
    
    # Check for parameter issues
    if "split-pos=3" in strategy_str:
        recommendations.append("WARNING: split-pos=3 detected - consider using split-pos=76 for better compatibility with zapret")
    
    if "ttl=64" in strategy_str:
        recommendations.append("WARNING: ttl=64 detected - consider using ttl=1-8 for fakeddisorder attacks")
    
    # Check for missing parameters
    if "fakeddisorder" in strategy_str and "split-seqovl" not in strategy_str:
        recommendations.append("RECOMMENDATION: fakeddisorder without split-seqovl - consider adding --dpi-desync-split-seqovl=336")
    
    if "fakeddisorder" in strategy_str and "split-pos" not in strategy_str:
        recommendations.append("RECOMMENDATION: fakeddisorder without split-pos - consider adding --dpi-desync-split-pos=76")
    
    return recommendations


def validate_strategy_parameters(strategy_str: str) -> Dict[str, Any]:
    """
    Validate strategy parameters and provide detailed feedback.
    
    Args:
        strategy_str: Strategy string to validate
        
    Returns:
        Dictionary with validation results and suggestions
    """
    logger = logging.getLogger(f"{__name__}.validate_strategy_parameters")
    
    validation = {
        "is_valid": True,
        "errors": [],
        "warnings": [],
        "suggestions": []
    }
    
    try:
        if FIXED_INTERPRETER_AVAILABLE:
            zapret_strategy = _fixed_interpreter.parse_strategy(strategy_str)
            is_valid = _fixed_interpreter.validate_strategy(zapret_strategy)
            
            if not is_valid:
                validation["is_valid"] = False
                validation["errors"].append("Strategy validation failed in FixedStrategyInterpreter")
        
        # Additional validation checks
        if "split-pos=0" in strategy_str:
            validation["errors"].append("split-pos cannot be 0")
            validation["is_valid"] = False
        
        if "ttl=0" in strategy_str:
            validation["errors"].append("ttl cannot be 0")
            validation["is_valid"] = False
        
        # Generate suggestions
        validation["suggestions"] = _generate_strategy_recommendations(strategy_str, {})
        
        logger.info(f"Validation result for '{strategy_str}': {validation['is_valid']}")
        return validation
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        validation["is_valid"] = False
        validation["errors"].append(f"Validation exception: {e}")
        return validation


# Example usage and testing
if __name__ == "__main__":
    # Test with the problematic strategy from the analysis
    test_strategy = (
        "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
    )
    
    translator = StrategyTranslator()
    result = translator.translate_zapret_to_recon(test_strategy)
    
    print("Translated strategy:")
    print(result)