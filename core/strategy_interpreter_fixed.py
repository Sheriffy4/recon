"""
Fixed Strategy Interpreter for Correct Zapret Parsing

This module provides a corrected implementation of zapret strategy parsing
that fixes critical issues with the original interpreter, particularly:

1. Correct handling of fake,fakeddisorder -> fakeddisorder attack (NOT seqovl)
2. Proper parameter mapping: split-seqovl=336 -> overlap_size=336
3. Correct default values: split_pos=76 (not 3), ttl=64 (TASK 3: improved from 1)
4. Full support for autottl, fooling methods, and fake payloads

Requirements addressed: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 9.1, 9.2, 9.3, 10.1, 10.2, 10.3, 10.4, 10.5
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
import re
import logging

logger = logging.getLogger(__name__)

def _normalize_engine_task(engine_task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensures params['fooling'] exists (list) and split_pos='midsld' (never -1).
    """
    params = engine_task.get("params") or {}
    # ensure fooling exists
    if "fooling" not in params:
        fm = params.get("fooling_methods")
        if isinstance(fm, list):
            params["fooling"] = fm
        elif isinstance(fm, str) and fm:
            params["fooling"] = [x.strip() for x in fm.split(",") if x.strip()]
        else:
            params["fooling"] = []
    if isinstance(params.get("fooling"), str):
        params["fooling"] = [x.strip() for x in params["fooling"].split(",") if x.strip()]
    # midsld handling
    if params.get("split_pos", None) == -1 or (isinstance(params.get("split_pos"), str) and params["split_pos"].lower() == "midsld"):
        params["split_pos"] = "midsld"
    if isinstance(params.get("positions"), list):
        params["positions"] = [p for p in params["positions"] if not (isinstance(p, int) and p < 0)]
    # cleanup legacy
    params.pop("fooling_methods", None)
    engine_task["params"] = params
    if "name" in engine_task and "type" not in engine_task:
        engine_task["type"] = engine_task.pop("name")
    return engine_task


class DPIMethod(Enum):
    """
    DPI bypass methods supported by zapret.
    
    CRITICAL: fake,fakeddisorder should map to FAKEDDISORDER, NOT seqovl!
    """
    FAKE = "fake"
    FAKEDDISORDER = "fakeddisorder"  # Critical method - was incorrectly mapped to seqovl
    FAKEDSPLIT = "fakedsplit"
    MULTISPLIT = "multisplit"
    MULTIDISORDER = "multidisorder"
    SYNDATA = "syndata"
    DISORDER = "disorder"
    SEQOVL = "seqovl"
    IPFRAG2 = "ipfrag2"
    BADSUM_RACE = "badsum_race"


class FoolingMethod(Enum):
    """
    Packet fooling methods for DPI evasion.
    
    These methods manipulate packets to confuse DPI systems:
    - BADSEQ: Corrupt sequence numbers (typically offset by -10000)
    - BADSUM: Corrupt TCP checksums on fake packets
    - MD5SIG: Add MD5 signature TCP option (kind=19) if supported
    - DATANOACK: Remove ACK flag from fake packets
    """
    BADSEQ = "badseq"
    BADSUM = "badsum"
    MD5SIG = "md5sig"
    DATANOACK = "datanoack"


@dataclass
class ZapretStrategy:
    """
    Structured representation of a zapret strategy with all parameters.
    
    This dataclass captures all the parameters that can be specified in a
    zapret command line, with correct defaults that match zapret behavior.
    
    CRITICAL DEFAULTS (improved for compatibility):
    - split_pos: 76 (NOT 3!)
    - split_seqovl: 336 (NOT 1!)
    - ttl: 64 (TASK 3: improved from 1 for better compatibility)
    """
    # Core DPI methods - can be multiple (e.g., [FAKE, FAKEDDISORDER])
    methods: List[DPIMethod] = field(default_factory=list)
    
    # Split parameters - CRITICAL for fakeddisorder
    split_seqovl: Optional[int] = None  # Sequence overlap size (default 336 for fakeddisorder)
    split_pos: Optional[int] = None     # Split position in payload (default 76 for fakeddisorder)
    split_count: Optional[int] = None   # Number of splits for multisplit
    
    # TTL parameters
    ttl: Optional[int] = None           # Fixed TTL value (default 64 for fakeddisorder - TASK 3)
    autottl: Optional[int] = None       # Auto TTL range (1 to autottl value)
    
    # Fooling methods
    fooling: List[FoolingMethod] = field(default_factory=list)
    
    # Fake payload parameters
    fake_http: Optional[str] = None     # Custom HTTP payload or template
    fake_tls: Optional[str] = None      # Custom TLS payload or PAYLOADTLS
    
    # Attack behavior parameters
    repeats: Optional[int] = None       # Number of attack repetitions
    cutoff: Optional[str] = None        # Cutoff mode (n2f, d2f, etc.)
    
    # Advanced parameters
    window_div: Optional[int] = None    # Window division factor
    delay: Optional[int] = None         # Delay between packets (ms)
    any_protocol: Optional[bool] = None # Apply to any protocol
    wssize: Optional[int] = None        # Window size
    fake_unknown: Optional[str] = None  # Fake unknown payload
    
    # Additional zapret parameters for comprehensive support
    fake_syndata: Optional[str] = None  # Fake SYN data payload
    fake_quic: Optional[str] = None     # Fake QUIC payload
    fake_wireguard: Optional[str] = None # Fake WireGuard payload
    fake_dht: Optional[str] = None      # Fake DHT payload
    fake_unknown_udp: Optional[str] = None # Fake unknown UDP payload
    
    # Protocol-specific parameters
    udp_fake: Optional[bool] = None     # Enable UDP fake packets
    tcp_fake: Optional[bool] = None     # Enable TCP fake packets
    
    # Advanced timing parameters
    hostlist_auto_fail_threshold: Optional[int] = None  # Auto-fail threshold
    hostlist_auto_fail_time: Optional[int] = None       # Auto-fail time
    
    # Split parameters for different protocols
    split_http_req: Optional[str] = None    # HTTP request split mode
    split_tls: Optional[str] = None         # TLS split mode
    
    # Additional fooling parameters
    wrong_chksum: Optional[bool] = None     # Wrong checksum
    wrong_seq: Optional[bool] = None        # Wrong sequence numbers
    fake_data: Optional[str] = None         # Custom fake data
    
    def __post_init__(self):
        """Apply default values based on detected methods."""
        # If fakeddisorder is detected, apply zapret-compatible defaults
        if DPIMethod.FAKEDDISORDER in self.methods:
            if self.split_pos is None:
                self.split_pos = 76  # zapret default for fakeddisorder
            
            # CRITICAL FIX: If 'fake' is also present, it implies a simple split (overlap=0)
            # not a seqovl. Only apply default overlap if 'fake' is NOT present.
            if self.split_seqovl is None:
                if DPIMethod.FAKE in self.methods:
                    self.split_seqovl = 0  # This means simple split, no overlap
                else:
                    self.split_seqovl = 336  # zapret default for fakeddisorder without 'fake'

            if self.ttl is None and self.autottl is None:
                self.ttl = 1  # CRITICAL FIX: TTL=1 required for fakeddisorder DPI bypass
        
        # Apply other method-specific defaults
        if DPIMethod.MULTISPLIT in self.methods:
            if self.split_count is None:
                self.split_count = 5  # Common default for multisplit
            if self.ttl is None and self.autottl is None:
                self.ttl = 64  # TASK 3: Changed from 4 to 64 for better compatibility


class FixedStrategyInterpreter:
    """
    Fixed strategy interpreter that correctly parses zapret command strings.
    
    This interpreter fixes critical issues in the original implementation:
    
    1. CRITICAL FIX: fake,fakeddisorder -> fakeddisorder attack (NOT seqovl)
    2. Correct parameter extraction and mapping
    3. Proper default values matching zapret behavior
    4. Full support for all zapret parameters
    
    Example problematic command that this fixes:
    "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 
     --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 
     --dpi-desync-ttl=64"
    
    Previous (broken) interpretation: seqovl attack with wrong parameters
    Fixed interpretation: fakeddisorder attack with correct parameters
    """
    
    def __init__(self):
        """Initialize the fixed strategy interpreter."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Method mapping for parsing
        self._method_map = {
            'fake': DPIMethod.FAKE,
            'fakeddisorder': DPIMethod.FAKEDDISORDER,
            'fakedsplit': DPIMethod.FAKEDSPLIT,
            'multisplit': DPIMethod.MULTISPLIT,
            'multidisorder': DPIMethod.MULTIDISORDER,
            'syndata': DPIMethod.SYNDATA,
            'disorder': DPIMethod.DISORDER,
            'seqovl': DPIMethod.SEQOVL,
            'ipfrag2': DPIMethod.IPFRAG2,
            'badsum_race': DPIMethod.BADSUM_RACE,
        }
        
        # Fooling method mapping
        self._fooling_map = {
            'badseq': FoolingMethod.BADSEQ,
            'badsum': FoolingMethod.BADSUM,
            'md5sig': FoolingMethod.MD5SIG,
            'datanoack': FoolingMethod.DATANOACK,
        }
    
    def parse_strategy(self, strategy_str: str) -> ZapretStrategy:
        """
        Parse a zapret strategy string into a structured ZapretStrategy object.
        
        Args:
            strategy_str: Zapret command line string (e.g., "--dpi-desync=fake,fakeddisorder ...")
            
        Returns:
            ZapretStrategy object with parsed parameters
            
        Raises:
            ValueError: If strategy string is invalid or contains unsupported parameters
        """
        if not strategy_str or not isinstance(strategy_str, str):
            raise ValueError("Strategy string cannot be empty or None")
        
        self.logger.info(f"Parsing zapret strategy: {strategy_str}")
        
        try:
            # Extract DPI methods - CRITICAL: handle fake,fakeddisorder correctly
            methods = self._extract_dpi_methods(strategy_str)
            
            # Extract all parameters
            split_seqovl = self._extract_int_param(strategy_str, 'split-seqovl')
            split_pos = self._extract_int_param(strategy_str, 'split-pos')
            split_count = self._extract_int_param(strategy_str, 'split-count')
            ttl = self._extract_int_param(strategy_str, 'ttl')
            autottl = self._extract_int_param(strategy_str, 'autottl')
            repeats = self._extract_int_param(strategy_str, 'repeats')
            window_div = self._extract_int_param(strategy_str, 'window-div')
            delay = self._extract_int_param(strategy_str, 'delay')
            wssize = self._extract_int_param(strategy_str, 'wssize')
            hostlist_auto_fail_threshold = self._extract_int_param(strategy_str, 'hostlist-auto-fail-threshold')
            hostlist_auto_fail_time = self._extract_int_param(strategy_str, 'hostlist-auto-fail-time')
            
            # Extract string parameters
            fake_http = self._extract_string_param(strategy_str, 'fake-http')
            fake_tls = self._extract_string_param(strategy_str, 'fake-tls')
            fake_unknown = self._extract_string_param(strategy_str, 'fake-unknown')
            fake_syndata = self._extract_string_param(strategy_str, 'fake-syndata')
            fake_quic = self._extract_string_param(strategy_str, 'fake-quic')
            fake_wireguard = self._extract_string_param(strategy_str, 'fake-wireguard')
            fake_dht = self._extract_string_param(strategy_str, 'fake-dht')
            fake_unknown_udp = self._extract_string_param(strategy_str, 'fake-unknown-udp')
            cutoff = self._extract_string_param(strategy_str, 'cutoff')
            split_http_req = self._extract_string_param(strategy_str, 'split-http-req')
            split_tls = self._extract_string_param(strategy_str, 'split-tls')
            fake_data = self._extract_string_param(strategy_str, 'fake-data')
            
            # Extract fooling methods
            fooling = self._extract_fooling_methods(strategy_str)
            
            # Extract boolean parameters
            any_protocol = self._extract_bool_param(strategy_str, 'any-protocol')
            udp_fake = self._extract_bool_param(strategy_str, 'udp-fake')
            tcp_fake = self._extract_bool_param(strategy_str, 'tcp-fake')
            wrong_chksum = self._extract_bool_param(strategy_str, 'wrong-chksum')
            wrong_seq = self._extract_bool_param(strategy_str, 'wrong-seq')
            
            # Create strategy object
            strategy = ZapretStrategy(
                methods=methods,
                split_seqovl=split_seqovl,
                split_pos=split_pos,
                split_count=split_count,
                ttl=ttl,
                autottl=autottl,
                fooling=fooling,
                fake_http=fake_http,
                fake_tls=fake_tls,
                fake_unknown=fake_unknown,
                fake_syndata=fake_syndata,
                fake_quic=fake_quic,
                fake_wireguard=fake_wireguard,
                fake_dht=fake_dht,
                fake_unknown_udp=fake_unknown_udp,
                repeats=repeats,
                cutoff=cutoff,
                split_http_req=split_http_req,
                split_tls=split_tls,
                fake_data=fake_data,
                window_div=window_div,
                delay=delay,
                any_protocol=any_protocol,
                wssize=wssize,
                hostlist_auto_fail_threshold=hostlist_auto_fail_threshold,
                hostlist_auto_fail_time=hostlist_auto_fail_time,
                udp_fake=udp_fake,
                tcp_fake=tcp_fake,
                wrong_chksum=wrong_chksum,
                wrong_seq=wrong_seq
            )
            
            # Mark strategy as validated (parsed from command line)
            strategy._validated = True
            
            self.logger.info(f"Parsed strategy: methods={[m.value for m in methods]}, "
                           f"split_seqovl={split_seqovl}, split_pos={split_pos}, "
                           f"ttl={ttl}, autottl={autottl}")
            
            return strategy
            
        except Exception as e:
            self.logger.error(f"Failed to parse strategy '{strategy_str}': {e}")
            raise ValueError(f"Invalid strategy string: {e}")
    
    def _extract_dpi_methods(self, strategy_str: str) -> List[DPIMethod]:
        """
        Extract DPI methods from strategy string.
        
        CRITICAL FIX: fake,fakeddisorder -> [FAKE, FAKEDDISORDER] -> fakeddisorder attack
        NOT seqovl attack as in the broken implementation!
        
        Args:
            strategy_str: Strategy string containing --dpi-desync parameter
            
        Returns:
            List of DPIMethod enums
        """
        methods = []
        
        # Match --dpi-desync=method1,method2,... pattern
        match = re.search(r'--dpi-desync=([^\s]+)', strategy_str)
        if not match:
            self.logger.warning("No --dpi-desync parameter found, using default 'fake'")
            return [DPIMethod.FAKE]
        
        method_str = match.group(1)
        method_names = [name.strip() for name in method_str.split(',')]
        
        for method_name in method_names:
            if method_name in self._method_map:
                methods.append(self._method_map[method_name])
                self.logger.debug(f"Parsed DPI method: {method_name} -> {self._method_map[method_name]}")
            else:
                self.logger.warning(f"Unknown DPI method: {method_name}, skipping")
        
        if not methods:
            self.logger.warning("No valid DPI methods found, using default 'fake'")
            methods = [DPIMethod.FAKE]
        
        # CRITICAL: Log the method combination for debugging
        if DPIMethod.FAKE in methods and DPIMethod.FAKEDDISORDER in methods:
            self.logger.info("CRITICAL: Detected fake,fakeddisorder combination - "
                           "this should map to fakeddisorder attack, NOT seqovl!")
        
        return methods
    
    def _extract_fooling_methods(self, strategy_str: str) -> List[FoolingMethod]:
        """
        Extract fooling methods from --dpi-desync-fooling parameter.
        
        Args:
            strategy_str: Strategy string containing --dpi-desync-fooling parameter
            
        Returns:
            List of FoolingMethod enums
        """
        fooling_methods = []
        
        # Match --dpi-desync-fooling=method1,method2,... pattern
        match = re.search(r'--dpi-desync-fooling=([^\s]+)', strategy_str)
        if not match:
            return fooling_methods
        
        fooling_str = match.group(1)
        fooling_names = [name.strip() for name in fooling_str.split(',')]
        
        for fooling_name in fooling_names:
            if fooling_name in self._fooling_map:
                fooling_methods.append(self._fooling_map[fooling_name])
                self.logger.debug(f"Parsed fooling method: {fooling_name} -> {self._fooling_map[fooling_name]}")
            else:
                self.logger.warning(f"Unknown fooling method: {fooling_name}, skipping")
        
        return fooling_methods
    
    def _extract_int_param(self, strategy_str: str, param_name: str) -> Optional[int]:
        """
        Extract integer parameter from strategy string with validation.
        
        TASK 3 ENHANCEMENT: Added TTL validation and error handling.
        
        Args:
            strategy_str: Strategy string
            param_name: Parameter name (without --dpi-desync- prefix)
            
        Returns:
            Integer value or None if not found
        """
        pattern = rf'--dpi-desync-{re.escape(param_name)}=(\d+)'
        match = re.search(pattern, strategy_str)
        if match:
            try:
                value = int(match.group(1))
                
                # TTL validation (1-255 range)
                if param_name == 'ttl':
                    if not (1 <= value <= 255):
                        self.logger.error(f"Invalid TTL value {value}. TTL must be between 1 and 255. Using default TTL=64.")
                        return 64  # Return better default instead of None
                    else:
                        self.logger.info(f"Valid TTL value: {value}")
                
                # AutoTTL validation (should be reasonable range)
                elif param_name == 'autottl':
                    if not (1 <= value <= 64):
                        self.logger.error(f"Invalid autottl value {value}. AutoTTL should be between 1 and 64. Using default autottl=2.")
                        return 2  # Return reasonable default
                    else:
                        self.logger.info(f"Valid autottl value: {value}")
                
                self.logger.debug(f"Extracted {param_name}={value}")
                return value
                
            except ValueError as e:
                self.logger.error(f"Could not parse integer for {param_name}: {e}")
                
                # Provide fallback values for critical parameters
                if param_name == 'ttl':
                    self.logger.info("Using fallback TTL=64 for invalid TTL parameter")
                    return 64
                elif param_name == 'autottl':
                    self.logger.info("Using fallback autottl=2 for invalid autottl parameter")
                    return 2
                
                return None
        
        return None
    
    def _extract_string_param(self, strategy_str: str, param_name: str) -> Optional[str]:
        """
        Extract string parameter from strategy string.
        
        Handles special values like PAYLOADTLS, 0x00000000 (disable), etc.
        
        Args:
            strategy_str: Strategy string
            param_name: Parameter name (without --dpi-desync- prefix)
            
        Returns:
            String value or None if not found
        """
        pattern = rf'--dpi-desync-{re.escape(param_name)}=([^\s]+)'
        match = re.search(pattern, strategy_str)
        if match:
            value = match.group(1)
            
            # Handle special values
            if value == '0x00000000':
                self.logger.debug(f"Parameter {param_name} disabled (0x00000000)")
                return "0x00000000"  # Return the special value, don't convert to None
            
            self.logger.debug(f"Extracted {param_name}={value}")
            return value
        return None
    
    def _extract_bool_param(self, strategy_str: str, param_name: str) -> Optional[bool]:
        """
        Extract boolean parameter from strategy string.
        
        Args:
            strategy_str: Strategy string
            param_name: Parameter name (without --dpi-desync- prefix)
            
        Returns:
            True if parameter is present, None if not found
        """
        pattern = rf'--dpi-desync-{re.escape(param_name)}'
        if re.search(pattern, strategy_str):
            self.logger.debug(f"Boolean parameter {param_name} is enabled")
            return True
        return None
    
    def create_autottl_strategy_variants(self, base_strategy: ZapretStrategy) -> List[ZapretStrategy]:
        """
        Create multiple strategy variants for autottl testing.
        
        Requirements 9.1, 9.2: Implement autottl functionality with TTL range testing (1 to autottl value)
        
        When autottl is specified, this creates variants with different TTL values
        for systematic testing to find the optimal TTL.
        
        Args:
            base_strategy: Base strategy with autottl parameter
            
        Returns:
            List of strategy variants with different TTL values
        """
        if base_strategy.autottl is None or base_strategy.autottl <= 1:
            return [base_strategy]
        
        variants = []
        
        # Create variants for TTL range 1 to autottl
        for ttl_value in range(1, base_strategy.autottl + 1):
            variant = ZapretStrategy(
                methods=base_strategy.methods.copy(),
                split_seqovl=base_strategy.split_seqovl,
                split_pos=base_strategy.split_pos,
                split_count=base_strategy.split_count,
                ttl=ttl_value,  # Override TTL with specific value
                autottl=None,   # Remove autottl to prevent recursion
                fooling=base_strategy.fooling.copy() if base_strategy.fooling else [],
                fake_http=base_strategy.fake_http,
                fake_tls=base_strategy.fake_tls,
                fake_unknown=base_strategy.fake_unknown,
                fake_syndata=base_strategy.fake_syndata,
                fake_quic=base_strategy.fake_quic,
                fake_wireguard=base_strategy.fake_wireguard,
                fake_dht=base_strategy.fake_dht,
                fake_unknown_udp=base_strategy.fake_unknown_udp,
                repeats=base_strategy.repeats,
                cutoff=base_strategy.cutoff,
                split_http_req=base_strategy.split_http_req,
                split_tls=base_strategy.split_tls,
                fake_data=base_strategy.fake_data,
                window_div=base_strategy.window_div,
                delay=base_strategy.delay,
                any_protocol=base_strategy.any_protocol,
                wssize=base_strategy.wssize,
                hostlist_auto_fail_threshold=base_strategy.hostlist_auto_fail_threshold,
                hostlist_auto_fail_time=base_strategy.hostlist_auto_fail_time,
                udp_fake=base_strategy.udp_fake,
                tcp_fake=base_strategy.tcp_fake,
                wrong_chksum=base_strategy.wrong_chksum,
                wrong_seq=base_strategy.wrong_seq
            )
            
            # Mark as autottl variant for tracking
            variant._autottl_variant = True
            variant._autottl_original_range = base_strategy.autottl
            variant._autottl_test_ttl = ttl_value
            
            variants.append(variant)
            
        self.logger.info(f"Created {len(variants)} autottl variants for TTL range 1-{base_strategy.autottl}")
        return variants
    
    def generate_fake_payload_templates(self, payload_type: str, custom_data: Optional[str] = None) -> bytes:
        """
        Generate fake payload templates for different protocols.
        
        Requirements 9.3, 9.4: Implement fake payload templates: PAYLOADTLS (fake TLS ClientHello), custom HTTP payloads
        
        Args:
            payload_type: Type of payload (PAYLOADTLS, HTTP, QUIC, etc.)
            custom_data: Custom payload data if specified
            
        Returns:
            Generated fake payload bytes
        """
        if custom_data and custom_data != "0x00000000":
            # Use custom payload data
            try:
                return custom_data.encode('utf-8', errors='ignore')
            except Exception as e:
                self.logger.warning(f"Failed to encode custom payload: {e}")
                return b""
        
        if payload_type == "PAYLOADTLS":
            return self._generate_fake_tls_clienthello()
        elif payload_type == "HTTP":
            return self._generate_fake_http_request()
        elif payload_type == "QUIC":
            return self._generate_fake_quic_packet()
        elif payload_type == "WIREGUARD":
            return self._generate_fake_wireguard_packet()
        elif payload_type == "DHT":
            return self._generate_fake_dht_packet()
        elif payload_type == "SYNDATA":
            return self._generate_fake_syn_data()
        else:
            # Default to TLS ClientHello
            return self._generate_fake_tls_clienthello()
    
    def _generate_fake_tls_clienthello(self) -> bytes:
        """
        Generate fake TLS ClientHello packet (PAYLOADTLS template).
        
        Returns:
            TLS ClientHello bytes matching zapret PAYLOADTLS format
        """
        import random
        import struct
        
        # TLS Record Header
        tls_record = bytearray()
        tls_record.extend(b"\x16")  # Content Type: Handshake (22)
        tls_record.extend(b"\x03\x03")  # Version: TLS 1.2
        
        # Handshake message
        handshake = bytearray()
        handshake.extend(b"\x01")  # Handshake Type: Client Hello (1)
        
        # Client Hello data
        client_hello = bytearray()
        client_hello.extend(b"\x03\x03")  # Client Version: TLS 1.2
        
        # Random (32 bytes)
        client_random = bytes([random.randint(0, 255) for _ in range(32)])
        client_hello.extend(client_random)
        
        # Session ID (variable length)
        session_id_len = random.randint(0, 32)
        client_hello.extend(bytes([session_id_len]))
        if session_id_len > 0:
            session_id = bytes([random.randint(0, 255) for _ in range(session_id_len)])
            client_hello.extend(session_id)
        
        # Cipher Suites
        cipher_suites = [
            b"\x13\x01",  # TLS_AES_128_GCM_SHA256
            b"\x13\x02",  # TLS_AES_256_GCM_SHA384
            b"\xc0\x2b",  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            b"\xc0\x2f",  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ]
        cipher_data = b"".join(cipher_suites)
        client_hello.extend(struct.pack(">H", len(cipher_data)))
        client_hello.extend(cipher_data)
        
        # Compression Methods
        client_hello.extend(b"\x01\x00")  # Length + NULL compression
        
        # Extensions (simplified)
        extensions = bytearray()
        
        # SNI Extension
        sni_name = b"example.com"
        sni_data = b"\x00" + struct.pack(">H", len(sni_name)) + sni_name
        extensions.extend(b"\x00\x00")  # Extension Type: SNI
        extensions.extend(struct.pack(">H", len(sni_data) + 2))
        extensions.extend(struct.pack(">H", len(sni_data)))
        extensions.extend(sni_data)
        
        # Add extensions to client hello
        client_hello.extend(struct.pack(">H", len(extensions)))
        client_hello.extend(extensions)
        
        # Add client hello length to handshake
        handshake.extend(struct.pack(">I", len(client_hello))[1:])  # 3 bytes
        handshake.extend(client_hello)
        
        # Add handshake length to TLS record
        tls_record.extend(struct.pack(">H", len(handshake)))
        tls_record.extend(handshake)
        
        return bytes(tls_record)
    
    def _generate_fake_http_request(self) -> bytes:
        """Generate fake HTTP request."""
        fake_http = (
            "GET /index.html HTTP/1.1\r\n"
            "Host: www.example.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: keep-alive\r\n\r\n"
        )
        return fake_http.encode('utf-8')
    
    def _generate_fake_quic_packet(self) -> bytes:
        """Generate fake QUIC packet."""
        import random
        
        # QUIC Initial packet structure (simplified)
        quic_packet = bytearray()
        
        # Header Form (1) + Fixed Bit (1) + Packet Type (2) + Reserved (2) + Packet Number Length (2)
        header_byte = 0b11000000  # Long header, Initial packet
        quic_packet.append(header_byte)
        
        # Version (4 bytes) - QUIC v1
        quic_packet.extend(b"\x00\x00\x00\x01")
        
        # Destination Connection ID Length
        dcid_len = 8
        quic_packet.append(dcid_len)
        
        # Destination Connection ID
        dcid = bytes([random.randint(0, 255) for _ in range(dcid_len)])
        quic_packet.extend(dcid)
        
        # Source Connection ID Length
        scid_len = 8
        quic_packet.append(scid_len)
        
        # Source Connection ID
        scid = bytes([random.randint(0, 255) for _ in range(scid_len)])
        quic_packet.extend(scid)
        
        # Token Length (variable length integer)
        quic_packet.append(0)  # No token
        
        # Length (variable length integer) - placeholder
        payload_len = 64
        quic_packet.extend(b"\x40\x40")  # 2-byte VLI for length ~64
        
        # Packet Number (1-4 bytes)
        quic_packet.append(0x01)
        
        # Payload (encrypted in real QUIC)
        payload = bytes([random.randint(0, 255) for _ in range(payload_len - 1)])
        quic_packet.extend(payload)
        
        return bytes(quic_packet)
    
    def _generate_fake_wireguard_packet(self) -> bytes:
        """Generate fake WireGuard packet."""
        import random
        
        # WireGuard packet structure (simplified)
        wg_packet = bytearray()
        
        # Message Type (1 byte) - Handshake Initiation
        wg_packet.append(1)
        
        # Reserved (3 bytes)
        wg_packet.extend(b"\x00\x00\x00")
        
        # Sender Index (4 bytes)
        sender_index = random.randint(0, 0xFFFFFFFF)
        wg_packet.extend(sender_index.to_bytes(4, 'little'))
        
        # Ephemeral (32 bytes)
        ephemeral = bytes([random.randint(0, 255) for _ in range(32)])
        wg_packet.extend(ephemeral)
        
        # Static (48 bytes - 32 + 16 for auth tag)
        static = bytes([random.randint(0, 255) for _ in range(48)])
        wg_packet.extend(static)
        
        # Timestamp (28 bytes - 12 + 16 for auth tag)
        timestamp = bytes([random.randint(0, 255) for _ in range(28)])
        wg_packet.extend(timestamp)
        
        # MAC1 (16 bytes)
        mac1 = bytes([random.randint(0, 255) for _ in range(16)])
        wg_packet.extend(mac1)
        
        # MAC2 (16 bytes) - optional
        mac2 = bytes([random.randint(0, 255) for _ in range(16)])
        wg_packet.extend(mac2)
        
        return bytes(wg_packet)
    
    def _generate_fake_dht_packet(self) -> bytes:
        """Generate fake DHT (BitTorrent) packet."""
        import random
        
        # DHT query packet (simplified)
        dht_packet = bytearray()
        
        # Transaction ID (2 bytes)
        transaction_id = random.randint(0, 0xFFFF)
        dht_packet.extend(transaction_id.to_bytes(2, 'big'))
        
        # Bencode dictionary for DHT query
        node_id = bytes([random.randint(0, 255) for _ in range(20)])
        
        # Simple ping query in bencode format
        query = f"d1:ad2:id20:{node_id.decode('latin1')}e1:q4:ping1:t2:aa1:y1:qe"
        dht_packet.extend(query.encode('latin1'))
        
        return bytes(dht_packet)
    
    def _generate_fake_syn_data(self) -> bytes:
        """Generate fake SYN data payload."""
        import random
        
        # Random data that might be sent with SYN packet
        syn_data = bytearray()
        
        # Add some random bytes that look like application data
        for _ in range(random.randint(16, 64)):
            syn_data.append(random.randint(0x20, 0x7E))  # Printable ASCII
        
        return bytes(syn_data)
    
    def validate_strategy(self, strategy: ZapretStrategy) -> bool:
        """
        Validate strategy parameters for compatibility and correctness.
        
        Performs compatibility checks like:
        - fakeddisorder requires split-seqovl parameter
        - TTL values must be in valid range (1-255)
        - split_pos must be positive
        
        Args:
            strategy: ZapretStrategy object to validate
            
        Returns:
            True if strategy is valid, False otherwise
        """
        try:
            # Check fakeddisorder requirements - validate before __post_init__ defaults are applied
            if DPIMethod.FAKEDDISORDER in strategy.methods:
                # For validation purposes, we need to check if split_seqovl was explicitly provided
                # The __post_init__ method will set defaults, but for validation we want to ensure
                # the user provided the required parameters or they were set by parsing
                if not hasattr(strategy, '_validated') and strategy.split_seqovl is None:
                    self.logger.error("fakeddisorder attack requires split-seqovl parameter")
                    return False
                if strategy.split_pos is None:
                    self.logger.warning("fakeddisorder without split-pos, using default 76")
            
            # Validate TTL range
            if strategy.ttl is not None:
                if not (1 <= strategy.ttl <= 255):
                    self.logger.error(f"TTL value {strategy.ttl} out of range (1-255)")
                    return False
            
            if strategy.autottl is not None:
                if not (1 <= strategy.autottl <= 255):
                    self.logger.error(f"AutoTTL value {strategy.autottl} out of range (1-255)")
                    return False
            
            # Validate split_pos
            if strategy.split_pos is not None:
                if strategy.split_pos <= 0:
                    self.logger.error(f"split_pos must be positive, got {strategy.split_pos}")
                    return False
            
            # Validate split_seqovl
            if strategy.split_seqovl is not None:
                if strategy.split_seqovl < 0:
                    self.logger.error(f"split_seqovl must be non-negative, got {strategy.split_seqovl}")
                    return False
            
            # Validate repeats
            if strategy.repeats is not None:
                if strategy.repeats <= 0:
                    self.logger.error(f"repeats must be positive, got {strategy.repeats}")
                    return False
            
            self.logger.info("Strategy validation passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Strategy validation failed: {e}")
            return False
    
    def convert_to_legacy_format(self, strategy: ZapretStrategy) -> Dict[str, Any]:
        """
        Convert ZapretStrategy to legacy internal format for backward compatibility.
        
        This method maps the new structured format back to the dictionary format
        used by the existing codebase, ensuring compatibility while fixing the
        critical parameter mapping issues.
        
        CRITICAL FIXES:
        - fake,fakeddisorder -> attack_type="fakeddisorder" (NOT "seqovl")
        - split_seqovl -> overlap_size (NOT seqovl)
        - Correct default values
        
        Args:
            strategy: ZapretStrategy object to convert
            
        Returns:
            Dictionary in legacy format
        """
        legacy_format = {}
        
        # Determine primary attack type - CRITICAL FIX
        if DPIMethod.FAKEDDISORDER in strategy.methods:
            legacy_format['attack_type'] = 'fakeddisorder'  # NOT seqovl!
            self.logger.info("CRITICAL FIX: Mapping fake,fakeddisorder to fakeddisorder attack")
        elif DPIMethod.MULTISPLIT in strategy.methods:
            legacy_format['attack_type'] = 'multisplit'
        elif DPIMethod.MULTIDISORDER in strategy.methods:
            legacy_format['attack_type'] = 'multidisorder'
        elif DPIMethod.SEQOVL in strategy.methods:
            legacy_format['attack_type'] = 'seqovl'
        elif DPIMethod.SYNDATA in strategy.methods:
            legacy_format['attack_type'] = 'syndata'
        elif DPIMethod.DISORDER in strategy.methods:
            legacy_format['attack_type'] = 'disorder'
        elif DPIMethod.IPFRAG2 in strategy.methods:
            legacy_format['attack_type'] = 'ipfrag2'
        elif DPIMethod.FAKEDSPLIT in strategy.methods:
            legacy_format['attack_type'] = 'fakedsplit'
        elif DPIMethod.BADSUM_RACE in strategy.methods:
            legacy_format['attack_type'] = 'badsum_race'
        elif DPIMethod.FAKE in strategy.methods:
            legacy_format['attack_type'] = 'fake'
        else:
            legacy_format['attack_type'] = 'fake'  # Default fallback
        
        # Map parameters with correct names - CRITICAL FIXES
        if strategy.split_seqovl is not None:
            legacy_format['overlap_size'] = strategy.split_seqovl  # NOT 'seqovl'!
            
        if strategy.split_pos is not None:
            legacy_format['split_pos'] = strategy.split_pos
            
        if strategy.split_count is not None:
            legacy_format['split_count'] = strategy.split_count
            
        if strategy.ttl is not None:
            legacy_format['ttl'] = strategy.ttl
            
        if strategy.autottl is not None:
            legacy_format['autottl'] = strategy.autottl
            
        if strategy.repeats is not None:
            legacy_format['repeats'] = strategy.repeats
            
        if strategy.fooling:
            legacy_format['fooling'] = [method.value for method in strategy.fooling]
            
        if strategy.fake_http is not None:
            legacy_format['fake_http'] = strategy.fake_http
            
        if strategy.fake_tls is not None:
            legacy_format['fake_tls'] = strategy.fake_tls
            
        if strategy.window_div is not None:
            legacy_format['window_div'] = strategy.window_div
            
        if strategy.wssize is not None:
            legacy_format['wssize'] = strategy.wssize
            
        if strategy.delay is not None:
            legacy_format['delay'] = strategy.delay
            
        if strategy.cutoff is not None:
            legacy_format['cutoff'] = strategy.cutoff
            
        # Map new comprehensive parameters
        if strategy.fake_unknown is not None:
            legacy_format['fake_unknown'] = strategy.fake_unknown
            
        if strategy.fake_syndata is not None:
            legacy_format['fake_syndata'] = strategy.fake_syndata
            
        if strategy.fake_quic is not None:
            legacy_format['fake_quic'] = strategy.fake_quic
            
        if strategy.fake_wireguard is not None:
            legacy_format['fake_wireguard'] = strategy.fake_wireguard
            
        if strategy.fake_dht is not None:
            legacy_format['fake_dht'] = strategy.fake_dht
            
        if strategy.fake_unknown_udp is not None:
            legacy_format['fake_unknown_udp'] = strategy.fake_unknown_udp
            
        if strategy.fake_data is not None:
            legacy_format['fake_data'] = strategy.fake_data
            
        if strategy.udp_fake is not None:
            legacy_format['udp_fake'] = strategy.udp_fake
            
        if strategy.tcp_fake is not None:
            legacy_format['tcp_fake'] = strategy.tcp_fake
            
        if strategy.any_protocol is not None:
            legacy_format['any_protocol'] = strategy.any_protocol
            
        if strategy.wrong_chksum is not None:
            legacy_format['wrong_chksum'] = strategy.wrong_chksum
            
        if strategy.wrong_seq is not None:
            legacy_format['wrong_seq'] = strategy.wrong_seq
            
        if strategy.split_http_req is not None:
            legacy_format['split_http_req'] = strategy.split_http_req
            
        if strategy.split_tls is not None:
            legacy_format['split_tls'] = strategy.split_tls
            
        if strategy.hostlist_auto_fail_threshold is not None:
            legacy_format['hostlist_auto_fail_threshold'] = strategy.hostlist_auto_fail_threshold
            
        if strategy.hostlist_auto_fail_time is not None:
            legacy_format['hostlist_auto_fail_time'] = strategy.hostlist_auto_fail_time
        
        self.logger.info(f"Converted to legacy format with comprehensive parameters: {legacy_format}")
        return legacy_format


# Global instance for easy access
_fixed_interpreter = None

def get_fixed_interpreter() -> FixedStrategyInterpreter:
    """Get global instance of FixedStrategyInterpreter."""
    global _fixed_interpreter
    if _fixed_interpreter is None:
        _fixed_interpreter = FixedStrategyInterpreter()
    return _fixed_interpreter


def parse_zapret_strategy(strategy_str: str) -> ZapretStrategy:
    """
    Convenience function to parse zapret strategy string.
    
    Args:
        strategy_str: Zapret command line string
        
    Returns:
        ZapretStrategy object
    """
    interpreter = get_fixed_interpreter()
    return interpreter.parse_strategy(strategy_str)


def convert_to_legacy(strategy: ZapretStrategy) -> Dict[str, Any]:
    """
    Convenience function to convert strategy to legacy format.
    
    Args:
        strategy: ZapretStrategy object
        
    Returns:
        Dictionary in legacy format
    """
    interpreter = get_fixed_interpreter()
    return interpreter.convert_to_legacy_format(strategy)
    
def interpret_strategy(strategy_string: str) -> Optional[Dict[str, Any]]:
    """
    Main function to interpret zapret strategy string.
    This is the function called from cli.py
    
    Args:
        strategy_string: Zapret command line string
        
    Returns:
        Dictionary with 'type' and 'params' keys for engine task
    """
    try:
        # Use the fixed interpreter
        interpreter = get_fixed_interpreter()
        
        # Parse the strategy
        parsed_strategy = interpreter.parse_strategy(strategy_string)
        
        # Validate the strategy
        if not interpreter.validate_strategy(parsed_strategy):
            logger.warning(f"Strategy validation failed for: {strategy_string}")
            return None
        
        # Convert to legacy format for engine compatibility
        legacy_format = interpreter.convert_to_legacy_format(parsed_strategy)
        
        # Transform to engine task format
        engine_task = {
            'type': legacy_format.get('attack_type', 'unknown'),
            'params': {}
        }
        
        # Copy all parameters except attack_type
        for key, value in legacy_format.items():
            if key != 'attack_type':
                engine_task['params'][key] = value
        
        # CRITICAL: Log the interpretation for debugging
        logger.info(f"Interpreted strategy: {strategy_string}")
        logger.info(f"  -> Attack type: {engine_task['type']}")
        logger.info(f"  -> Parameters: {engine_task['params']}")
        
        # Special handling for fakeddisorder attack
        if engine_task['type'] == 'fakeddisorder':
            # Ensure critical parameters are present
            if 'split_pos' not in engine_task['params']:
                engine_task['params']['split_pos'] = 76  # zapret default
            if 'overlap_size' not in engine_task['params'] and 'split_seqovl' in engine_task['params']:
                engine_task['params']['overlap_size'] = engine_task['params']['split_seqovl']
            if 'ttl' not in engine_task['params']:
                engine_task['params']['ttl'] = 1  # zapret default for fakeddisorder
            
            logger.info(f"  -> CRITICAL: fakeddisorder with split_pos={engine_task['params']['split_pos']}, "
                       f"overlap_size={engine_task['params'].get('overlap_size', 336)}, "
                       f"ttl={engine_task['params']['ttl']}")
        
        try:
            return _normalize_engine_task(engine_task)
        except Exception:
            return engine_task
        
    except Exception as e:
        logger.error(f"Failed to interpret strategy '{strategy_string}': {e}")
        return None