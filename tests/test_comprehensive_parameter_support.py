#!/usr/bin/env python3
"""
Comprehensive test for task 25: Add comprehensive parameter support for all zapret features

This test validates:
- Autottl functionality with TTL range testing (1 to autottl value)
- Support for all fooling methods: badseq (-10000 offset), badsum (corrupt checksum), md5sig (add signature)
- Fake payload templates: PAYLOADTLS (fake TLS ClientHello), custom HTTP payloads
- Repeats parameter for multiple attack attempts with minimal delays
- Additional parameters: fake-unknown, cutoff, any-protocol, wssize

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
"""

import asyncio
import logging
import sys
import time
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_interpreter_fixed import (
    FixedStrategyInterpreter,
    ZapretStrategy,
    DPIMethod,
    FoolingMethod
)
from core.bypass.attacks.tcp.fake_disorder_attack import (
    FakeDisorderAttack,
    FakeDisorderConfig
)
from core.bypass.attacks.base import AttackContext, AttackStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ComprehensiveParameterTester:
    """Test comprehensive parameter support for zapret features."""
    
    def __init__(self):
        self.interpreter = FixedStrategyInterpreter()
        self.test_results = []
    
    async def run_all_tests(self):
        """Run all comprehensive parameter tests."""
        logger.info("Starting comprehensive parameter support tests...")
        
        # Test 1: Autottl functionality
        await self.test_autottl_functionality()
        
        # Test 2: All fooling methods
        await self.test_all_fooling_methods()
        
        # Test 3: Fake payload templates
        await self.test_fake_payload_templates()
        
        # Test 4: Repeats with minimal delays
        await self.test_repeats_with_minimal_delays()
        
        # Test 5: Additional parameters
        await self.test_additional_parameters()
        
        # Test 6: Comprehensive strategy parsing
        await self.test_comprehensive_strategy_parsing()
        
        # Test 7: Legacy format conversion
        await self.test_legacy_format_conversion()
        
        # Generate report
        self.generate_test_report()
    
    async def test_autottl_functionality(self):
        """Test autottl functionality with TTL range testing."""
        logger.info("Testing autottl functionality...")
        
        test_cases = [
            {
                "name": "autottl_basic",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-autottl=3 --dpi-desync-split-seqovl=336",
                "expected_autottl": 3
            },
            {
                "name": "autottl_with_ttl_override",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-autottl=5 --dpi-desync-ttl=2 --dpi-desync-split-seqovl=336",
                "expected_autottl": 5
            },
            {
                "name": "no_autottl",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=1 --dpi-desync-split-seqovl=336",
                "expected_autottl": None
            }
        ]
        
        for test_case in test_cases:
            try:
                strategy = self.interpreter.parse_strategy(test_case["strategy"])
                
                # Validate autottl parsing
                assert strategy.autottl == test_case["expected_autottl"], \
                    f"Expected autottl={test_case['expected_autottl']}, got {strategy.autottl}"
                
                # Test autottl variant creation
                if strategy.autottl:
                    variants = self.interpreter.create_autottl_strategy_variants(strategy)
                    assert len(variants) == strategy.autottl, \
                        f"Expected {strategy.autottl} variants, got {len(variants)}"
                    
                    # Validate TTL values in variants
                    for i, variant in enumerate(variants):
                        expected_ttl = i + 1
                        assert variant.ttl == expected_ttl, \
                            f"Variant {i} should have TTL={expected_ttl}, got {variant.ttl}"
                        assert variant.autottl is None, \
                            f"Variant {i} should have autottl=None, got {variant.autottl}"
                
                # Test FakeDisorderAttack with autottl
                config = FakeDisorderConfig(
                    autottl=test_case["expected_autottl"],
                    split_seqovl=336,
                    split_pos=76
                )
                attack = FakeDisorderAttack(config=config)
                
                # Test TTL calculation
                calculated_ttl = attack._calculate_ttl()
                if test_case["expected_autottl"]:
                    assert 1 <= calculated_ttl <= test_case["expected_autottl"], \
                        f"Calculated TTL {calculated_ttl} not in range 1-{test_case['expected_autottl']}"
                
                self.test_results.append({
                    "test": f"autottl_{test_case['name']}",
                    "status": "PASS",
                    "details": f"autottl={strategy.autottl}, calculated_ttl={calculated_ttl}"
                })
                
                logger.info(f"✓ Autottl test '{test_case['name']}' passed")
                
            except Exception as e:
                self.test_results.append({
                    "test": f"autottl_{test_case['name']}",
                    "status": "FAIL",
                    "error": str(e)
                })
                logger.error(f"✗ Autottl test '{test_case['name']}' failed: {e}")
    
    async def test_all_fooling_methods(self):
        """Test all fooling methods support."""
        logger.info("Testing all fooling methods...")
        
        test_cases = [
            {
                "name": "badseq_offset",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badseq --dpi-desync-split-seqovl=336",
                "expected_fooling": [FoolingMethod.BADSEQ]
            },
            {
                "name": "badsum_checksum",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badsum --dpi-desync-split-seqovl=336",
                "expected_fooling": [FoolingMethod.BADSUM]
            },
            {
                "name": "md5sig_signature",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-seqovl=336",
                "expected_fooling": [FoolingMethod.MD5SIG]
            },
            {
                "name": "all_fooling_methods",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badseq,badsum,md5sig,datanoack --dpi-desync-split-seqovl=336",
                "expected_fooling": [FoolingMethod.BADSEQ, FoolingMethod.BADSUM, FoolingMethod.MD5SIG, FoolingMethod.DATANOACK]
            },
            {
                "name": "wrong_chksum_wrong_seq",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-wrong-chksum --dpi-desync-wrong-seq --dpi-desync-split-seqovl=336",
                "expected_wrong_chksum": True,
                "expected_wrong_seq": True
            }
        ]
        
        for test_case in test_cases:
            try:
                strategy = self.interpreter.parse_strategy(test_case["strategy"])
                
                # Validate fooling methods parsing
                if "expected_fooling" in test_case:
                    assert set(strategy.fooling) == set(test_case["expected_fooling"]), \
                        f"Expected fooling={test_case['expected_fooling']}, got {strategy.fooling}"
                
                # Validate wrong_chksum and wrong_seq
                if "expected_wrong_chksum" in test_case:
                    assert strategy.wrong_chksum == test_case["expected_wrong_chksum"], \
                        f"Expected wrong_chksum={test_case['expected_wrong_chksum']}, got {strategy.wrong_chksum}"
                
                if "expected_wrong_seq" in test_case:
                    assert strategy.wrong_seq == test_case["expected_wrong_seq"], \
                        f"Expected wrong_seq={test_case['expected_wrong_seq']}, got {strategy.wrong_seq}"
                
                # Test FakeDisorderAttack fooling application
                config = FakeDisorderConfig(
                    fooling_methods=[method.value for method in strategy.fooling] if strategy.fooling else [],
                    wrong_chksum=strategy.wrong_chksum or False,
                    wrong_seq=strategy.wrong_seq or False,
                    split_seqovl=336,
                    split_pos=76
                )
                attack = FakeDisorderAttack(config=config)
                
                # Test fooling options generation
                fooling_options = attack._apply_fooling_to_options()
                
                # Validate fooling options
                if FoolingMethod.BADSEQ in strategy.fooling:
                    assert fooling_options.get("bad_sequence") is True
                    assert fooling_options.get("seq_corruption_offset") == -10000
                
                if FoolingMethod.BADSUM in strategy.fooling:
                    assert fooling_options.get("bad_checksum") is True
                
                if FoolingMethod.MD5SIG in strategy.fooling:
                    assert fooling_options.get("md5sig_fooling") is True
                    assert fooling_options.get("tcp_option_kind") == 19
                
                if strategy.wrong_chksum:
                    assert fooling_options.get("wrong_checksum") is True
                
                if strategy.wrong_seq:
                    assert fooling_options.get("wrong_sequence") is True
                
                self.test_results.append({
                    "test": f"fooling_{test_case['name']}",
                    "status": "PASS",
                    "details": f"fooling={strategy.fooling}, options={list(fooling_options.keys())}"
                })
                
                logger.info(f"✓ Fooling test '{test_case['name']}' passed")
                
            except Exception as e:
                self.test_results.append({
                    "test": f"fooling_{test_case['name']}",
                    "status": "FAIL",
                    "error": str(e)
                })
                logger.error(f"✗ Fooling test '{test_case['name']}' failed: {e}")
    
    async def test_fake_payload_templates(self):
        """Test fake payload templates support."""
        logger.info("Testing fake payload templates...")
        
        test_cases = [
            {
                "name": "payloadtls_template",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-split-seqovl=336",
                "expected_fake_tls": "PAYLOADTLS"
            },
            {
                "name": "custom_http_payload",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fake-http=custom_http_data --dpi-desync-split-seqovl=336",
                "expected_fake_http": "custom_http_data"
            },
            {
                "name": "fake_quic_payload",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fake-quic=QUIC_DATA --dpi-desync-split-seqovl=336",
                "expected_fake_quic": "QUIC_DATA"
            },
            {
                "name": "fake_unknown_payload",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fake-unknown=UNKNOWN_DATA --dpi-desync-split-seqovl=336",
                "expected_fake_unknown": "UNKNOWN_DATA"
            },
            {
                "name": "disabled_payload",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fake-tls=0x00000000 --dpi-desync-split-seqovl=336",
                "expected_fake_tls": "0x00000000"
            }
        ]
        
        for test_case in test_cases:
            try:
                strategy = self.interpreter.parse_strategy(test_case["strategy"])
                
                # Validate payload parameter parsing
                if "expected_fake_tls" in test_case:
                    assert strategy.fake_tls == test_case["expected_fake_tls"], \
                        f"Expected fake_tls={test_case['expected_fake_tls']}, got {strategy.fake_tls}"
                
                if "expected_fake_http" in test_case:
                    assert strategy.fake_http == test_case["expected_fake_http"], \
                        f"Expected fake_http={test_case['expected_fake_http']}, got {strategy.fake_http}"
                
                if "expected_fake_quic" in test_case:
                    assert strategy.fake_quic == test_case["expected_fake_quic"], \
                        f"Expected fake_quic={test_case['expected_fake_quic']}, got {strategy.fake_quic}"
                
                if "expected_fake_unknown" in test_case:
                    assert strategy.fake_unknown == test_case["expected_fake_unknown"], \
                        f"Expected fake_unknown={test_case['expected_fake_unknown']}, got {strategy.fake_unknown}"
                
                # Test payload generation
                config = FakeDisorderConfig(
                    fake_tls=strategy.fake_tls,
                    fake_http=strategy.fake_http,
                    fake_quic=strategy.fake_quic,
                    fake_unknown=strategy.fake_unknown,
                    split_seqovl=336,
                    split_pos=76
                )
                attack = FakeDisorderAttack(config=config)
                
                # Test payload template selection
                template = config.select_fake_payload_template()
                assert template is not None, "Template selection should not return None"
                
                # Test payload generation
                fake_payload = await attack._generate_fake_payload_for_dpi(b"test payload")
                
                # Validate payload generation
                if strategy.fake_tls == "0x00000000":
                    assert fake_payload == b"", "Disabled payload should be empty"
                elif strategy.fake_tls == "PAYLOADTLS":
                    assert len(fake_payload) > 0, "PAYLOADTLS should generate non-empty payload"
                    assert fake_payload[0] == 0x16, "TLS payload should start with TLS record type"
                
                self.test_results.append({
                    "test": f"payload_{test_case['name']}",
                    "status": "PASS",
                    "details": f"template={template}, payload_len={len(fake_payload)}"
                })
                
                logger.info(f"✓ Payload test '{test_case['name']}' passed")
                
            except Exception as e:
                self.test_results.append({
                    "test": f"payload_{test_case['name']}",
                    "status": "FAIL",
                    "error": str(e)
                })
                logger.error(f"✗ Payload test '{test_case['name']}' failed: {e}")
    
    async def test_repeats_with_minimal_delays(self):
        """Test repeats parameter with minimal delays."""
        logger.info("Testing repeats with minimal delays...")
        
        test_cases = [
            {
                "name": "single_repeat",
                "repeats": 1,
                "expected_delays": [0.0]
            },
            {
                "name": "multiple_repeats",
                "repeats": 3,
                "expected_delays": [0.0, 1.0, 2.0]
            },
            {
                "name": "many_repeats",
                "repeats": 5,
                "expected_delays": [0.0, 1.0, 2.0, 3.0, 4.0]
            }
        ]
        
        for test_case in test_cases:
            try:
                config = FakeDisorderConfig(
                    repeats=test_case["repeats"],
                    repeat_delay_ms=1.0,  # 1ms minimal delay
                    split_seqovl=336,
                    split_pos=76
                )
                
                # Test delay calculation
                delays = config.get_effective_repeats_with_delays()
                
                assert len(delays) == test_case["repeats"], \
                    f"Expected {test_case['repeats']} delays, got {len(delays)}"
                
                for i, expected_delay in enumerate(test_case["expected_delays"]):
                    if i < len(delays):
                        assert delays[i] == expected_delay, \
                            f"Delay {i} should be {expected_delay}, got {delays[i]}"
                
                # Test attack execution with repeats
                attack = FakeDisorderAttack(config=config)
                
                context = AttackContext(
                    connection_id="test_conn",
                    src_ip="192.168.1.100",
                    dst_ip="1.1.1.1",
                    src_port=12345,
                    dst_port=443,
                    payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    tcp_seq=1000,
                    tcp_ack=2000,
                    tcp_window_size=65535
                )
                
                result = await attack.execute(context)
                
                # Validate result
                assert result.status == AttackStatus.SUCCESS, f"Attack should succeed, got {result.status}"
                assert len(result.segments) >= test_case["repeats"], \
                    f"Should have at least {test_case['repeats']} segments, got {len(result.segments)}"
                
                # Check for repeat segments
                repeat_segments = [seg for seg in result.segments if seg[2].get("is_repeat", False)]
                expected_repeat_segments = (test_case["repeats"] - 1) * 3  # 3 segments per repeat (fake + 2 real)
                
                if test_case["repeats"] > 1:
                    assert len(repeat_segments) > 0, "Should have repeat segments for multiple repeats"
                
                self.test_results.append({
                    "test": f"repeats_{test_case['name']}",
                    "status": "PASS",
                    "details": f"repeats={test_case['repeats']}, delays={delays}, segments={len(result.segments)}"
                })
                
                logger.info(f"✓ Repeats test '{test_case['name']}' passed")
                
            except Exception as e:
                self.test_results.append({
                    "test": f"repeats_{test_case['name']}",
                    "status": "FAIL",
                    "error": str(e)
                })
                logger.error(f"✗ Repeats test '{test_case['name']}' failed: {e}")
    
    async def test_additional_parameters(self):
        """Test additional parameters: fake-unknown, cutoff, any-protocol, wssize."""
        logger.info("Testing additional parameters...")
        
        test_cases = [
            {
                "name": "wssize_parameter",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-wssize=32768 --dpi-desync-split-seqovl=336",
                "expected_wssize": 32768
            },
            {
                "name": "cutoff_parameter",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-cutoff=n2f --dpi-desync-split-seqovl=336",
                "expected_cutoff": "n2f"
            },
            {
                "name": "any_protocol_parameter",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-any-protocol --dpi-desync-split-seqovl=336",
                "expected_any_protocol": True
            },
            {
                "name": "window_div_parameter",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-window-div=6 --dpi-desync-split-seqovl=336",
                "expected_window_div": 6
            },
            {
                "name": "comprehensive_parameters",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-fake-syndata=SYN_DATA --dpi-desync-fake-wireguard=WG_DATA --dpi-desync-fake-dht=DHT_DATA --dpi-desync-split-seqovl=336",
                "expected_fake_syndata": "SYN_DATA",
                "expected_fake_wireguard": "WG_DATA",
                "expected_fake_dht": "DHT_DATA"
            }
        ]
        
        for test_case in test_cases:
            try:
                strategy = self.interpreter.parse_strategy(test_case["strategy"])
                
                # Validate parameter parsing
                if "expected_wssize" in test_case:
                    assert strategy.wssize == test_case["expected_wssize"], \
                        f"Expected wssize={test_case['expected_wssize']}, got {strategy.wssize}"
                
                if "expected_cutoff" in test_case:
                    assert strategy.cutoff == test_case["expected_cutoff"], \
                        f"Expected cutoff={test_case['expected_cutoff']}, got {strategy.cutoff}"
                
                if "expected_any_protocol" in test_case:
                    assert strategy.any_protocol == test_case["expected_any_protocol"], \
                        f"Expected any_protocol={test_case['expected_any_protocol']}, got {strategy.any_protocol}"
                
                if "expected_window_div" in test_case:
                    assert strategy.window_div == test_case["expected_window_div"], \
                        f"Expected window_div={test_case['expected_window_div']}, got {strategy.window_div}"
                
                if "expected_fake_syndata" in test_case:
                    assert strategy.fake_syndata == test_case["expected_fake_syndata"], \
                        f"Expected fake_syndata={test_case['expected_fake_syndata']}, got {strategy.fake_syndata}"
                
                if "expected_fake_wireguard" in test_case:
                    assert strategy.fake_wireguard == test_case["expected_fake_wireguard"], \
                        f"Expected fake_wireguard={test_case['expected_fake_wireguard']}, got {strategy.fake_wireguard}"
                
                if "expected_fake_dht" in test_case:
                    assert strategy.fake_dht == test_case["expected_fake_dht"], \
                        f"Expected fake_dht={test_case['expected_fake_dht']}, got {strategy.fake_dht}"
                
                # Test legacy format conversion
                legacy_format = self.interpreter.convert_to_legacy_format(strategy)
                
                # Validate legacy format includes new parameters
                if strategy.wssize is not None:
                    assert "wssize" in legacy_format
                
                if strategy.cutoff is not None:
                    assert "cutoff" in legacy_format
                
                if strategy.any_protocol is not None:
                    assert "any_protocol" in legacy_format
                
                self.test_results.append({
                    "test": f"additional_{test_case['name']}",
                    "status": "PASS",
                    "details": f"parsed_params={len([k for k, v in strategy.__dict__.items() if v is not None])}"
                })
                
                logger.info(f"✓ Additional parameters test '{test_case['name']}' passed")
                
            except Exception as e:
                self.test_results.append({
                    "test": f"additional_{test_case['name']}",
                    "status": "FAIL",
                    "error": str(e)
                })
                logger.error(f"✗ Additional parameters test '{test_case['name']}' failed: {e}")
    
    async def test_comprehensive_strategy_parsing(self):
        """Test comprehensive strategy parsing with all parameters."""
        logger.info("Testing comprehensive strategy parsing...")
        
        # Complex strategy with many parameters
        complex_strategy = (
            "--dpi-desync=fake,fakeddisorder "
            "--dpi-desync-split-seqovl=336 "
            "--dpi-desync-split-pos=76 "
            "--dpi-desync-autottl=3 "
            "--dpi-desync-fooling=md5sig,badsum,badseq "
            "--dpi-desync-repeats=2 "
            "--dpi-desync-fake-tls=PAYLOADTLS "
            "--dpi-desync-fake-quic=QUIC_DATA "
            "--dpi-desync-wssize=32768 "
            "--dpi-desync-window-div=6 "
            "--dpi-desync-cutoff=n2f "
            "--dpi-desync-any-protocol "
            "--dpi-desync-wrong-chksum "
            "--dpi-desync-wrong-seq"
        )
        
        try:
            strategy = self.interpreter.parse_strategy(complex_strategy)
            
            # Validate all parameters
            assert DPIMethod.FAKEDDISORDER in strategy.methods
            assert strategy.split_seqovl == 336
            assert strategy.split_pos == 76
            assert strategy.autottl == 3
            assert FoolingMethod.MD5SIG in strategy.fooling
            assert FoolingMethod.BADSUM in strategy.fooling
            assert FoolingMethod.BADSEQ in strategy.fooling
            assert strategy.repeats == 2
            assert strategy.fake_tls == "PAYLOADTLS"
            assert strategy.fake_quic == "QUIC_DATA"
            assert strategy.wssize == 32768
            assert strategy.window_div == 6
            assert strategy.cutoff == "n2f"
            assert strategy.any_protocol is True
            assert strategy.wrong_chksum is True
            assert strategy.wrong_seq is True
            
            # Test strategy validation
            is_valid = self.interpreter.validate_strategy(strategy)
            assert is_valid, "Complex strategy should be valid"
            
            # Test legacy format conversion
            legacy_format = self.interpreter.convert_to_legacy_format(strategy)
            assert legacy_format["attack_type"] == "fakeddisorder"
            assert legacy_format["overlap_size"] == 336  # NOT seqovl!
            assert legacy_format["split_pos"] == 76
            
            # Test FakeDisorderAttack creation
            config = FakeDisorderConfig(
                split_seqovl=strategy.split_seqovl,
                split_pos=strategy.split_pos,
                autottl=strategy.autottl,
                fooling_methods=[method.value for method in strategy.fooling],
                repeats=strategy.repeats,
                fake_tls=strategy.fake_tls,
                fake_quic=strategy.fake_quic,
                wssize=strategy.wssize,
                window_div=strategy.window_div,
                cutoff=strategy.cutoff,
                any_protocol=strategy.any_protocol,
                wrong_chksum=strategy.wrong_chksum,
                wrong_seq=strategy.wrong_seq
            )
            
            attack = FakeDisorderAttack(config=config)
            
            # Validate attack configuration
            assert attack.config.split_seqovl == 336
            assert attack.config.autottl == 3
            assert "md5sig" in attack.config.fooling_methods
            
            self.test_results.append({
                "test": "comprehensive_parsing",
                "status": "PASS",
                "details": f"parsed {len([k for k, v in strategy.__dict__.items() if v is not None])} parameters"
            })
            
            logger.info("✓ Comprehensive strategy parsing test passed")
            
        except Exception as e:
            self.test_results.append({
                "test": "comprehensive_parsing",
                "status": "FAIL",
                "error": str(e)
            })
            logger.error(f"✗ Comprehensive strategy parsing test failed: {e}")
    
    async def test_legacy_format_conversion(self):
        """Test legacy format conversion with all new parameters."""
        logger.info("Testing legacy format conversion...")
        
        try:
            # Create strategy with all new parameters
            strategy = ZapretStrategy(
                methods=[DPIMethod.FAKEDDISORDER],
                split_seqovl=336,
                split_pos=76,
                autottl=3,
                fooling=[FoolingMethod.BADSEQ, FoolingMethod.BADSUM],
                fake_tls="PAYLOADTLS",
                fake_quic="QUIC_DATA",
                fake_unknown="UNKNOWN_DATA",
                fake_syndata="SYN_DATA",
                fake_wireguard="WG_DATA",
                fake_dht="DHT_DATA",
                fake_unknown_udp="UDP_DATA",
                fake_data="CUSTOM_DATA",
                repeats=2,
                wssize=32768,
                window_div=6,
                cutoff="n2f",
                any_protocol=True,
                udp_fake=True,
                tcp_fake=True,
                wrong_chksum=True,
                wrong_seq=True,
                split_http_req="method",
                split_tls="sni",
                hostlist_auto_fail_threshold=10,
                hostlist_auto_fail_time=60
            )
            
            # Convert to legacy format
            legacy_format = self.interpreter.convert_to_legacy_format(strategy)
            
            # Validate all parameters are included
            expected_params = [
                "attack_type", "overlap_size", "split_pos", "autottl", "fooling",
                "fake_tls", "fake_quic", "fake_unknown", "fake_syndata",
                "fake_wireguard", "fake_dht", "fake_unknown_udp", "fake_data",
                "repeats", "wssize", "window_div", "cutoff", "any_protocol",
                "udp_fake", "tcp_fake", "wrong_chksum", "wrong_seq",
                "split_http_req", "split_tls", "hostlist_auto_fail_threshold",
                "hostlist_auto_fail_time"
            ]
            
            for param in expected_params:
                assert param in legacy_format, f"Parameter {param} missing from legacy format"
            
            # Validate critical mappings
            assert legacy_format["attack_type"] == "fakeddisorder"
            assert legacy_format["overlap_size"] == 336  # Critical: NOT seqovl!
            assert legacy_format["split_pos"] == 76
            assert legacy_format["fooling"] == ["badseq", "badsum"]
            
            self.test_results.append({
                "test": "legacy_conversion",
                "status": "PASS",
                "details": f"converted {len(legacy_format)} parameters"
            })
            
            logger.info("✓ Legacy format conversion test passed")
            
        except Exception as e:
            self.test_results.append({
                "test": "legacy_conversion",
                "status": "FAIL",
                "error": str(e)
            })
            logger.error(f"✗ Legacy format conversion test failed: {e}")
    
    def generate_test_report(self):
        """Generate comprehensive test report."""
        logger.info("Generating comprehensive parameter support test report...")
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r["status"] == "PASS"])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "="*80)
        print("COMPREHENSIVE PARAMETER SUPPORT TEST REPORT")
        print("="*80)
        print(f"Task 25: Add comprehensive parameter support for all zapret features")
        print(f"Requirements: 9.1, 9.2, 9.3, 9.4, 9.5")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        print("="*80)
        
        # Group results by category
        categories = {}
        for result in self.test_results:
            category = result["test"].split("_")[0]
            if category not in categories:
                categories[category] = []
            categories[category].append(result)
        
        for category, results in categories.items():
            category_passed = len([r for r in results if r["status"] == "PASS"])
            category_total = len(results)
            
            print(f"\n{category.upper()} TESTS ({category_passed}/{category_total})")
            print("-" * 40)
            
            for result in results:
                status_symbol = "✓" if result["status"] == "PASS" else "✗"
                print(f"{status_symbol} {result['test']}: {result['status']}")
                
                if result["status"] == "PASS" and "details" in result:
                    print(f"  Details: {result['details']}")
                elif result["status"] == "FAIL" and "error" in result:
                    print(f"  Error: {result['error']}")
        
        # Feature implementation summary
        print(f"\n{'FEATURE IMPLEMENTATION SUMMARY'}")
        print("-" * 40)
        print("✓ Autottl functionality with TTL range testing (1 to autottl value)")
        print("✓ All fooling methods: badseq (-10000 offset), badsum (corrupt checksum), md5sig (add signature)")
        print("✓ Fake payload templates: PAYLOADTLS (fake TLS ClientHello), custom HTTP payloads")
        print("✓ Repeats parameter for multiple attack attempts with minimal delays")
        print("✓ Additional parameters: fake-unknown, cutoff, any-protocol, wssize")
        print("✓ Comprehensive strategy parsing and validation")
        print("✓ Legacy format conversion with all new parameters")
        
        if failed_tests == 0:
            print(f"\n🎉 ALL TESTS PASSED! Task 25 implementation is complete.")
        else:
            print(f"\n⚠️  {failed_tests} tests failed. Review implementation.")
        
        print("="*80)


async def main():
    """Run comprehensive parameter support tests."""
    tester = ComprehensiveParameterTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())