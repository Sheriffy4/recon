# Module Registry

**Generated:** 2025-12-24 16:03:17  
**Total Modules:** 998  
**Total Functions:** 1367  
**Total Classes:** 2819

This document provides a comprehensive registry of all Python modules in the project, organized by functionality. Use this registry to understand existing functionality and avoid code duplication.

## Table of Contents

- [Attack](#attack) (185 modules)
- [Cli](#cli) (92 modules)
- [Config](#config) (54 modules)
- [Files](#files) (219 modules)
- [Logging](#logging) (68 modules)
- [Network](#network) (145 modules)
- [Other](#other) (8 modules)
- [Strategy](#strategy) (117 modules)
- [Testing](#testing) (53 modules)
- [Validation](#validation) (57 modules)

## Overview

### Modules by Category

- **Files**: 219 modules
- **Attack**: 185 modules
- **Network**: 145 modules
- **Strategy**: 117 modules
- **Cli**: 92 modules
- **Logging**: 68 modules
- **Validation**: 57 modules
- **Config**: 54 modules
- **Testing**: 53 modules
- **Other**: 8 modules

### Largest Modules (by function count)

- `tests\duplicate_analysis\test_serialization_properties.py`: 26 functions, 1 classes
- `find_rst_triggers.py`: 21 functions, 8 classes
- `cli.py`: 16 functions, 10 classes
- `retransmission_root_cause_analyzer.py`: 16 functions, 0 classes
- `core\duplicate_analysis\utils.py`: 16 functions, 1 classes
- `tests\duplicate_analysis\conftest.py`: 15 functions, 0 classes
- `core\attack_parity\cli.py`: 13 functions, 0 classes
- `examples\segment_performance_optimization_example.py`: 12 functions, 0 classes
- `trace_deps.py`: 11 functions, 2 classes
- `tools\manage_feature_flags.py`: 11 functions, 0 classes

## Attack

Modules implementing security testing, bypass techniques, and attack strategies.

### `apply_bypass.py`

Attack/security module with 4 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `apply_forced_override()`
- `apply_system_bypass()`
- `check_admin_rights()`
- `find_executable()`

**Key Imports:**
- `platform`
- `subprocess`


### `attack_handlers_stub.py`

Attack/security module with 2 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `get_stub_handlers()`
- `patch_attack_registry()`

**Classes:**
- `AttackHandlerStub`


### `bypass_problem_investigator.py`

Attack/security module with 1 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `main()`

**Classes:**
- `BypassProblemInvestigator`

**Key Imports:**
- `requests`
- `subprocess`


### `compare_log_pcap.py`

Attack/security module with 5 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `analyze_pcap_attacks()`
- `compare_strategies()`
- `extract_sni()`
- `main()`
- `parse_log_strategies()`

**Key Imports:**
- `scapy.all`
- `struct`


### `core\async_utils\import_manager.py`

Attack/security module with 3 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `ensure_attack_execution_context()`
- `inject_attack_imports()`
- `with_attack_imports()`

**Classes:**
- `ImportManager`

**Key Imports:**
- `importlib`


### `core\attack_combinator.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AdaptiveMetrics`
- `AttackChain`
- `AttackCombinator`
- `AttackResult`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `strategy_interpreter`
- `strategy_selector`
- `threading`


### `core\attack_execution_engine.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `AttackExecutionEngine`
- `ExecutionConfig`
- `ExecutionResult`

**Key Imports:**
- `__future__`
- `core.attack_parameter_mapper`
- `core.bypass.attacks.attack_registry`
- `dataclasses`
- `threading`


### `core\attack_mapping.py`

Attack/security module with 4 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `generate_zapret_command()`
- `get_attack_mapping()`
- `get_supported_attacks()`
- `is_attack_supported()`

**Classes:**
- `AttackInfo`
- `ComprehensiveAttackMapping`

**Key Imports:**
- `dataclasses`


### `core\attack_parity\canonical_definitions.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `CanonicalAttackRegistry`

**Key Imports:**
- `models`


### `core\attack_parity\correlation_engine.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `AttackCorrelationEngine`
- `CombinationCorrelationEngine`
- `TimingAnalyzer`

**Key Imports:**
- `interfaces`
- `models`


### `core\attack_parity\models.py`

Attack/security module with 3 functions and 22 classes for security testing and bypass techniques

**Functions:**
- `classify_attack_from_modifications()`
- `detect_packet_modifications()`
- `group_modifications_by_attack()`

**Classes:**
- `AttackCombination`
- `AttackDefinition`
- `AttackEvent`
- `AttackSequence`
- `CombinationConstraint`
- `ConflictResolution`
- `CorrelationResult`
- `DetectedAttack`
- `ExecutionMode`
- `InteractionRule`
- `InteractionType`
- `ModificationEffect`
- `ModificationType`
- `PacketInfo`
- `PacketModification`
- `PacketModificationSpec`
- `ParameterDiff`
- `ParityResult`
- `TimingAnalysis`
- `TimingConstraint`
- `TimingInfo`
- `TruthViolation`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\attack_parity\report_generator.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `AttackParityReportGenerator`

**Key Imports:**
- `dataclasses`
- `models`


### `core\attack_spec_loader.py`

Attack/security module with 1 functions and 7 classes for security testing and bypass techniques

**Functions:**
- `get_spec_loader()`

**Classes:**
- `AttackParameter`
- `AttackSpec`
- `AttackSpecLoader`
- `ErrorCase`
- `ExpectedPacket`
- `TestVariation`
- `ValidationRule`

**Key Imports:**
- `dataclasses`
- `yaml`


### `core\bypass\analytics\analytics_models.py`

Attack/security module with 0 functions and 9 classes for security testing and bypass techniques

**Classes:**
- `AnalyticsReport`
- `AttackMetrics`
- `DomainAnalytics`
- `MetricType`
- `PerformanceTrend`
- `PredictionResult`
- `RealtimeMetrics`
- `StrategyMetrics`
- `TrendDirection`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\attacks\alias_map.py`

Attack/security module with 1 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `normalize_attack_name()`


### `core\bypass\attacks\attack_classifier.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AttackCategory`
- `AttackClassifier`
- `AttackLevel`
- `AttackProfile`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\attacks\attack_definition.py`

Attack/security module with 0 functions and 6 classes for security testing and bypass techniques

**Classes:**
- `AttackCategory`
- `AttackComplexity`
- `AttackDefinition`
- `AttackStability`
- `CompatibilityMode`
- `TestCase`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\attacks\attack_registry.py`

Attack/security module with 9 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `clear_registry()`
- `configure_lazy_loading()`
- `get_attack_handler()`
- `get_attack_metadata()`
- `get_attack_registry()`
- `get_lazy_loading_config()`
- `list_attacks()`
- `register_attack()`
- `validate_attack_parameters()`

**Classes:**
- `AttackRegistry`

**Key Imports:**
- `base`
- `importlib`
- `inspect`
- `metadata`


### `core\bypass\attacks\audit\attack_auditor.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `AttackAuditReport`
- `AttackAuditor`

**Key Imports:**
- `attack_registry`
- `dataclasses`
- `metadata`


### `core\bypass\attacks\audit\registration_audit.py`

Attack/security module with 1 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `run_audit()`

**Classes:**
- `AttackRegistrationAuditor`
- `AttackRegistrationStatus`
- `RegistrationAuditReport`

**Key Imports:**
- `dataclasses`


### `core\bypass\attacks\base.py`

Attack/security module with 0 functions and 20 classes for security testing and bypass techniques

**Classes:**
- `AttackContext`
- `AttackResult`
- `AttackResultHelper`
- `AttackStatus`
- `BaseAttack`
- `BaselineResult`
- `BatchTestResult`
- `BlockType`
- `BypassMode`
- `BypassResult`
- `ComboAttack`
- `EffectivenessResult`
- `EngineHealth`
- `ManipulationAttack`
- `PayloadAttack`
- `SegmentOrchestrationHelper`
- `SegmentationAttack`
- `TestRequest`
- `TimingAttack`
- `TunnelingAttack`

**Key Imports:**
- `abc`
- `asyncio`
- `dataclasses`
- `enum`


### `core\bypass\attacks\base_classes\dns_attack_base.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `DNSAttackBase`
- `DNSHeader`
- `DNSPacket`
- `DNSQuestion`
- `DNSRecord`

**Key Imports:**
- `abc`
- `base64`
- `binascii`
- `socket`
- `struct`


### `core\bypass\attacks\base_classes\http_attack_base.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `HTTPAttackBase`

**Key Imports:**
- `abc`
- `base`
- `metadata`


### `core\bypass\attacks\base_classes\ip_attack_base.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `IPAttackBase`
- `IPPacket`

**Key Imports:**
- `abc`
- `base`
- `metadata`
- `socket`
- `struct`


### `core\bypass\attacks\base_classes\payload_attack_base.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `PayloadAttackBase`

**Key Imports:**
- `abc`
- `base`
- `metadata`


### `core\bypass\attacks\base_classes\tls_attack_base.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `TLSAttackBase`

**Key Imports:**
- `abc`
- `base`
- `metadata`
- `struct`


### `core\bypass\attacks\base_classes\udp_attack_base.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `QUICPacket`
- `STUNMessage`
- `UDPAttackBase`
- `UDPPacket`

**Key Imports:**
- `abc`
- `base`
- `secrets`
- `socket`
- `struct`


### `core\bypass\attacks\combo\adaptive_combo.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `DPIResponseAdaptiveAttack`
- `LearningAdaptiveAttack`
- `NetworkConditionAdaptiveAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.real_effectiveness_tester`
- `hashlib`


### `core\bypass\attacks\combo\baseline.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BaselineAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\combo\dynamic_combo.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `DynamicComboAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.integration.attack_adapter`


### `core\bypass\attacks\combo\full_session_simulation.py`

Attack/security module with 1 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `create_full_session_attack()`

**Classes:**
- `FullSessionSimulationAttack`
- `SessionConfig`
- `SessionPhase`
- `SessionTiming`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `hashlib`
- `socket`
- `struct`


### `core\bypass\attacks\combo\multi_flow_correlation.py`

Attack/security module with 1 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `create_multi_flow_attack()`

**Classes:**
- `BackgroundFlow`
- `CorrelationConfig`
- `MultiFlowCorrelationAttack`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `core.bypass.attacks.base`
- `dataclasses`
- `threading`


### `core\bypass\attacks\combo\multi_layer.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AdaptiveMultiLayerAttack`
- `PayloadTunnelingComboAttack`
- `TCPHTTPComboAttack`
- `TLSFragmentationComboAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\combo\steganography.py`

Attack/security module with 0 functions and 10 classes for security testing and bypass techniques

**Classes:**
- `AdvancedImageSteganographyAttack`
- `AdvancedProtocolFieldSteganographyAttack`
- `AdvancedTimingChannelSteganographyAttack`
- `CombinedFieldSteganographyAttack`
- `CovertChannelComboAttack`
- `IPIDSteganographyAttack`
- `ImageSteganographyAttack`
- `NetworkProtocolSteganographyAttack`
- `TCPTimestampSteganographyAttack`
- `TimingChannelSteganographyAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `struct`


### `core\bypass\attacks\combo\traffic_mimicry.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `TrafficMimicryAttack`
- `TrafficPattern`
- `TrafficProfile`
- `TrafficType`

**Key Imports:**
- `abc`
- `asyncio`
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`


### `core\bypass\attacks\compatibility\migration_utilities.py`

Attack/security module with 2 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `analyze_attack_for_migration()`
- `generate_migration_template()`

**Classes:**
- `AttackMigrationUtility`
- `MigrationTemplate`

**Key Imports:**
- `core.bypass.attacks.base`
- `dataclasses`
- `inspect`


### `core\bypass\attacks\custom_aliases.py`

Attack/security module with 1 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `register_custom_aliases()`

**Key Imports:**
- `core.bypass.attacks.attack_registry`


### `core\bypass\attacks\dns\dns_base.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `AttackResult`
- `AttackStatus`
- `BaseAttack`

**Key Imports:**
- `abc`
- `dataclasses`
- `enum`


### `core\bypass\attacks\dns\dns_tunneling.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `DNSNullTunnelingAttack`
- `DNSResponseReassembler`
- `DNSTXTTunnelingAttack`
- `DNSTunnelingAttack`

**Key Imports:**
- `attack_registry`
- `base`
- `base_classes.dns_attack_base`
- `metadata`
- `struct`


### `core\bypass\attacks\http\header_attacks.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `HTTPHeaderCaseAttack`
- `HTTPHeaderInjectionAttack`
- `HTTPHeaderOrderAttack`
- `HTTPHostHeaderAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.base_classes.http_attack_base`
- `core.bypass.attacks.metadata`


### `core\bypass\attacks\http\host_manipulation.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `HTTPHostHeaderAttack`

**Key Imports:**
- `asyncio`
- `attack_registry`
- `base`
- `base_classes.http_attack_base`
- `metadata`


### `core\bypass\attacks\http\http2_attacks.py`

Attack/security module with 0 functions and 12 classes for security testing and bypass techniques

**Classes:**
- `H2CSmugglingAttack`
- `H2ClearTextUpgradeAttack`
- `H2FrameSplittingAttack`
- `H2HPACKAdvancedManipulationAttack`
- `H2HPACKBombAttack`
- `H2HPACKIndexManipulationAttack`
- `H2HPACKManipulationAttack`
- `H2PriorityManipulationAttack`
- `H2SmugglingAttack`
- `H2StreamMultiplexingAttack`
- `HPACKEncoder`
- `HTTP2Frame`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `secrets`
- `struct`


### `core\bypass\attacks\http\method_attacks.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `HTTPMethodCaseAttack`
- `HTTPMethodObfuscationAttack`
- `HTTPMethodSubstitutionAttack`
- `HTTPPathObfuscationAttack`
- `HTTPVersionManipulationAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.base_classes.http_attack_base`
- `core.bypass.attacks.metadata`


### `core\bypass\attacks\http\quic_attacks.py`

Attack/security module with 1 functions and 12 classes for security testing and bypass techniques

**Functions:**
- `create_0rtt_enhanced_attack()`

**Classes:**
- `AdvancedPacketNumberSpaceConfusion`
- `AdvancedQUICConnectionIDRotation`
- `BaseQUICAttack`
- `QUICFrame`
- `QUICFrameType`
- `QUICHTTP3FullSession`
- `QUICMigrationSimulation`
- `QUICMixedEncryptionLevelAttack`
- `QUICPacket`
- `QUICPacketCoalescingAttack`
- `QUICPacketType`
- `QUICZeroRTTEarlyDataAttack`

**Key Imports:**
- `abc`
- `asyncio`
- `dataclasses`
- `secrets`
- `struct`


### `core\bypass\attacks\http_manipulation.py`

Attack/security module with 0 functions and 8 classes for security testing and bypass techniques

**Classes:**
- `BaseHTTPManipulationAttack`
- `CaseManipulationAttack`
- `ChunkedEncodingAttack`
- `HTTPManipulationConfig`
- `HeaderModificationAttack`
- `HeaderSplittingAttack`
- `MethodManipulationAttack`
- `PipelineManipulationAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `dataclasses`


### `core\bypass\attacks\ip\fragmentation.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `IPFragmentDisorderAttack`
- `IPFragmentOverlapAttack`
- `IPFragmentationAdvancedAttack`
- `IPFragmentationAttack`
- `IPFragmentationRandomAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.base_classes.ip_attack_base`
- `core.bypass.attacks.metadata`


### `core\bypass\attacks\ip\header_manipulation.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `IPIDManipulationAttack`
- `IPTOSManipulationAttack`
- `IPTTLManipulationAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\ip_obfuscation.py`

Attack/security module with 1 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `register_ip_obfuscation_attacks()`

**Classes:**
- `BaseIPObfuscationAttack`
- `IPIDManipulationAttack`
- `IPTTLManipulationAttack`
- `TimingObfuscationAttack`

**Key Imports:**
- `attack_registry`
- `base`
- `core.bypass.attacks.attack_registry`
- `metadata`


### `core\bypass\attacks\metadata.py`

Attack/security module with 1 functions and 10 classes for security testing and bypass techniques

**Functions:**
- `create_attack_metadata()`

**Classes:**
- `AttackCategories`
- `AttackEntry`
- `AttackExecutionContext`
- `AttackMetadata`
- `AttackParameterTypes`
- `FoolingMethods`
- `RegistrationPriority`
- `RegistrationResult`
- `SpecialParameterValues`
- `ValidationResult`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\attacks\obfuscation\icmp_obfuscation.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `ICMPCovertChannelObfuscationAttack`
- `ICMPDataTunnelingObfuscationAttack`
- `ICMPRedirectTunnelingObfuscationAttack`
- `ICMPTimestampTunnelingObfuscationAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `struct`


### `core\bypass\attacks\obfuscation\payload_encryption.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AESPayloadEncryptionAttack`
- `ChaCha20PayloadEncryptionAttack`
- `MultiLayerEncryptionAttack`
- `XORPayloadEncryptionAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `hashlib`
- `struct`


### `core\bypass\attacks\obfuscation\protocol_mimicry.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `FTPProtocolMimicryAttack`
- `HTTPProtocolMimicryAttack`
- `SMTPProtocolMimicryAttack`
- `TLSProtocolMimicryAttack`

**Key Imports:**
- `asyncio`
- `base64`
- `core.bypass.attacks.attack_registry`
- `hashlib`
- `struct`


### `core\bypass\attacks\obfuscation\protocol_tunneling.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `DNSOverHTTPSTunnelingAttack`
- `HTTPTunnelingObfuscationAttack`
- `SSHTunnelingObfuscationAttack`
- `VPNTunnelingObfuscationAttack`
- `WebSocketTunnelingObfuscationAttack`

**Key Imports:**
- `asyncio`
- `base64`
- `core.bypass.attacks.attack_registry`
- `hashlib`
- `struct`


### `core\bypass\attacks\obfuscation\quic_obfuscation.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `QUICFragmentationObfuscationAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `struct`


### `core\bypass\attacks\obfuscation\traffic_obfuscation.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `FlowObfuscationAttack`
- `PacketSizeObfuscationAttack`
- `TimingObfuscationAttack`
- `TrafficPatternObfuscationAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\pacing_attack.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `PacingAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`


### `core\bypass\attacks\payload\base64_encoding.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `PayloadBase64Attack`

**Key Imports:**
- `attack_registry`
- `base`
- `base64`
- `base_classes.payload_attack_base`
- `metadata`


### `core\bypass\attacks\payload\encryption.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `PayloadBase64Attack`
- `PayloadEncryptionAttack`
- `PayloadROT13Attack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`


### `core\bypass\attacks\payload\noise.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `DecoyPacketsAttack`
- `NoiseInjectionAttack`
- `PayloadPaddingAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\payload\obfuscation.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `PayloadObfuscationAttack`

**Key Imports:**
- `attack_registry`
- `base`
- `base_classes.payload_attack_base`
- `metadata`


### `core\bypass\attacks\payload\padding_injection.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `PayloadPaddingAttack`

**Key Imports:**
- `attack_registry`
- `base`
- `base_classes.payload_attack_base`
- `metadata`


### `core\bypass\attacks\performance\attack_performance_monitor.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `AttackExecutionMetrics`
- `AttackPerformanceMonitor`
- `AttackPerformanceStats`

**Key Imports:**
- `dataclasses`
- `psutil`


### `core\bypass\attacks\performance\instance_cache.py`

Attack/security module with 2 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `configure_instance_cache()`
- `get_instance_cache()`

**Classes:**
- `AttackInstanceCache`
- `CacheEntry`
- `CacheMetrics`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\bypass\attacks\performance\lazy_loader.py`

Attack/security module with 2 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `configure_lazy_loading()`
- `get_lazy_loader()`

**Classes:**
- `AttackCacheEntry`
- `AttackLazyLoader`
- `LoadMetrics`

**Key Imports:**
- `dataclasses`
- `importlib`


### `core\bypass\attacks\registry_adapter.py`

Attack/security module with 1 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `create_attack_registry_adapter()`

**Classes:**
- `AttackEffectivenessData`
- `AttackRegistryAdapter`
- `EnhancedAttackMetadata`
- `IntentCategory`

**Key Imports:**
- `attack_registry`
- `dataclasses`
- `enum`
- `metadata`


### `core\bypass\attacks\simple_attack_executor.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `SimpleAttackExecutor`

**Key Imports:**
- `core.bypass.attacks.base`


### `core\bypass\attacks\standardized_registration_examples.py`

Attack/security module with 1 functions and 9 classes for security testing and bypass techniques

**Functions:**
- `simple_ttl_manipulation()`

**Classes:**
- `AdvancedTCPSplitAttack`
- `AutoNamedAttack`
- `CoreFakeDisorderAttack`
- `HTTPHeaderCaseEvasionAttack`
- `LegacyWrapperAttack`
- `MultiLayerEvasionAttack`
- `SimpleDisorderAttack`
- `TLSSNIFragmentationAttack`
- `XORPayloadObfuscationAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`


### `core\bypass\attacks\stateful_fragmentation.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `AdvancedOverlapAttack`
- `StatefulFragmentationAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`


### `core\bypass\attacks\tcp\disorder_split.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `DisorderSplitAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\tcp\fakeddisorder_attack.py`

Attack/security module with 2 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `create_optimized_fakeddisorder()`
- `create_x_com_optimized_fakeddisorder()`

**Classes:**
- `FakedDisorderAttack`
- `FakedDisorderConfig`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.techniques.primitives`
- `dataclasses`


### `core\bypass\attacks\tcp\fooling.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `BadSeqFoolingAttack`
- `BadSumFoolingAttack`
- `MD5SigFoolingAttack`
- `TTLManipulationAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\tcp\manipulation.py`

Attack/security module with 0 functions and 10 classes for security testing and bypass techniques

**Classes:**
- `TCPFragmentationAttack`
- `TCPMultiSplitAttack`
- `TCPOptionsModificationAttack`
- `TCPOptionsPaddingAttack`
- `TCPSequenceNumberManipulationAttack`
- `TCPTimestampAttack`
- `TCPWindowManipulationAttack`
- `TCPWindowScalingAttack`
- `TCPWindowSizeLimitAttack`
- `UrgentPointerAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\tcp\passthrough.py`

Attack/security module with 1 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `register_attack()`

**Classes:**
- `PassthroughAttack`


### `core\bypass\attacks\tcp\race_attacks.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `BadChecksumRaceAttack`
- `CacheConfusionAttack`
- `LowTTLPoisoningAttack`
- `MD5SigRaceAttack`
- `RaceAttackConfig`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `dataclasses`


### `core\bypass\attacks\tcp\stateful_attacks.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `FakeDisorderAttack`
- `MultiDisorderAttack`
- `SequenceOverlapAttack`
- `StatefulAttackConfig`
- `TimingManipulationAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `dataclasses`


### `core\bypass\attacks\tcp\timing.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `BurstTimingEvasionAttack`
- `DripFeedAttack`
- `TimingBasedEvasionAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.tcp.race_attacks`


### `core\bypass\attacks\tcp_advanced.py`

Attack/security module with 1 functions and 8 classes for security testing and bypass techniques

**Functions:**
- `register_tcp_advanced_attacks()`

**Classes:**
- `BaseTCPAdvancedAttack`
- `TCPOptionsPaddingAttack`
- `TCPSequenceManipulationAttack`
- `TCPTimestampManipulationAttack`
- `TCPWindowManipulationAttack`
- `TCPWindowScalingAttack`
- `TCPWindowSizeLimitAttack`
- `UrgentPointerManipulationAttack`

**Key Imports:**
- `attack_registry`
- `base`
- `core.bypass.attacks.attack_registry`
- `metadata`


### `core\bypass\attacks\telemetry\metrics_collector.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AttackMetrics`
- `AttackMetricsCollector`
- `MetricsSnapshot`
- `ThroughputMetrics`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\bypass\attacks\telemetry\telemetry_system.py`

Attack/security module with 2 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `get_telemetry_system()`
- `initialize_telemetry()`

**Classes:**
- `AttackTelemetrySystem`
- `ExecutionContext`

**Key Imports:**
- `contextlib`
- `error_logger`
- `execution_logger`
- `metrics_collector`
- `performance_monitor`


### `core\bypass\attacks\timing\burst_traffic.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `BurstConfiguration`
- `BurstMetrics`
- `BurstTiming`
- `BurstType`
- `TimingBurstAttack`

**Key Imports:**
- `concurrent.futures`
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`
- `threading`


### `core\bypass\attacks\timing\delay_evasion.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `DelayEvasionConfiguration`
- `DelayPattern`
- `TimingDelayAttack`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `core.bypass.attacks.timing.timing_base`
- `dataclasses`
- `enum`


### `core\bypass\attacks\timing\jitter_injection.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `JitterConfiguration`
- `JitterType`
- `TimingJitterAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `core.bypass.attacks.timing.timing_base`
- `dataclasses`


### `core\bypass\attacks\timing\timing_base.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `TimingAttackBase`
- `TimingConfiguration`
- `TimingPattern`
- `TimingResult`

**Key Imports:**
- `abc`
- `core.bypass.attacks.base`
- `core.bypass.attacks.timing_controller`
- `dataclasses`
- `enum`


### `core\bypass\attacks\tls\confusion.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `ProtocolConfusionAttack`
- `TLSContentTypeConfusionAttack`
- `TLSVersionConfusionAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\tls\early_data_smuggling.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `EarlyDataSmugglingAttack`

**Key Imports:**
- `config`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\tls\early_data_tunnel.py`

Attack/security module with 1 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `derive_secret()`

**Classes:**
- `TLS13EarlyDataTunnelingAttack`
- `TLSEarlyDataAttack`

**Key Imports:**
- `cryptography.hazmat.primitives`
- `cryptography.hazmat.primitives.ciphers`
- `hashlib`
- `hmac`
- `struct`


### `core\bypass\attacks\tls\ech_attacks.py`

Attack/security module with 2 functions and 6 classes for security testing and bypass techniques

**Functions:**
- `integrate_with_prober()`
- `test_ech_attack_effectiveness()`

**Classes:**
- `ECHAdvancedFragmentationAttack`
- `ECHAdvancedGreaseAttack`
- `ECHDecoyAttack`
- `ECHFragmentationAttack`
- `ECHGreaseAttack`
- `ECHOuterSNIManipulationAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.protocols.tls`
- `secrets`
- `struct`


### `core\bypass\attacks\tls\extension_attacks.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `ALPNManipulationAttack`
- `GREASEAttack`
- `SNIManipulationAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `core.protocols.tls`
- `struct`


### `core\bypass\attacks\tls\fingerprint_evasion.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `TLS13ExtensionManipulationAttack`
- `TLSExtensionPaddingAttack`
- `TLSExtensionReorderAttack`
- `TLSGREASEAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.base_classes.tls_attack_base`
- `core.bypass.attacks.metadata`
- `struct`


### `core\bypass\attacks\tls\ja3_mimicry.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `JA3FingerprintMimicryAttack`
- `JA4FingerprintMimicryAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.fingerprint.profiles`
- `core.protocols.tls`
- `hashlib`


### `core\bypass\attacks\tls\record_manipulation.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `TLSRecordFragmentationAttack`
- `TLSRecordPaddingAttack`
- `TLSRecordSplitAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `struct`


### `core\bypass\attacks\tls\tls_evasion.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `TLSExtensionManipulationAttack`
- `TLSHandshakeManipulationAttack`
- `TLSRecordFragmentationAttack`
- `TLSVersionDowngradeAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `struct`


### `core\bypass\attacks\tls_advanced.py`

Attack/security module with 1 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `register_tls_advanced_attacks()`

**Classes:**
- `ALPNManipulationAttack`
- `BaseTLSAdvancedAttack`
- `GREASEInjectionAttack`
- `SNIManipulationAttack`

**Key Imports:**
- `attack_registry`
- `base`
- `core.bypass.attacks.attack_registry`
- `metadata`
- `struct`


### `core\bypass\attacks\tls_record_manipulation.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `ClientHelloSplitAttack`
- `TLSRecordPaddingAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `struct`


### `core\bypass\attacks\tunneling\dns_tunneling_legacy.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `DNSAmplificationAttack`
- `DNSCachePoisoningAttack`
- `DNSSubdomainTunnelingAttack`
- `DNSTXTTunnelingAttack`

**Key Imports:**
- `base64`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`


### `core\bypass\attacks\tunneling\icmp_tunneling.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `ICMPCovertChannelAttack`
- `ICMPDataTunnelingAttack`
- `ICMPRedirectTunnelingAttack`
- `ICMPTimestampTunnelingAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.bypass.attacks.metadata`
- `struct`


### `core\bypass\attacks\tunneling\protocol_tunneling.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `HTTPTunnelingAttack`
- `SSHTunnelingAttack`
- `VPNTunnelingAttack`
- `WebSocketTunnelingAttack`

**Key Imports:**
- `base64`
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `struct`


### `core\bypass\attacks\tunneling\quic_fragmentation.py`

Attack/security module with 1 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `encode_variable_length()`

**Classes:**
- `QUICFragmentationAttack`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `struct`


### `core\bypass\attacks\udp\quic_bypass.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `QUICBypassAttack`
- `QUICBypassConfig`

**Key Imports:**
- `base`
- `base_classes.udp_attack_base`
- `dataclasses`
- `secrets`
- `struct`


### `core\bypass\attacks\udp\quic_fragmentation.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `QUICFragmentationAttack`
- `QUICFragmentationConfig`

**Key Imports:**
- `base`
- `base_classes.udp_attack_base`
- `dataclasses`
- `registry`
- `struct`


### `core\bypass\attacks\udp\stun_bypass.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `STUNBypassAttack`
- `STUNBypassConfig`

**Key Imports:**
- `base`
- `core.bypass.attacks.attack_registry`
- `dataclasses`
- `registry`
- `struct`


### `core\bypass\attacks\udp\udp_fragmentation.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `UDPFragmentationAttack`
- `UDPFragmentationConfig`

**Key Imports:**
- `base`
- `core.bypass.attacks.attack_registry`
- `dataclasses`
- `registry`


### `core\bypass\diagnostics\metrics.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `BypassQualityMetrics`
- `MetricData`
- `MetricsCollector`

**Key Imports:**
- `dataclasses`


### `core\bypass\engine\attack_combination_validator.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `AttackCombinationValidator`
- `CombinationValidationResult`

**Key Imports:**
- `dataclasses`


### `core\bypass\engine\attack_dispatcher.py`

Attack/security module with 1 functions and 11 classes for security testing and bypass techniques

**Functions:**
- `create_attack_dispatcher()`

**Classes:**
- `AttackDispatcher`
- `AttackExecutionError`
- `AttackNotFoundError`
- `DisorderMethod`
- `DispatcherConfig`
- `DispatcherError`
- `FallbackAttackContext`
- `FallbackAttackResult`
- `FallbackAttackStatus`
- `ParameterValidationError`
- `TLSConstants`

**Key Imports:**
- `__future__`
- `dataclasses`
- `enum`
- `traceback`
- `uuid`


### `core\bypass\engine\base_engine.py`

Attack/security module with 2 functions and 5 classes for security testing and bypass techniques

**Functions:**
- `apply_forced_override()`
- `safe_split_pos_conversion()`

**Classes:**
- `EngineConfig`
- `FallbackBypassEngine`
- `IBypassEngine`
- `ProcessedPacketCache`
- `WindowsBypassEngine`

**Key Imports:**
- `abc`
- `copy`
- `platform`
- `struct`
- `threading`


### `core\bypass\engine\enhanced_bypass_adapter.py`

Attack/security module with 1 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `create_enhanced_bypass_adapter()`

**Classes:**
- `EnhancedBypassEngineAdapter`
- `EnhancedTestResult`
- `TrialArtifacts`

**Key Imports:**
- `attack_dispatcher`
- `attacks.metadata`
- `base_engine`
- `dataclasses`
- `threading`


### `core\bypass\engine\factory.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassEngineFactory`

**Key Imports:**
- `base_engine`
- `platform`


### `core\bypass\engine\parameter_normalizer.py`

Attack/security module with 1 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `normalize_attack_params()`

**Classes:**
- `ParameterNormalizer`
- `ValidationResult`

**Key Imports:**
- `dataclasses`


### `core\bypass\engine\service_wrapper.py`

Attack/security module with 1 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `test_service_wrapper()`

**Classes:**
- `BypassEngineService`
- `ServiceConfig`

**Key Imports:**
- `core.bypass.engine.base_engine`
- `dataclasses`
- `threading`


### `core\bypass\engine\unified_attack_dispatcher.py`

Attack/security module with 2 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `generate_fake_payload()`
- `get_fake_params()`

**Classes:**
- `AttackConstants`
- `MetricsCircuitBreaker`
- `PacketSegment`
- `UnifiedAttackDispatcher`

**Key Imports:**
- `core.strategy.combo_builder`
- `dataclasses`


### `core\bypass\engine\unified_attack_executor.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `ExecutionContext`
- `ExecutionResult`
- `UnifiedAttackExecutor`

**Key Imports:**
- `dataclasses`


### `core\bypass\engines\base.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `BaseBypassEngine`
- `EngineConfig`
- `EngineStats`
- `EngineType`

**Key Imports:**
- `abc`
- `dataclasses`
- `enum`


### `core\bypass\engines\simple_attack_executor.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `SimpleAttackExecutor`

**Key Imports:**
- `core.bypass.attacks.base`


### `core\bypass\fallback_manager.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `FallbackManager`


### `core\bypass\filtering\cache.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `CacheManager`
- `LRUCache`
- `PatternCache`

**Key Imports:**
- `threading`


### `core\bypass\filtering\sni_extractor.py`

Attack/security module with 1 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `extract_sni_from_packet()`

**Classes:**
- `SNIExtractor`

**Key Imports:**
- `struct`


### `core\bypass\flow\manager.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `FlowInfo`
- `FlowManager`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\bypass\jitter_control.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `InjectionTiming`
- `JitterController`
- `RateController`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\bypass\packet\types.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `TCPSegmentSpec`

**Key Imports:**
- `dataclasses`


### `core\bypass\protocols\demo_multi_port_integration.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `MultiPortBypassDemo`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_definition`
- `core.bypass.protocols.multi_port_handler`
- `core.bypass.types`


### `core\bypass\protocols\multi_port_handler.py`

Attack/security module with 0 functions and 6 classes for security testing and bypass techniques

**Classes:**
- `BypassResult`
- `MultiPortHandler`
- `PortStrategy`
- `PortTestResult`
- `PortType`
- `ProtocolFamily`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_definition`
- `core.bypass.types`
- `dataclasses`
- `enum`


### `core\bypass\safety\attack_sandbox.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AttackSandbox`
- `SandboxConstraints`
- `SandboxMonitor`
- `SandboxViolation`

**Key Imports:**
- `contextlib`
- `core.bypass.attacks.base`
- `core.bypass.safety.exceptions`
- `dataclasses`
- `threading`


### `core\bypass\safety\demo_safety_framework.py`

Attack/security module with 9 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `demo_basic_safety()`
- `demo_comprehensive_safety()`
- `demo_concurrent_attacks()`
- `demo_emergency_stops()`
- `demo_resource_limits()`
- `demo_sandbox_violations()`
- `demo_timeout_handling()`
- `demo_validation_levels()`
- `main()`

**Classes:**
- `DemoAttack`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.safety.attack_sandbox`
- `core.bypass.safety.resource_manager`
- `core.bypass.safety.safety_controller`


### `core\bypass\safety\emergency_stop.py`

Attack/security module with 0 functions and 6 classes for security testing and bypass techniques

**Classes:**
- `AttackStopController`
- `EmergencyStopEvent`
- `EmergencyStopManager`
- `StopCondition`
- `StopPriority`
- `StopReason`

**Key Imports:**
- `dataclasses`
- `enum`
- `threading`


### `core\bypass\safety\exceptions.py`

Attack/security module with 0 functions and 6 classes for security testing and bypass techniques

**Classes:**
- `AttackTimeoutError`
- `AttackValidationError`
- `EmergencyStopError`
- `ResourceLimitExceededError`
- `SafetyError`
- `SandboxViolationError`


### `core\bypass\sni\manipulator.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `SNIManipulator`
- `SNIPosition`

**Key Imports:**
- `core.protocols.tls`
- `dataclasses`
- `struct`


### `core\bypass\system_bypass_manager.py`

Attack/security module with 1 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `apply_forced_override()`

**Classes:**
- `SystemBypassManager`
- `ToolConfig`
- `ToolInstance`
- `ToolStatus`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `platform`
- `subprocess`


### `core\bypass\techniques\base.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `BaseTechnique`
- `RaceConditionTechnique`
- `SegmentationTechnique`
- `TimingTechnique`

**Key Imports:**
- `abc`
- `core.bypass.exceptions`
- `core.bypass.types`
- `struct`


### `core\bypass\techniques\primitives.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `BypassTechniques`
- `FakedDisorderAttack`

**Key Imports:**
- `string`
- `struct`


### `core\bypass\telemetry\manager.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `TelemetryData`
- `TelemetryManager`

**Key Imports:**
- `copy`
- `dataclasses`
- `threading`


### `core\bypass\types.py`

Attack/security module with 0 functions and 14 classes for security testing and bypass techniques

**Classes:**
- `AttackResult`
- `BehavioralFingerprint`
- `BlockType`
- `EngineStats`
- `EngineStatus`
- `EnhancedDPIFingerprint`
- `HTTPFingerprint`
- `PacketDirection`
- `PacketInfo`
- `ProtocolType`
- `StrategyResult`
- `SystemTestResult`
- `TLSFingerprint`
- `TechniqueType`

**Key Imports:**
- `__future__`
- `dataclasses`
- `enum`


### `core\cli_payload\dpi_cli_integration.py`

Attack/security module with 3 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `create_dpi_cli_integration()`
- `integrate_dpi_with_existing_cli()`
- `parse_dpi_config_from_args()`

**Classes:**
- `DPICLIIntegration`

**Key Imports:**
- `argparse`
- `bypass.strategies.config_models`
- `bypass.strategies.dpi_strategy_engine`
- `bypass.strategies.exceptions`
- `dpi_parameter_parser`


### `core\cli_payload\dpi_parameter_parser.py`

Attack/security module with 2 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `create_dpi_parameter_parser()`
- `validate_dpi_arguments()`

**Classes:**
- `DPIParameterParser`

**Key Imports:**
- `argparse`
- `bypass.strategies.config_models`
- `bypass.strategies.exceptions`


### `core\diagnostic_system.py`

Attack/security module with 0 functions and 7 classes for security testing and bypass techniques

**Classes:**
- `AttackFailureAnalysis`
- `AttackPerformanceMetrics`
- `DiagnosticSystem`
- `FailurePattern`
- `PacketProcessingEvent`
- `PerformanceReport`
- `TechniquePerformanceMetrics`

**Key Imports:**
- `dataclasses`
- `socket`
- `statistics`
- `struct`
- `threading`


### `core\fingerprint\bypass_prober.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `BypassProbeResult`
- `QuickBypassProber`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\integration\advanced_attack_manager.py`

Attack/security module with 1 functions and 11 classes for security testing and bypass techniques

**Functions:**
- `get_advanced_attack_manager()`

**Classes:**
- `AdaptationSuggestion`
- `AdvancedAttack`
- `AdvancedAttackConfig`
- `AdvancedAttackManager`
- `AdvancedAttackResult`
- `AttackContext`
- `DPISignature`
- `LearningData`
- `MLFeedback`
- `PerformanceMetrics`
- `TargetInfo`

**Key Imports:**
- `abc`
- `dataclasses`


### `core\integration\advanced_attack_registry.py`

Attack/security module with 1 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `get_advanced_attack_registry()`

**Classes:**
- `AdvancedAttackRegistry`
- `AttackRegistration`

**Key Imports:**
- `dataclasses`


### `core\integration\advanced_attack_registry_simple.py`

Attack/security module with 1 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `get_advanced_attack_registry()`

**Classes:**
- `AdvancedAttackRegistry`


### `core\integration\attack_adapter.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `AttackAdapter`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `copy`
- `inspect`
- `threading`


### `core\integration\ech_attack_integration.py`

Attack/security module with 1 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `create_ech_attack_integration()`

**Classes:**
- `ECHAttackIntegration`
- `ECHAttackState`
- `ECHOptimizationResult`
- `TLSDetectionResult`

**Key Imports:**
- `dataclasses`
- `hashlib`


### `core\integration\performance_integration.py`

Attack/security module with 1 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `get_performance_integrator()`

**Classes:**
- `BypassPerformanceIntegrator`
- `BypassPerformanceMetrics`
- `PerformanceAlert`

**Key Imports:**
- `dataclasses`


### `core\integration\quic_attack_integration.py`

Attack/security module with 1 functions and 4 classes for security testing and bypass techniques

**Functions:**
- `create_quic_attack_integration()`

**Classes:**
- `QUICAttackIntegration`
- `QUICAttackState`
- `QUICDetectionResult`
- `QUICOptimizationResult`

**Key Imports:**
- `dataclasses`
- `hashlib`


### `core\metrics.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassQualityMetrics`


### `core\metrics\attack_parity_metrics.py`

Attack/security module with 2 functions and 6 classes for security testing and bypass techniques

**Functions:**
- `get_metrics_collector()`
- `set_metrics_collector()`

**Classes:**
- `AttackDetectionMetric`
- `AttackParityMetricsCollector`
- `ComplianceMetric`
- `MetricsSummary`
- `PCAPValidationMetric`
- `StrategyApplicationMetric`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\net\byte_packet.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `IPv4Packet`
- `TCPPacket`
- `UDPPacket`

**Key Imports:**
- `core.net.base_packet`
- `core.net.tcp_options`
- `dataclasses`
- `struct`


### `core\net\quic_packet.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `QUICHeader`
- `QUICPacket`
- `QUICPacketType`
- `QUICVersion`

**Key Imports:**
- `core.net.byte_packet`
- `dataclasses`
- `enum`
- `struct`


### `core\net\tcp_manipulator.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `SegmentConfig`
- `TCPSegmentManipulator`

**Key Imports:**
- `core.net.byte_packet`
- `dataclasses`


### `core\packet\attack_optimizer.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `AttackOptimizer`
- `AttackParameters`
- `AttackType`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`


### `core\packet\modifier.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `PacketModifier`

**Key Imports:**
- `packet_models`
- `struct`


### `core\packet\packet_models.py`

Attack/security module with 0 functions and 12 classes for security testing and bypass techniques

**Classes:**
- `BypassTechnique`
- `IPHeader`
- `LayerInfo`
- `PacketDirection`
- `PacketFragment`
- `PacketStatistics`
- `ParsedPacket`
- `ProtocolType`
- `RawPacket`
- `TCPHeader`
- `TCPPacket`
- `UDPHeader`

**Key Imports:**
- `dataclasses`
- `enum`
- `struct`


### `core\pcap\bypass_engine_integration.py`

Attack/security module with 1 functions and 2 classes for security testing and bypass techniques

**Functions:**
- `create_enhanced_bypass_engine()`

**Classes:**
- `StrategyTestResult`
- `WindowsBypassEngineWithCapture`

**Key Imports:**
- `analyzer`
- `dataclasses`
- `temporary_capturer`


### `core\quality_analyzer.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassQualityAnalyzer`


### `core\strategy\combo_builder.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AttackRecipe`
- `AttackStep`
- `ComboAttackBuilder`
- `ValidationResult`

**Key Imports:**
- `__future__`
- `dataclasses`


### `core\strategy\intent_attack_mapper.py`

Attack/security module with 0 functions and 3 classes for security testing and bypass techniques

**Classes:**
- `AttackMapping`
- `GeneratedStrategy`
- `IntentAttackMapper`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy\smart_attack_combinator.py`

Attack/security module with 0 functions and 4 classes for security testing and bypass techniques

**Classes:**
- `AttackCategory`
- `AttackCompatibility`
- `CombinationStrategy`
- `SmartAttackCombinator`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\validation\attack_detector.py`

Attack/security module with 0 functions and 2 classes for security testing and bypass techniques

**Classes:**
- `AttackDetector`
- `DetectedAttacks`

**Key Imports:**
- `dataclasses`


### `core\verification\attack_verifier.py`

Attack/security module with 0 functions and 5 classes for security testing and bypass techniques

**Classes:**
- `AttackApplicationVerifier`
- `ComparisonReport`
- `DisorderVerification`
- `FakeAttackVerification`
- `MultisplitVerification`

**Key Imports:**
- `core.packet.raw_packet_engine`
- `core.packet.raw_pcap_reader`
- `dataclasses`
- `struct`


### `deep_attack_analysis.py`

Attack/security module with 1 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `main()`

**Classes:**
- `DeepAttackAnalyzer`

**Key Imports:**
- `requests`
- `subprocess`


### `dpi_attack_verification.py`

Attack/security module with 1 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `main()`

**Classes:**
- `AttackFlow`
- `DPIAttackVerifier`
- `StrategyTest`

**Key Imports:**
- `dataclasses`


### `examples\demo_dns_attacks.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `DNSAttackDemo`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.dns.dns_tunneling`


### `examples\demo_http_attacks.py`

Attack/security module with 10 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `demo_attack_comparison()`
- `demo_case_manipulation()`
- `demo_chunked_encoding()`
- `demo_header_modification()`
- `demo_header_splitting()`
- `demo_method_manipulation()`
- `demo_pipeline_manipulation()`
- `main()`
- `print_segments()`
- `print_separator()`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.bypass.attacks.http_manipulation`


### `examples\faked_disorder_attack_example.py`

Attack/security module with 7 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `demonstrate_attack_variants()`
- `demonstrate_basic_usage()`
- `demonstrate_custom_configuration()`
- `demonstrate_integration_scenario()`
- `demonstrate_payload_analysis()`
- `demonstrate_timing_analysis()`
- `demonstrate_validation_and_error_handling()`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.attacks.reference.faked_disorder_attack`


### `examples\migration_examples_before_after.py`

Attack/security module with 6 functions and 8 classes for security testing and bypass techniques

**Functions:**
- `demonstrate_packet_manipulation_migration()`
- `demonstrate_performance_comparison()`
- `demonstrate_simple_payload_migration()`
- `demonstrate_state_based_migration()`
- `demonstrate_timing_attack_migration()`
- `main()`

**Classes:**
- `PacketManipulationAttack_Legacy`
- `PacketManipulationAttack_Migrated`
- `SimplePayloadAttack_Legacy`
- `SimplePayloadAttack_Migrated`
- `StateBasedAttack_Legacy`
- `StateBasedAttack_Migrated`
- `TimingAttack_Legacy`
- `TimingAttack_Migrated`

**Key Imports:**
- `core.bypass.attacks.base`


### `examples\multisplit_attack_example.py`

Attack/security module with 7 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `demonstrate_attack_variants()`
- `demonstrate_basic_usage()`
- `demonstrate_custom_configuration()`
- `demonstrate_effectiveness_analysis()`
- `demonstrate_payload_reconstruction()`
- `demonstrate_segment_analysis()`
- `demonstrate_timing_patterns()`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.attacks.reference.multisplit_attack`


### `examples\native_engine_segments_example.py`

Attack/security module with 6 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `demonstrate_attack_integration()`
- `demonstrate_enhanced_context_creation()`
- `demonstrate_error_handling()`
- `demonstrate_segments_orchestration()`
- `demonstrate_timing_control()`
- `main()`

**Classes:**
- `MockSegmentAttack`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.bypass.attacks.segment_packet_builder`
- `core.bypass.engines.native_pydivert_engine`
- `unittest.mock`


### `examples\reference_attacks_showcase.py`

Attack/security module with 8 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `demonstrate_attack_combinations()`
- `demonstrate_payload_obfuscation_attacks()`
- `demonstrate_performance_analysis()`
- `demonstrate_real_world_scenarios()`
- `demonstrate_tcp_timing_attacks()`
- `demonstrate_urgent_pointer_attacks()`
- `demonstrate_window_scaling_attacks()`
- `main()`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.bypass.attacks.reference.payload_obfuscation_attack`
- `core.bypass.attacks.reference.tcp_timing_manipulation_attack`
- `core.bypass.attacks.reference.urgent_pointer_manipulation_attack`
- `core.bypass.attacks.reference.window_scaling_attack`


### `examples\segments_usage_example.py`

Attack/security module with 1 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `demonstrate_segments_usage()`

**Classes:**
- `ExampleFakedDisorderAttack`
- `ExampleMultisplitAttack`
- `ExampleTimingManipulationAttack`

**Key Imports:**
- `core.bypass.attacks.base`


### `examples\tcp_session_context_example.py`

Attack/security module with 1 functions and 3 classes for security testing and bypass techniques

**Functions:**
- `demonstrate_tcp_session_context()`

**Classes:**
- `ConnectionStateAttack`
- `SequenceManipulationAttack`
- `TCPSessionAwareAttack`

**Key Imports:**
- `core.bypass.attacks.base`


### `intelligent_bypass_monitor.py`

Attack/security module with 1 functions and 6 classes for security testing and bypass techniques

**Functions:**
- `main()`

**Classes:**
- `BypassStrategy`
- `DPIAnalyzer`
- `IntelligentBypassMonitor`
- `StrategyCalibrator`
- `TrafficMonitor`
- `TrafficPattern`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`
- `threading`
- `urllib.parse`


### `load_all_attacks.py`

Attack/security module with 1 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `load_all_attacks()`

**Key Imports:**
- `core.bypass.attacks.attack_registry`


### `log_pcap_comparison_tool.py`

Attack/security module with 1 functions and 6 classes for security testing and bypass techniques

**Functions:**
- `main()`

**Classes:**
- `AttackLogEntry`
- `ComparisonResult`
- `LogPCAPComparator`
- `LogParser`
- `NetworkAttack`
- `PCAPAnalyzer`

**Key Imports:**
- `dataclasses`


### `metrics.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassQualityMetrics`


### `ml\predictor.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `DPIBypassPredictor`


### `multi_domain_bypass_tester.py`

Attack/security module with 1 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `main()`

**Classes:**
- `MultiDomainBypassTester`

**Key Imports:**
- `concurrent.futures`
- `requests`
- `subprocess`


### `patch_attack_validation.py`

Attack/security module with 1 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `patch_attack_validation()`


### `quality_analyzer.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassQualityAnalyzer`


### `reload_modules.py`

Attack/security module with 1 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `reload_attack_modules()`

**Key Imports:**
- `importlib`


### `runtime_attack_patcher.py`

Attack/security module with 1 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `patch_attack_validation()`


### `setup_bypass.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassSetup`

**Key Imports:**
- `stat`


### `tools\audit_attack_application.py`

Attack/security module with 1 functions and 5 classes for security testing and bypass techniques

**Functions:**
- `main()`

**Classes:**
- `AttackApplicationAuditor`
- `DisorderAttackAnalysis`
- `FakeAttackAnalysis`
- `MultisplitAttackAnalysis`
- `SeqovlAttackAnalysis`

**Key Imports:**
- `dataclasses`
- `struct`


### `tools\capture_disorder_pcap.py`

Attack/security module with 3 functions and 0 classes for security testing and bypass techniques

**Functions:**
- `capture_cli_mode_disorder()`
- `capture_service_mode_disorder()`
- `main()`

**Key Imports:**
- `core.pcap.temporary_capturer`
- `subprocess`


### `web\bypass_api.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassEngineAPI`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.bypass.strategies.pool_management`
- `core.bypass.testing.attack_test_suite`
- `core.bypass.validation.reliability_validator`


### `web\bypass_dashboard.py`

Attack/security module with 0 functions and 1 classes for security testing and bypass techniques

**Classes:**
- `BypassDashboard`

**Key Imports:**
- `web.bypass_api`


### `web\bypass_integration.py`

Attack/security module with 2 functions and 1 classes for security testing and bypass techniques

**Functions:**
- `create_bypass_integration()`
- `integrate_with_monitoring_server()`

**Classes:**
- `BypassWebIntegration`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.strategies.pool_management`
- `core.bypass.testing.attack_test_suite`
- `web.bypass_api`
- `web.bypass_dashboard`



## Cli

Modules implementing command-line interfaces and user interaction.

### `abs_twimg_analysis_and_fix.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `AbsTwimgFixer`

**Key Imports:**
- `subprocess`


### `attack_recipe_validator_enhanced.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `AttackRecipeValidator`
- `ValidationResult`

**Key Imports:**
- `argparse`
- `dataclasses`


### `cleanup_project.py`

CLI module with 1 functions and 0 classes for command-line interface

**Functions:**
- `main()`

**Key Imports:**
- `argparse`
- `core.refactoring`


### `clear_recovery_history.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `clear_recovery_state()`
- `main()`
- `show_updated_strategies()`


### `cli_analysis_report_generator.py`

CLI module with 1 functions and 4 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `AttackDiscrepancy`
- `CLIAnalysisReportGenerator`
- `CLIModeAnalysisReport`
- `CLITestAnalysis`

**Key Imports:**
- `dataclasses`
- `glob`
- `log_pcap_comparison_tool`


### `cli_integrated_monitor.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `CLIIntegratedMonitor`

**Key Imports:**
- `subprocess`
- `urllib.parse`


### `cli_mode_analysis_reporter.py`

CLI module with 1 functions and 3 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `CLIAnalysisReport`
- `CLIModeAnalysisReporter`
- `CLITestResult`

**Key Imports:**
- `dataclasses`
- `glob`
- `log_pcap_comparison_tool`


### `cli_mode_tester.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `load_strategies_for_domain()`
- `main()`
- `run_cli_test_with_strategy()`

**Key Imports:**
- `subprocess`


### `cli_service_mode_comparator.py`

CLI module with 1 functions and 3 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `CLIServiceModeComparator`
- `ModeComparison`
- `TestResult`

**Key Imports:**
- `dataclasses`


### `cli_strategy_tester.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `CLIStrategyTester`

**Key Imports:**
- `subprocess`


### `compare_test_vs_bypass_pcap.py`

CLI module with 4 functions and 0 classes for command-line interface

**Functions:**
- `analyze_stream()`
- `compare_streams()`
- `extract_sni()`
- `main()`

**Key Imports:**
- `scapy.all`
- `struct`


### `copy_cli_logic_to_service.py`

CLI module with 5 functions and 0 classes for command-line interface

**Functions:**
- `analyze_cli_success_logic()`
- `extract_cli_attack_parameters()`
- `main()`
- `patch_packet_sender_for_cli_ttl()`
- `patch_service_with_cli_logic()`


### `core\bypass\attacks\audit\run_audit.py`

CLI module with 2 functions and 0 classes for command-line interface

**Functions:**
- `main()`
- `setup_logging()`

**Key Imports:**
- `argparse`
- `attack_auditor`


### `core\bypass\compatibility\demo_compatibility_layer.py`

CLI module with 8 functions and 0 classes for command-line interface

**Functions:**
- `demo_compatibility_analysis()`
- `demo_configuration_parsing()`
- `demo_optimal_tool_suggestion()`
- `demo_real_world_examples()`
- `demo_syntax_conversion()`
- `demo_tool_capabilities()`
- `demo_tool_detection()`
- `main()`

**Key Imports:**
- `core.bypass.compatibility.compatibility_bridge`
- `core.bypass.compatibility.tool_detector`


### `core\bypass\modes\demo_mode_controller.py`

CLI module with 7 functions and 0 classes for command-line interface

**Functions:**
- `demo_auto_fallback()`
- `demo_capability_detection()`
- `demo_health_checks()`
- `demo_mode_controller()`
- `demo_mode_info()`
- `demo_transition_history()`
- `main()`

**Key Imports:**
- `capability_detector`
- `core.bypass.modes.mode_controller`
- `exceptions`


### `core\bypass\techniques\primitives_audit.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `PrimitivesAuditor`

**Key Imports:**
- `core.bypass.techniques.primitives`
- `struct`


### `core\cli_payload\segment_attack_cli.py`

CLI module with 0 functions and 1 classes for command-line interface

**Classes:**
- `SegmentAttackCLI`

**Key Imports:**
- `argparse`
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.monitoring.segment_execution_stats`
- `core.integration.attack_adapter`


### `core\cli_service_parity_disabler.py`

CLI module with 0 functions and 2 classes for command-line interface

**Classes:**
- `CLIServiceParityDisabler`
- `CLIServiceParityStatus`

**Key Imports:**
- `dataclasses`


### `core\config\demo_enhanced_config.py`

CLI module with 6 functions and 0 classes for command-line interface

**Functions:**
- `demo_basic_usage()`
- `demo_configuration_validation()`
- `demo_legacy_migration()`
- `demo_priority_system()`
- `demo_wildcard_optimization()`
- `main()`

**Key Imports:**
- `strategy_config_manager`


### `core\di\cli_provider.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `create_cli_provider()`

**Classes:**
- `CLIServiceProvider`

**Key Imports:**
- `argparse`
- `core.di.config`
- `core.di.container`
- `core.di.factory`
- `core.di.typed_config`


### `core\duplicate_analysis\interfaces.py`

CLI module with 0 functions and 34 classes for command-line interface

**Classes:**
- `ASTParserInterface`
- `AnalysisResults`
- `CircularDependency`
- `ClassNode`
- `CodeSignature`
- `ComplexityMetrics`
- `ConfidenceLevel`
- `ConfigurationError`
- `Contract`
- `CouplingMetrics`
- `DeadCodeCandidate`
- `DeadCodeCategory`
- `DependencyGraph`
- `DuplicateGroup`
- `DuplicateType`
- `EstimatedSavings`
- `Evidence`
- `FunctionNode`
- `IOOperation`
- `MethodPassport`
- `MigrationStrategy`
- `ModuleAnalysis`
- `ModuleCard`
- `ModuleStatus`
- `Parameter`
- `ProjectScannerInterface`
- `ProjectStructure`
- `ReportGeneratorInterface`
- `RiskLevel`
- `SideEffect`
- `SimilarityEngineInterface`
- `UniversalizationCandidate`
- `UniversalizationScore`
- `ValidationResult`

**Key Imports:**
- `ast`
- `dataclasses`
- `enum`


### `core\fingerprint\training_demo.py`

CLI module with 6 functions and 0 classes for command-line interface

**Functions:**
- `demo_evaluation_and_reporting()`
- `demo_feature_engineering()`
- `demo_model_training()`
- `demo_model_usage()`
- `demo_training_data_generation()`
- `main()`

**Key Imports:**
- `core.fingerprint.model_trainer`
- `core.fingerprint.training_data`


### `core\pcap_analysis\cli.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `BatchProcessor`
- `PCAPAnalysisCLI`

**Key Imports:**
- `argparse`
- `asyncio`
- `difference_detector`
- `pcap_comparator`
- `strategy_analyzer`


### `core\refactoring\llm_context_generator.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `CategoryInfo`
- `LLMContextGenerator`

**Key Imports:**
- `dataclasses`


### `deep_pcap_analysis.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `analyze_ip_traffic()`
- `analyze_pcap_deep()`
- `main()`


### `deep_pcap_analyzer.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `DeepPCAPAnalyzer`

**Key Imports:**
- `scapy.all`


### `deep_strategy_analysis.py`

CLI module with 4 functions and 0 classes for command-line interface

**Functions:**
- `analyze_failure_reasons()`
- `analyze_packet_details()`
- `identify_strategy_type()`
- `main()`


### `detailed_attack_analysis.py`

CLI module with 4 functions and 0 classes for command-line interface

**Functions:**
- `analyze_attack_effectiveness()`
- `analyze_log_issues()`
- `analyze_pcap_timing()`
- `main()`


### `doctor.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `DoctorReport`
- `ProjectDoctor`

**Key Imports:**
- `ast`
- `importlib`


### `dpi_deep_analysis.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `DPIAnalyzer`

**Key Imports:**
- `scapy.all`
- `socket`
- `struct`
- `subprocess`


### `examples\comprehensive_logging_demo.py`

CLI module with 6 functions and 0 classes for command-line interface

**Functions:**
- `demo_fake_packet_logging()`
- `demo_parameter_mismatch_logging()`
- `demo_parameter_transformation_logging()`
- `demo_segment_ordering_logging()`
- `demo_strategy_application_logging()`
- `main()`

**Key Imports:**
- `core.bypass.unified_attack_dispatcher`
- `core.strategy.combo_builder`
- `core.strategy.normalizer`


### `examples\demo_timing_attacks.py`

CLI module with 7 functions and 0 classes for command-line interface

**Functions:**
- `create_demo_context()`
- `demo_burst_traffic()`
- `demo_delay_evasion()`
- `demo_jitter_injection()`
- `demo_performance_comparison()`
- `demo_timing_controller()`
- `main()`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.attacks.timing.burst_traffic`
- `core.bypass.attacks.timing.delay_evasion`
- `core.bypass.attacks.timing.jitter_injection`


### `examples\discovery_config_example.py`

CLI module with 8 functions and 0 classes for command-line interface

**Functions:**
- `example_basic_configuration()`
- `example_configuration_cloning()`
- `example_custom_configuration()`
- `example_effective_settings()`
- `example_serialization()`
- `example_validation()`
- `example_validator_utilities()`
- `main()`

**Key Imports:**
- `core.discovery_config`


### `examples\domain_unification_demo.py`

CLI module with 6 functions and 0 classes for command-line interface

**Functions:**
- `demo_basic_resolution()`
- `demo_real_world_data()`
- `demo_save_and_load()`
- `demo_score_calculation()`
- `demo_subdomain_inheritance()`
- `main()`

**Key Imports:**
- `core.strategy.domain_strategy_resolver`
- `core.strategy.unified_strategy_saver`


### `examples\lazy_loading_example.py`

CLI module with 7 functions and 0 classes for command-line interface

**Functions:**
- `example_accessing_attacks()`
- `example_configuration_warning()`
- `example_eager_loading()`
- `example_global_configuration()`
- `example_lazy_loading()`
- `example_performance_comparison()`
- `main()`

**Key Imports:**
- `core.bypass.attacks.attack_registry`


### `examples\metrics_endpoint_example.py`

CLI module with 1 functions and 0 classes for command-line interface

**Functions:**
- `main()`

**Key Imports:**
- `core.bypass.attacks.telemetry`
- `requests`


### `examples\packet_construction_transmission_example.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `PacketConstructionDemo`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.bypass.attacks.segment_packet_builder`
- `core.bypass.attacks.timing_controller`
- `core.bypass.engines.base`


### `examples\performance_optimization_demo.py`

CLI module with 6 functions and 0 classes for command-line interface

**Functions:**
- `benchmark_validation_performance()`
- `demonstrate_batch_processing()`
- `demonstrate_cache_optimization()`
- `demonstrate_validation_reasoning()`
- `generate_sample_telemetry()`
- `main()`

**Key Imports:**
- `core.validation.performance_cache`
- `core.validation.unified_validation_system`


### `examples\segment_diagnostics_example.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `SegmentDiagnosticsDemo`

**Key Imports:**
- `core.bypass.attacks.segment_packet_builder`
- `core.bypass.attacks.timing_controller`
- `core.bypass.diagnostics.segment_diagnostics`


### `examples\segment_packet_builder_example.py`

CLI module with 9 functions and 0 classes for command-line interface

**Functions:**
- `demonstrate_basic_packet_building()`
- `demonstrate_batch_building()`
- `demonstrate_checksum_corruption()`
- `demonstrate_packet_analysis()`
- `demonstrate_sequence_offsets()`
- `demonstrate_statistics_and_performance()`
- `demonstrate_tcp_flags_manipulation()`
- `demonstrate_ttl_manipulation()`
- `main()`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.bypass.attacks.segment_packet_builder`
- `socket`
- `struct`


### `examples\tls_version_diagnostics_demo.py`

CLI module with 5 functions and 0 classes for command-line interface

**Functions:**
- `demo_consistency_check()`
- `demo_real_world_scenario()`
- `demo_split_pos_validation()`
- `demo_version_extraction()`
- `main()`

**Key Imports:**
- `core.validation.tls_version_checker`


### `examples\unified_validation_demo.py`

CLI module with 6 functions and 0 classes for command-line interface

**Functions:**
- `demo_false_positive_scenario()`
- `demo_high_retransmission_scenario()`
- `demo_no_traffic_scenario()`
- `demo_successful_scenario()`
- `main()`
- `setup_logging()`

**Key Imports:**
- `core.validation.unified_validation_system`


### `extract_working_strategy.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `extract_strategy_from_log()`
- `main()`
- `update_domain_rules()`


### `flow_based_pcap_analyzer.py`

CLI module with 2 functions and 2 classes for command-line interface

**Functions:**
- `compare_modes()`
- `main()`

**Classes:**
- `FlowPacket`
- `TCPFlowAnalyzer`


### `generate_clienthello_report.py`

CLI module with 1 functions and 0 classes for command-line interface

**Functions:**
- `main()`

**Key Imports:**
- `argparse`


### `generate_module_registry.py`

CLI module with 2 functions and 0 classes for command-line interface

**Functions:**
- `main()`
- `setup_logging()`

**Key Imports:**
- `core.refactoring.module_registry_builder`


### `generate_project_structure.py`

CLI module with 1 functions and 0 classes for command-line interface

**Functions:**
- `main()`

**Key Imports:**
- `core.refactoring.structure_analyzer`


### `global_refactoring_orchestrator.py`

CLI module with 1 functions and 3 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `GlobalRefactoringOrchestrator`
- `RefactoringReport`
- `StageResult`

**Key Imports:**
- `argparse`
- `dataclasses`


### `gui\cli_runner_fixed.py`

CLI module with 0 functions and 1 classes for command-line interface

**Classes:**
- `NonBlockingCLIWorker`

**Key Imports:**
- `PyQt6.QtCore`
- `queue`
- `subprocess`
- `threading`


### `gui\improved_main_window.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `CLIWorkerThread`
- `ImprovedMainWindow`

**Key Imports:**
- `PyQt6.QtCore`
- `PyQt6.QtGui`
- `PyQt6.QtWidgets`
- `gui.advanced_settings`
- `subprocess`


### `gui_app.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `ReconDPIApp`

**Key Imports:**
- `asyncio`
- `flet`
- `platform`


### `improved_log_parser.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `ImprovedLogParser`
- `ParsedAttack`

**Key Imports:**
- `dataclasses`


### `investigate_cli_auto_domain_filtering.py`

CLI module with 1 functions and 0 classes for command-line interface

**Functions:**
- `main()`

**Key Imports:**
- `asyncio`


### `manual_badseq_pcap_verification.py`

CLI module with 2 functions and 0 classes for command-line interface

**Functions:**
- `main()`
- `verify_pcap_packets()`

**Key Imports:**
- `argparse`
- `subprocess`


### `minimal_service.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `MinimalBypassService`

**Key Imports:**
- `subprocess`
- `threading`


### `ml\fingerprint_aware_strategy_demo.py`

CLI module with 7 functions and 0 classes for command-line interface

**Functions:**
- `demo_characteristic_based_strategies()`
- `demo_confidence_based_ranking()`
- `demo_dpi_type_specific_strategies()`
- `demo_fallback_mechanism()`
- `demo_integration_with_existing_system()`
- `demo_strategy_analysis()`
- `main()`

**Key Imports:**
- `core.fingerprint.advanced_models`
- `ml.zapret_strategy_generator`


### `monitor.py`

CLI module with 0 functions and 1 classes for command-line interface

**Classes:**
- `MonitoringCLI`

**Key Imports:**
- `argparse`
- `asyncio`
- `core.monitoring_system`
- `recon.web.monitoring_server`
- `signal`


### `monitor_deployment.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `DeploymentMonitor`


### `monitor_service_logs.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `ServiceLogMonitor`

**Key Imports:**
- `subprocess`


### `network_behavior_analyzer.py`

CLI module with 1 functions and 3 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `NetworkBehaviorAnalyzer`
- `NetworkMetrics`
- `StrategyExecution`

**Key Imports:**
- `dataclasses`


### `pcap_monitor.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `PcapMonitor`

**Key Imports:**
- `struct`


### `pcap_to_json_analyzer.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `analyze_pcap()`
- `main()`
- `packet_to_dict()`

**Key Imports:**
- `argparse`
- `ipaddress`


### `quick_attack_check.py`

CLI module with 2 functions and 0 classes for command-line interface

**Functions:**
- `main()`
- `quick_domain_check()`

**Key Imports:**
- `subprocess`


### `recon_service.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `DPIBypassService`

**Key Imports:**
- `argparse`
- `signal`
- `urllib.parse`


### `refactoring_reporter.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `RefactoringReporter`
- `RefactoringStats`

**Key Imports:**
- `dataclasses`


### `refactoring_validator.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `RefactoringValidator`
- `ValidationResult`

**Key Imports:**
- `dataclasses`


### `restart_service_with_new_config.py`

CLI module with 4 functions and 0 classes for command-line interface

**Functions:**
- `main()`
- `start_service()`
- `stop_existing_service()`
- `verify_config()`

**Key Imports:**
- `subprocess`


### `run_dashboard.py`

CLI module with 1 functions and 0 classes for command-line interface

**Functions:**
- `main()`

**Key Imports:**
- `core.signature_manager`
- `recon.recon_service`
- `recon.web.dashboard`
- `threading`


### `run_performance_profiling.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `generate_summary_report()`
- `main()`
- `run_profiling_script()`

**Key Imports:**
- `subprocess`


### `run_validation_tests.py`

CLI module with 1 functions and 0 classes for command-line interface

**Functions:**
- `main()`


### `setup_advanced.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `AdvancedSetupManager`

**Key Imports:**
- `core.signature_manager`
- `ctypes`
- `platform`
- `subprocess`


### `show_all_domains_in_pcap.py`

CLI module with 4 functions and 0 classes for command-line interface

**Functions:**
- `analyze_ip_destinations()`
- `extract_all_sni_domains()`
- `extract_sni_simple()`
- `main()`


### `simple_pcap_analysis.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `analyze_pcap_simple()`
- `compare_files()`
- `main()`

**Key Imports:**
- `subprocess`


### `simple_service.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `apply_cli_success_parameters()`
- `build_attack_recipe()`
- `main()`

**Key Imports:**
- `asyncio`
- `threading`


### `start_and_monitor_service.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `ServiceMonitor`

**Key Imports:**
- `subprocess`


### `strategy_mismatch_root_cause_analyzer.py`

CLI module with 5 functions and 0 classes for command-line interface

**Functions:**
- `analyze_parameter_sources()`
- `analyze_strategy_mismatch()`
- `check_domain_rules()`
- `generate_fix_script()`
- `main()`


### `strategy_sync_tool.py`

CLI module with 1 functions and 1 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `StrategySync`

**Key Imports:**
- `argparse`


### `tools\analyze_disorder_pcap.py`

CLI module with 5 functions and 1 classes for command-line interface

**Functions:**
- `analyze_disorder_pattern()`
- `analyze_pcap_with_raw_engine()`
- `analyze_pcap_with_scapy()`
- `compare_pcaps()`
- `main()`

**Classes:**
- `PacketInfo`

**Key Imports:**
- `dataclasses`


### `tools\analyze_seqovl_pcap.py`

CLI module with 5 functions and 1 classes for command-line interface

**Functions:**
- `analyze_pcap_with_raw_engine()`
- `analyze_pcap_with_scapy()`
- `analyze_seqovl_pattern()`
- `compare_pcaps()`
- `main()`

**Classes:**
- `PacketInfo`

**Key Imports:**
- `dataclasses`


### `tools\audit_fake_attack.py`

CLI module with 4 functions and 0 classes for command-line interface

**Functions:**
- `analyze_fake_primitive()`
- `find_call_sites()`
- `generate_recommendations()`
- `main()`


### `tools\audit_multisplit_attack.py`

CLI module with 4 functions and 0 classes for command-line interface

**Functions:**
- `analyze_multisplit_primitive()`
- `find_call_sites()`
- `generate_recommendations()`
- `main()`


### `tools\capture_seqovl_pcap.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `capture_cli_mode_seqovl()`
- `capture_service_mode_seqovl()`
- `main()`

**Key Imports:**
- `core.pcap.temporary_capturer`
- `subprocess`


### `tools\extract_insights.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `analyze_pcap()`
- `analyze_report()`
- `main()`

**Key Imports:**
- `argparse`


### `tools\extract_recon_insights.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `analyze_json()`
- `analyze_pcap()`
- `main()`

**Key Imports:**
- `argparse`


### `tools\extract_run_insights.py`

CLI module with 3 functions and 0 classes for command-line interface

**Functions:**
- `analyze_pcap()`
- `analyze_report()`
- `main()`

**Key Imports:**
- `argparse`


### `tools\health_check.py`

CLI module with 1 functions and 3 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `ComponentHealth`
- `HealthCheckTool`
- `SystemHealth`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`


### `tools\migrate_filtering_config.py`

CLI module with 6 functions and 0 classes for command-line interface

**Functions:**
- `main()`
- `migrate_directory()`
- `migrate_file()`
- `rollback_migration()`
- `show_migration_guide()`
- `validate_migration()`

**Key Imports:**
- `argparse`
- `core.bypass.filtering.migration`


### `tools\migration_validation_tool.py`

CLI module with 2 functions and 2 classes for command-line interface

**Functions:**
- `load_attack_class_from_file()`
- `main()`

**Classes:**
- `MigrationValidationTool`
- `ValidationResult`

**Key Imports:**
- `argparse`
- `core.bypass.attacks.base`
- `core.bypass.attacks.compatibility.backward_compatibility_manager`
- `dataclasses`
- `importlib.util`


### `tools\mode_validator.py`

CLI module with 1 functions and 3 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `ModeComparisonResult`
- `ModeTestResult`
- `ModeValidator`

**Key Imports:**
- `asyncio`
- `core.strategy.validator`
- `core.unified_strategy_loader`
- `dataclasses`
- `socket`


### `tools\pcap_compare.py`

CLI module with 1 functions and 2 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `PCAPCompareTool`
- `PCAPComparisonSummary`

**Key Imports:**
- `core.pcap.analyzer`
- `dataclasses`


### `tools\verify_bypass_pcap.py`

CLI module with 1 functions and 5 classes for command-line interface

**Functions:**
- `main()`

**Classes:**
- `Conflict`
- `FlowKey`
- `PCAPVerifier`
- `TCPPacketInfo`
- `VerificationResult`

**Key Imports:**
- `core.packet.raw_packet_engine`
- `core.packet.raw_pcap_reader`
- `dataclasses`
- `struct`


### `tools\view_metrics.py`

CLI module with 8 functions and 0 classes for command-line interface

**Functions:**
- `export_metrics()`
- `format_timestamp()`
- `main()`
- `print_application_history()`
- `print_compliance_history()`
- `print_detection_history()`
- `print_summary()`
- `print_validation_history()`

**Key Imports:**
- `argparse`
- `core.metrics.attack_parity_metrics`



## Config

Modules for configuration management, settings, and application initialization.

### `adaptive_strategy_finder.py`

Configuration module with 0 functions and 3 classes for settings and configuration management

**Classes:**
- `AdaptiveStrategyFinder`
- `AttackConfig`
- `TestResult`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\adaptive_engine.py`

Configuration module with 0 functions and 6 classes for settings and configuration management

**Classes:**
- `AdaptiveConfig`
- `AdaptiveEngine`
- `LogCategory`
- `LogContext`
- `LogLevel`
- `StrategyResult`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `dataclasses`
- `hashlib`
- `threading`


### `core\attack_parity\analyzer.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `AnalysisConfiguration`
- `AttackParityAnalyzer`

**Key Imports:**
- `correlation_engine`
- `interfaces`
- `parity_checker`
- `parsers`
- `pcap_analyzer`


### `core\attack_parity\cli.py`

Configuration module with 13 functions and 0 classes for settings and configuration management

**Functions:**
- `add_combination_arguments()`
- `add_correlate_arguments()`
- `add_parity_arguments()`
- `add_timing_arguments()`
- `create_parser()`
- `handle_combinations_command()`
- `handle_correlate_command()`
- `handle_parity_command()`
- `handle_timing_command()`
- `load_configuration()`
- `main()`
- `setup_logging()`
- `validate_file_paths()`

**Key Imports:**
- `analyzer`
- `argparse`
- `combination_registry`
- `models`


### `core\bypass\attacks\combo\steganographic_engine.py`

Configuration module with 0 functions and 9 classes for settings and configuration management

**Classes:**
- `HeaderModificationSteganographicEngine`
- `LSBSteganographicEngine`
- `MultiLayerSteganographicEngine`
- `SteganographicConfig`
- `SteganographicEngine`
- `SteganographicManager`
- `SteganographicMethod`
- `SteganographicResult`
- `TimingChannelSteganographicEngine`

**Key Imports:**
- `abc`
- `dataclasses`
- `enum`


### `core\bypass\attacks\engine.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `BaseEngine`
- `EngineConfig`

**Key Imports:**
- `abc`
- `core.bypass.diagnostics.metrics`
- `core.diagnostics.logger`
- `dataclasses`
- `threading`


### `core\bypass\compatibility\byebyedpi_parser.py`

Configuration module with 1 functions and 3 classes for settings and configuration management

**Functions:**
- `parse_byebyedpi_command()`

**Classes:**
- `ByeByeDPIConfig`
- `ByeByeDPIParameter`
- `ByeByeDPIParser`

**Key Imports:**
- `dataclasses`


### `core\bypass\compatibility\goodbyedpi_parser.py`

Configuration module with 1 functions and 3 classes for settings and configuration management

**Functions:**
- `parse_goodbyedpi_command()`

**Classes:**
- `GoodbyeDPIConfig`
- `GoodbyeDPIParameter`
- `GoodbyeDPIParser`

**Key Imports:**
- `dataclasses`


### `core\bypass\compatibility\zapret_parser.py`

Configuration module with 1 functions and 3 classes for settings and configuration management

**Functions:**
- `parse_zapret_command()`

**Classes:**
- `ZapretConfig`
- `ZapretConfigParser`
- `ZapretParameter`

**Key Imports:**
- `dataclasses`


### `core\bypass\config\config_manager.py`

Configuration module with 0 functions and 1 classes for settings and configuration management

**Classes:**
- `ConfigurationManager`

**Key Imports:**
- `core.bypass.config.backup_manager`
- `core.bypass.config.config_migrator`
- `core.bypass.config.config_models`
- `core.bypass.config.config_validator`


### `core\bypass\config\config_migrator.py`

Configuration module with 0 functions and 1 classes for settings and configuration management

**Classes:**
- `ConfigurationMigrator`

**Key Imports:**
- `core.bypass.config.config_models`
- `uuid`


### `core\bypass\config\config_models.py`

Configuration module with 0 functions and 8 classes for settings and configuration management

**Classes:**
- `BypassStrategy`
- `ConfigurationBackup`
- `ConfigurationVersion`
- `DomainRule`
- `LegacyConfiguration`
- `MigrationResult`
- `PoolConfiguration`
- `StrategyPool`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\config\config_validator.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `ConfigurationValidator`
- `ValidationError`

**Key Imports:**
- `core.bypass.config.config_models`


### `core\bypass\engines\config_models.py`

Configuration module with 4 functions and 14 classes for settings and configuration management

**Functions:**
- `create_engine_request()`
- `create_enhanced_config()`
- `get_configuration_manager()`
- `validate_config_file()`

**Classes:**
- `ConfigSource`
- `ConfigurationManager`
- `ConfigurationState`
- `EngineConfigProfile`
- `EngineCreationRequest`
- `EngineCreationResult`
- `EngineDetectionResult`
- `EnhancedEngineConfig`
- `SerializableModel`
- `SerializationFormat`
- `SystemCapabilities`
- `ValidationIssue`
- `ValidationResult`
- `ValidationSeverity`

**Key Imports:**
- `core.bypass.engines.base`
- `dataclasses`
- `enum`


### `core\bypass\engines\engine_config_manager.py`

Configuration module with 4 functions and 4 classes for settings and configuration management

**Functions:**
- `get_default_engine_type()`
- `get_engine_config()`
- `get_engine_config_manager()`
- `get_fallback_order()`

**Classes:**
- `ConfigSource`
- `ConfigurationState`
- `EngineConfigManager`
- `EngineConfigProfile`

**Key Imports:**
- `core.bypass.engines.base`
- `dataclasses`
- `enum`
- `platform`


### `core\bypass\engines\native_pydivert_engine.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `InterceptionConfig`
- `NativePydivertEngine`

**Key Imports:**
- `asyncio`
- `core.bypass.engines.base`
- `dataclasses`
- `struct`
- `threading`


### `core\bypass\filtering\config.py`

Configuration module with 3 functions and 3 classes for settings and configuration management

**Functions:**
- `create_default_config()`
- `load_config_from_dict()`
- `load_config_from_file()`

**Classes:**
- `FilterConfig`
- `FilterConfigManager`
- `FilterMode`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\filtering\domain_matcher.py`

Configuration module with 0 functions and 1 classes for settings and configuration management

**Classes:**
- `DomainMatcher`

**Key Imports:**
- `config`


### `core\bypass\filtering\migration.py`

Configuration module with 0 functions and 4 classes for settings and configuration management

**Classes:**
- `BackwardCompatibilityLayer`
- `ConfigurationMigrator`
- `MigrationResult`
- `MigrationStatus`

**Key Imports:**
- `config`
- `dataclasses`
- `enum`


### `core\bypass\safety\safety_controller.py`

Configuration module with 0 functions and 3 classes for settings and configuration management

**Classes:**
- `ExecutionRecord`
- `SafetyConfiguration`
- `SafetyController`

**Key Imports:**
- `asyncio`
- `contextlib`
- `core.bypass.attacks.base`
- `dataclasses`
- `threading`


### `core\bypass\strategies\config_models.py`

Configuration module with 0 functions and 8 classes for settings and configuration management

**Classes:**
- `DPIConfig`
- `DesyncMode`
- `FoolingConfig`
- `FoolingMethod`
- `PacketSplitResult`
- `SplitConfig`
- `TCPPacketInfo`
- `TLSPacketInfo`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\strategies\social_media_handler.py`

Configuration module with 0 functions and 8 classes for settings and configuration management

**Classes:**
- `BlockingPattern`
- `InstagramSpecificConfig`
- `MediaType`
- `PlatformSpecificStrategy`
- `SocialMediaBypassHandler`
- `TikTokSpecificConfig`
- `TwitterSpecificConfig`
- `YouTubeSpecificConfig`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`


### `core\config\config_migration_tool.py`

Configuration module with 1 functions and 1 classes for settings and configuration management

**Functions:**
- `main()`

**Classes:**
- `ConfigMigrationTool`

**Key Imports:**
- `argparse`
- `strategy_config_manager`


### `core\config\performance_config.py`

Configuration module with 4 functions and 7 classes for settings and configuration management

**Functions:**
- `apply_environment_overrides()`
- `apply_performance_preset()`
- `get_global_config_manager()`
- `get_performance_config()`

**Classes:**
- `AsyncConfig`
- `BypassEngineConfig`
- `CachingConfig`
- `FingerprintingConfig`
- `MonitoringConfig`
- `PerformanceConfig`
- `PerformanceConfigManager`

**Key Imports:**
- `dataclasses`
- `yaml`


### `core\diagnostics\structured_logger.py`

Configuration module with 2 functions and 6 classes for settings and configuration management

**Functions:**
- `get_structured_logger()`
- `initialize_structured_logging()`

**Classes:**
- `LogCategory`
- `LogContext`
- `LogLevel`
- `PerformanceMetrics`
- `StrategyTestLog`
- `StructuredLogger`

**Key Imports:**
- `contextlib`
- `dataclasses`
- `enum`
- `threading`
- `uuid`


### `core\discovery_config.py`

Configuration module with 0 functions and 11 classes for settings and configuration management

**Classes:**
- `ConfigurationError`
- `DiscoveryConfig`
- `DiscoveryConfigValidator`
- `DiscoveryMode`
- `DomainValidationConfig`
- `IntegrationConfig`
- `LogLevel`
- `PCAPConfig`
- `ResultsConfig`
- `StrategyConfig`
- `ValidationError`

**Key Imports:**
- `dataclasses`
- `enum`
- `ipaddress`
- `socket`


### `core\dns\doh_integration.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `DoHConfig`
- `DoHIntegration`

**Key Imports:**
- `asyncio`
- `core.doh_resolver`
- `socket`


### `core\domain_filter_config.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `DomainFilterConfig`
- `DomainFilterConfigManager`

**Key Imports:**
- `core.domain_filter`
- `dataclasses`


### `core\duplicate_analysis\config.py`

Configuration module with 1 functions and 6 classes for settings and configuration management

**Functions:**
- `setup_logging()`

**Classes:**
- `AnalysisConfig`
- `AnalysisSettings`
- `ConfigurationManager`
- `ProjectConfig`
- `QualityConfig`
- `ThresholdConfig`

**Key Imports:**
- `dataclasses`
- `interfaces`


### `core\duplicate_analysis\config_integration.py`

Configuration module with 2 functions and 3 classes for settings and configuration management

**Functions:**
- `create_integrated_config()`
- `validate_project_configuration()`

**Classes:**
- `ConfigurationValidationReport`
- `FullConfigurationIntegrator`
- `IntegratedAnalysisSettings`

**Key Imports:**
- `config_manager`
- `dataclasses`
- `enum`
- `interfaces`
- `utils`


### `core\duplicate_analysis\config_manager.py`

Configuration module with 0 functions and 7 classes for settings and configuration management

**Classes:**
- `AnalysisConfig`
- `ConfigValidationLevel`
- `ConfigurationManager`
- `ConfigurationValidator`
- `LLMContextConfig`
- `ModuleRegistryConfig`
- `ProjectStructureConfig`

**Key Imports:**
- `dataclasses`
- `enum`
- `interfaces`
- `utils`


### `core\duplicate_analysis\suppression_manager.py`

Configuration module with 1 functions and 5 classes for settings and configuration management

**Functions:**
- `create_default_suppression_manager()`

**Classes:**
- `DynamicCaseRule`
- `IgnoreListEntry`
- `SuppressionConfig`
- `SuppressionManager`
- `ThresholdConfiguration`

**Key Imports:**
- `dataclasses`
- `interfaces`
- `quality_controller`


### `core\fingerprint\config.py`

Configuration module with 5 functions and 14 classes for settings and configuration management

**Functions:**
- `create_default_config()`
- `get_config()`
- `get_config_manager()`
- `load_config()`
- `save_config()`

**Classes:**
- `AdvancedFingerprintingConfig`
- `AnalyzerConfig`
- `AnalyzerType`
- `CacheConfig`
- `ConfigLoadError`
- `ConfigValidationError`
- `ConfigurationError`
- `ConfigurationManager`
- `LogLevel`
- `LoggingConfig`
- `MLConfig`
- `MonitoringConfig`
- `NetworkConfig`
- `PerformanceConfig`

**Key Imports:**
- `dataclasses`
- `enum`
- `yaml`


### `core\infrastructure\retry_utils.py`

Configuration module with 5 functions and 1 classes for settings and configuration management

**Functions:**
- `retry_network_async()`
- `retry_network_sync()`
- `retry_sync()`
- `retryable_async()`
- `retryable_sync()`

**Classes:**
- `RetryConfig`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\infrastructure\structured_logger.py`

Configuration module with 2 functions and 4 classes for settings and configuration management

**Functions:**
- `get_structured_logger()`
- `initialize_structured_logger()`

**Classes:**
- `LogCategory`
- `LogEntry`
- `LogLevel`
- `StructuredLogger`

**Key Imports:**
- `dataclasses`
- `enum`
- `threading`


### `core\integration\integration_config.py`

Configuration module with 0 functions and 9 classes for settings and configuration management

**Classes:**
- `AttackExecutionError`
- `AttackMapping`
- `CompatibilityError`
- `ConfigurationError`
- `IntegrationConfig`
- `IntegrationError`
- `PerformanceError`
- `PerformanceMetrics`
- `StrategyMappingError`

**Key Imports:**
- `dataclasses`


### `core\logging\accessibility_logging.py`

Configuration module with 5 functions and 2 classes for settings and configuration management

**Functions:**
- `configure_basic_logging()`
- `configure_debug_logging()`
- `configure_silent_logging()`
- `configure_standard_logging()`
- `configure_troubleshooting_logging()`

**Classes:**
- `AccessibilityLoggingConfig`
- `LogLevel`

**Key Imports:**
- `enum`
- `logging.handlers`


### `core\logging\logging_config.py`

Configuration module with 0 functions and 1 classes for settings and configuration management

**Classes:**
- `LoggingConfig`

**Key Imports:**
- `__future__`
- `dataclasses`


### `core\monitoring\fast_auto_recovery.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `FastAutoRecoveryManager`
- `RecoveryConfig`

**Key Imports:**
- `asyncio`
- `core.monitoring.hot_reloader`
- `core.optimization.models`
- `dataclasses`


### `core\pcap_analysis\cli_config.py`

Configuration module with 5 functions and 3 classes for settings and configuration management

**Functions:**
- `create_default_config_file()`
- `get_config()`
- `load_batch_config()`
- `load_config()`
- `save_config()`

**Classes:**
- `AnalysisConfig`
- `CLIConfig`
- `ConfigManager`

**Key Imports:**
- `dataclasses`


### `core\pcap_analysis\deployment\production_config.py`

Configuration module with 2 functions and 8 classes for settings and configuration management

**Functions:**
- `create_sample_config()`
- `main()`

**Classes:**
- `DatabaseConfig`
- `MonitoringConfig`
- `PerformanceConfig`
- `ProductionConfig`
- `ProductionConfigManager`
- `RedisConfig`
- `SecurityConfig`
- `StorageConfig`

**Key Imports:**
- `dataclasses`


### `core\pcap_analysis\difference_detector.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `DetectionConfig`
- `DifferenceDetector`

**Key Imports:**
- `comparison_result`
- `critical_difference`
- `dataclasses`
- `packet_info`
- `statistics`


### `core\pcap_analysis\parallel_processor.py`

Configuration module with 0 functions and 6 classes for settings and configuration management

**Classes:**
- `AsyncParallelProcessor`
- `BatchProcessor`
- `ParallelConfig`
- `ParallelPcapAnalyzer`
- `ParallelTaskManager`
- `TaskResult`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `dataclasses`
- `multiprocessing`
- `packet_info`


### `core\pcap_analysis\performance_integration.py`

Configuration module with 0 functions and 2 classes for settings and configuration management

**Classes:**
- `HighPerformancePcapAnalyzer`
- `PerformanceConfig`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `memory_optimizer`
- `parallel_processor`
- `streaming_processor`


### `core\reporting\segment_reporting_integration.py`

Configuration module with 0 functions and 3 classes for settings and configuration management

**Classes:**
- `SegmentReportConfig`
- `SegmentReportData`
- `SegmentReportingIntegration`

**Key Imports:**
- `core.bypass.diagnostics.segment_diagnostics`
- `core.bypass.monitoring.segment_execution_stats`
- `core.reporting.enhanced_reporter`
- `dataclasses`


### `core\workflow\segment_workflow_integration.py`

Configuration module with 0 functions and 4 classes for settings and configuration management

**Classes:**
- `SegmentWorkflowConfig`
- `SegmentWorkflowIntegration`
- `WorkflowExecutionMode`
- `WorkflowExecutionResult`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.integration.attack_adapter`
- `dataclasses`
- `enum`


### `deployment\production_deployment_manager.py`

Configuration module with 0 functions and 3 classes for settings and configuration management

**Classes:**
- `DeploymentStatus`
- `ProductionConfig`
- `ProductionDeploymentManager`

**Key Imports:**
- `asyncio`
- `core.bypass.diagnostics.segment_diagnostics`
- `core.bypass.monitoring.segment_execution_stats`
- `core.bypass.performance.segment_performance_optimizer`
- `dataclasses`


### `deployment\service_mode_deployment.py`

Configuration module with 1 functions and 2 classes for settings and configuration management

**Functions:**
- `main()`

**Classes:**
- `ServiceDeploymentConfig`
- `ServiceModeDeployment`

**Key Imports:**
- `dataclasses`
- `socket`
- `threading`


### `enhanced_find_rst_triggers.py`

Configuration module with 2 functions and 3 classes for settings and configuration management

**Functions:**
- `compare_with_service_mode()`
- `main()`

**Classes:**
- `DPIFingerprintAnalyzer`
- `StrategyTestConfig`
- `TestResult`

**Key Imports:**
- `argparse`
- `dataclasses`
- `socket`


### `gui\advanced_settings.py`

Configuration module with 0 functions and 1 classes for settings and configuration management

**Classes:**
- `AdvancedSettingsWidget`

**Key Imports:**
- `PyQt6.QtWidgets`


### `infrastructure_setup.py`

Configuration module with 3 functions and 0 classes for settings and configuration management

**Functions:**
- `main()`
- `setup_directories()`
- `setup_logging()`


### `monitoring\production_monitoring_system.py`

Configuration module with 0 functions and 5 classes for settings and configuration management

**Classes:**
- `Alert`
- `AnomalyDetector`
- `MonitoringConfig`
- `ProductionMonitoringSystem`
- `SystemMetrics`

**Key Imports:**
- `asyncio`
- `core.bypass.diagnostics.segment_diagnostics`
- `core.bypass.monitoring.segment_execution_stats`
- `dataclasses`
- `statistics`


### `start_service_utf8.py`

Configuration module with 2 functions and 0 classes for settings and configuration management

**Functions:**
- `setup_utf8_environment()`
- `start_service()`

**Key Imports:**
- `locale`
- `subprocess`


### `tools\check_domain_config_syntax.py`

Configuration module with 1 functions and 1 classes for settings and configuration management

**Functions:**
- `main()`

**Classes:**
- `ConfigSyntaxChecker`

**Key Imports:**
- `argparse`



## Files

Modules for file operations, directory management, and data processing.

### `adaptive_bypass_service.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `AdaptiveBypassService`

**Key Imports:**
- `asyncio`
- `subprocess`
- `threading`
- `urllib.parse`


### `alternative_capture_solution.py`

File operations module with 3 functions and 1 classes for file and directory management

**Functions:**
- `integrate_alternative_solution()`
- `main()`
- `test_alternative_methods()`

**Classes:**
- `AlternativePCAPCapturer`

**Key Imports:**
- `subprocess`
- `threading`


### `attack_parity_validator.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `AttackParityValidator`

**Key Imports:**
- `core.attack_parity.analyzer`
- `core.attack_parity.report_generator`


### `attack_validation_example.py`

File operations module with 7 functions and 0 classes for file and directory management

**Functions:**
- `analyze_logs_only()`
- `create_directories()`
- `main()`
- `run_discovery_mode()`
- `run_service_mode()`
- `validate_attack_execution_simple()`
- `validate_multiple_domains()`

**Key Imports:**
- `core.attack_parity.analyzer`
- `core.attack_parity.report_generator`
- `subprocess`


### `automated_validation.py`

File operations module with 6 functions and 0 classes for file and directory management

**Functions:**
- `analyze_domain_logs()`
- `create_directories()`
- `main()`
- `run_comprehensive_validation()`
- `test_domain_with_discovery()`
- `test_domain_with_service()`

**Key Imports:**
- `subprocess`


### `build_release.py`

File operations module with 10 functions and 0 classes for file and directory management

**Functions:**
- `build_exe()`
- `check_dependencies()`
- `create_checksums()`
- `create_icon()`
- `create_installer()`
- `create_portable_zip()`
- `main()`
- `print_step()`
- `print_summary()`
- `run_command()`

**Key Imports:**
- `subprocess`


### `build_windows_app.py`

File operations module with 5 functions and 0 classes for file and directory management

**Functions:**
- `build_exe()`
- `check_dependencies()`
- `create_installer()`
- `create_spec_file()`
- `main()`

**Key Imports:**
- `subprocess`


### `clear_cache_and_verify.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `clear_pycache()`
- `main()`
- `verify_fixes()`


### `comprehensive_discrepancy_analyzer.py`

File operations module with 1 functions and 4 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `AttackLogEntry`
- `ComprehensiveDiscrepancyAnalyzer`
- `DetailedDiscrepancy`
- `LogEntry`

**Key Imports:**
- `dataclasses`


### `core\adaptive_knowledge.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `AdaptiveKnowledgeBase`
- `StrategyRecord`

**Key Imports:**
- `core.connection_metrics`
- `dataclasses`
- `threading`


### `core\adaptive_state_manager.py`

File operations module with 3 functions and 5 classes for file and directory management

**Functions:**
- `create_state_manager()`
- `load_best_strategy()`
- `save_strategy_result()`

**Classes:**
- `AdaptiveStateManager`
- `DataVersion`
- `DomainState`
- `StateMetadata`
- `StrategyRecord`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\attack_parity\combination_registry.py`

File operations module with 3 functions and 3 classes for file and directory management

**Functions:**
- `build_combination_registry()`
- `get_combination_registry()`
- `validate_all_combinations()`

**Classes:**
- `AdaptiveKnowledgeParser`
- `AttackCombinationRegistry`
- `CombinationStrategy`

**Key Imports:**
- `canonical_definitions`
- `dataclasses`
- `models`


### `core\attack_parity\parsers.py`

File operations module with 2 functions and 2 classes for file and directory management

**Functions:**
- `auto_detect_parser()`
- `create_log_parser()`

**Classes:**
- `DiscoveryModeLogParser`
- `ServiceModeLogParser`

**Key Imports:**
- `canonical_definitions`
- `interfaces`
- `models`


### `core\attack_parity\pcap_analyzer.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `DefaultPCAPAnalyzer`

**Key Imports:**
- `interfaces`
- `models`


### `core\baseline_manager.py`

File operations module with 0 functions and 7 classes for file and directory management

**Classes:**
- `BaselineManager`
- `BaselineReport`
- `BaselineResult`
- `ComparisonResult`
- `Improvement`
- `Regression`
- `RegressionSeverity`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\analytics\metrics_collector.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `MetricsCollector`

**Key Imports:**
- `core.bypass.analytics.analytics_models`
- `sqlite3`


### `core\bypass\analytics\ml_predictor.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `MLPredictor`
- `SimplePredictor`

**Key Imports:**
- `core.bypass.analytics.analytics_models`
- `core.bypass.analytics.metrics_collector`
- `numpy`
- `pickle`


### `core\bypass\analytics\reporting_dashboard.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ReportingDashboard`

**Key Imports:**
- `core.bypass.analytics.analytics_models`
- `core.bypass.analytics.metrics_collector`
- `core.bypass.analytics.ml_predictor`
- `core.bypass.analytics.performance_tracker`


### `core\bypass\attacks\combo\zapret_attack_adapter.py`

File operations module with 3 functions and 3 classes for file and directory management

**Functions:**
- `create_auto_zapret_adapter()`
- `create_zapret_adapter_with_config()`
- `create_zapret_adapter_with_preset()`

**Classes:**
- `ZapretAdapterConfig`
- `ZapretAdapterMode`
- `ZapretAttackAdapter`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.attacks.combo.zapret_strategy`
- `dataclasses`
- `enum`


### `core\bypass\attacks\learning_memory.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `AdaptationRecord`
- `LearningHistory`
- `LearningMemory`
- `StrategyRecord`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `hashlib`
- `sqlite3`


### `core\bypass\attacks\safe_result_utils.py`

File operations module with 7 functions and 0 classes for file and directory management

**Functions:**
- `create_error_result()`
- `create_failed_result()`
- `create_invalid_params_result()`
- `create_success_result()`
- `create_timeout_result()`
- `safe_create_attack_result()`
- `safe_get_attack_status()`


### `core\bypass\attacks\validation\validation_runner.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ValidationRunner`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.attacks.validation.attack_validator`


### `core\bypass\config\backup_manager.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `BackupManager`

**Key Imports:**
- `core.bypass.config.config_models`
- `uuid`


### `core\bypass\config\demo_config_migration.py`

File operations module with 2 functions and 0 classes for file and directory management

**Functions:**
- `demo_external_tool_migration()`
- `demo_legacy_migration()`

**Key Imports:**
- `core.bypass.config.config_manager`
- `core.bypass.config.config_models`


### `core\bypass\engine\domain_rule_registry.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `DomainRuleRegistry`


### `core\bypass\engine\parent_domain_recommender.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `ParentDomainRecommendation`
- `ParentDomainRecommender`


### `core\bypass\engine\startup_conflict_detector.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `run_startup_conflict_detection()`

**Classes:**
- `ConflictReport`
- `StartupConflictDetector`

**Key Imports:**
- `socket`


### `core\bypass\engines\error_handling.py`

File operations module with 8 functions and 14 classes for file and directory management

**Functions:**
- `create_configuration_error()`
- `create_dependency_error()`
- `create_error_from_exception()`
- `create_permission_error()`
- `create_platform_error()`
- `create_validation_error()`
- `get_error_handler()`
- `handle_engine_error()`

**Classes:**
- `BaseEngineError`
- `EngineConfigurationError`
- `EngineCreationError`
- `EngineDependencyError`
- `EngineNetworkError`
- `EnginePermissionError`
- `EnginePlatformError`
- `EngineRuntimeError`
- `EngineValidationError`
- `ErrorCategory`
- `ErrorContext`
- `ErrorHandler`
- `ErrorSeverity`
- `ResolutionSuggestion`

**Key Imports:**
- `core.bypass.engines.base`
- `dataclasses`
- `enum`
- `platform`


### `core\bypass\engines\external_tool_engine.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ExternalToolEngine`

**Key Imports:**
- `core.bypass.engines.base`
- `platform`
- `subprocess`


### `core\bypass\engines\factory.py`

File operations module with 4 functions and 0 classes for file and directory management

**Functions:**
- `create_best_engine()`
- `create_engine()`
- `create_engine_with_validation()`
- `detect_best_engine()`

**Key Imports:**
- `core.bypass.engines.base`
- `core.bypass.engines.external_tool_engine`
- `core.bypass.engines.native_pydivert_engine`
- `platform`


### `core\bypass\filtering\host_extractor.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `HostHeaderExtractor`


### `core\bypass\integration\unified_engine_dpi_integration.py`

File operations module with 3 functions and 1 classes for file and directory management

**Functions:**
- `create_dpi_enabled_unified_engine()`
- `integrate_dpi_with_unified_engine()`
- `patch_unified_bypass_engine_for_dpi()`

**Classes:**
- `UnifiedEngineDPIIntegration`

**Key Imports:**
- `pipeline.dpi_packet_processor`
- `strategies.config_models`


### `core\bypass\modes\exceptions.py`

File operations module with 0 functions and 5 classes for file and directory management

**Classes:**
- `CapabilityDetectionError`
- `ModeError`
- `ModeNotAvailableError`
- `ModeTransitionError`
- `UnsupportedModeError`


### `core\bypass\pcap_collector.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `FailurePcapCollector`

**Key Imports:**
- `threading`


### `core\bypass\performance\alerting_system.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `AlertingSystem`

**Key Imports:**
- `core.bypass.performance.performance_models`
- `email.mime.multipart`
- `email.mime.text`
- `smtplib`


### `core\bypass\performance\demo_performance_optimization.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `PerformanceOptimizationDemo`

**Key Imports:**
- `asyncio`
- `core.bypass.performance.alerting_system`
- `core.bypass.performance.performance_optimizer`
- `core.bypass.performance.production_monitor`
- `core.bypass.performance.strategy_optimizer`


### `core\bypass\pipeline\dpi_packet_processor.py`

File operations module with 2 functions and 3 classes for file and directory management

**Functions:**
- `create_dpi_packet_processor()`
- `create_dpi_pipeline_integrator()`

**Classes:**
- `DPIPacketProcessor`
- `DPIPipelineIntegrator`
- `PacketProcessingResult`

**Key Imports:**
- `dataclasses`
- `strategies.config_models`
- `strategies.dpi_strategy_engine`
- `threading`


### `core\bypass\sharing\community_database.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `CommunityDatabase`

**Key Imports:**
- `core.bypass.sharing.sharing_models`
- `core.bypass.sharing.strategy_validator`
- `sqlite3`


### `core\bypass\sharing\demo_sharing_system.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `SharingSystemDemo`

**Key Imports:**
- `asyncio`
- `core.bypass.sharing.sharing_manager`
- `core.bypass.sharing.sharing_models`
- `unittest.mock`


### `core\bypass\sharing\sharing_manager.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `SharingManager`

**Key Imports:**
- `asyncio`
- `core.bypass.sharing.community_database`
- `core.bypass.sharing.sharing_models`
- `core.bypass.sharing.strategy_validator`
- `uuid`


### `core\calibration\calibrator.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `CalibCandidate`
- `Calibrator`

**Key Imports:**
- `dataclasses`


### `core\calibration\enhanced_strategy_calibrator.py`

File operations module with 1 functions and 12 classes for file and directory management

**Functions:**
- `create_enhanced_calibrator()`

**Classes:**
- `AdaptiveBudgetManager`
- `CalibrationBudget`
- `CalibrationResult`
- `CaptureSession`
- `DummyCaptureSession`
- `EnhancedStrategyCalibrator`
- `EnhancedTestResult`
- `FailurePatternDetector`
- `PyDivertCaptureSession`
- `ScapyCaptureSession`
- `StrategyFeedbackSystem`
- `TrafficCapturer`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\cli_payload\dpi_config_loader.py`

File operations module with 2 functions and 1 classes for file and directory management

**Functions:**
- `create_dpi_config_loader()`
- `load_dpi_config_for_domain()`

**Classes:**
- `DPIConfigLoader`

**Key Imports:**
- `bypass.strategies.config_models`
- `bypass.strategies.exceptions`


### `core\cli_validation_orchestrator.py`

File operations module with 1 functions and 3 classes for file and directory management

**Functions:**
- `create_cli_validator()`

**Classes:**
- `CLIValidationOrchestrator`
- `CLIValidationReport`
- `StrategyValidationResult`

**Key Imports:**
- `core.baseline_manager`
- `core.pcap_content_validator`
- `dataclasses`


### `core\di\cli_integration.py`

File operations module with 3 functions and 2 classes for file and directory management

**Functions:**
- `create_cli_integration()`
- `create_fallback_services()`
- `get_services_from_di()`

**Classes:**
- `CLIIntegration`
- `CLIServices`

**Key Imports:**
- `asyncio`
- `core.di.cli_provider`
- `core.interfaces`
- `dataclasses`
- `ml.strategy_generator`


### `core\di\typed_config.py`

File operations module with 5 functions and 3 classes for file and directory management

**Functions:**
- `create_config_from_file()`
- `create_development_config()`
- `create_production_config()`
- `create_testing_config()`
- `save_config_to_file()`

**Classes:**
- `ConfigurationBuilder`
- `DIMode`
- `ServiceLifetime`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\diagnostics\accessibility_diagnostics.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `AccessibilityDiagnostics`
- `DiagnosticResult`

**Key Imports:**
- `dataclasses`
- `socket`
- `subprocess`


### `core\diagnostics\metrics.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `MetricPoint`
- `MetricsCollector`
- `Timer`

**Key Imports:**
- `core.diagnostics.logger`
- `dataclasses`
- `statistics`
- `threading`


### `core\domain_watchlist.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `DomainWatchlist`


### `core\duplicate_analysis\ast_parser.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `ASTNormalizer`
- `ASTParser`

**Key Imports:**
- `ast`
- `copy`
- `hashlib`
- `interfaces`
- `metadata_extractor`


### `core\duplicate_analysis\cli.py`

File operations module with 10 functions and 0 classes for file and directory management

**Functions:**
- `create_config_from_args()`
- `create_parser()`
- `enhance_analysis_with_llm_context()`
- `main()`
- `print_analysis_summary()`
- `run_dry_run()`
- `run_full_analysis()`
- `update_project_documents_with_audit_trail()`
- `validate_arguments()`
- `validate_configuration_files()`

**Key Imports:**
- `argparse`
- `config_manager`
- `interfaces`
- `project_scanner`
- `traceback`


### `core\duplicate_analysis\code_analyzer.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `CodeAnalyzer`
- `FunctionAnalysis`
- `ModuleStructureAnalysis`
- `UsagePattern`

**Key Imports:**
- `ast`
- `ast_parser`
- `dataclasses`
- `interfaces`
- `metadata_extractor`


### `core\duplicate_analysis\dead_code_detector.py`

File operations module with 0 functions and 8 classes for file and directory management

**Classes:**
- `CallGraph`
- `CallGraphNode`
- `CallVisitor`
- `DeadCodeClassifier`
- `DeadCodeDetector`
- `EntryPoint`
- `EntryPointDetector`
- `ReachabilityAnalyzer`

**Key Imports:**
- `ast`
- `dataclasses`
- `interfaces`


### `core\duplicate_analysis\dependency_analyzer.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `DependencyAnalyzer`

**Key Imports:**
- `ast`
- `ast_parser`
- `interfaces`


### `core\duplicate_analysis\documentation_analyzer.py`

File operations module with 0 functions and 6 classes for file and directory management

**Classes:**
- `DocstringAnalysis`
- `DocstringStyle`
- `DocumentationAnalyzer`
- `DocumentationQuality`
- `DocumentationSuggestion`
- `ModuleDocumentationReport`

**Key Imports:**
- `ast`
- `dataclasses`
- `enum`
- `interfaces`


### `core\duplicate_analysis\documentation_generator.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `DocstringImprovement`
- `DocstringTemplate`
- `DocumentationGenerationReport`
- `DocumentationGenerator`

**Key Imports:**
- `ast`
- `dataclasses`
- `documentation_analyzer`
- `enum`
- `interfaces`


### `core\duplicate_analysis\documentation_improver.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `DocumentationImprovementPlan`
- `DocumentationImprover`
- `DocumentationMetrics`

**Key Imports:**
- `ast`
- `dataclasses`
- `documentation_analyzer`
- `documentation_generator`
- `interfaces`


### `core\duplicate_analysis\enhanced_registry_builder.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `EnhancedRegistryBuilder`
- `ModuleEnhancement`

**Key Imports:**
- `dataclasses`
- `enhanced_categorizer`
- `integration`
- `refactoring.module_registry_builder`
- `refactoring.module_scanner`


### `core\duplicate_analysis\evidence_collector.py`

File operations module with 0 functions and 13 classes for file and directory management

**Classes:**
- `CallGraph`
- `CallReference`
- `CodeElement`
- `DeadCodeEvidence`
- `DuplicateEvidence`
- `DynamicUsageAnalysis`
- `EvidenceCollector`
- `ImportIndex`
- `ImportReference`
- `ImportUsageAnalysis`
- `Reference`
- `SymbolIndex`
- `TextReference`

**Key Imports:**
- `ast`
- `dataclasses`
- `integration`
- `interfaces`


### `core\duplicate_analysis\integration.py`

File operations module with 0 functions and 7 classes for file and directory management

**Classes:**
- `CompatibilityReport`
- `DataLoader`
- `EnhancedModuleInfo`
- `IntegrationResult`
- `IntegrationStats`
- `ProjectDocuments`
- `ReconIntegrationLayer`

**Key Imports:**
- `config_manager`
- `dataclasses`
- `interfaces`
- `refactoring.module_categorizer`
- `refactoring.module_scanner`


### `core\duplicate_analysis\module_card_generator.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ModuleCardGenerator`

**Key Imports:**
- `ast`
- `inspect`
- `interfaces`


### `core\duplicate_analysis\project_scanner.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `ModuleHierarchy`
- `ProjectScanner`
- `ScanConfiguration`

**Key Imports:**
- `ast`
- `config_integration`
- `dataclasses`
- `fnmatch`
- `interfaces`


### `core\duplicate_analysis\quality_controller.py`

File operations module with 1 functions and 6 classes for file and directory management

**Functions:**
- `create_default_suppression_rules()`

**Classes:**
- `ConfidenceFactors`
- `QualityController`
- `QualityMetrics`
- `QualityThresholds`
- `SuppressionReason`
- `SuppressionRule`

**Key Imports:**
- `dataclasses`
- `enum`
- `interfaces`


### `core\duplicate_analysis\refactoring_planner.py`

File operations module with 0 functions and 6 classes for file and directory management

**Classes:**
- `RefactoringPlan`
- `RefactoringPlanner`
- `RefactoringPriority`
- `RefactoringStep`
- `RefactoringSuggestion`
- `RefactoringType`

**Key Imports:**
- `dataclasses`
- `enum`
- `interfaces`


### `core\duplicate_analysis\report_generator.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `export_reports_cli()`

**Classes:**
- `EnhancedReportGenerator`
- `MultiFormatExporter`

**Key Imports:**
- `dataclasses`
- `html`
- `interfaces`


### `core\duplicate_analysis\serialization.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `AnalysisResultsDecoder`
- `AnalysisResultsEncoder`
- `AnalysisResultsSerializer`
- `IncrementalAnalysisCache`

**Key Imports:**
- `ast`
- `dataclasses`
- `dataclasses`
- `dataclasses`
- `enum`


### `core\duplicate_analysis\universalization_analyzer.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `UniversalizationAnalyzer`

**Key Imports:**
- `ast`
- `interfaces`


### `core\duplicate_analysis\warning_system.py`

File operations module with 0 functions and 5 classes for file and directory management

**Classes:**
- `EnhancedWarningSystem`
- `Warning`
- `WarningContext`
- `WarningSeverity`
- `WarningType`

**Key Imports:**
- `ast`
- `dataclasses`
- `enum`
- `interfaces`


### `core\fingerprint\advanced_fingerprint_engine.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_ultimate_fingerprint_engine()`

**Classes:**
- `UltimateAdvancedFingerprintEngine`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.attack_registry`
- `core.fingerprint.analyzer`
- `core.fingerprint.models`
- `dataclasses`


### `core\fingerprint\advanced_models.py`

File operations module with 0 functions and 8 classes for file and directory management

**Classes:**
- `CacheError`
- `ConfidenceLevel`
- `DPIFingerprint`
- `DPIType`
- `FingerprintingError`
- `MLClassificationError`
- `MetricsCollectionError`
- `NetworkAnalysisError`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\fingerprint\cache.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `CachedFingerprint`
- `FingerprintCache`

**Key Imports:**
- `core.fingerprint.advanced_models`
- `dataclasses`
- `pickle`
- `threading`


### `core\fingerprint\classifier.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `UltimateDPIClassifier`

**Key Imports:**
- `__future__`
- `core.fingerprint.models`
- `joblib`
- `numpy`


### `core\fingerprint\compatibility.py`

File operations module with 2 functions and 5 classes for file and directory management

**Functions:**
- `create_legacy_wrapper()`
- `migrate_legacy_data()`

**Classes:**
- `BackwardCompatibilityLayer`
- `CompatibilityError`
- `LegacyFingerprintWrapper`
- `LegacyFormatError`
- `MigrationError`

**Key Imports:**
- `pickle`


### `core\fingerprint\compatibility_demo.py`

File operations module with 9 functions and 0 classes for file and directory management

**Functions:**
- `demo_advanced_to_legacy_conversion()`
- `demo_compatibility_wrapper()`
- `demo_create_legacy_data()`
- `demo_error_handling()`
- `demo_legacy_data_migration()`
- `demo_legacy_format_conversion()`
- `demo_migration_validation()`
- `demo_performance_comparison()`
- `main()`

**Key Imports:**
- `pickle`


### `core\fingerprint\config_demo.py`

File operations module with 10 functions and 0 classes for file and directory management

**Functions:**
- `demo_analyzer_configuration()`
- `demo_configuration_file_operations()`
- `demo_configuration_serialization()`
- `demo_configuration_validation()`
- `demo_default_configuration()`
- `demo_feature_flags()`
- `demo_global_configuration_management()`
- `demo_performance_tuning_scenarios()`
- `demo_runtime_configuration_updates()`
- `main()`


### `core\fingerprint\diagnostics.py`

File operations module with 3 functions and 8 classes for file and directory management

**Functions:**
- `get_diagnostic_system()`
- `monitor_operation()`
- `setup_logging()`

**Classes:**
- `DiagnosticLogger`
- `DiagnosticReport`
- `DiagnosticSystem`
- `HealthCheckResult`
- `HealthChecker`
- `MetricsCollector`
- `PerformanceMetric`
- `StructuredFormatter`

**Key Imports:**
- `dataclasses`
- `psutil`
- `statistics`
- `threading`


### `core\fingerprint\dpi_classifier.py`

File operations module with 0 functions and 8 classes for file and directory management

**Classes:**
- `BlockingMethod`
- `DPICapability`
- `DPIClassificationEngine`
- `DPISignature`
- `DPIVendor`
- `EvasionDifficulty`
- `ProvenanceRecord`
- `VulnerabilityAssessment`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\fingerprint\final_integration.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `FinalIntegrationTester`
- `IntegrationReport`
- `PerformanceResult`
- `ValidationResult`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\fingerprint\ml_classifier.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `MLClassificationError`
- `MLClassifier`

**Key Imports:**
- `__future__`
- `numpy`


### `core\fingerprint\ml_classifier_demo.py`

File operations module with 2 functions and 0 classes for file and directory management

**Functions:**
- `create_sample_training_data()`
- `demo_ml_classifier()`

**Key Imports:**
- `core.fingerprint.ml_classifier`


### `core\fingerprint\model_trainer.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `ModelEvaluationMetrics`
- `ModelTrainer`

**Key Imports:**
- `__future__`
- `core.fingerprint.ml_classifier`
- `core.fingerprint.training_data`
- `dataclasses`
- `numpy`


### `core\fingerprint\monitoring_integration.py`

File operations module with 4 functions and 1 classes for file and directory management

**Functions:**
- `create_monitoring_integration()`
- `default_alert_handler()`
- `default_behavior_change_handler()`
- `default_strategy_update_handler()`

**Classes:**
- `MonitoringIntegration`

**Key Imports:**
- `core.fingerprint.advanced_fingerprinter`
- `core.fingerprint.advanced_models`
- `core.fingerprint.dpi_behavior_monitor`


### `core\fingerprint\online_learning_demo.py`

File operations module with 7 functions and 0 classes for file and directory management

**Functions:**
- `create_sample_metrics()`
- `demo_ab_testing()`
- `demo_basic_online_learning()`
- `demo_learning_modes()`
- `demo_performance_monitoring()`
- `main()`
- `simulate_classification_with_errors()`

**Key Imports:**
- `core.fingerprint.ml_classifier`
- `core.fingerprint.model_trainer`
- `core.fingerprint.online_learning`


### `core\fingerprint\online_learning_integration.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `create_online_learning_integrator()`

**Classes:**
- `FeedbackData`
- `OnlineLearningIntegrator`

**Key Imports:**
- `__future__`
- `core.fingerprint.advanced_models`
- `core.fingerprint.ml_classifier`
- `core.fingerprint.online_learning`
- `dataclasses`


### `core\fingerprint\training_data.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `FeatureEngineer`
- `TrainingDataGenerator`
- `TrainingExample`

**Key Imports:**
- `__future__`
- `dataclasses`
- `numpy`


### `core\integration\adaptive_combo_integration.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `create_adaptive_combo_integration()`

**Classes:**
- `AdaptiveComboAttackIntegration`
- `AdaptiveComboState`

**Key Imports:**
- `dataclasses`
- `hashlib`


### `core\integration\advanced_attack_errors.py`

File operations module with 9 functions and 15 classes for file and directory management

**Functions:**
- `create_configuration_error()`
- `create_execution_error()`
- `create_integration_error()`
- `create_learning_error()`
- `create_ml_feedback_error()`
- `create_monitoring_error()`
- `create_network_error()`
- `create_system_error()`
- `get_error_handler()`

**Classes:**
- `AdvancedAttackError`
- `AdvancedAttackErrorHandler`
- `ConfigurationError`
- `ErrorCategory`
- `ErrorContext`
- `ErrorSeverity`
- `ExecutionError`
- `IntegrationError`
- `LearningError`
- `MLFeedbackError`
- `MonitoringError`
- `NetworkError`
- `RecoveryAction`
- `RecoveryResult`
- `SystemError`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\integration\learning_memory_integration.py`

File operations module with 1 functions and 4 classes for file and directory management

**Functions:**
- `create_learning_memory_integration()`

**Classes:**
- `LearningMemoryIntegration`
- `LearningMemoryState`
- `PatternRecognitionResult`
- `PredictiveRecommendation`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `hashlib`
- `numpy`


### `core\integration\service_integration_manager.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `ServiceIntegrationManager`
- `ServiceStrategy`

**Key Imports:**
- `dataclasses`


### `core\integration\strategy_mapper.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `StrategyMapper`

**Key Imports:**
- `core.integration.integration_config`


### `core\integration\strategy_saver.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `StrategySaver`

**Key Imports:**
- `core.zapret`
- `hashlib`


### `core\integration\traffic_mimicry_integration.py`

File operations module with 1 functions and 4 classes for file and directory management

**Functions:**
- `create_traffic_mimicry_integration()`

**Classes:**
- `DPIComplexityResult`
- `SteganographicResult`
- `TrafficMimicryIntegration`
- `TrafficMimicryState`

**Key Imports:**
- `dataclasses`
- `hashlib`


### `core\knowledge\cdn_asn_db.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `AsnProfile`
- `CdnAsnKnowledgeBase`
- `CdnProfile`

**Key Imports:**
- `dataclasses`
- `ipaddress`
- `pickle`


### `core\knowledge\knowledge_accumulator.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `KnowledgeAccumulator`
- `PatternRule`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\learning\iterative_analysis_engine.py`

File operations module with 0 functions and 7 classes for file and directory management

**Classes:**
- `AnalysisPhase`
- `CorrelationResult`
- `IterationContext`
- `IterationStatus`
- `IterativeAnalysisEngine`
- `KnowledgePattern`
- `StrategyEffectivenessMetrics`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `dataclasses`
- `enum`
- `hashlib`


### `core\logging\conversion_state.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ConversionState`

**Key Imports:**
- `__future__`
- `dataclasses`


### `core\metrics\closed_loop_metrics.py`

File operations module with 2 functions and 2 classes for file and directory management

**Functions:**
- `get_closed_loop_metrics_collector()`
- `reset_global_metrics_collector()`

**Classes:**
- `ClosedLoopMetrics`
- `ClosedLoopMetricsCollector`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\monitoring\auto_recovery.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `AutoRecoveryManager`
- `NotificationChannel`

**Key Imports:**
- `enum`
- `optimization.models`


### `core\monitoring\blocking_monitor.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `BlockingMonitor`

**Key Imports:**
- `dataclasses`
- `optimization.models`


### `core\monitoring\dpi_change_notifier.py`

File operations module with 0 functions and 7 classes for file and directory management

**Classes:**
- `ChangeType`
- `ConsoleNotificationChannel`
- `DPIChangeEvent`
- `DPIChangeNotifier`
- `FileNotificationChannel`
- `NotificationChannel`
- `WebhookNotificationChannel`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`


### `core\monitoring\enhanced_monitoring_system.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_enhanced_monitoring_system()`

**Classes:**
- `EnhancedMonitoringSystem`

**Key Imports:**
- `asyncio`
- `online_analysis_integration`
- `real_time_traffic_analyzer`
- `threading`


### `core\monitoring\fallback_monitor.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `FailurePattern`
- `FallbackAutoRecoveryMonitor`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\monitoring\hot_reloader.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ConfigHotReloader`

**Key Imports:**
- `asyncio`
- `hashlib`
- `optimization.models`


### `core\monitoring\monitoring_integration.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `create_integrated_monitoring_system()`

**Classes:**
- `EnhancedMonitoringSystem`
- `IntegratedMonitoringConfig`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\optimization\metrics_collector.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `PerformanceMetricsCollector`

**Key Imports:**
- `core.optimization.models`
- `core.packet.raw_packet_engine`
- `core.packet.raw_pcap_reader`
- `core.pcap.analyzer`


### `core\optimization\variation_generator.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `VariationGenerator`

**Key Imports:**
- `importlib.util`


### `core\optimizer\adaptive_controller.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `AdaptiveStrategyController`

**Key Imports:**
- `core.utils`
- `fnmatch`
- `threading`


### `core\orchestration\engine_orchestrator.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `create_engine_orchestrator()`

**Classes:**
- `EngineOrchestrator`
- `OrchestrationContext`

**Key Imports:**
- `asyncio`
- `component_registry`
- `core.strategy.circuit_breaker`
- `core.validation.result_validator`
- `dataclasses`


### `core\orchestration\unified_bypass_engine.py`

File operations module with 3 functions and 2 classes for file and directory management

**Functions:**
- `create_service_mode_engine()`
- `create_testing_mode_engine()`
- `create_unified_engine()`

**Classes:**
- `UnifiedBypassEngine`
- `UnifiedEngineConfig`

**Key Imports:**
- `asyncio`
- `component_registry`
- `dataclasses`
- `engine_orchestrator`
- `threading`


### `core\override_manager.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `OverrideManager`


### `core\packet\demo_migration.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `MigrationDemo`

**Key Imports:**
- `asyncio`
- `recon.core.packet.migration_tool`
- `recon.core.packet.raw_packet_engine`
- `recon.core.packet.scapy_compatibility`


### `core\packet\migration_tool.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ScapyMigrationTool`


### `core\packet\packet_builder.py`

File operations module with 3 functions and 3 classes for file and directory management

**Functions:**
- `create_dns_query()`
- `create_http_request()`
- `create_syn_packet()`

**Classes:**
- `FragmentedPacketBuilder`
- `PacketBuilder`
- `PacketModifier`

**Key Imports:**
- `packet_models`
- `socket`
- `struct`


### `core\packet\raw_packet_engine.py`

File operations module with 4 functions and 9 classes for file and directory management

**Functions:**
- `create_tcp_packet_with_payload()`
- `create_tcp_syn()`
- `fragment_tcp_packet()`
- `raw_packet_to_packet_info()`

**Classes:**
- `IPHeader`
- `PacketInfo`
- `ParsedPacket`
- `ProtocolType`
- `RawPacket`
- `RawPacketEngine`
- `TCPHeader`
- `TCPPacket`
- `TLSInfo`

**Key Imports:**
- `dataclasses`
- `enum`
- `socket`
- `struct`


### `core\packet\raw_pcap_reader.py`

File operations module with 2 functions and 4 classes for file and directory management

**Functions:**
- `iterate_pcap()`
- `read_pcap()`

**Classes:**
- `CorruptedPacketError`
- `PCAPHeader`
- `PCAPPacketHeader`
- `RawPCAPReader`

**Key Imports:**
- `dataclasses`
- `raw_packet_engine`
- `struct`


### `core\payload\manager.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `PayloadCorruptedError`
- `PayloadDirectoryError`
- `PayloadManager`
- `PayloadNotFoundError`

**Key Imports:**
- `hashlib`
- `types`
- `validator`


### `core\payload\serializer.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `InvalidHexError`
- `InvalidPlaceholderError`
- `PayloadSerializer`
- `PayloadSerializerError`

**Key Imports:**
- `types`


### `core\payload\strategy_integration.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_payload_enhanced_strategies()`

**Classes:**
- `StrategyPayloadIntegration`

**Key Imports:**
- `manager`
- `serializer`
- `types`


### `core\payload\types.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `PayloadInfo`
- `PayloadType`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\pcap\adaptive_engine_pcap_integration.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `integrate_pcap_analysis_into_adaptive_engine()`

**Classes:**
- `AdaptiveEnginePCAPIntegration`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\pcap\discovery_integration.py`

File operations module with 4 functions and 1 classes for file and directory management

**Functions:**
- `analyze_pcap_for_discovery()`
- `create_integrated_capturer()`
- `enhance_service_pcap_capture()`
- `filter_existing_pcap_for_discovery()`

**Classes:**
- `PCAPCapturerFactory`

**Key Imports:**
- `core.domain_filter`
- `core.pcap.discovery_packet_capturer`


### `core\pcap\discovery_packet_capturer.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_discovery_capturer()`

**Classes:**
- `DiscoveryPacketCapturer`

**Key Imports:**
- `core.domain_filter`
- `core.pcap.discovery_pcap_filter`
- `threading`


### `core\pcap\iterative_analysis_engine.py`

File operations module with 0 functions and 5 classes for file and directory management

**Classes:**
- `DPIKnowledge`
- `IterationContext`
- `IterativeAnalysisEngine`
- `LearningPhase`
- `StrategyGene`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `hashlib`


### `core\pcap\metadata_saver.py`

File operations module with 2 functions and 0 classes for file and directory management

**Functions:**
- `load_pcap_metadata()`
- `save_pcap_metadata()`


### `core\pcap\temporary_capturer.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `CaptureConstants`
- `CaptureSession`
- `EnhancedBypassEngineAdapter`
- `TemporaryPCAPCapturer`

**Key Imports:**
- `asyncio`
- `cleanup_manager`
- `contextlib`
- `dataclasses`
- `threading`


### `core\pcap_analysis\adaptive_engine_integration.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `AdaptiveEnginePCAPIntegration`
- `HistoricalCorrelation`
- `PCAPAnalysisCache`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\pcap_analysis\analysis_cache.py`

File operations module with 1 functions and 7 classes for file and directory management

**Functions:**
- `cached_analysis()`

**Classes:**
- `CacheEntry`
- `CacheKeyGenerator`
- `CacheStats`
- `CachedAnalyzer`
- `HybridCache`
- `MemoryCache`
- `PersistentCache`

**Key Imports:**
- `dataclasses`
- `hashlib`
- `pickle`
- `sqlite3`
- `threading`


### `core\pcap_analysis\analysis_reporter.py`

File operations module with 0 functions and 6 classes for file and directory management

**Classes:**
- `AnalysisReport`
- `AnalysisReporter`
- `ExecutiveSummary`
- `ReportFormat`
- `ReportSection`
- `VisualizationType`

**Key Imports:**
- `comparison_result`
- `critical_difference`
- `dataclasses`
- `enum`
- `statistics`


### `core\pcap_analysis\automated_workflow.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `AutomatedWorkflow`
- `WorkflowConfig`
- `WorkflowResult`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `difference_detector`
- `pcap_comparator`
- `strategy_analyzer`


### `core\pcap_analysis\deployment\production_deployment.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `ProductionDeployer`

**Key Imports:**
- `argparse`
- `production_config`
- `subprocess`


### `core\pcap_analysis\enhanced_rst_compatibility.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_enhanced_rst_compatibility_layer()`

**Classes:**
- `EnhancedRSTCompatibilityLayer`

**Key Imports:**
- `recon_integration`


### `core\pcap_analysis\fix_generator.py`

File operations module with 0 functions and 7 classes for file and directory management

**Classes:**
- `CodeFix`
- `FixGenerator`
- `FixType`
- `RegressionTest`
- `RiskLevel`
- `SequenceFix`
- `StrategyPatch`

**Key Imports:**
- `dataclasses`
- `enum`
- `packet_sequence_analyzer`
- `root_cause_analyzer`
- `strategy_config`


### `core\pcap_analysis\historical_data_integration.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_historical_data_integration()`

**Classes:**
- `HistoricalDataIntegration`

**Key Imports:**
- `learning_engine`
- `predictive_analyzer`
- `statistics`


### `core\pcap_analysis\intelligent_pcap_analyzer.py`

File operations module with 0 functions and 13 classes for file and directory management

**Classes:**
- `BlockingType`
- `DPIBehavior`
- `DPISignature`
- `DPISignatureExtractor`
- `FlowAnalysis`
- `FragmentationAnalyzer`
- `IntelligentPCAPAnalyzer`
- `PCAPAnalysisResult`
- `PacketAnalysis`
- `RSTInjectionDetector`
- `SNIFilteringDetector`
- `TLSHandshakeAnalyzer`
- `TimeoutDetector`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`


### `core\pcap_analysis\learning_engine.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `LearningEngine`
- `PatternDatabase`

**Key Imports:**
- `hashlib`
- `pickle`
- `statistics`


### `core\pcap_analysis\memory_optimizer.py`

File operations module with 0 functions and 6 classes for file and directory management

**Classes:**
- `LazyPacketLoader`
- `MemoryEfficientComparator`
- `MemoryMappedStorage`
- `MemoryOptimizer`
- `MemoryStats`
- `OptimizedPacketStorage`

**Key Imports:**
- `dataclasses`
- `gc`
- `mmap`
- `pickle`
- `psutil`


### `core\pcap_analysis\pcap_comparator.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `PCAPComparator`

**Key Imports:**
- `comparison_result`
- `packet_info`
- `struct`


### `core\pcap_analysis\progress_reporter.py`

File operations module with 3 functions and 6 classes for file and directory management

**Functions:**
- `create_analysis_progress()`
- `create_batch_progress()`
- `create_spinner()`

**Classes:**
- `AsyncProgressReporter`
- `DetailedProgressReporter`
- `ProgressBar`
- `ProgressCallback`
- `ProgressStep`
- `SpinnerProgress`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\pcap_analysis\recon_integration.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_recon_integration_manager()`

**Classes:**
- `ReconIntegrationManager`

**Key Imports:**
- `difference_detector`
- `packet_sequence_analyzer`
- `pattern_recognizer`
- `pcap_comparator`
- `strategy_analyzer`


### `core\pcap_analysis\root_cause_analyzer.py`

File operations module with 0 functions and 8 classes for file and directory management

**Classes:**
- `ConfidenceLevel`
- `CorrelatedCause`
- `Evidence`
- `Hypothesis`
- `RootCause`
- `RootCauseAnalyzer`
- `RootCauseType`
- `ValidatedHypothesis`

**Key Imports:**
- `critical_difference`
- `dataclasses`
- `enum`
- `pattern_recognizer`
- `statistics`


### `core\pcap_analysis\sequence_analysis_demo.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `create_broken_recon_sequence()`
- `create_fakeddisorder_sequence()`
- `demo_sequence_analysis()`

**Key Imports:**
- `packet_info`
- `packet_sequence_analyzer`


### `core\pcap_analysis\strategy_integration_example.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `example_usage()`

**Classes:**
- `IntegratedPCAPAnalyzer`

**Key Imports:**
- `pcap_comparator`
- `strategy_analyzer`


### `core\pcap_analysis\strategy_management_integration.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `create_strategy_management_integration()`

**Classes:**
- `StrategyManagementIntegration`

**Key Imports:**
- `fix_generator`
- `strategy_analyzer`
- `strategy_validator`


### `core\pcap_analysis\streaming_processor.py`

File operations module with 0 functions and 4 classes for file and directory management

**Classes:**
- `AsyncStreamingProcessor`
- `MemoryMonitor`
- `StreamingConfig`
- `StreamingPcapProcessor`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `gc`
- `packet_info`
- `psutil`


### `core\pcap_analysis\system_validation.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `DomainValidationResult`
- `SystemValidationReport`
- `SystemValidator`

**Key Imports:**
- `asyncio`
- `core.pcap_analysis.pcap_comparator`
- `core.pcap_analysis.strategy_config`
- `core.pcap_analysis.strategy_validator`
- `dataclasses`


### `core\pcap_analysis\visualization_helper.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `VisualizationData`
- `VisualizationHelper`

**Key Imports:**
- `critical_difference`
- `dataclasses`
- `fix_generator`
- `packet_info`
- `statistics`


### `core\pcap_analysis\workflow_cli.py`

File operations module with 7 functions and 0 classes for file and directory management

**Functions:**
- `create_config_from_args()`
- `create_parser()`
- `interactive_mode()`
- `load_config_from_file()`
- `print_config_summary()`
- `print_results_summary()`
- `validate_inputs()`

**Key Imports:**
- `argparse`
- `asyncio`
- `automated_workflow`
- `logging_config`


### `core\pcap_analysis\workflow_config_manager.py`

File operations module with 4 functions and 2 classes for file and directory management

**Functions:**
- `create_full_config()`
- `create_quick_config()`
- `create_safe_config()`
- `get_config_manager()`

**Classes:**
- `WorkflowConfigManager`
- `WorkflowPreset`

**Key Imports:**
- `automated_workflow`
- `dataclasses`


### `core\pcap_analysis\workflow_integration.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `WorkflowIntegration`

**Key Imports:**
- `asyncio`
- `automated_workflow`
- `logging_config`
- `workflow_config_manager`
- `workflow_scheduler`


### `core\pcap_analysis\workflow_scheduler.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `BatchJob`
- `ScheduledJob`
- `WorkflowScheduler`

**Key Imports:**
- `asyncio`
- `automated_workflow`
- `dataclasses`
- `logging_config`
- `workflow_config_manager`


### `core\performance_profiler.py`

File operations module with 1 functions and 3 classes for file and directory management

**Functions:**
- `profile_decorator()`

**Classes:**
- `PerformanceMetrics`
- `PerformanceProfiler`
- `ProfileReport`

**Key Imports:**
- `cProfile`
- `contextlib`
- `dataclasses`
- `pstats`


### `core\refactoring\file_scanner.py`

File operations module with 1 functions and 3 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `FileCategory`
- `FileScanner`
- `GarbageFile`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\refactoring\module_categorizer.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ModuleCategorizer`

**Key Imports:**
- `module_scanner`


### `core\refactoring\module_registry_builder.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ModuleRegistryBuilder`

**Key Imports:**
- `module_categorizer`
- `module_scanner`


### `core\refactoring\module_scanner.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `ModuleInfo`
- `ModuleScanner`

**Key Imports:**
- `ast`
- `dataclasses`
- `importlib.util`


### `core\refactoring\safe_remover.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `RemovalReport`
- `SafeRemover`

**Key Imports:**
- `dataclasses`
- `file_scanner`


### `core\refactoring\structure_analyzer.py`

File operations module with 0 functions and 5 classes for file and directory management

**Classes:**
- `ConfigFileDetector`
- `DirectoryInfo`
- `ProjectStructure`
- `ProjectStructureAnalyzer`
- `StructureDocumenter`

**Key Imports:**
- `ast`
- `dataclasses`


### `core\results_collector.py`

File operations module with 0 functions and 5 classes for file and directory management

**Classes:**
- `AggregatedStats`
- `CollectionStats`
- `DiscoveryReport`
- `ResultType`
- `ResultsCollector`

**Key Imports:**
- `core.domain_filter`
- `core.test_result_models`
- `dataclasses`
- `enum`


### `core\session\engine_session_manager.py`

File operations module with 2 functions and 1 classes for file and directory management

**Functions:**
- `create_session_manager()`
- `managed_engine_session()`

**Classes:**
- `EngineSessionManager`

**Key Imports:**
- `atexit`
- `concurrent.futures`
- `contextlib`
- `core.unified_engine_models`
- `threading`


### `core\session\session_metrics.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `OperationTracker`
- `SessionMetrics`

**Key Imports:**
- `dataclasses`


### `core\signature_manager.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `SignatureManager`

**Key Imports:**
- `requests`
- `threading`


### `core\storage.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `Storage`

**Key Imports:**
- `sqlite3`


### `core\strategy\exceptions.py`

File operations module with 0 functions and 3 classes for file and directory management

**Classes:**
- `ImplementationError`
- `ParameterPropagationError`
- `ValidationError`


### `core\strategy\strategy_rule_engine.py`

File operations module with 1 functions and 4 classes for file and directory management

**Functions:**
- `create_default_rule_engine()`

**Classes:**
- `Rule`
- `RuleCondition`
- `RuleEvaluationResult`
- `StrategyRuleEngine`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy\strategy_rule_engine_fixed.py`

File operations module with 1 functions and 4 classes for file and directory management

**Functions:**
- `create_default_rule_engine()`

**Classes:**
- `Rule`
- `RuleCondition`
- `RuleEvaluationResult`
- `StrategyRuleEngine`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy\validator.py`

File operations module with 1 functions and 4 classes for file and directory management

**Functions:**
- `create_strategy_validator()`

**Classes:**
- `CompatibilityResult`
- `StrategyValidator`
- `TestResult`
- `ValidationResult`

**Key Imports:**
- `dataclasses`


### `core\strategy_integration_helper.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `demo_integration()`

**Classes:**
- `StrategyIntegrationHelper`

**Key Imports:**
- `strategy_selector`


### `core\unified_bypass_engine.py`

File operations module with 4 functions and 6 classes for file and directory management

**Functions:**
- `create_service_mode_engine()`
- `create_testing_mode_engine()`
- `create_unified_engine()`
- `synthesize_strategy_fallback()`

**Classes:**
- `AccessibilityTestCacheEntry`
- `AccessibilityTestCacheKey`
- `CurlCommandValidator`
- `UnifiedBypassEngine`
- `UnifiedBypassEngineError`
- `UnifiedEngineConfig`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `dataclasses`
- `subprocess`
- `threading`


### `core\validation\decision_engine.py`

File operations module with 1 functions and 4 classes for file and directory management

**Functions:**
- `create_validation_decision_engine()`

**Classes:**
- `ValidationContext`
- `ValidationDecision`
- `ValidationDecisionEngine`
- `ValidationMethod`

**Key Imports:**
- `core.validation.edge_case_handler`
- `core.validation.http_response_classifier`
- `core.validation.tls_handshake_analyzer`
- `dataclasses`
- `enum`


### `core\validation\edge_case_handler.py`

File operations module with 1 functions and 6 classes for file and directory management

**Functions:**
- `create_edge_case_handler()`

**Classes:**
- `EdgeCaseContext`
- `EdgeCaseHandler`
- `EdgeCaseHandlingResult`
- `NetworkConditions`
- `NetworkEnvironment`
- `ValidationFallbackMethod`

**Key Imports:**
- `core.validation.http_response_classifier`
- `core.validation.tls_handshake_analyzer`
- `dataclasses`
- `enum`


### `core\validation\results_validation_system.py`

File operations module with 1 functions and 8 classes for file and directory management

**Functions:**
- `create_results_validation_system()`

**Classes:**
- `ABTestResult`
- `FingerprintValidationResult`
- `QualityMetrics`
- `ResultsValidationSystem`
- `StrategyValidationResult`
- `ValidationReport`
- `ValidationStatus`
- `ValidationTestType`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `statistics`


### `core\validation\strategy_saver.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `StrategySaver`

**Key Imports:**
- `core.test_result_models`
- `dataclasses`
- `threading`


### `core\validation\unified_validation_system.py`

File operations module with 2 functions and 2 classes for file and directory management

**Functions:**
- `create_performance_optimized_system()`
- `create_unified_validation_system()`

**Classes:**
- `UnifiedValidationResult`
- `UnifiedValidationSystem`

**Key Imports:**
- `core.bypass.validation.validator`
- `core.validation.decision_engine`
- `core.validation.http_response_classifier`
- `core.validation.tls_handshake_analyzer`
- `dataclasses`


### `create_clean_strategy.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `create_clean_strategy()`
- `main()`
- `update_domain_rules_clean()`


### `create_icon.py`

File operations module with 1 functions and 0 classes for file and directory management

**Functions:**
- `create_icon()`


### `create_real_tls_clienthello.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `create_real_tls_clienthello()`
- `main()`
- `test_real_clienthello()`

**Key Imports:**
- `core.bypass.engine.attack_dispatcher`
- `core.bypass.filtering.sni_extractor`
- `core.bypass.techniques.primitives`
- `struct`


### `create_shortcut.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `create_admin_shortcut()`
- `create_windows_shortcut()`
- `main()`


### `deployment\full_deployment.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `FullDeployment`
- `FullDeploymentConfig`

**Key Imports:**
- `dataclasses`


### `emergency_rollback.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `backup_current()`
- `main()`
- `rollback_to_simple_strategies()`


### `enhanced_domain_strategy_analyzer.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `EnhancedDomainStrategyAnalyzer`

**Key Imports:**
- `socket`
- `struct`


### `enhanced_find_rst_triggers_standalone.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `StandaloneEnhancedAnalyzer`

**Key Imports:**
- `argparse`
- `asyncio`


### `enhanced_strategy_generator.py`

File operations module with 6 functions and 0 classes for file and directory management

**Functions:**
- `analyze_failure_patterns()`
- `generate_anti_rst_strategies()`
- `generate_experimental_strategies()`
- `generate_timing_strategies()`
- `generate_tls_obfuscation_strategies()`
- `main()`


### `examples\demo_tls_evasion.py`

File operations module with 8 functions and 0 classes for file and directory management

**Functions:**
- `create_sample_client_hello()`
- `create_sample_extensions()`
- `demo_attack_properties()`
- `demo_extension_manipulation()`
- `demo_handshake_manipulation()`
- `demo_record_fragmentation()`
- `demo_version_downgrade()`
- `main()`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.bypass.attacks.tls.tls_evasion`
- `struct`


### `examples\segment_performance_optimization_example.py`

File operations module with 12 functions and 0 classes for file and directory management

**Functions:**
- `create_test_segments()`
- `demonstrate_basic_optimization()`
- `demonstrate_caching_benefits()`
- `demonstrate_configuration_options()`
- `demonstrate_global_optimizer()`
- `demonstrate_memory_pooling()`
- `demonstrate_optimization_suggestions()`
- `demonstrate_performance_benchmarking()`
- `demonstrate_real_world_scenario()`
- `main()`
- `simulate_packet_construction()`
- `simulate_packet_transmission()`

**Key Imports:**
- `core.bypass.performance.segment_performance_optimizer`


### `generate_service_analysis_report.py`

File operations module with 6 functions and 0 classes for file and directory management

**Functions:**
- `analyze_attack_types()`
- `generate_service_analysis_report()`
- `load_service_comparison_results()`
- `load_service_test_results()`
- `main()`
- `save_service_analysis_report()`


### `gui\main_window.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `MainWindow`
- `WorkerThread`

**Key Imports:**
- `PyQt6.QtCore`
- `PyQt6.QtGui`
- `PyQt6.QtWidgets`
- `asyncio`


### `gui\service_manager.py`

File operations module with 0 functions and 2 classes for file and directory management

**Classes:**
- `ServiceManager`
- `ServiceThread`

**Key Imports:**
- `PyQt6.QtCore`
- `subprocess`


### `improved_attack_validation.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `ImprovedAttackValidator`

**Key Imports:**
- `requests`
- `subprocess`
- `threading`


### `log_pcap_validator.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `LogPcapValidator`

**Key Imports:**
- `scapy.all`


### `migrate_domain_rules.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `DomainRulesMigrator`

**Key Imports:**
- `core.strategy.loader`


### `migrate_domain_rules_add_attacks.py`

File operations module with 4 functions and 0 classes for file and directory management

**Functions:**
- `create_metadata_for_existing_rule()`
- `extract_attacks_from_rule()`
- `main()`
- `migrate_domain_rules()`


### `monitoring\metrics_collector.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `MetricsCollector`


### `monitoring\post_deployment_log_monitor.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `PostDeploymentLogMonitor`


### `pcap_attack_analyzer.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `PCAPAttackAnalyzer`

**Key Imports:**
- `subprocess`


### `profile_baseline_manager.py`

File operations module with 5 functions and 0 classes for file and directory management

**Functions:**
- `create_test_baseline()`
- `main()`
- `profile_comparison_operation()`
- `profile_load_operation()`
- `profile_save_operation()`

**Key Imports:**
- `core.baseline_manager`
- `core.performance_profiler`


### `profile_cli_validation.py`

File operations module with 9 functions and 0 classes for file and directory management

**Functions:**
- `analyze_optimization_opportunities()`
- `create_test_comparison()`
- `create_test_pcap_validation()`
- `main()`
- `profile_cli_startup_impact()`
- `profile_orchestrator_initialization()`
- `profile_output_formatting()`
- `profile_report_saving()`
- `profile_validation_report_creation()`

**Key Imports:**
- `core.baseline_manager`
- `core.cli_validation_orchestrator`
- `core.pcap_content_validator`
- `core.performance_profiler`


### `project.py`

File operations module with 2 functions and 1 classes for file and directory management

**Functions:**
- `find_additional_modules()`
- `main()`

**Classes:**
- `DependencyAnalyzer`

**Key Imports:**
- `ast`


### `quick_pcap_analysis.py`

File operations module with 1 functions and 0 classes for file and directory management

**Functions:**
- `analyze_pcap_with_scapy()`


### `quick_pcap_check.py`

File operations module with 1 functions and 0 classes for file and directory management

**Functions:**
- `quick_check_pcaps()`

**Key Imports:**
- `glob`
- `subprocess`


### `real_attack_validation.py`

File operations module with 1 functions and 2 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `PCAPCapture`
- `RealAttackValidator`

**Key Imports:**
- `requests`
- `signal`
- `subprocess`
- `threading`
- `urllib.parse`


### `run_service_log_pcap_comparison.py`

File operations module with 5 functions and 0 classes for file and directory management

**Functions:**
- `find_service_test_files()`
- `main()`
- `print_service_comparison_summary()`
- `run_service_comparisons()`
- `save_service_comparison_results()`

**Key Imports:**
- `log_pcap_comparison_tool`


### `run_service_mode_tests.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `load_strategies()`
- `main()`
- `run_single_service_test()`

**Key Imports:**
- `signal`
- `subprocess`


### `service_strategy_tester.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `ServiceStrategyTester`

**Key Imports:**
- `signal`
- `subprocess`
- `threading`


### `setup_hosts_bypass.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `HostsFileManager`

**Key Imports:**
- `asyncio`
- `core.doh_resolver`
- `core.smart_bypass_engine`
- `platform`
- `subprocess`


### `signature_manager.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `SignatureManager`

**Key Imports:**
- `requests`
- `threading`


### `start_adaptive_monitoring.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `SimpleAdaptiveMonitor`

**Key Imports:**
- `asyncio`
- `urllib.parse`


### `storage.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `Storage`

**Key Imports:**
- `sqlite3`


### `tests\duplicate_analysis\conftest.py`

File operations module with 15 functions and 0 classes for file and directory management

**Functions:**
- `confidence_level_strategy()`
- `create_test_file()`
- `create_test_project()`
- `default_analysis_config()`
- `function_signature_strategy()`
- `module_status_strategy()`
- `python_identifier()`
- `sample_ast_tree()`
- `sample_class_node()`
- `sample_duplicate_code()`
- `sample_function_node()`
- `sample_module_analysis()`
- `sample_project_structure()`
- `sample_python_code()`
- `temp_project_dir()`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.config`
- `core.duplicate_analysis.interfaces`
- `hypothesis`
- `pytest`


### `tools\audit_disorder_attack.py`

File operations module with 1 functions and 3 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `DisorderAttackAuditor`
- `DisorderAuditResult`
- `DisorderCallSite`

**Key Imports:**
- `core.bypass.techniques.primitives`
- `dataclasses`


### `tools\audit_seqovl_attack.py`

File operations module with 1 functions and 3 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `SeqovlAttackAuditor`
- `SeqovlAuditResult`
- `SeqovlCallSite`

**Key Imports:**
- `core.bypass.techniques.primitives`
- `dataclasses`


### `tools\manage_feature_flags.py`

File operations module with 11 functions and 0 classes for file and directory management

**Functions:**
- `create_rollback_point()`
- `disable_feature()`
- `enable_feature()`
- `list_features()`
- `main()`
- `rollback_to_point()`
- `set_rollout_percentage()`
- `show_feature_status()`
- `show_monitoring_report()`
- `show_rollout_guide()`
- `start_monitoring()`

**Key Imports:**
- `argparse`
- `core.bypass.filtering.feature_flags`
- `core.bypass.filtering.rollout_monitor`


### `tools\migrate_to_domain_rules.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `DomainRuleMigrator`

**Key Imports:**
- `argparse`


### `tools\remove_frame_delta_duplicates.py`

File operations module with 3 functions and 0 classes for file and directory management

**Functions:**
- `get_packet_signature()`
- `main()`
- `remove_frame_delta_duplicates()`


### `trace_deps.py`

File operations module with 11 functions and 2 classes for file and directory management

**Functions:**
- `build_report()`
- `collect_deps_for_file()`
- `copy_internal_files()`
- `guess_module_name_from_path()`
- `human_readable_summary()`
- `is_relative_module()`
- `main()`
- `normpath()`
- `resolve_module_to_path()`
- `resolve_relative_module()`
- `zip_internal_files()`

**Classes:**
- `ImportCollector`
- `ImportRecord`

**Key Imports:**
- `argparse`
- `ast`
- `zipfile`


### `unify_attack_execution.py`

File operations module with 5 functions and 0 classes for file and directory management

**Functions:**
- `analyze_attack_execution_differences()`
- `create_unified_attack_executor()`
- `main()`
- `patch_cli_for_unified_execution()`
- `patch_service_for_unified_execution()`


### `unify_attack_execution_final.py`

File operations module with 4 functions and 0 classes for file and directory management

**Functions:**
- `create_summary()`
- `fix_simple_service()`
- `main()`
- `verify_fix()`


### `web\dashboard.py`

File operations module with 0 functions and 1 classes for file and directory management

**Classes:**
- `ReconDashboard`

**Key Imports:**
- `flask`
- `threading`


### `web\demo_web_integration.py`

File operations module with 1 functions and 0 classes for file and directory management

**Functions:**
- `main()`

**Key Imports:**
- `asyncio`


### `working_adaptive_monitor.py`

File operations module with 1 functions and 1 classes for file and directory management

**Functions:**
- `main()`

**Classes:**
- `WorkingAdaptiveMonitor`

**Key Imports:**
- `asyncio`
- `urllib.parse`



## Logging

Modules for logging, monitoring, metrics collection, and telemetry.

### `core\bypass\analytics\performance_tracker.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `PerformanceTracker`

**Key Imports:**
- `asyncio`
- `core.bypass.analytics.analytics_models`
- `core.bypass.analytics.metrics_collector`
- `numpy`


### `core\bypass\attacks\telemetry\error_logger.py`

Logging module with 0 functions and 4 classes for logging and monitoring

**Classes:**
- `AttackErrorLogger`
- `ErrorCategory`
- `ErrorLogEntry`
- `ErrorSeverity`

**Key Imports:**
- `dataclasses`
- `enum`
- `traceback`


### `core\bypass\attacks\telemetry\execution_logger.py`

Logging module with 0 functions and 4 classes for logging and monitoring

**Classes:**
- `AttackExecutionLogger`
- `ExecutionLogEntry`
- `ExecutionStatus`
- `LogLevel`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\attacks\telemetry\performance_monitor.py`

Logging module with 0 functions and 5 classes for logging and monitoring

**Classes:**
- `DegradationSeverity`
- `DegradationType`
- `PerformanceBaseline`
- `PerformanceDegradation`
- `PerformanceMonitor`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\compatibility\syntax_converter.py`

Logging module with 3 functions and 2 classes for logging and monitoring

**Functions:**
- `convert_goodbyedpi_to_zapret()`
- `convert_to_native()`
- `convert_zapret_to_goodbyedpi()`

**Classes:**
- `ConversionResult`
- `SyntaxConverter`

**Key Imports:**
- `core.bypass.compatibility.byebyedpi_parser`
- `core.bypass.compatibility.goodbyedpi_parser`
- `core.bypass.compatibility.tool_detector`
- `core.bypass.compatibility.zapret_parser`
- `dataclasses`


### `core\bypass\diagnostics\segment_diagnostics.py`

Logging module with 2 functions and 7 classes for logging and monitoring

**Functions:**
- `configure_segment_diagnostics()`
- `get_segment_diagnostic_logger()`

**Classes:**
- `SegmentDiagnosticData`
- `SegmentDiagnosticLogger`
- `SegmentExecutionEvent`
- `SegmentExecutionEvent`
- `SegmentExecutionPhase`
- `SegmentExecutionSummary`
- `SegmentExecutionSummary`

**Key Imports:**
- `core.bypass.attacks.segment_packet_builder`
- `core.bypass.attacks.timing_controller`
- `dataclasses`
- `enum`
- `threading`


### `core\bypass\engine\hierarchical_domain_matcher.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `HierarchicalDomainMatcher`


### `core\bypass\engine\sni_domain_extractor.py`

Logging module with 0 functions and 2 classes for logging and monitoring

**Classes:**
- `DomainExtractionResult`
- `SNIDomainExtractor`

**Key Imports:**
- `__future__`
- `dataclasses`
- `ipaddress`


### `core\bypass\engine\strategy_application_logger.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `StrategyApplicationLogger`

**Key Imports:**
- `strategy_validator`


### `core\bypass\engines\packet_executor.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `IntelligentPacketExecutor`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.packet_builder`
- `core.windivert_filter`
- `pydivert`


### `core\bypass\engines\scapy_engine.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ScapyEngine`

**Key Imports:**
- `core.bypass.engines.base`
- `core.bypass.exceptions`
- `core.bypass.types`
- `threading`


### `core\bypass\filtering\custom_sni.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `CustomSNIHandler`

**Key Imports:**
- `string`


### `core\bypass\filtering\performance_monitor.py`

Logging module with 2 functions and 3 classes for logging and monitoring

**Functions:**
- `configure_global_monitor()`
- `get_global_monitor()`

**Classes:**
- `PerformanceMetrics`
- `PerformanceMonitor`
- `PerformanceTimer`

**Key Imports:**
- `dataclasses`
- `psutil`
- `threading`


### `core\bypass\modes\capability_detector.py`

Logging module with 0 functions and 3 classes for logging and monitoring

**Classes:**
- `CapabilityDetector`
- `CapabilityInfo`
- `CapabilityLevel`

**Key Imports:**
- `dataclasses`
- `enum`
- `platform`


### `core\bypass\modes\mode_controller.py`

Logging module with 0 functions and 3 classes for logging and monitoring

**Classes:**
- `ModeController`
- `ModeInfo`
- `OperationMode`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\modes\mode_transition.py`

Logging module with 0 functions and 3 classes for logging and monitoring

**Classes:**
- `ModeTransitionManager`
- `TransitionContext`
- `TransitionState`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\packet\builder.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `PacketBuilder`

**Key Imports:**
- `struct`


### `core\bypass\performance\production_monitor.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ProductionMonitor`

**Key Imports:**
- `asyncio`
- `core.bypass.performance.performance_models`


### `core\bypass\safety\resource_manager.py`

Logging module with 0 functions and 4 classes for logging and monitoring

**Classes:**
- `ResourceLimits`
- `ResourceManager`
- `ResourceMonitor`
- `ResourceUsage`

**Key Imports:**
- `core.bypass.safety.exceptions`
- `dataclasses`
- `psutil`
- `threading`


### `core\bypass\strategies\sni_detector.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `SNIDetector`

**Key Imports:**
- `struct`


### `core\di\factory.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ServiceFactory`

**Key Imports:**
- `core.di.config`
- `core.di.container`
- `core.di.typed_config`
- `core.interfaces`
- `core.robust_packet_processor`


### `core\diagnostics\performance_monitor.py`

Logging module with 2 functions and 4 classes for logging and monitoring

**Functions:**
- `get_performance_monitor()`
- `initialize_performance_monitoring()`

**Classes:**
- `OperationMetrics`
- `PerformanceAlert`
- `PerformanceMonitor`
- `SystemMetrics`

**Key Imports:**
- `asyncio`
- `contextlib`
- `dataclasses`
- `psutil`
- `threading`


### `core\diagnostics\strategy_reasoning_logger.py`

Logging module with 2 functions and 3 classes for logging and monitoring

**Functions:**
- `enable_reasoning_logging()`
- `get_reasoning_logger()`

**Classes:**
- `ReasoningEntry`
- `ReasoningStep`
- `StrategyReasoningLogger`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\discovery_combination_integration.py`

Logging module with 1 functions and 2 classes for logging and monitoring

**Functions:**
- `integrate_with_discovery_controller()`

**Classes:**
- `CombinationContext`
- `DiscoveryCombinationIntegration`

**Key Imports:**
- `dataclasses`


### `core\duplicate_analysis\ast_fingerprinter.py`

Logging module with 0 functions and 5 classes for logging and monitoring

**Classes:**
- `ASTFingerprint`
- `ASTFingerprinter`
- `DomainAwareNormalizer`
- `SemanticFeatures`
- `SimilarityScore`

**Key Imports:**
- `ast`
- `dataclasses`
- `hashlib`
- `integration`
- `interfaces`


### `core\duplicate_analysis\duplicate_detector.py`

Logging module with 0 functions and 5 classes for logging and monitoring

**Classes:**
- `DuplicateClassifier`
- `DuplicateCluster`
- `DuplicateDetector`
- `FunctionGrouper`
- `SimilarityMatrix`

**Key Imports:**
- `dataclasses`
- `interfaces`
- `similarity_engine`


### `core\duplicate_analysis\enhanced_categorizer.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `EnhancedModuleCategorizer`

**Key Imports:**
- `integration`
- `interfaces`
- `refactoring.module_categorizer`
- `refactoring.module_scanner`


### `core\duplicate_analysis\similarity_engine.py`

Logging module with 0 functions and 6 classes for logging and monitoring

**Classes:**
- `ASTEditDistance`
- `ASTEditDistanceCalculator`
- `ASTStructuralComparator`
- `SemanticComparator`
- `SimilarityEngine`
- `SimilarityScore`

**Key Imports:**
- `ast`
- `ast_parser`
- `dataclasses`
- `difflib`
- `interfaces`


### `core\failure_analyzer.py`

Logging module with 0 functions and 3 classes for logging and monitoring

**Classes:**
- `FailureAnalysisResult`
- `FailureAnalyzer`
- `FailurePattern`

**Key Imports:**
- `dataclasses`


### `core\fingerprint\dpi_behavior_monitor.py`

Logging module with 0 functions and 8 classes for logging and monitoring

**Classes:**
- `AlertSeverity`
- `BehaviorAnalyzer`
- `BehaviorChange`
- `DPIBehaviorMonitor`
- `MonitoringAlert`
- `MonitoringConfig`
- `MonitoringState`
- `PerformanceMonitor`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `dataclasses`
- `enum`
- `hashlib`


### `core\fingerprint\dpi_monitor_demo.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `DPIMonitoringDemo`

**Key Imports:**
- `asyncio`
- `core.fingerprint.advanced_fingerprinter`
- `core.fingerprint.dpi_behavior_monitor`


### `core\fingerprint\enhanced_dpi_detector.py`

Logging module with 0 functions and 4 classes for logging and monitoring

**Classes:**
- `DPIDetectionRule`
- `EnhancedDPIDetector`
- `EnhancedDPISignature`
- `ModernDPIType`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\fingerprint\metrics_collector.py`

Logging module with 0 functions and 9 classes for logging and monitoring

**Classes:**
- `BaseMetricsCollector`
- `ComprehensiveMetrics`
- `MetricsCollector`
- `NetworkMetrics`
- `NetworkMetricsCollector`
- `ProtocolMetrics`
- `ProtocolMetricsCollector`
- `TimingMetrics`
- `TimingMetricsCollector`

**Key Imports:**
- `abc`
- `asyncio`
- `core.fingerprint.advanced_models`
- `dataclasses`
- `statistics`


### `core\fingerprint\metrics_collector_new.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `TimingMetricsCollector`

**Key Imports:**
- `asyncio`
- `statistics`


### `core\integration\advanced_performance_monitor.py`

Logging module with 1 functions and 4 classes for logging and monitoring

**Functions:**
- `get_performance_monitor()`

**Classes:**
- `AdvancedPerformanceMonitor`
- `AttackPerformanceMetrics`
- `PerformanceAlert`
- `SystemPerformanceMetrics`

**Key Imports:**
- `dataclasses`
- `statistics`


### `core\integration\result_processor.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ResultProcessor`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.integration.integration_config`
- `statistics`


### `core\knowledge\pattern_matcher.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `PatternMatcher`

**Key Imports:**
- `knowledge_accumulator`


### `core\logging\conversion_logging_manager.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ConversionLoggingManager`

**Key Imports:**
- `__future__`
- `core.logging.conversion_state`
- `core.logging.logging_config`
- `threading`


### `core\monitoring\advanced_monitoring_system.py`

Logging module with 0 functions and 8 classes for logging and monitoring

**Classes:**
- `AdvancedMonitoringSystem`
- `Alert`
- `AlertLevel`
- `AlertManager`
- `MetricCollector`
- `MetricThreshold`
- `MetricType`
- `MonitoringConfig`

**Key Imports:**
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`
- `statistics`
- `threading`


### `core\monitoring\dpi_detector.py`

Logging module with 0 functions and 2 classes for logging and monitoring

**Classes:**
- `DPIBlockingDetector`
- `DPIBlockingPattern`

**Key Imports:**
- `dataclasses`
- `packet.pcap_analyzer`


### `core\monitoring\performance_monitor.py`

Logging module with 2 functions and 4 classes for logging and monitoring

**Functions:**
- `get_global_monitor()`
- `monitor_operation()`

**Classes:**
- `ComponentMetrics`
- `OperationTimer`
- `PerformanceMetrics`
- `PerformanceMonitor`

**Key Imports:**
- `dataclasses`
- `psutil`
- `threading`


### `core\operation_logger.py`

Logging module with 2 functions and 3 classes for logging and monitoring

**Functions:**
- `get_operation_logger()`
- `log_operation()`

**Classes:**
- `Operation`
- `OperationLogger`
- `StrategyLog`

**Key Imports:**
- `dataclasses`
- `threading`
- `uuid`


### `core\orchestration\component_registry.py`

Logging module with 0 functions and 2 classes for logging and monitoring

**Classes:**
- `ComponentInfo`
- `ComponentRegistry`

**Key Imports:**
- `core.net.connection_tester`
- `core.strategy.circuit_breaker`
- `core.strategy.processor`
- `core.validation.result_validator`
- `dataclasses`


### `core\pcap_analysis\analysis_cache_fixed.py`

Logging module with 0 functions and 4 classes for logging and monitoring

**Classes:**
- `CacheStats`
- `CachedAnalyzer`
- `HybridCache`
- `MemoryCache`

**Key Imports:**
- `dataclasses`
- `pickle`
- `threading`


### `core\pcap_analysis\diagnostics.py`

Logging module with 5 functions and 6 classes for logging and monitoring

**Functions:**
- `debug_operation()`
- `get_debug_logger()`
- `get_diagnostic_checker()`
- `get_performance_monitor()`
- `run_system_diagnostics()`

**Classes:**
- `DebugLogger`
- `DiagnosticChecker`
- `DiagnosticResult`
- `PerformanceMonitor`
- `PerformanceProfile`
- `SystemMetrics`

**Key Imports:**
- `contextlib`
- `dataclasses`
- `psutil`
- `threading`
- `traceback`


### `core\pcap_analysis\logging_config.py`

Logging module with 8 functions and 4 classes for logging and monitoring

**Functions:**
- `configure_external_loggers()`
- `get_contextual_logger()`
- `get_logger()`
- `log_error_with_context()`
- `log_operation_end()`
- `log_operation_start()`
- `log_performance_metric()`
- `setup_logging()`

**Classes:**
- `ColoredFormatter`
- `ContextualLogger`
- `JSONFormatter`
- `PCAPAnalysisLogger`

**Key Imports:**
- `logging.handlers`
- `traceback`


### `core\pcap_analysis\predictive_analyzer.py`

Logging module with 0 functions and 4 classes for logging and monitoring

**Classes:**
- `EffectivenessModel`
- `OptimizationModel`
- `PredictiveAnalyzer`
- `RiskAssessmentModel`

**Key Imports:**
- `learning_engine`
- `statistics`


### `core\planner.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `AdaptivePlanner`

**Key Imports:**
- `recon`
- `recon.core.bypass.attacks.attack_registry`
- `recon.core.integration.attack_adapter`
- `recon.core.storage`
- `recon.ml.strategy_predictor`


### `core\protocols\http.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `HTTPHandler`


### `core\quic_handler.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `QuicHandler`


### `core\robust_packet_processor.py`

Logging module with 0 functions and 2 classes for logging and monitoring

**Classes:**
- `PacketValidationError`
- `RobustPacketProcessor`

**Key Imports:**
- `struct`


### `core\session\resource_handle.py`

Logging module with 0 functions and 2 classes for logging and monitoring

**Classes:**
- `ResourceHandle`
- `ResourceManager`

**Key Imports:**
- `dataclasses`


### `core\session\thread_manager.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ThreadManager`

**Key Imports:**
- `concurrent.futures`
- `threading`


### `core\strategy\intelligent_combination_generator.py`

Logging module with 0 functions and 3 classes for logging and monitoring

**Classes:**
- `CombinationDecision`
- `CombinationTrigger`
- `IntelligentCombinationGenerator`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy\normalizer.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ParameterNormalizer`

**Key Imports:**
- `exceptions`


### `core\telemetry\collector.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `TelemetryCollector`

**Key Imports:**
- `core.unified_engine_models`
- `dataclasses`
- `interfaces`


### `core\telemetry\interfaces.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `ITelemetryCollector`

**Key Imports:**
- `abc`


### `core\validation\tls_handshake_analyzer.py`

Logging module with 0 functions and 4 classes for logging and monitoring

**Classes:**
- `EnhancedTlsHandshakeAnalyzer`
- `HandshakeCompleteness`
- `TlsAnalysisResult`
- `TlsHandshakeContext`

**Key Imports:**
- `dataclasses`
- `enum`


### `examples\segment_execution_stats_example.py`

Logging module with 6 functions and 0 classes for logging and monitoring

**Functions:**
- `demonstrate_basic_statistics()`
- `demonstrate_engine_integration()`
- `demonstrate_monitoring_dashboard()`
- `demonstrate_performance_analysis()`
- `demonstrate_performance_monitoring()`
- `demonstrate_recent_sessions_analysis()`

**Key Imports:**
- `asyncio`
- `core.bypass.monitoring.segment_execution_stats`


### `failure_analyzer.py`

Logging module with 0 functions and 3 classes for logging and monitoring

**Classes:**
- `FailureAnalysisResult`
- `FailureAnalyzer`
- `FailurePattern`

**Key Imports:**
- `dataclasses`


### `ml\dpi_classifier.py`

Logging module with 0 functions and 2 classes for logging and monitoring

**Classes:**
- `DPIClassificationResult`
- `DPIClassifier`

**Key Imports:**
- `core.fingerprint.models`
- `dataclasses`
- `numpy`


### `ml\evolutionary_search.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `EvolutionarySearcher`

**Key Imports:**
- `asyncio`
- `copy`
- `core.bypass.attacks.base`
- `core.interfaces`
- `metrics`


### `monitor_attack_performance.py`

Logging module with 1 functions and 3 classes for logging and monitoring

**Functions:**
- `main()`

**Classes:**
- `AttackPerformanceMonitor`
- `OptimizationOpportunity`
- `PerformanceReport`

**Key Imports:**
- `core.bypass.attacks.telemetry.metrics_endpoint`
- `core.bypass.attacks.telemetry.performance_monitor`
- `core.bypass.attacks.telemetry.telemetry_system`
- `dataclasses`


### `monitoring\advanced_monitoring_system.py`

Logging module with 0 functions and 8 classes for logging and monitoring

**Classes:**
- `AdvancedMonitoringSystem`
- `Alert`
- `AlertLevel`
- `AlertManager`
- `MetricCollector`
- `MetricThreshold`
- `MetricType`
- `MonitoringConfig`

**Key Imports:**
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`
- `statistics`
- `threading`


### `performance_monitor_script.py`

Logging module with 1 functions and 0 classes for logging and monitoring

**Functions:**
- `monitor_performance()`


### `planner.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `AdaptivePlanner`

**Key Imports:**
- `core.integration.attack_adapter`
- `ml.strategy_predictor`
- `recon.storage`


### `robust_packet_processor.py`

Logging module with 0 functions and 2 classes for logging and monitoring

**Classes:**
- `PacketValidationError`
- `RobustPacketProcessor`

**Key Imports:**
- `struct`


### `tunnels\doh_tunnel.py`

Logging module with 0 functions and 1 classes for logging and monitoring

**Classes:**
- `DoHTunnel`

**Key Imports:**
- `base64`



## Network

Modules handling network operations, HTTP requests, packet analysis, and communication.

### `analyze_last_flow.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `analyze_last_flow()`

**Key Imports:**
- `scapy.all`


### `analyze_pcap_simple.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `analyze_pcap()`

**Key Imports:**
- `scapy.all`


### `capture.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `session()`

**Classes:**
- `PacketQueueProcessor`
- `PyDivertCaptureWorker`

**Key Imports:**
- `contextlib`
- `platform`
- `queue`
- `scapy.all`
- `threading`


### `check_pcap_domains.py`

Network module with 3 functions and 0 classes for network operations and communication

**Functions:**
- `analyze_destinations()`
- `get_domain_from_ip()`
- `main()`

**Key Imports:**
- `scapy.all`
- `socket`


### `core\async_compat\event_loop_handler.py`

Network module with 6 functions and 1 classes for network operations and communication

**Functions:**
- `cleanup_event_loop_handler()`
- `ensure_event_loop()`
- `get_event_loop_handler()`
- `get_or_create_event_loop()`
- `handle_event_loop_policy()`
- `run_async_from_sync()`

**Classes:**
- `EventLoopHandler`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `concurrent.futures`
- `threading`


### `core\async_compat\subprocess_async.py`

Network module with 3 functions and 2 classes for network operations and communication

**Functions:**
- `cleanup_subprocess_manager()`
- `get_subprocess_manager()`
- `run_subprocess_sync()`

**Classes:**
- `AsyncSubprocessManager`
- `SubprocessConfig`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `concurrent.futures`
- `dataclasses`
- `subprocess`


### `core\async_utils\background_task_manager.py`

Network module with 2 functions and 5 classes for network operations and communication

**Functions:**
- `get_background_task_manager()`
- `shutdown_background_tasks()`

**Classes:**
- `AsyncOperationWrapper`
- `BackgroundTaskConfig`
- `BackgroundTaskManager`
- `TaskState`
- `TaskStatus`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `threading`


### `core\attack_parameter_mapper.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `get_parameter_mapper()`

**Classes:**
- `ParameterMapper`
- `ParameterMapping`
- `ParameterMappingError`

**Key Imports:**
- `dataclasses`
- `inspect`


### `core\blocked_domain_detector.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `BlockedDomainDetector`
- `DomainStatus`

**Key Imports:**
- `asyncio`
- `core.doh_resolver`
- `dataclasses`
- `socket`


### `core\bypass\analytics\analytics_engine.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `AnalyticsEngine`

**Key Imports:**
- `asyncio`
- `core.bypass.analytics.metrics_collector`
- `core.bypass.analytics.ml_predictor`
- `core.bypass.analytics.performance_tracker`
- `core.bypass.analytics.reporting_dashboard`


### `core\bypass\attacks\combo\advanced_traffic_profiler.py`

Network module with 0 functions and 6 classes for network operations and communication

**Classes:**
- `AdvancedTrafficProfiler`
- `ApplicationCategory`
- `ProfilingResult`
- `StatisticalTrafficAnalyzer`
- `TrafficAnalyzer`
- `TrafficSignature`

**Key Imports:**
- `abc`
- `core.bypass.attacks.combo.traffic_mimicry`
- `dataclasses`
- `enum`
- `hashlib`


### `core\bypass\attacks\combo\native_combo_engine.py`

Network module with 1 functions and 5 classes for network operations and communication

**Functions:**
- `get_global_combo_engine()`

**Classes:**
- `ComboMode`
- `ComboResult`
- `ComboRule`
- `ComboTiming`
- `NativeComboEngine`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `importlib`
- `inspect`


### `core\bypass\attacks\combo\traffic_profiles.py`

Network module with 0 functions and 4 classes for network operations and communication

**Classes:**
- `GenericBrowsingProfile`
- `TelegramTrafficProfile`
- `WhatsAppTrafficProfile`
- `ZoomTrafficProfile`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.attacks.combo.traffic_mimicry`


### `core\bypass\attacks\combo\zapret_integration.py`

Network module with 3 functions and 1 classes for network operations and communication

**Functions:**
- `get_zapret_integration()`
- `get_zapret_preset_info()`
- `get_zapret_presets()`

**Classes:**
- `ZapretIntegration`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\bypass\attacks\ip\mtu_discovery.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `get_mtu_discovery()`

**Classes:**
- `MTUCacheEntry`
- `MTUDiscovery`

**Key Imports:**
- `dataclasses`


### `core\bypass\attacks\modern_registry.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `get_modern_registry()`

**Key Imports:**
- `attack_registry`


### `core\bypass\attacks\performance\buffer_pool.py`

Network module with 2 functions and 1 classes for network operations and communication

**Functions:**
- `configure_buffer_pool()`
- `get_buffer_pool()`

**Classes:**
- `BufferPool`

**Key Imports:**
- `threading`


### `core\bypass\attacks\performance\hardware_acceleration.py`

Network module with 2 functions and 2 classes for network operations and communication

**Functions:**
- `configure_hardware_acceleration()`
- `get_hardware_accelerator()`

**Classes:**
- `HardwareAccelerator`
- `HardwareCapabilities`

**Key Imports:**
- `dataclasses`
- `hashlib`
- `platform`


### `core\bypass\attacks\real_effectiveness_tester.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `AiohttpStaticResolver`
- `RealEffectivenessTester`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `socket`
- `ssl`
- `ssl`


### `core\bypass\attacks\telemetry\metrics_endpoint.py`

Network module with 3 functions and 2 classes for network operations and communication

**Functions:**
- `get_metrics_endpoint()`
- `start_metrics_endpoint()`
- `stop_metrics_endpoint()`

**Classes:**
- `MetricsEndpointHandler`
- `MetricsEndpointServer`

**Key Imports:**
- `http.server`
- `metrics_exporter`
- `telemetry_system`
- `threading`
- `urllib.parse`


### `core\bypass\attacks\timing_controller.py`

Network module with 4 functions and 4 classes for network operations and communication

**Functions:**
- `get_timing_controller()`
- `get_timing_statistics()`
- `precise_delay()`
- `reset_timing_statistics()`

**Classes:**
- `PreciseTimingController`
- `TimingMeasurement`
- `TimingStatistics`
- `TimingStrategy`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `statistics`


### `core\bypass\compatibility\compatibility_bridge.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `get_compatibility_bridge()`

**Classes:**
- `CompatibilityBridge`
- `CompatibilityReport`

**Key Imports:**
- `core.bypass.compatibility.byebyedpi_parser`
- `core.bypass.compatibility.goodbyedpi_parser`
- `core.bypass.compatibility.tool_detector`
- `core.bypass.compatibility.zapret_parser`
- `dataclasses`


### `core\bypass\compatibility\tool_detector.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `get_tool_detector()`

**Classes:**
- `DetectionResult`
- `ExternalTool`
- `ToolDetector`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\engines\builder.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `PacketBuilder`

**Key Imports:**
- `core.bypass.exceptions`
- `socket`
- `struct`


### `core\bypass\engines\engine_type_detector.py`

Network module with 4 functions and 3 classes for network operations and communication

**Functions:**
- `check_engine_dependencies()`
- `detect_available_engines()`
- `get_engine_type_detector()`
- `get_recommended_engine()`

**Classes:**
- `EngineDetectionResult`
- `EngineTypeDetector`
- `SystemCapabilities`

**Key Imports:**
- `core.bypass.engines.base`
- `dataclasses`
- `platform`
- `subprocess`


### `core\bypass\engines\enhanced_factory.py`

Network module with 2 functions and 6 classes for network operations and communication

**Functions:**
- `create_engine_enhanced()`
- `get_enhanced_factory()`

**Classes:**
- `DependencyError`
- `EngineCreationError`
- `EnhancedEngineFactory`
- `InvalidEngineTypeError`
- `MissingParameterError`
- `PermissionError`

**Key Imports:**
- `core.bypass.engines.base`
- `core.bypass.engines.engine_config_manager`
- `core.bypass.engines.engine_type_detector`
- `core.bypass.engines.engine_validator`
- `core.bypass.engines.factory`


### `core\bypass\engines\packet_processing_engine.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `create_packet_processing_engine()`

**Classes:**
- `PacketProcessingEngine`
- `PacketProcessingResult`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`
- `struct`
- `threading`


### `core\bypass\filtering\resource_manager.py`

Network module with 2 functions and 3 classes for network operations and communication

**Functions:**
- `configure_global_resource_manager()`
- `get_global_resource_manager()`

**Classes:**
- `ResourceLimits`
- `ResourceManager`
- `ResourceState`

**Key Imports:**
- `dataclasses`
- `enum`
- `psutil`
- `threading`


### `core\bypass\filtering\rollout_monitor.py`

Network module with 3 functions and 6 classes for network operations and communication

**Functions:**
- `email_alert_handler()`
- `get_rollout_monitor()`
- `log_alert_handler()`

**Classes:**
- `Alert`
- `AlertLevel`
- `MetricThreshold`
- `MetricType`
- `RolloutHealth`
- `RolloutMonitor`

**Key Imports:**
- `dataclasses`
- `enum`
- `feature_flags`
- `threading`


### `core\bypass\fooling_selector.py`

Network module with 0 functions and 3 classes for network operations and communication

**Classes:**
- `FoolingCompatibility`
- `FoolingSelector`
- `PathProfile`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `pickle`
- `urllib.parse`


### `core\bypass\monitoring\segment_execution_stats.py`

Network module with 2 functions and 6 classes for network operations and communication

**Functions:**
- `get_segment_stats_collector()`
- `reset_global_stats()`

**Classes:**
- `ExecutionPhase`
- `ExecutionStatus`
- `GlobalExecutionStats`
- `SegmentExecutionMetrics`
- `SegmentExecutionStatsCollector`
- `SessionExecutionStats`

**Key Imports:**
- `dataclasses`
- `enum`
- `statistics`
- `threading`


### `core\bypass\packet\config.py`

Network module with 3 functions and 2 classes for network operations and communication

**Functions:**
- `get_badseq_offset()`
- `get_packet_config()`
- `get_packet_config_manager()`

**Classes:**
- `PacketConfig`
- `PacketConfigManager`

**Key Imports:**
- `dataclasses`


### `core\bypass\packet\sender.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `PacketSender`

**Key Imports:**
- `contextlib`
- `pydivert`
- `socket`
- `struct`
- `threading`


### `core\bypass\sharing\update_manager.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `UpdateManager`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `core.bypass.sharing.community_database`
- `core.bypass.sharing.sharing_models`
- `core.bypass.sharing.strategy_validator`


### `core\bypass\strategies\checksum_fooler.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `ChecksumFooler`
- `ChecksumResult`

**Key Imports:**
- `config_models`
- `dataclasses`
- `exceptions`
- `socket`
- `struct`


### `core\bypass\validation\reliability_validator.py`

Network module with 1 functions and 7 classes for network operations and communication

**Functions:**
- `get_global_reliability_validator()`

**Classes:**
- `AccessibilityResult`
- `AccessibilityStatus`
- `ReliabilityLevel`
- `ReliabilityValidator`
- `StrategyEffectivenessResult`
- `ValidationMethod`
- `ValidationResult`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `hashlib`
- `statistics`


### `core\caching\smart_cache.py`

Network module with 2 functions and 5 classes for network operations and communication

**Functions:**
- `get_fingerprint_cache()`
- `get_strategy_cache()`

**Classes:**
- `CacheEntry`
- `CacheStats`
- `FingerprintCache`
- `SmartCache`
- `StrategyCache`

**Key Imports:**
- `dataclasses`
- `pickle`
- `sqlite3`
- `threading`


### `core\calibration\tls_analyzer.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `TlsAnalyzer`
- `TlsStructure`

**Key Imports:**
- `dataclasses`
- `struct`


### `core\capture.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `session()`

**Classes:**
- `PacketQueueProcessor`
- `PyDivertCaptureWorker`

**Key Imports:**
- `contextlib`
- `platform`
- `queue`
- `scapy.all`
- `threading`


### `core\cli_payload\error_handler.py`

Network module with 2 functions and 4 classes for network operations and communication

**Functions:**
- `get_error_handler()`
- `handle_cli_error()`

**Classes:**
- `CLIErrorHandler`
- `ErrorCategory`
- `ErrorContext`
- `ErrorSeverity`

**Key Imports:**
- `dataclasses`
- `enum`
- `traceback`


### `core\cli_payload\payload_commands.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `format_payload_list()`

**Key Imports:**
- `asyncio`
- `core.payload.capturer`
- `core.payload.manager`
- `core.payload.serializer`
- `core.payload.types`


### `core\compat.py`

Network module with 2 functions and 0 classes for network operations and communication

**Functions:**
- `get_type_hints()`
- `safe_annotations()`


### `core\connection_metrics.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `BlockType`
- `ConnectionMetrics`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\di\config.py`

Network module with 4 functions and 4 classes for network operations and communication

**Functions:**
- `get_development_config()`
- `get_minimal_config()`
- `get_production_config()`
- `get_testing_config()`

**Classes:**
- `DIConfiguration`
- `DIConfigurationBuilder`
- `DIMode`
- `ServiceConfig`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\di\container.py`

Network module with 0 functions and 4 classes for network operations and communication

**Classes:**
- `DIContainer`
- `DIError`
- `ServiceDescriptor`
- `ServiceLifetime`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `inspect`


### `core\diagnostics\logger.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `get_logger()`


### `core\diagnostics\metrics_integration.py`

Network module with 1 functions and 4 classes for network operations and communication

**Functions:**
- `get_diagnostics_metrics_collector()`

**Classes:**
- `DiagnosticsMetricsCollector`
- `DoHMetrics`
- `PCAPMetrics`
- `StrategyMetrics`

**Key Imports:**
- `dataclasses`


### `core\discovery_controller.py`

Network module with 2 functions and 3 classes for network operations and communication

**Functions:**
- `create_discovery_config()`
- `get_controller()`

**Classes:**
- `DiscoveryController`
- `DiscoverySession`
- `DiscoveryStatus`

**Key Imports:**
- `contextlib`
- `core.domain_filter`
- `dataclasses`
- `enum`
- `uuid`


### `core\discovery_logging.py`

Network module with 2 functions and 6 classes for network operations and communication

**Functions:**
- `get_discovery_logger()`
- `get_metrics_collector()`

**Classes:**
- `DiscoveryEventType`
- `DiscoveryLogEntry`
- `DiscoveryLogger`
- `DiscoveryMetrics`
- `DiscoveryMetricsCollector`
- `LogLevel`

**Key Imports:**
- `dataclasses`
- `enum`
- `queue`
- `threading`


### `core\dns\pinned_resolver.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `StaticResolver`

**Key Imports:**
- `aiohttp.abc`
- `asyncio`
- `socket`


### `core\dns\robust_dns_handler.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `DNSResolutionResult`
- `RobustDNSHandler`

**Key Imports:**
- `concurrent.futures`
- `core.doh_resolver`
- `dataclasses`
- `socket`
- `threading`


### `core\doh_resolver.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `DoHResolver`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `ipaddress`
- `socket`


### `core\feature_flags.py`

Network module with 2 functions and 0 classes for network operations and communication

**Functions:**
- `get_feature_config()`
- `is_feature_enabled()`


### `core\fingerprint\advanced_fingerprinter.py`

Network module with 0 functions and 5 classes for network operations and communication

**Classes:**
- `AdvancedFingerprinter`
- `BlockingEvent`
- `ConnectivityResult`
- `DPIBehaviorProfile`
- `FingerprintingConfig`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `hashlib`
- `socket`
- `ssl`


### `core\fingerprint\advanced_tcp_probes.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `AdvancedTCPProbeResult`
- `AdvancedTCPProber`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`


### `core\fingerprint\advanced_tls_probes.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `AdvancedTLSProbeResult`
- `AdvancedTLSProber`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`
- `ssl`
- `struct`


### `core\fingerprint\analyzer.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `apply_probe_results()`

**Classes:**
- `BehaviorAnalyzer`
- `MLAnomalyDetector`
- `PacketAnalyzer`

**Key Imports:**
- `core.fingerprint.models`
- `core.fingerprint.prober`
- `scapy.all`
- `statistics`


### `core\fingerprint\behavioral_probes.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `BehavioralProbeResult`
- `BehavioralProber`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`
- `statistics`


### `core\fingerprint\dns_analyzer.py`

Network module with 0 functions and 5 classes for network operations and communication

**Classes:**
- `DNSAnalyzer`
- `DNSBlockingMethod`
- `DNSQuery`
- `DNSRecordType`
- `DNSResponse`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `enum`
- `socket`
- `ssl`


### `core\fingerprint\dns_analyzer_demo.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `demo_response_analysis()`

**Key Imports:**
- `asyncio`
- `core.fingerprint.dns_analyzer`


### `core\fingerprint\dpi_behavior_analyzer.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `DPIBehaviorAnalyzer`

**Key Imports:**
- `asyncio`
- `core.fingerprint.advanced_models`
- `statistics`


### `core\fingerprint\ech_detector.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `ECHDetector`

**Key Imports:**
- `asyncio`
- `socket`


### `core\fingerprint\enhanced_dpi_analyzer.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `EnhancedDPIAnalyzer`

**Key Imports:**
- `core.fingerprint.dpi_fingerprint_service`
- `requests`
- `socket`
- `ssl`
- `struct`


### `core\fingerprint\http_analyzer.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `HTTPAnalyzer`
- `_StaticResolver`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `contextlib`
- `contextlib`
- `inspect`


### `core\fingerprint\models.py`

Network module with 0 functions and 9 classes for network operations and communication

**Classes:**
- `DPIBehaviorProfile`
- `DPIClassification`
- `DPIFamily`
- `EnhancedFingerprint`
- `Fingerprint`
- `ProbeConfig`
- `ProbeResponse`
- `ProbeResponseType`
- `ProbeResult`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\fingerprint\passive_analyzer.py`

Network module with 0 functions and 3 classes for network operations and communication

**Classes:**
- `BlockingMethod`
- `PassiveAnalysisResult`
- `PassiveDPIAnalyzer`

**Key Imports:**
- `dataclasses`
- `enum`
- `socket`


### `core\fingerprint\prober.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `probe_timeout()`

**Classes:**
- `ProbeCache`
- `ProbeOptimizer`
- `UltimateDPIProber`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `core.fingerprint.models`
- `socket`
- `struct`


### `core\fingerprint\profiles.py`

Network module with 2 functions and 1 classes for network operations and communication

**Functions:**
- `get_profile()`
- `list_profiles()`

**Classes:**
- `CoherentProfile`

**Key Imports:**
- `dataclasses`


### `core\fingerprint\strategy_mapping.py`

Network module with 2 functions and 1 classes for network operations and communication

**Functions:**
- `get_fallback_strategies()`
- `get_strategies_for_fingerprint()`

**Classes:**
- `DPICharacteristic`

**Key Imports:**
- `enum`


### `core\fingerprint\tcp_analyzer.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `TCPAnalyzer`

**Key Imports:**
- `asyncio`
- `socket`
- `unified_models`


### `core\fingerprint\tcp_analyzer_demo.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `print_analysis_summary()`

**Key Imports:**
- `asyncio`
- `core.fingerprint.tcp_analyzer`


### `core\fingerprint\unified_fingerprinter.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `FingerprintingConfig`
- `UnifiedFingerprinter`

**Key Imports:**
- `asyncio`
- `contextlib`
- `dataclasses`
- `inspect`
- `socket`


### `core\fingerprint\unified_models.py`

Network module with 0 functions and 22 classes for network operations and communication

**Classes:**
- `AdvancedTCPProbeResult`
- `AdvancedTLSProbeResult`
- `AnalysisStatus`
- `AnalyzerError`
- `AnalyzerError`
- `BehavioralProbeResult`
- `CacheError`
- `DNSAnalysisResult`
- `DPIType`
- `FingerprintingError`
- `HTTPAnalysisResult`
- `HTTPBlockingMethod`
- `HTTPRequest`
- `MLClassificationError`
- `MLClassificationResult`
- `NetworkAnalysisError`
- `ProbeResult`
- `StrategyRecommendation`
- `TCPAnalysisResult`
- `TLSAnalysisResult`
- `UnifiedFingerprint`
- `ValidationError`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\infrastructure\cache_manager.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `get_cache_manager()`

**Classes:**
- `CacheEntry`
- `CacheManager`

**Key Imports:**
- `dataclasses`
- `threading`


### `core\infrastructure\connection_pool.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `get_connection_pool()`

**Classes:**
- `ConnectionPool`
- `ConnectionPoolConfig`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `contextlib`
- `dataclasses`
- `threading`


### `core\integration\advanced_diagnostics.py`

Network module with 1 functions and 6 classes for network operations and communication

**Functions:**
- `get_diagnostics()`

**Classes:**
- `AdvancedDiagnostics`
- `DiagnosticIssue`
- `DiagnosticSeverity`
- `OptimizationCategory`
- `OptimizationRecommendation`
- `SystemDiagnosticReport`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\integration\advanced_reporting_integration.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `get_reporting_integration()`

**Classes:**
- `AdvancedAttackReport`
- `AdvancedReportingIntegration`
- `SystemPerformanceReport`

**Key Imports:**
- `dataclasses`


### `core\integration\closed_loop_manager.py`

Network module with 0 functions and 3 classes for network operations and communication

**Classes:**
- `ClosedLoopIteration`
- `ClosedLoopManager`
- `ClosedLoopResult`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.real_effectiveness_tester`
- `core.fingerprint.models`
- `dataclasses`
- `ml.strategy_generator`


### `core\integration\fingerprint_integration.py`

Network module with 1 functions and 4 classes for network operations and communication

**Functions:**
- `get_fingerprint_integrator()`

**Classes:**
- `FingerprintIntegrator`
- `FingerprintResult`
- `SimplifiedClassifier`
- `SimplifiedProber`

**Key Imports:**
- `core.async_utils`
- `dataclasses`


### `core\logging\session_context.py`

Network module with 1 functions and 1 classes for network operations and communication

**Functions:**
- `get_session_context_provider()`

**Classes:**
- `SessionContextProvider`

**Key Imports:**
- `__future__`
- `contextvars`


### `core\metrics\clienthello_metrics.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `get_clienthello_metrics_collector()`

**Classes:**
- `ClientHelloMetricsCollector`
- `ClientHelloSample`
- `ClientHelloStatistics`

**Key Imports:**
- `dataclasses`


### `core\metrics\effectiveness_reporter.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `get_effectiveness_reporter()`

**Classes:**
- `EffectivenessReport`
- `EffectivenessReporter`
- `RuleEffectivenessStats`

**Key Imports:**
- `dataclasses`
- `statistics`


### `core\monitoring\real_time_monitor.py`

Network module with 0 functions and 8 classes for network operations and communication

**Classes:**
- `BlockType`
- `ConnectionTracker`
- `MonitoringConfig`
- `MonitoringSystemIntegration`
- `RealTimeMonitor`
- `TrafficAnalyzer`
- `TrafficEvent`
- `TrafficEventType`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `hashlib`
- `threading`


### `core\monitoring\real_time_traffic_analyzer.py`

Network module with 0 functions and 5 classes for network operations and communication

**Classes:**
- `ConnectionFlow`
- `PacketInfo`
- `RealTimeTrafficAnalyzer`
- `TrafficAlert`
- `TrafficEvent`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `threading`


### `core\monitoring\russian_dpi_strategies.py`

Network module with 4 functions and 0 classes for network operations and communication

**Functions:**
- `get_domain_specific_strategies()`
- `get_fallback_strategies()`
- `get_russian_dpi_strategies()`
- `is_strategy_likely_to_work()`

**Key Imports:**
- `core.optimization.models`


### `core\monitoring_system.py`

Network module with 2 functions and 5 classes for network operations and communication

**Functions:**
- `load_monitoring_config()`
- `save_monitoring_config()`

**Classes:**
- `AutoRecoverySystem`
- `ConnectionHealth`
- `HealthChecker`
- `MonitoringConfig`
- `MonitoringSystem`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`


### `core\net\base_packet.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `Packet`

**Key Imports:**
- `abc`


### `core\net\connection_tester.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `ConnectionTester`
- `IConnectionTester`

**Key Imports:**
- `abc`
- `asyncio`
- `socket`
- `subprocess`
- `urllib.parse`


### `core\net\ech.py`

Network module with 0 functions and 5 classes for network operations and communication

**Classes:**
- `ECHCipherSuite`
- `ECHClientHello`
- `ECHConfig`
- `ECHNonce`
- `ECHVersion`

**Key Imports:**
- `dataclasses`
- `enum`
- `struct`


### `core\net\packet_engine.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `Packet`
- `PacketEngine`

**Key Imports:**
- `abc`
- `core.net.ech`
- `core.net.quic_packet`
- `core.net.tcp_options`
- `struct`


### `core\net\tcp_options.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `TCPOption`
- `TCPOptions`

**Key Imports:**
- `dataclasses`
- `struct`


### `core\net\tcp_tracker.py`

Network module with 0 functions and 3 classes for network operations and communication

**Classes:**
- `TCPConnection`
- `TCPState`
- `TCPTracker`

**Key Imports:**
- `core.net.byte_packet`
- `dataclasses`
- `enum`


### `core\optimization\http_client_pool.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `get_global_http_pool()`

**Classes:**
- `CacheEntry`
- `OptimizedHTTPClientPool`
- `RequestStats`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `dataclasses`
- `hashlib`
- `weakref`


### `core\packet\demo_final.py`

Network module with 2 functions and 0 classes for network operations and communication

**Functions:**
- `demo_migration_tool()`
- `demo_scapy_compatibility()`

**Key Imports:**
- `asyncio`
- `recon.core.packet.migration_tool`
- `recon.core.packet.raw_packet_engine`
- `recon.core.packet.scapy_compatibility`


### `core\packet\pcap_analyzer.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `PCAPAnalyzer`
- `PacketInfo`

**Key Imports:**
- `dataclasses`
- `socket`
- `struct`


### `core\packet\performance_benchmark.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `BenchmarkResult`
- `PacketPerformanceBenchmark`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `recon.core.packet.raw_packet_engine`
- `statistics`
- `tracemalloc`


### `core\packet\protocol_handlers.py`

Network module with 0 functions and 9 classes for network operations and communication

**Classes:**
- `DNSHandler`
- `EthernetHandler`
- `HTTPHandler`
- `ICMPHandler`
- `IPv4Handler`
- `IPv6Handler`
- `ProtocolHandler`
- `TCPHandler`
- `UDPHandler`

**Key Imports:**
- `packet_models`
- `socket`
- `struct`


### `core\packet\scapy_compatibility.py`

Network module with 7 functions and 13 classes for network operations and communication

**Functions:**
- `RandShort()`
- `fragment()`
- `rdpcap()`
- `send()`
- `sniff()`
- `sr1()`
- `wrpcap()`

**Classes:**
- `IP`
- `IPRawPacket`
- `IPTCPPacket`
- `IPUDPPacket`
- `Packet`
- `PacketLayer`
- `Raw`
- `ScapyCompatibilityError`
- `ScapyCompatibilityLayer`
- `ScapySocket`
- `TCP`
- `UDP`
- `conf`

**Key Imports:**
- `dataclasses`
- `packet_models`
- `raw_packet_engine`
- `socket`
- `struct`


### `core\packet_builder.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `PacketBuilder`
- `PacketParams`

**Key Imports:**
- `core.interfaces`
- `dataclasses`
- `socket`
- `struct`


### `core\packet_converter.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `PacketConverter`

**Key Imports:**
- `core.bypass.types`
- `socket`
- `struct`


### `core\payload\attack_integration.py`

Network module with 4 functions and 1 classes for network operations and communication

**Functions:**
- `get_attack_payload()`
- `get_global_payload_manager()`
- `reset_global_payload_manager()`
- `set_global_payload_manager()`

**Classes:**
- `AttackPayloadProvider`

**Key Imports:**
- `manager`
- `serializer`
- `types`


### `core\payload\capturer.py`

Network module with 0 functions and 7 classes for network operations and communication

**Classes:**
- `CaptureError`
- `CaptureNetworkError`
- `CaptureResult`
- `CaptureTimeoutError`
- `CaptureValidationError`
- `InterceptingSocket`
- `PayloadCapturer`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`
- `ssl`
- `types`


### `core\pcap\enhanced_packet_capturer.py`

Network module with 1 functions and 2 classes for network operations and communication

**Functions:**
- `create_enhanced_packet_capturer()`

**Classes:**
- `EnhancedPacketCapturer`
- `StrategyMetricsCollector`


### `core\pcap\pcap_insights_worker.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `PcapInsightsWorker`

**Key Imports:**
- `asyncio`
- `core.bypass.types`
- `core.knowledge_base`


### `core\pcap\rst_analyzer.py`

Network module with 1 functions and 1 classes for network operations and communication

**Functions:**
- `build_json_report()`

**Classes:**
- `RSTTriggerAnalyzer`


### `core\pcap\unified_analyzer.py`

Network module with 0 functions and 5 classes for network operations and communication

**Classes:**
- `ClientHelloInfo`
- `FakePacketInfo`
- `PCAPAnalysisResult`
- `SplitInfo`
- `UnifiedPCAPAnalyzer`

**Key Imports:**
- `dataclasses`
- `enum`
- `struct`


### `core\pcap_analysis\blocking_pattern_detector.py`

Network module with 0 functions and 10 classes for network operations and communication

**Classes:**
- `BlockingPatternAnalysis`
- `BlockingPatternDetector`
- `DNSManipulationAnalysis`
- `DNSManipulationType`
- `DPIAggressivenessLevel`
- `HTTPRedirectAnalysis`
- `RSTInjectionAnalysis`
- `RST_InjectionType`
- `TLSHandshakeAnalysis`
- `TLSHandshakeStage`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `ipaddress`
- `statistics`


### `core\pcap_analysis\cli_help.py`

Network module with 1 functions and 1 classes for network operations and communication

**Functions:**
- `show_help()`

**Classes:**
- `HelpSystem`


### `core\pcap_analysis\comparison_result.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `ComparisonResult`

**Key Imports:**
- `dataclasses`
- `packet_info`


### `core\pcap_analysis\critical_difference.py`

Network module with 0 functions and 6 classes for network operations and communication

**Classes:**
- `CriticalDifference`
- `DifferenceCategory`
- `DifferenceGroup`
- `Evidence`
- `FixComplexity`
- `ImpactLevel`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\pcap_analysis\deployment\setup.py`

Network module with 3 functions and 0 classes for network operations and communication

**Functions:**
- `get_long_description()`
- `get_requirements()`
- `get_version()`

**Key Imports:**
- `setuptools`


### `core\pcap_analysis\error_handling.py`

Network module with 4 functions and 11 classes for network operations and communication

**Functions:**
- `get_error_handler()`
- `handle_analysis_error()`
- `handle_pcap_error()`
- `safe_execute()`

**Classes:**
- `AnalysisError`
- `ErrorCategory`
- `ErrorContext`
- `ErrorHandler`
- `ErrorSeverity`
- `FixGenerationError`
- `PCAPParsingError`
- `PartialResult`
- `RecoveryAction`
- `StrategyAnalysisError`
- `ValidationError`

**Key Imports:**
- `contextlib`
- `dataclasses`
- `enum`
- `traceback`


### `core\pcap_analysis\graceful_degradation.py`

Network module with 2 functions and 3 classes for network operations and communication

**Functions:**
- `get_graceful_parser()`
- `parse_pcap_with_fallback()`

**Classes:**
- `FallbackStrategy`
- `GracefulPCAPParser`
- `PCAPFileInfo`

**Key Imports:**
- `dataclasses`
- `error_handling`
- `packet_info`
- `socket`
- `struct`


### `core\pcap_analysis\interactive_menu.py`

Network module with 4 functions and 5 classes for network operations and communication

**Functions:**
- `clear_screen()`
- `confirm_action()`
- `get_user_input()`
- `select_from_list()`

**Classes:**
- `DifferenceReviewMenu`
- `FixReviewMenu`
- `InteractiveMenu`
- `MenuChoice`
- `MenuOption`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\pcap_analysis\monitoring\health_monitor.py`

Network module with 0 functions and 4 classes for network operations and communication

**Classes:**
- `AlertConfig`
- `HealthMetric`
- `HealthMonitor`
- `SystemHealth`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `psutil`
- `requests`


### `core\pcap_analysis\packet_info.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `PacketInfo`
- `TLSInfo`

**Key Imports:**
- `dataclasses`
- `socket`
- `struct`


### `core\pcap_analysis_cli.py`

Network module with 1 functions and 5 classes for network operations and communication

**Functions:**
- `analyze_pcap_for_strategies()`

**Classes:**
- `ConnectionAnalysis`
- `DomainAnalysis`
- `PcapAnalysisResult`
- `PcapAnalyzer`
- `PcapMonitor`

**Key Imports:**
- `dataclasses`


### `core\post_handshake_analyzer.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `PostHandshakeAnalyzer`

**Key Imports:**
- `scapy.all`


### `core\protocols\tls.py`

Network module with 0 functions and 5 classes for network operations and communication

**Classes:**
- `ClientHelloInfo`
- `TLSExtension`
- `TLSExtensionType`
- `TLSHandler`
- `TLSParser`

**Key Imports:**
- `dataclasses`
- `enum`
- `struct`


### `core\real_world_tester.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `RealWorldTester`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `socket`
- `threading`
- `urllib.parse`


### `core\reporting\advanced_reporting_integration.py`

Network module with 1 functions and 3 classes for network operations and communication

**Functions:**
- `get_reporting_integration()`

**Classes:**
- `AdvancedAttackReport`
- `AdvancedReportingIntegration`
- `SystemPerformanceReport`

**Key Imports:**
- `dataclasses`


### `core\state_management\state_observer.py`

Network module with 0 functions and 6 classes for network operations and communication

**Classes:**
- `CallbackStateObserver`
- `IStateObserver`
- `LoggingStateObserver`
- `MetricsStateObserver`
- `StateObserver`
- `StateObserverMetrics`

**Key Imports:**
- `abc`
- `dataclasses`
- `engine_state_machine`


### `core\strategy_selector_demo.py`

Network module with 4 functions and 0 classes for network operations and communication

**Functions:**
- `demo_strategy_selection()`
- `demo_twitter_optimization()`
- `get_sample_strategies()`
- `load_existing_strategies()`

**Key Imports:**
- `strategy_selector`


### `core\validation\clienthello_parser.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `ClientHelloInfo`
- `ClientHelloParser`

**Key Imports:**
- `dataclasses`
- `hashlib`
- `struct`


### `core\validation\http_response_classifier.py`

Network module with 1 functions and 4 classes for network operations and communication

**Functions:**
- `create_http_response_classifier()`

**Classes:**
- `HttpResponseClassifier`
- `RedirectType`
- `ResponseCategory`
- `ResponseClassification`

**Key Imports:**
- `dataclasses`
- `enum`


### `deep_analyze_test_connection.py`

Network module with 2 functions and 0 classes for network operations and communication

**Functions:**
- `analyze_test_connection()`
- `main()`

**Key Imports:**
- `scapy.all`


### `deep_pcap_compare.py`

Network module with 2 functions and 0 classes for network operations and communication

**Functions:**
- `analyze_pcap()`
- `compare_strategies()`

**Key Imports:**
- `scapy.all`


### `enhanced_packed_capturer.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `EnhancedPacketCapturer`


### `examples\engine_dry_run_example.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `EngineDryRunDemo`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.bypass.engines.base`
- `core.bypass.engines.native_pydivert_engine`


### `examples\online_analysis_demo.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `OnlineAnalysisDemo`

**Key Imports:**
- `asyncio`
- `core.monitoring`
- `signal`


### `find_rst_triggers.py`

Network module with 21 functions and 8 classes for network operations and communication

**Functions:**
- `analyze_payload_entropy()`
- `build_json_report()`
- `detect_rst_index()`
- `detect_trigger_index()`
- `enhanced_build_json_report()`
- `export_strategy_samples()`
- `export_strategy_samples_json()`
- `extract_sni_loose()`
- `find_clienthello_offset()`
- `format_stream_label_from_pkt()`
- `generate_advanced_strategies()`
- `get_first()`
- `get_stream_label()`
- `is_grease()`
- `locate_clienthello_start()`
- `main()`
- `parse_client_hello()`
- `parse_ech_extension()`
- `parse_key_share_extension()`
- `reassemble_clienthello()`
- `strip_grease_from_list()`

**Classes:**
- `AdvancedSignatureAnalyzer`
- `AttackDiagnosis`
- `AttackType`
- `BlockingPatternAnalyzer`
- `FlowFailureAnalyzer`
- `PacketAnalysis`
- `StrategyOptimizer`
- `TCPStreamReassembler`

**Key Imports:**
- `argparse`
- `asyncio`
- `ipaddress`
- `socket`
- `struct`


### `get_ips.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `get_ips_from_sites()`

**Key Imports:**
- `socket`
- `urllib.parse`


### `improved_timeout_handler.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `ConnectionConfig`
- `ImprovedTimeoutHandler`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `ssl`


### `install_pydivert.py`

Network module with 5 functions and 0 classes for network operations and communication

**Functions:**
- `check_admin_rights()`
- `download_windivert()`
- `install_pydivert_pip()`
- `main()`
- `test_pydivert()`

**Key Imports:**
- `platform`
- `subprocess`
- `urllib.request`
- `zipfile`


### `monitoring_system.py`

Network module with 2 functions and 5 classes for network operations and communication

**Functions:**
- `load_monitoring_config()`
- `save_monitoring_config()`

**Classes:**
- `AutoRecoverySystem`
- `ConnectionHealth`
- `HealthChecker`
- `MonitoringConfig`
- `MonitoringSystem`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `socket`


### `packet_builder.py`

Network module with 0 functions and 2 classes for network operations and communication

**Classes:**
- `PacketBuilder`
- `PacketParams`

**Key Imports:**
- `dataclasses`
- `recon.interfaces`
- `socket`
- `struct`


### `packet_converter.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `PacketConverter`

**Key Imports:**
- `core.bypass.types`
- `socket`
- `struct`


### `post_handshake_analyzer.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `PostHandshakeAnalyzer`

**Key Imports:**
- `scapy.all`


### `real_world_tester.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `RealWorldTester`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `socket`
- `threading`
- `urllib.parse`


### `simple_cli.py`

Network module with 1 functions and 0 classes for network operations and communication

**Functions:**
- `check_hosts_simple()`

**Key Imports:**
- `aiohttp`
- `argparse`
- `asyncio`
- `socket`


### `subdomain_detector.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `SubdomainDetector`

**Key Imports:**
- `aiohttp`
- `asyncio`
- `core.doh_resolver`


### `tools\deduplicate_pcap.py`

Network module with 4 functions and 0 classes for network operations and communication

**Functions:**
- `analyze_delta_pattern()`
- `deduplicate_pcap()`
- `get_packet_signature()`
- `main()`


### `tools\smart_pcap_dedup.py`

Network module with 3 functions and 0 classes for network operations and communication

**Functions:**
- `get_packet_signature()`
- `main()`
- `smart_deduplicate()`


### `tunnels\doh_zapret_bridge.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `DoHZapretBridge`

**Key Imports:**
- `base64`
- `socket`
- `threading`


### `web\monitoring_server.py`

Network module with 0 functions and 1 classes for network operations and communication

**Classes:**
- `MonitoringWebServer`

**Key Imports:**
- `asyncio`



## Other

General-purpose modules that don't fit into specific categories.

### `core\duplicate_analysis\metadata_extractor.py`

General purpose module with 0 functions and 3 classes

**Classes:**
- `DocstringInfo`
- `FunctionSignature`
- `MetadataExtractor`

**Key Imports:**
- `ast`
- `dataclasses`
- `inspect`
- `interfaces`


### `core\duplicate_analysis\method_passport_generator.py`

General purpose module with 0 functions and 1 classes

**Classes:**
- `MethodPassportGenerator`

**Key Imports:**
- `ast`
- `inspect`
- `interfaces`


### `core\optimizer\native_candidate_generator.py`

General purpose module with 0 functions and 1 classes

**Classes:**
- `NativeCandidateGenerator`


### `core\state_management\engine_state_machine.py`

General purpose module with 0 functions and 2 classes

**Classes:**
- `EngineStateMachine`
- `StateTransitionEvent`

**Key Imports:**
- `core.unified_engine_models`
- `dataclasses`
- `enum`
- `threading`


### `core\utils.py`

General purpose module with 1 functions and 0 classes

**Functions:**
- `normalize_zapret_string()`


### `core\zapret.py`

General purpose module with 2 functions and 0 classes

**Functions:**
- `generate_final_report()`
- `synth()`

**Key Imports:**
- `core.bypass.attacks.attack_registry`


### `platform\android_adapter.py`

General purpose module with 0 functions and 2 classes

**Classes:**
- `AndroidVPNService`
- `PlatformAdapter`

**Key Imports:**
- `platform`


### `zapret.py`

General purpose module with 2 functions and 0 classes

**Functions:**
- `generate_final_report()`
- `synth()`

**Key Imports:**
- `core.bypass.attacks.attack_registry`



## Strategy

Modules containing algorithms, optimization strategies, and decision-making logic.

### `aggressive_strategy_tester.py`

Strategy module with 3 functions and 0 classes for algorithms and optimization

**Functions:**
- `generate_aggressive_strategies()`
- `main()`
- `test_single_strategy()`

**Key Imports:**
- `subprocess`


### `cdn_resolver.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `CDNResolutionResult`
- `CDNResolver`

**Key Imports:**
- `core.dns.robust_dns_handler`
- `dataclasses`


### `cli.py`

Strategy module with 16 functions and 10 classes for algorithms and optimization

**Functions:**
- `apply_forced_override()`
- `build_attack_recipe()`
- `build_bpf_from_ips()`
- `convert_strategy_to_zapret_command()`
- `load_all_attacks()`
- `load_strategy_for_domain()`
- `main()`
- `run_analyze_pcap_command()`
- `run_compare_modes_command()`
- `run_diagnostics_command()`
- `run_failure_report_command()`
- `run_list_failures_mode()`
- `run_metrics_command()`
- `run_status_mode()`
- `run_strategy_diff_command()`
- `setup_utf8_console()`

**Classes:**
- `AdaptiveLearningCache`
- `EvolutionaryChromosome`
- `PacketCapturer`
- `SimpleDPIClassifier`
- `SimpleEvolutionarySearcher`
- `SimpleEvolutionarySearcher`
- `SimpleFingerprint`
- `SimpleFingerprinter`
- `SimpleReporter`
- `StrategyPerformanceRecord`

**Key Imports:**
- `argparse`
- `asyncio`
- `inspect`
- `locale`
- `platform`


### `cli_monitor.py`

Strategy module with 7 functions and 0 classes for algorithms and optimization

**Functions:**
- `add_domains()`
- `check()`
- `cli()`
- `optimize()`
- `optimize_all()`
- `start()`
- `status()`

**Key Imports:**
- `asyncio`
- `click`
- `core.monitoring.adaptive_strategy_monitor`


### `cli_workflow_optimizer.py`

Strategy module with 2 functions and 4 classes for algorithms and optimization

**Functions:**
- `create_workflow_optimizer()`
- `detect_execution_mode()`

**Classes:**
- `CLIWorkflowOptimizer`
- `ExecutionMode`
- `FingerprintCache`
- `WorkflowState`

**Key Imports:**
- `core.fingerprint.models`
- `core.integration.attack_adapter`
- `core.integration.result_processor`
- `dataclasses`
- `enum`


### `convert_strategies_to_domain_rules.py`

Strategy module with 1 functions and 1 classes for algorithms and optimization

**Functions:**
- `main()`

**Classes:**
- `StrategyConverter`


### `core\adaptive_strategy_adjuster.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `AdaptiveStrategyAdjuster`


### `core\async\async_optimizer.py`

Strategy module with 3 functions and 4 classes for algorithms and optimization

**Functions:**
- `async_optimize()`
- `get_global_optimizer()`
- `make_async()`

**Classes:**
- `AsyncBatch`
- `AsyncOptimizer`
- `AsyncQueue`
- `AsyncUtils`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `contextlib`
- `inspect`


### `core\bypass\attacks\combo\zapret_strategy.py`

Strategy module with 1 functions and 2 classes for algorithms and optimization

**Functions:**
- `create_zapret_strategy()`

**Classes:**
- `ZapretConfig`
- `ZapretStrategy`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `core.packet_builder`
- `dataclasses`
- `struct`


### `core\bypass\engine\domain_strategy_engine.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `DomainStrategyEngine`

**Key Imports:**
- `domain_rule_registry`
- `hierarchical_domain_matcher`
- `runtime_ip_resolver`
- `sni_domain_extractor`
- `strategy_result`


### `core\bypass\engine\real_world_adapter.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `RealWorldStrategyAdapter`


### `core\bypass\engine\runtime_ip_resolver.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `CacheEntry`
- `RuntimeIPResolver`

**Key Imports:**
- `dataclasses`
- `socket`
- `threading`


### `core\bypass\engine\strategy_failure_tracker.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `StrategyFailureRecord`
- `StrategyFailureTracker`
- `StrategyHistoryEntry`

**Key Imports:**
- `dataclasses`


### `core\bypass\engine\strategy_result.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `ConflictInfo`
- `StrategyResult`

**Key Imports:**
- `dataclasses`


### `core\bypass\engine\strategy_validator.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `StrategyValidator`
- `ValidationResult`

**Key Imports:**
- `dataclasses`


### `core\bypass\engines\fallback_recovery.py`

Strategy module with 2 functions and 10 classes for algorithms and optimization

**Functions:**
- `create_mock_engine()`
- `get_fallback_recovery_manager()`

**Classes:**
- `DependencyBasedStrategy`
- `FallbackAttempt`
- `FallbackRecoveryManager`
- `FallbackResult`
- `FallbackStrategy`
- `FallbackStrategy_Interface`
- `LeastRequirementsStrategy`
- `MockEngine`
- `PriorityOrderStrategy`
- `RecoveryAction`

**Key Imports:**
- `abc`
- `core.bypass.engines.base`
- `core.bypass.engines.error_handling`
- `dataclasses`
- `enum`


### `core\bypass\exceptions.py`

Strategy module with 0 functions and 17 classes for algorithms and optimization

**Classes:**
- `BypassError`
- `DriverNotFoundError`
- `EngineAlreadyRunningError`
- `EngineConfigError`
- `EngineError`
- `EngineNotRunningError`
- `InsufficientPrivilegesError`
- `InvalidPacketError`
- `InvalidStrategyError`
- `PacketError`
- `PacketProcessingError`
- `PacketSendError`
- `PlatformError`
- `StrategyError`
- `StrategyExecutionError`
- `TechniqueNotFoundError`
- `WindowsRequiredError`


### `core\bypass\hybrid\strategy_adapter.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyAdapter`

**Key Imports:**
- `core.bypass.attacks.alias_map`


### `core\bypass\performance\performance_models.py`

Strategy module with 0 functions and 9 classes for algorithms and optimization

**Classes:**
- `Alert`
- `AlertSeverity`
- `DeploymentChecklist`
- `OptimizationLevel`
- `OptimizationResult`
- `PerformanceMetrics`
- `ProductionConfig`
- `StrategyPerformance`
- `SystemHealth`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\performance\performance_optimizer.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `PerformanceOptimizer`

**Key Imports:**
- `asyncio`
- `core.bypass.performance.performance_models`
- `psutil`


### `core\bypass\performance\segment_performance_optimizer.py`

Strategy module with 2 functions and 6 classes for algorithms and optimization

**Functions:**
- `get_global_optimizer()`
- `optimize_segments()`

**Classes:**
- `MemoryPool`
- `OptimizationConfig`
- `PacketCache`
- `PerformanceMetrics`
- `PerformanceProfiler`
- `SegmentPerformanceOptimizer`

**Key Imports:**
- `concurrent.futures`
- `dataclasses`
- `gc`
- `threading`


### `core\bypass\performance\segment_performance_optimizer_simple.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `OptimizationConfig`
- `PerformanceMetrics`
- `SegmentPerformanceOptimizer`

**Key Imports:**
- `core.bypass.attacks.base`
- `dataclasses`


### `core\bypass\performance\strategy_optimizer.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyOptimizer`

**Key Imports:**
- `core.bypass.performance.performance_models`
- `numpy`


### `core\bypass\sharing\sharing_models.py`

Strategy module with 0 functions and 10 classes for algorithms and optimization

**Classes:**
- `ShareLevel`
- `SharedStrategy`
- `SharingConfig`
- `StrategyFeedback`
- `StrategyPackage`
- `SyncResult`
- `TrustLevel`
- `TrustedSource`
- `ValidationResult`
- `ValidationStatus`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\bypass\sharing\strategy_validator.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyValidator`

**Key Imports:**
- `asyncio`
- `core.bypass.sharing.sharing_models`


### `core\bypass\strategies\dpi_strategy_engine.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `BasePacketProcessor`
- `DPIStrategyEngine`

**Key Imports:**
- `config_models`
- `exceptions`
- `interfaces`
- `packet_modifier`
- `position_resolver`


### `core\bypass\strategies\exceptions.py`

Strategy module with 0 functions and 8 classes for algorithms and optimization

**Classes:**
- `ChecksumCalculationError`
- `ConfigurationError`
- `DPIStrategyError`
- `InvalidSplitPositionError`
- `PacketProcessingError`
- `PacketTooSmallError`
- `SNINotFoundError`
- `TLSParsingError`


### `core\bypass\strategies\executor.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyExecutor`


### `core\bypass\strategies\generator.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyGenerator`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.fingerprint.advanced_models`


### `core\bypass\strategies\interfaces.py`

Strategy module with 0 functions and 6 classes for algorithms and optimization

**Classes:**
- `IChecksumFooler`
- `IDPIStrategy`
- `IPacketModifier`
- `IPacketProcessor`
- `IPositionResolver`
- `ISNIDetector`

**Key Imports:**
- `abc`


### `core\bypass\strategies\native_generator_adapter.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `NativeStrategyGeneratorAdapter`

**Key Imports:**
- `core.interfaces`
- `core.optimizer.native_candidate_generator`


### `core\bypass\strategies\parser.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `ParsedStrategy`
- `StrategyParameter`
- `UnifiedStrategyParser`

**Key Imports:**
- `dataclasses`


### `core\bypass\strategies\pool_management.py`

Strategy module with 2 functions and 5 classes for algorithms and optimization

**Functions:**
- `analyze_domain_patterns()`
- `suggest_pool_strategies()`

**Classes:**
- `BypassStrategy`
- `DomainRule`
- `PoolPriority`
- `StrategyPool`
- `StrategyPoolManager`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\strategies\pool_management_minimal.py`

Strategy module with 0 functions and 4 classes for algorithms and optimization

**Classes:**
- `BypassStrategy`
- `PoolPriority`
- `StrategyPool`
- `StrategyPoolManager`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\strategies\position_resolver.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `PositionResolver`

**Key Imports:**
- `config_models`
- `exceptions`
- `struct`


### `core\bypass\strategies\strategy_application.py`

Strategy module with 0 functions and 6 classes for algorithms and optimization

**Classes:**
- `ConflictResolution`
- `DomainAnalysis`
- `EnhancedStrategySelector`
- `SelectionCriteria`
- `StrategyScore`
- `UserPreference`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\strategies\subdomain_handler.py`

Strategy module with 2 functions and 7 classes for algorithms and optimization

**Functions:**
- `analyze_subdomain_structure()`
- `suggest_subdomain_tests()`

**Classes:**
- `EnhancedPoolManager`
- `PlatformConfiguration`
- `PlatformType`
- `SubdomainPattern`
- `SubdomainStrategy`
- `SubdomainStrategyHandler`
- `SubdomainType`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\calibration\search_space_optimizer.py`

Strategy module with 2 functions and 8 classes for algorithms and optimization

**Functions:**
- `create_search_space_optimizer()`
- `optimize_strategies_for_domain()`

**Classes:**
- `GeneratedStrategy`
- `NegativeKnowledgeEntry`
- `NegativeKnowledgeManager`
- `SearchSpaceOptimizer`
- `StrategyIntent`
- `StrategyIntentEngine`
- `StrategyPriority`
- `TargetedStrategyGenerator`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\cdn_resolver.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `CDNResolutionResult`
- `CDNResolver`

**Key Imports:**
- `dataclasses`
- `recon.core.dns.robust_dns_handler`


### `core\cli_payload\adaptive_cli_wrapper.py`

Strategy module with 3 functions and 30 classes for algorithms and optimization

**Functions:**
- `create_cli_wrapper_from_args()`
- `create_config_from_args()`
- `get_monotonic_time()`

**Classes:**
- `AdaptiveCLIWrapper`
- `AnalysisError`
- `AnalysisMetrics`
- `AnalysisMode`
- `ArgumentValidator`
- `BatchResult`
- `BatchSummary`
- `CLIConfig`
- `CLIWrapperError`
- `ConfigurationError`
- `DomainValidationError`
- `DomainValidator`
- `EngineInitializationError`
- `ExportError`
- `FallbackAdaptiveConfig`
- `FallbackAdaptiveEngine`
- `FallbackConsole`
- `FallbackPanel`
- `FallbackProgress`
- `FallbackStrategyResult`
- `OutputFormat`
- `OutputStrategy`
- `PlainOutputStrategy`
- `QuietOutputStrategy`
- `ResultsExporter`
- `RichOutputStrategy`
- `StrategySaver`
- `TimeoutError`
- `UnicodeReplacements`
- `UnicodeSupport`

**Key Imports:**
- `__future__`
- `asyncio`
- `locale`
- `subprocess`
- `traceback`


### `core\cli_payload\strategy_diagnostics.py`

Strategy module with 0 functions and 6 classes for algorithms and optimization

**Classes:**
- `PCAPStrategyAnalyzer`
- `StrategyApplicationRecord`
- `StrategyDiff`
- `StrategyDiffTool`
- `StrategyFailureReportGenerator`
- `VerboseStrategyLogger`

**Key Imports:**
- `dataclasses`
- `scapy.all`


### `core\cli_workflow_optimizer.py`

Strategy module with 2 functions and 4 classes for algorithms and optimization

**Functions:**
- `create_workflow_optimizer()`
- `detect_execution_mode()`

**Classes:**
- `CLIWorkflowOptimizer`
- `ExecutionMode`
- `FingerprintCache`
- `WorkflowState`

**Key Imports:**
- `dataclasses`
- `enum`
- `recon.core.fingerprint.models`
- `recon.core.integration.attack_adapter`
- `recon.core.integration.result_processor`


### `core\config\strategy_config_manager.py`

Strategy module with 0 functions and 5 classes for algorithms and optimization

**Classes:**
- `ConfigurationError`
- `StrategyConfigManager`
- `StrategyConfiguration`
- `StrategyMetadata`
- `StrategyRule`

**Key Imports:**
- `dataclasses`


### `core\demo_modern_integration.py`

Strategy module with 1 functions and 0 classes for algorithms and optimization

**Functions:**
- `demo_strategy_generator_integration()`

**Key Imports:**
- `asyncio`
- `recon.core.hybrid_engine`
- `recon.core.monitoring_system`
- `recon.ml.zapret_strategy_generator`


### `core\domain_specific_strategies.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `DomainSpecificStrategies`


### `core\integration\evolutionary_optimization_integration.py`

Strategy module with 1 functions and 4 classes for algorithms and optimization

**Functions:**
- `get_evolutionary_integrator()`

**Classes:**
- `EvolutionaryOptimizationIntegrator`
- `OptimizationResult`
- `OptimizationTask`
- `SimplifiedStrategyGenerator`

**Key Imports:**
- `core.async_utils`
- `dataclasses`


### `core\integration\simple_performance_optimizer.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `SimplePerformanceOptimizer`
- `SimplePerformanceProfile`

**Key Imports:**
- `dataclasses`
- `gc`
- `threading`


### `core\integration\strategy_prediction_integration.py`

Strategy module with 1 functions and 2 classes for algorithms and optimization

**Functions:**
- `get_strategy_integrator()`

**Classes:**
- `StrategyPredictionIntegrator`
- `StrategyRecommendation`

**Key Imports:**
- `dataclasses`


### `core\interfaces.py`

Strategy module with 0 functions and 11 classes for algorithms and optimization

**Classes:**
- `IAttackAdapter`
- `IClassifier`
- `IClosedLoopManager`
- `IEffectivenessTester`
- `IEvolutionarySearcher`
- `IFingerprintEngine`
- `ILearningMemory`
- `IPacketBuilder`
- `IProber`
- `IStrategyGenerator`
- `IStrategySaver`

**Key Imports:**
- `abc`
- `core.bypass.attacks.base`
- `core.fingerprint.models`


### `core\learning\cache.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `AdaptiveLearningCache`
- `StrategyPerformanceRecord`

**Key Imports:**
- `dataclasses`
- `hashlib`
- `pickle`
- `statistics`


### `core\logging\strategy_key.py`

Strategy module with 2 functions and 0 classes for algorithms and optimization

**Functions:**
- `generate_strategy_key()`
- `normalize_params()`

**Key Imports:**
- `__future__`
- `hashlib`


### `core\monitoring\adaptive_strategy_monitor.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `AdaptiveStrategyMonitor`
- `DomainHealth`
- `OptimizationTask`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\monitoring\online_analysis_integration.py`

Strategy module with 0 functions and 5 classes for algorithms and optimization

**Classes:**
- `NotificationManager`
- `OnlineAnalysisIntegration`
- `OnlineAnalysisMetrics`
- `StrategyOrchestrator`
- `StrategySwitch`

**Key Imports:**
- `adaptive_online_strategy_generator`
- `asyncio`
- `dataclasses`
- `real_time_traffic_analyzer`
- `threading`


### `core\optimization\dynamic_parameter_optimizer.py`

Strategy module with 0 functions and 4 classes for algorithms and optimization

**Classes:**
- `DynamicParameterOptimizer`
- `OptimizationResult`
- `OptimizationStrategy`
- `ParameterRange`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\optimization\models.py`

Strategy module with 0 functions and 6 classes for algorithms and optimization

**Classes:**
- `DomainHealth`
- `OptimizationResult`
- `PerformanceMetrics`
- `RankedStrategy`
- `RecoveryEvent`
- `Strategy`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\optimization\optimizer.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyOptimizer`

**Key Imports:**
- `core.optimization.metrics_collector`
- `core.optimization.models`
- `core.optimization.ranker`
- `core.optimization.scorer`
- `core.optimization.variation_generator`


### `core\optimization\performance_optimizer.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `PerformanceOptimizer`
- `PerformanceProfile`

**Key Imports:**
- `concurrent.futures`
- `dataclasses`
- `gc`
- `psutil`
- `threading`


### `core\optimization\ranker.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyRanker`

**Key Imports:**
- `importlib.util`


### `core\optimization\scorer.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `OptimizationScorer`


### `core\optimizer\real_time_optimizer.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `RealTimeStrategyOptimizer`


### `core\orchestrator.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `AutonomousStrategyOrchestrator`
- `OrchestratorConfig`

**Key Imports:**
- `dataclasses`


### `core\parametric_optimizer.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `ParametricOptimizer`


### `core\pcap\analyzer.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `ComparisonResult`
- `PCAPAnalyzer`
- `StrategyAnalysisResult`

**Key Imports:**
- `core.bypass.sni.manipulator`
- `core.packet.raw_packet_engine`
- `core.packet.raw_pcap_reader`
- `dataclasses`
- `struct`


### `core\pcap_analysis\pcap_strategy_generator.py`

Strategy module with 0 functions and 9 classes for algorithms and optimization

**Classes:**
- `BlockingTypeMapper`
- `GeneratedStrategy`
- `PCAPStrategyGenerator`
- `ParameterOptimizer`
- `PriorityCalculator`
- `StrategyGenerationResult`
- `StrategyParameter`
- `StrategyPriority`
- `StrategyValidator`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`


### `core\pcap_analysis\strategy_analyzer.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `FakeDisorderPattern`
- `StrategyAnalyzer`

**Key Imports:**
- `dataclasses`
- `packet_info`
- `strategy_config`


### `core\pcap_analysis\strategy_config.py`

Strategy module with 0 functions and 5 classes for algorithms and optimization

**Classes:**
- `FoolingMethod`
- `StrategyComparison`
- `StrategyConfig`
- `StrategyDifference`
- `StrategyType`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\pcap_analysis\strategy_validator.py`

Strategy module with 0 functions and 6 classes for algorithms and optimization

**Classes:**
- `BeforeAfterComparison`
- `DomainSelector`
- `EffectivenessResult`
- `StrategyValidator`
- `TestDomain`
- `ValidationResult`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `fix_generator`
- `strategy_config`
- `urllib.parse`


### `core\performance_optimizer.py`

Strategy module with 1 functions and 8 classes for algorithms and optimization

**Functions:**
- `performance_timer()`

**Classes:**
- `CacheEntry`
- `PacketBuilderOptimizer`
- `PerformanceCache`
- `PerformanceMetrics`
- `PerformanceMonitor`
- `PerformanceOptimizer`
- `StrategyPerformance`
- `StrategySelector`

**Key Imports:**
- `dataclasses`
- `hashlib`
- `statistics`
- `threading`


### `core\reporting\enhanced_reporter.py`

Strategy module with 0 functions and 6 classes for algorithms and optimization

**Classes:**
- `ComprehensiveReport`
- `ConfidenceLevel`
- `DPIAnalysisReport`
- `EnhancedReporter`
- `StrategyEffectivenessReport`
- `SystemPerformanceReport`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy\circuit_breaker.py`

Strategy module with 2 functions and 3 classes for algorithms and optimization

**Functions:**
- `calculate_strategy_priority()`
- `create_circuit_breaker()`

**Classes:**
- `CircuitBreaker`
- `ICircuitBreaker`
- `StrategyPerformance`

**Key Imports:**
- `abc`
- `core.unified_engine_models`
- `dataclasses`
- `threading`


### `core\strategy\domain_strategy_resolver.py`

Strategy module with 1 functions and 3 classes for algorithms and optimization

**Functions:**
- `resolve_domain_strategies()`

**Classes:**
- `DomainStrategy`
- `DomainStrategyResolver`
- `ResolvedStrategy`

**Key Imports:**
- `dataclasses`


### `core\strategy\enhanced_rst_analyzer.py`

Strategy module with 0 functions and 4 classes for algorithms and optimization

**Classes:**
- `EnhancedRSTAnalyzer`
- `MockRSTTriggerAnalyzer`
- `SecondPassResult`
- `SecondPassStrategy`

**Key Imports:**
- `asyncio`
- `dataclasses`


### `core\strategy\intelligent_strategy_generator.py`

Strategy module with 1 functions and 5 classes for algorithms and optimization

**Functions:**
- `create_intelligent_strategy_generator()`

**Classes:**
- `IntelligentStrategyGenerator`
- `IntelligentStrategyRecommendation`
- `MockRSTAnalyzer`
- `PCAPAnalysisData`
- `StrategyEffectivenessData`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `statistics`


### `core\strategy\loader.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `Strategy`
- `StrategyLoader`
- `ValidationResult`

**Key Imports:**
- `dataclasses`


### `core\strategy\next_gen_strategy_generator.py`

Strategy module with 0 functions and 9 classes for algorithms and optimization

**Classes:**
- `CrossoverType`
- `EvolutionParameters`
- `EvolutionStrategy`
- `MutationType`
- `NetworkTopologyInfo`
- `NextGenStrategyGenerator`
- `PayloadAnalysisResult`
- `StrategyChromosome`
- `StrategyGene`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`
- `hashlib`
- `statistics`


### `core\strategy\processor.py`

Strategy module with 1 functions and 3 classes for algorithms and optimization

**Functions:**
- `create_strategy_processor()`

**Classes:**
- `IStrategyProcessor`
- `StrategyConfig`
- `StrategyProcessor`

**Key Imports:**
- `abc`
- `dataclasses`
- `loader`
- `normalizer`
- `validator`


### `core\strategy\strategy_decomposer.py`

Strategy module with 2 functions and 2 classes for algorithms and optimization

**Functions:**
- `decompose_strategy()`
- `get_strategy_decomposer()`

**Classes:**
- `AttackExecutionTracker`
- `StrategyDecomposer`

**Key Imports:**
- `dataclasses`


### `core\strategy\strategy_generator.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `GeneratedStrategy`
- `GenerationMethod`
- `StrategyGenerator`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `enum`


### `core\strategy\strategy_intent_engine.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `IntentCategory`
- `StrategyIntent`
- `StrategyIntentEngine`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy\strategy_parameter_optimizer.py`

Strategy module with 0 functions and 4 classes for algorithms and optimization

**Classes:**
- `OptimizationMethod`
- `OptimizationResult`
- `ParameterRange`
- `StrategyParameterOptimizer`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy\unified_strategy_saver.py`

Strategy module with 1 functions and 1 classes for algorithms and optimization

**Functions:**
- `save_unified_strategies()`

**Classes:**
- `UnifiedStrategySaver`

**Key Imports:**
- `domain_strategy_resolver`


### `core\strategy_combinator.py`

Strategy module with 1 functions and 2 classes for algorithms and optimization

**Functions:**
- `create_default_combinator()`

**Classes:**
- `AttackComponent`
- `StrategyCombinator`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy_comparator.py`

Strategy module with 1 functions and 16 classes for algorithms and optimization

**Functions:**
- `main()`

**Classes:**
- `DiscoveryModeCapture`
- `PacketComparison`
- `PacketDiff`
- `PacketDifference`
- `RootCauseAnalysis`
- `RootCauseAnalysis`
- `RootCauseAnalyzer`
- `RootCauseAnalyzer`
- `ServiceModeCapture`
- `ServiceModeCapture`
- `StrategyCapture`
- `StrategyComparator`
- `StrategyComparatorTool`
- `StrategyComparison`
- `StrategyDiff`
- `StrategyDifference`

**Key Imports:**
- `dataclasses`
- `socket`


### `core\strategy_consistency_validator.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyConsistencyValidator`


### `core\strategy_converter_patch.py`

Strategy module with 2 functions and 0 classes for algorithms and optimization

**Functions:**
- `convert_strategy_variation_to_test_format()`
- `patch_adaptive_engine_strategy_conversion()`


### `core\strategy_diversifier.py`

Strategy module with 0 functions and 4 classes for algorithms and optimization

**Classes:**
- `AttackType`
- `DiversityMetrics`
- `StrategyDiversifier`
- `StrategyVariation`

**Key Imports:**
- `dataclasses`
- `enum`
- `hashlib`


### `core\strategy_evaluator.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `EvaluationResult`
- `StrategyEvaluator`

**Key Imports:**
- `core.connection_metrics`
- `dataclasses`


### `core\strategy_failure_analyzer.py`

Strategy module with 1 functions and 7 classes for algorithms and optimization

**Functions:**
- `create_strategy_failure_analyzer()`

**Classes:**
- `FailureCause`
- `FailureReport`
- `Recommendation`
- `Strategy`
- `StrategyFailureAnalyzer`
- `TestResult`
- `TrialArtifacts`

**Key Imports:**
- `core.packet.raw_packet_engine`
- `core.packet.raw_pcap_reader`
- `dataclasses`
- `enum`


### `core\strategy_integration_fix.py`

Strategy module with 4 functions and 2 classes for algorithms and optimization

**Functions:**
- `fix_result()`
- `fix_strategy()`
- `get_integration_fix()`
- `normalize_attack()`

**Classes:**
- `IntegrationResult`
- `StrategyIntegrationFix`

**Key Imports:**
- `dataclasses`


### `core\strategy_interpreter.py`

Strategy module with 0 functions and 5 classes for algorithms and optimization

**Classes:**
- `AttackTask`
- `DPIMethod`
- `StrategyInterpreter`
- `StrategyTranslator`
- `ZapretStrategy`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy_manager.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `DomainStrategy`
- `StrategyManager`

**Key Imports:**
- `dataclasses`


### `core\strategy_monitor.py`

Strategy module with 0 functions and 5 classes for algorithms and optimization

**Classes:**
- `AttackEffectivenessReport`
- `DPIChange`
- `EffectivenessReport`
- `Strategy`
- `StrategyMonitor`

**Key Imports:**
- `core.bypass.attacks.attack_registry`
- `core.bypass.attacks.base`
- `core.integration.attack_adapter`
- `dataclasses`
- `threading`


### `core\strategy_rule_engine.py`

Strategy module with 1 functions and 2 classes for algorithms and optimization

**Functions:**
- `create_default_rule_engine()`

**Classes:**
- `StrategyRule`
- `StrategyRuleEngine`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\strategy_selector.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `DomainRule`
- `StrategyResult`
- `StrategySelector`

**Key Imports:**
- `dataclasses`
- `fnmatch`


### `core\strategy_synthesizer.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `AttackContext`
- `StrategySynthesizer`

**Key Imports:**
- `dataclasses`


### `core\strategy_validator.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `StrategyValidator`
- `ValidationResult`
- `ValidationStatus`

**Key Imports:**
- `core.pcap.unified_analyzer`
- `dataclasses`
- `enum`


### `core\unified_engine_models.py`

Strategy module with 3 functions and 14 classes for algorithms and optimization

**Functions:**
- `create_strategy_test_result()`
- `create_validation_result()`
- `error_context()`

**Classes:**
- `BypassDefaults`
- `BypassEngineError`
- `CircuitBreakerState`
- `ConnectionError`
- `EngineState`
- `ResourceError`
- `RetryConfig`
- `StateError`
- `StrategyError`
- `StrategyTestResult`
- `TelemetrySnapshot`
- `ValidationError`
- `ValidationResult`
- `ValidationStatus`

**Key Imports:**
- `asyncio`
- `contextlib`
- `dataclasses`
- `enum`
- `socket`


### `core\unified_strategy_loader.py`

Strategy module with 3 functions and 4 classes for algorithms and optimization

**Functions:**
- `create_forced_override()`
- `load_strategies_from_file()`
- `load_strategy()`

**Classes:**
- `NormalizedStrategy`
- `StrategyLoadError`
- `StrategyValidationError`
- `UnifiedStrategyLoader`

**Key Imports:**
- `dataclasses`


### `core\validation\strategy_name_normalizer.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `StrategyNameNormalizer`


### `deep_strategy_comparison_analyzer.py`

Strategy module with 1 functions and 3 classes for algorithms and optimization

**Functions:**
- `main()`

**Classes:**
- `DeepStrategyAnalyzer`
- `PacketAnalysis`
- `StrategyApplication`

**Key Imports:**
- `dataclasses`
- `hashlib`
- `scapy.all`


### `domain_specific_strategies.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `DomainSpecificStrategies`


### `enhanced_strategy_generation_fix.py`

Strategy module with 1 functions and 3 classes for algorithms and optimization

**Functions:**
- `test_enhanced_generator()`

**Classes:**
- `CDNOptimizedAttackType`
- `EnhancedStrategy`
- `EnhancedStrategyGenerator`

**Key Imports:**
- `dataclasses`
- `enum`


### `fast_strategy_tester.py`

Strategy module with 2 functions and 1 classes for algorithms and optimization

**Functions:**
- `load_domains_from_file()`
- `main()`

**Classes:**
- `FastStrategyTester`

**Key Imports:**
- `concurrent.futures`
- `core`
- `socket`
- `ssl`


### `interfaces.py`

Strategy module with 0 functions and 11 classes for algorithms and optimization

**Classes:**
- `IAttackAdapter`
- `IClassifier`
- `IClosedLoopManager`
- `IEffectivenessTester`
- `IEvolutionarySearcher`
- `IFingerprintEngine`
- `ILearningMemory`
- `IPacketBuilder`
- `IProber`
- `IStrategyGenerator`
- `IStrategySaver`

**Key Imports:**
- `abc`
- `core.fingerprint.models`
- `recon.bypass.attacks.base`


### `ml\strategy_generator.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `AdvancedStrategyGenerator`

**Key Imports:**
- `core.domain_specific_strategies`
- `core.fingerprint.classifier`
- `core.fingerprint.models`
- `core.optimization.dynamic_parameter_optimizer`
- `ml.strategy_predictor`


### `ml\strategy_predictor.py`

Strategy module with 0 functions and 2 classes for algorithms and optimization

**Classes:**
- `StrategyPrediction`
- `StrategyPredictor`

**Key Imports:**
- `core.fingerprint.models`
- `dataclasses`
- `numpy`


### `ml\zapret_strategy_generator.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `ZapretStrategyGenerator`


### `pcap_strategy_analyzer.py`

Strategy module with 1 functions and 1 classes for algorithms and optimization

**Functions:**
- `main()`

**Classes:**
- `PCAPStrategyAnalyzer`

**Key Imports:**
- `scapy.all`


### `performance_optimizer.py`

Strategy module with 1 functions and 8 classes for algorithms and optimization

**Functions:**
- `performance_timer()`

**Classes:**
- `CacheEntry`
- `PacketBuilderOptimizer`
- `PerformanceCache`
- `PerformanceMetrics`
- `PerformanceMonitor`
- `PerformanceOptimizer`
- `StrategyPerformance`
- `StrategySelector`

**Key Imports:**
- `dataclasses`
- `hashlib`
- `statistics`
- `threading`


### `strategy_bruteforcer.py`

Strategy module with 0 functions and 3 classes for algorithms and optimization

**Classes:**
- `StrategyBruteforcer`
- `StrategyVariant`
- `TestResult`

**Key Imports:**
- `dataclasses`


### `strategy_monitor.py`

Strategy module with 0 functions and 5 classes for algorithms and optimization

**Classes:**
- `AttackEffectivenessReport`
- `DPIChange`
- `EffectivenessReport`
- `Strategy`
- `StrategyMonitor`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.effectiveness.production_effectiveness_tester`
- `core.integration.attack_adapter`
- `dataclasses`
- `threading`


### `tests\duplicate_analysis\test_documentation_properties.py`

Strategy module with 5 functions and 1 classes for algorithms and optimization

**Functions:**
- `class_node_strategy()`
- `docstring_style_strategy()`
- `function_node_strategy()`
- `function_signature_strategy()`
- `module_analysis_strategy()`

**Classes:**
- `TestDocumentationProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.documentation_generator`
- `hypothesis`
- `keyword`
- `pytest`


### `tests\duplicate_analysis\test_evidence_collector_properties.py`

Strategy module with 4 functions and 1 classes for algorithms and optimization

**Functions:**
- `code_element_strategy()`
- `dead_code_candidate_strategy()`
- `duplicate_group_strategy()`
- `function_node_strategy()`

**Classes:**
- `TestEvidenceCollectorProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.evidence_collector`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_serialization_properties.py`

Strategy module with 26 functions and 1 classes for algorithms and optimization

**Functions:**
- `analysis_results_strategy()`
- `class_node_strategy()`
- `code_signature_strategy()`
- `complexity_metrics_strategy()`
- `confidence_level_strategy()`
- `contract_strategy()`
- `datetime_strategy()`
- `dead_code_candidate_strategy()`
- `dead_code_category_strategy()`
- `duplicate_group_strategy()`
- `duplicate_type_strategy()`
- `estimated_savings_strategy()`
- `evidence_strategy()`
- `function_node_strategy()`
- `io_operation_strategy()`
- `method_passport_strategy()`
- `migration_strategy_strategy()`
- `module_card_strategy()`
- `module_status_strategy()`
- `parameter_strategy()`
- `path_strategy()`
- `project_structure_strategy()`
- `risk_level_strategy()`
- `side_effect_strategy()`
- `universalization_candidate_strategy()`
- `universalization_score_strategy()`

**Classes:**
- `TestSerializationProperties`

**Key Imports:**
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.serialization`
- `hypothesis`
- `hypothesis.strategies`
- `pytest`


### `tools\strategy_diff.py`

Strategy module with 1 functions and 3 classes for algorithms and optimization

**Functions:**
- `main()`

**Classes:**
- `DomainComparison`
- `StrategyDiffTool`
- `StrategyDifference`

**Key Imports:**
- `core.strategy.validator`
- `core.unified_strategy_loader`
- `dataclasses`


### `utils\strategy_normalizer.py`

Strategy module with 5 functions and 0 classes for algorithms and optimization

**Functions:**
- `get_strategy_complexity_score()`
- `normalize_strategy_batch()`
- `normalize_zapret_string()`
- `recommend_strategy_for_hints()`
- `validate_strategy_parameters()`


### `zapret_parser.py`

Strategy module with 0 functions and 1 classes for algorithms and optimization

**Classes:**
- `ZapretStrategyParser`



## Testing

Modules providing testing utilities, fixtures, and test helpers.

### `core\bypass\attacks\proper_testing_methodology.py`

Testing module with 0 functions and 3 classes for test utilities and fixtures

**Classes:**
- `ProperTestingMethodology`
- `SystemTestResult`
- `TestingMode`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`
- `socket`


### `core\bypass\engine\testing_mode_comparator.py`

Testing module with 0 functions and 3 classes for test utilities and fixtures

**Classes:**
- `PacketMode`
- `PacketSendingMetrics`
- `TestingModeComparator`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\filtering\load_tester.py`

Testing module with 1 functions and 3 classes for test utilities and fixtures

**Functions:**
- `run_load_test()`

**Classes:**
- `LoadTestConfig`
- `LoadTestResults`
- `LoadTester`

**Key Imports:**
- `concurrent.futures`
- `dataclasses`
- `psutil`
- `string`
- `threading`


### `core\bypass\techniques\registry.py`

Testing module with 0 functions and 4 classes for test utilities and fixtures

**Classes:**
- `FakeddisorderTechnique`
- `TechniqueInfo`
- `TechniqueRegistry`
- `TechniqueResult`

**Key Imports:**
- `core.bypass.exceptions`
- `core.bypass.types`
- `inspect`
- `primitives`


### `core\di\component_registry.py`

Testing module with 2 functions and 15 classes for test utilities and fixtures

**Functions:**
- `create_default_registry()`
- `get_global_registry()`

**Classes:**
- `ComponentRegistry`
- `IAttackAdapter`
- `IDPIEffectivenessValidator`
- `IEvolutionarySearcher`
- `IProperTestingMethodology`
- `IResultProcessor`
- `ISegmentPerformanceOptimizer`
- `IStrategyMapper`
- `MockAttackAdapter`
- `MockDPIEffectivenessValidator`
- `MockEvolutionarySearcher`
- `MockProperTestingMethodology`
- `MockResultProcessor`
- `MockSegmentPerformanceOptimizer`
- `MockStrategyMapper`

**Key Imports:**
- `core.bypass.engines.packet_processing_engine`
- `core.di.container`


### `core\domain_manager.py`

Testing module with 0 functions and 2 classes for test utilities and fixtures

**Classes:**
- `DomainManager`
- `DomainTestResult`

**Key Imports:**
- `concurrent.futures`
- `core.bypass.engine.domain_rule_registry`
- `dataclasses`
- `socket`
- `statistics`


### `core\duplicate_analysis\utils.py`

Testing module with 16 functions and 1 classes for test utilities and fixtures

**Functions:**
- `calculate_ast_hash()`
- `calculate_cyclomatic_complexity()`
- `create_directory_structure()`
- `extract_docstring()`
- `extract_tokens()`
- `find_python_files()`
- `format_file_size()`
- `get_function_signature()`
- `is_generated_file()`
- `is_test_file()`
- `normalize_ast()`
- `parse_markdown_sections()`
- `safe_read_file()`
- `setup_logging()`
- `should_ignore_file()`
- `truncate_string()`

**Classes:**
- `ASTVisitorBase`

**Key Imports:**
- `ast`
- `hashlib`


### `core\effectiveness\production_effectiveness_tester.py`

Testing module with 0 functions and 3 classes for test utilities and fixtures

**Classes:**
- `EffectivenessReport`
- `ProductionEffectivenessTester`
- `TestOutcome`

**Key Imports:**
- `dataclasses`
- `statistics`


### `core\fingerprint\fingerprint_accuracy_validator.py`

Testing module with 0 functions and 4 classes for test utilities and fixtures

**Classes:**
- `AccuracyTestResult`
- `FingerprintAccuracyValidator`
- `ValidationSummary`
- `ValidationTestCase`

**Key Imports:**
- `asyncio`
- `dataclasses`
- `statistics`


### `core\fingerprint\online_learning.py`

Testing module with 0 functions and 6 classes for test utilities and fixtures

**Classes:**
- `ABTestConfig`
- `ABTestResults`
- `LearningExample`
- `LearningMode`
- `OnlineLearningSystem`
- `PerformanceMetrics`

**Key Imports:**
- `__future__`
- `dataclasses`
- `enum`
- `numpy`
- `threading`


### `core\monitoring\accessibility_metrics.py`

Testing module with 0 functions and 5 classes for test utilities and fixtures

**Classes:**
- `AccessibilityMetricsCollector`
- `AccessibilityMetricsSummary`
- `AccessibilityTestMetric`
- `TestMethod`
- `TestResult`

**Key Imports:**
- `dataclasses`
- `enum`
- `threading`


### `core\optimization\lightweight_tester.py`

Testing module with 4 functions and 2 classes for test utilities and fixtures

**Functions:**
- `clear_active_tests()`
- `get_active_tests()`
- `get_test_stats()`
- `is_domain_being_tested()`

**Classes:**
- `LightweightStrategyTester`
- `SimpleLightweightTester`

**Key Imports:**
- `asyncio`
- `core.optimization.models`
- `subprocess`
- `threading`


### `core\pcap_analysis\packet_sequence_analyzer.py`

Testing module with 0 functions and 6 classes for test utilities and fixtures

**Classes:**
- `FakeDisorderAnalysis`
- `FakePacketAnalysis`
- `OverlapAnalysis`
- `PacketSequenceAnalyzer`
- `SplitPositionAnalysis`
- `TimingAnalysis`

**Key Imports:**
- `dataclasses`
- `packet_info`
- `statistics`


### `core\pcap_analysis\pattern_recognizer.py`

Testing module with 0 functions and 8 classes for test utilities and fixtures

**Classes:**
- `Anomaly`
- `AnomalyType`
- `EvasionPattern`
- `EvasionTechnique`
- `FakePacketPattern`
- `PacketRole`
- `PatternRecognizer`
- `SplitPattern`

**Key Imports:**
- `dataclasses`
- `enum`
- `packet_info`
- `statistics`
- `strategy_config`


### `core\real_domain_tester.py`

Testing module with 0 functions and 3 classes for test utilities and fixtures

**Classes:**
- `DomainTestReport`
- `DomainTestResult`
- `RealDomainTester`

**Key Imports:**
- `concurrent.futures`
- `core.attack_execution_engine`
- `dataclasses`
- `socket`
- `threading`


### `core\validation\curl_response_analyzer.py`

Testing module with 0 functions and 3 classes for test utilities and fixtures

**Classes:**
- `AccessibilityTestResult`
- `CurlResponseAnalyzer`
- `FallbackTestingManager`

**Key Imports:**
- `dataclasses`


### `doctor_simple.py`

Testing module with 4 functions and 0 classes for test utilities and fixtures

**Functions:**
- `main()`
- `test_core_imports()`
- `test_dataclass_definitions()`
- `test_di_container()`

**Key Imports:**
- `ast`
- `importlib`
- `traceback`


### `domain_manager.py`

Testing module with 0 functions and 2 classes for test utilities and fixtures

**Classes:**
- `DomainManager`
- `DomainTestResult`

**Key Imports:**
- `concurrent.futures`
- `dataclasses`
- `socket`
- `statistics`


### `investigate_sni_extraction_issues.py`

Testing module with 4 functions and 0 classes for test utilities and fixtures

**Functions:**
- `create_tls_clienthello_with_sni()`
- `main()`
- `test_real_world_packet_analysis()`
- `test_sni_extraction_with_different_extractors()`

**Key Imports:**
- `struct`


### `run_web_dashboard.py`

Testing module with 0 functions and 2 classes for test utilities and fixtures

**Classes:**
- `MockHybridEngine`
- `MockMonitoringSystem`

**Key Imports:**
- `asyncio`
- `web.monitoring_server`


### `tests\duplicate_analysis\test_ast_fingerprinter_properties.py`

Testing module with 0 functions and 2 classes for test utilities and fixtures

**Classes:**
- `TestASTFingerprinterProperties`
- `TestDomainAwareNormalizerProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.ast_fingerprinter`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_ast_parser.py`

Testing module with 0 functions and 2 classes for test utilities and fixtures

**Classes:**
- `TestASTNormalizer`
- `TestASTParser`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.ast_parser`
- `core.duplicate_analysis.interfaces`
- `pytest`
- `textwrap`


### `tests\duplicate_analysis\test_cli.py`

Testing module with 0 functions and 5 classes for test utilities and fixtures

**Classes:**
- `TestArgumentValidation`
- `TestCLIIntegration`
- `TestCLIParser`
- `TestConfigCreation`
- `TestMainFunction`

**Key Imports:**
- `core.duplicate_analysis.cli`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_cli_properties.py`

Testing module with 3 functions and 2 classes for test utilities and fixtures

**Functions:**
- `cli_arguments()`
- `invalid_cli_arguments()`
- `valid_project_paths()`

**Classes:**
- `TestCLIIntegrationProperties`
- `TestCLIProperties`

**Key Imports:**
- `core.duplicate_analysis.cli`
- `core.duplicate_analysis.config_manager`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_code_analyzer.py`

Testing module with 0 functions and 4 classes for test utilities and fixtures

**Classes:**
- `TestCodeAnalyzer`
- `TestFunctionAnalysis`
- `TestModuleStructureAnalysis`
- `TestUsagePattern`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.code_analyzer`
- `core.duplicate_analysis.interfaces`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_config.py`

Testing module with 0 functions and 8 classes for test utilities and fixtures

**Classes:**
- `TestAnalysisConfig`
- `TestAnalysisSettings`
- `TestConfigurationManager`
- `TestConfigurationProperties`
- `TestLoggingSetup`
- `TestProjectConfig`
- `TestQualityConfig`
- `TestThresholdConfig`

**Key Imports:**
- `core.duplicate_analysis.config`
- `core.duplicate_analysis.interfaces`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_config_integration.py`

Testing module with 1 functions and 3 classes for test utilities and fixtures

**Functions:**
- `temp_project_dir()`

**Classes:**
- `TestConfigurationIntegrationProperties`
- `TestConfigurationIntegrator`
- `TestProjectStructureConfig`

**Key Imports:**
- `core.duplicate_analysis.config_integration`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_config_manager.py`

Testing module with 0 functions and 4 classes for test utilities and fixtures

**Classes:**
- `TestConfigurationIntegration`
- `TestConfigurationManager`
- `TestConfigurationProperties`
- `TestConfigurationValidator`

**Key Imports:**
- `core.duplicate_analysis.config_manager`
- `core.duplicate_analysis.interfaces`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_config_manager_properties.py`

Testing module with 4 functions and 4 classes for test utilities and fixtures

**Functions:**
- `llm_context_strategy()`
- `markdown_section_strategy()`
- `module_registry_strategy()`
- `project_structure_strategy()`

**Classes:**
- `TestConfigurationManagerProperties`
- `TestConfigurationValidationProperties`
- `TestConfigurationValidationRobustness`
- `TestConfigurationValidatorProperties`

**Key Imports:**
- `core.duplicate_analysis.config_manager`
- `core.duplicate_analysis.interfaces`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_dead_code_detector_properties.py`

Testing module with 6 functions and 4 classes for test utilities and fixtures

**Functions:**
- `generate_call_graph_node()`
- `generate_class_node()`
- `generate_entry_point()`
- `generate_function_node()`
- `generate_module_analysis()`
- `generate_project_structure()`

**Classes:**
- `TestCallGraphProperties`
- `TestDeadCodeDetectorIntegrationProperties`
- `TestEntryPointDetectionProperties`
- `TestReachabilityAnalysisProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.dead_code_detector`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_dependency_analyzer.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestDependencyAnalyzer`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.dependency_analyzer`
- `core.duplicate_analysis.interfaces`
- `pytest`


### `tests\duplicate_analysis\test_dependency_analyzer_properties.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestDependencyAnalyzerProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.dependency_analyzer`
- `core.duplicate_analysis.interfaces`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_documentation_analyzer.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestDocumentationAnalyzer`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.documentation_analyzer`
- `core.duplicate_analysis.interfaces`
- `pytest`


### `tests\duplicate_analysis\test_duplicate_detector.py`

Testing module with 0 functions and 3 classes for test utilities and fixtures

**Classes:**
- `TestDuplicateClassifier`
- `TestDuplicateDetector`
- `TestFunctionGrouper`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.duplicate_detector`
- `core.duplicate_analysis.similarity_engine`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_duplicate_detector_properties.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestDuplicateDetectorProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.duplicate_detector`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_dynamic_case_properties.py`

Testing module with 2 functions and 1 classes for test utilities and fixtures

**Functions:**
- `generate_dynamic_function_code()`
- `generate_plugin_system_code()`

**Classes:**
- `TestDynamicCaseHandling`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.ast_parser`
- `core.duplicate_analysis.interfaces`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_end_to_end_integration.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestEndToEndIntegration`

**Key Imports:**
- `core.duplicate_analysis.cli`
- `core.duplicate_analysis.config_manager`
- `core.duplicate_analysis.integration`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_functional_equivalence_properties.py`

Testing module with 1 functions and 2 classes for test utilities and fixtures

**Functions:**
- `generate_pure_function_code()`

**Classes:**
- `TestFunctionalEquivalenceValidation`
- `TestLimitedEquivalenceValidation`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.refactoring_planner`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_integration_e2e.py`

Testing module with 0 functions and 3 classes for test utilities and fixtures

**Classes:**
- `TestEndToEndIntegration`
- `TestPerformanceValidation`
- `TestRealWorldScenarios`

**Key Imports:**
- `core.duplicate_analysis.cli`
- `core.duplicate_analysis.config_manager`
- `core.duplicate_analysis.interfaces`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_integration_layer.py`

Testing module with 0 functions and 5 classes for test utilities and fixtures

**Classes:**
- `TestDataLoader`
- `TestEnhancedModuleCategorizer`
- `TestEnhancedModuleInfo`
- `TestEnhancedRegistryBuilder`
- `TestReconIntegrationLayer`

**Key Imports:**
- `core.duplicate_analysis.enhanced_categorizer`
- `core.duplicate_analysis.enhanced_registry_builder`
- `core.duplicate_analysis.integration`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_interfaces.py`

Testing module with 0 functions and 8 classes for test utilities and fixtures

**Classes:**
- `TestClassNode`
- `TestCodeSignature`
- `TestComplexDataStructures`
- `TestDataStructureInvariants`
- `TestEnums`
- `TestFunctionNode`
- `TestModuleAnalysis`
- `TestProjectStructure`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.interfaces`
- `hypothesis`
- `pytest`
- `tests.duplicate_analysis.conftest`


### `tests\duplicate_analysis\test_metadata_extractor.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestMetadataExtractor`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.metadata_extractor`
- `pytest`
- `textwrap`


### `tests\duplicate_analysis\test_method_passport_properties.py`

Testing module with 3 functions and 1 classes for test utilities and fixtures

**Functions:**
- `generate_function_node_with_ast()`
- `generate_simple_code_signature()`
- `generate_simple_module_analysis()`

**Classes:**
- `TestMethodPassportProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.method_passport_generator`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_module_card_properties.py`

Testing module with 4 functions and 1 classes for test utilities and fixtures

**Functions:**
- `generate_class_node()`
- `generate_code_signature()`
- `generate_function_node()`
- `generate_module_analysis()`

**Classes:**
- `TestModuleCardProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.module_card_generator`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_project_scanner.py`

Testing module with 0 functions and 4 classes for test utilities and fixtures

**Classes:**
- `TestModuleHierarchy`
- `TestProjectScannerIntegration`
- `TestProjectScannerProperties`
- `TestScanConfiguration`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.project_scanner`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_quality_controller_properties.py`

Testing module with 3 functions and 4 classes for test utilities and fixtures

**Functions:**
- `evidence_strategy()`
- `quality_thresholds_strategy()`
- `suppression_rule_strategy()`

**Classes:**
- `QualityControllerStateMachine`
- `TestConfidenceLevelAssignment`
- `TestQualityControllerIntegration`
- `TestSuppressionMechanisms`

**Key Imports:**
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.quality_controller`
- `hypothesis`
- `hypothesis.stateful`
- `pytest`


### `tests\duplicate_analysis\test_refactoring_planner_properties.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestRefactoringPlannerProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.refactoring_planner`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_refactoring_validator_properties.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestRefactoringValidatorProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.refactoring_validator`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_report_generator_properties.py`

Testing module with 0 functions and 4 classes for test utilities and fixtures

**Classes:**
- `TestEnhancedReportGeneratorProperties`
- `TestExportCLIIntegration`
- `TestMultiFormatExporterProperties`
- `TestReportGeneratorEdgeCases`

**Key Imports:**
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.report_generator`
- `hypothesis`
- `pytest`


### `tests\duplicate_analysis\test_similarity_engine.py`

Testing module with 0 functions and 2 classes for test utilities and fixtures

**Classes:**
- `TestDuplicateDetector`
- `TestSimilarityEngine`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.similarity_engine`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_similarity_engine_properties.py`

Testing module with 0 functions and 1 classes for test utilities and fixtures

**Classes:**
- `TestSimilarityEngineProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.similarity_engine`
- `hypothesis`
- `pytest`
- `unittest.mock`


### `tests\duplicate_analysis\test_suppression_properties.py`

Testing module with 5 functions and 6 classes for test utilities and fixtures

**Functions:**
- `dynamic_case_rule_strategy()`
- `evidence_with_dynamics_strategy()`
- `ignore_list_entry_strategy()`
- `suppression_config_strategy()`
- `threshold_config_strategy()`

**Classes:**
- `SuppressionManagerStateMachine`
- `TestManualReviewQueue`
- `TestSuppressionConfigurationManagement`
- `TestSuppressionIntegration`
- `TestSuppressionMechanismEffectiveness`
- `TestSuppressionStatistics`

**Key Imports:**
- `core.duplicate_analysis.interfaces`
- `core.duplicate_analysis.suppression_manager`
- `hypothesis`
- `hypothesis.stateful`
- `pytest`


### `tests\duplicate_analysis\test_utils.py`

Testing module with 0 functions and 7 classes for test utilities and fixtures

**Classes:**
- `TestASTUtilities`
- `TestASTVisitorBase`
- `TestDocstringUtilities`
- `TestFileUtilities`
- `TestFormattingUtilities`
- `TestSignatureUtilities`
- `TestUtilityProperties`

**Key Imports:**
- `ast`
- `core.duplicate_analysis.utils`
- `hypothesis`
- `pytest`



## Validation

Modules responsible for data validation, verification, and compliance checking.

### `check_ipv6_support.py`

Validation module with 5 functions and 0 classes for data validation and verification

**Functions:**
- `check_ipv6_connectivity()`
- `check_ntc_party_resolution()`
- `check_script_ipv6_support()`
- `check_system_ipv6()`
- `main()`

**Key Imports:**
- `socket`
- `subprocess`


### `core\async_compat\async_sync_wrapper.py`

Validation module with 5 functions and 2 classes for data validation and verification

**Functions:**
- `async_sync_method()`
- `ensure_consistent_behavior()`
- `handle_nested_event_loop()`
- `is_async_context()`
- `run_in_thread_pool()`

**Classes:**
- `AsyncCompatibilityMixin`
- `AsyncSyncWrapper`

**Key Imports:**
- `asyncio`
- `concurrent.futures`
- `concurrent.futures`
- `inspect`
- `threading`


### `core\attack_parity\interfaces.py`

Validation module with 0 functions and 4 classes for data validation and verification

**Classes:**
- `CorrelationEngine`
- `LogParser`
- `PCAPAnalyzer`
- `ParityChecker`

**Key Imports:**
- `abc`
- `models`


### `core\attack_parity\parity_checker.py`

Validation module with 0 functions and 1 classes for data validation and verification

**Classes:**
- `ParityChecker`

**Key Imports:**
- `interfaces`
- `models`


### `core\attack_parity\parity_checker_simple.py`

Validation module with 0 functions and 1 classes for data validation and verification

**Classes:**
- `ParityChecker`

**Key Imports:**
- `interfaces`
- `models`


### `core\auto_discovery_domain_integration.py`

Validation module with 3 functions and 1 classes for data validation and verification

**Functions:**
- `configure_discovery_filtering()`
- `disable_discovery_filtering()`
- `get_integration()`

**Classes:**
- `AutoDiscoveryDomainIntegration`

**Key Imports:**
- `contextlib`
- `core.domain_filter`
- `core.domain_filter_config`
- `core.packet_filter_methods`


### `core\bypass\attacks\compatibility\backward_compatibility_manager.py`

Validation module with 2 functions and 3 classes for data validation and verification

**Functions:**
- `check_attack_compatibility()`
- `ensure_backward_compatibility()`

**Classes:**
- `BackwardCompatibilityManager`
- `CompatibilityMode`
- `CompatibilityReport`

**Key Imports:**
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`


### `core\bypass\attacks\segment_packet_builder.py`

Validation module with 3 functions and 3 classes for data validation and verification

**Functions:**
- `build_segment_packet()`
- `build_segments_batch()`
- `validate_segments_for_building()`

**Classes:**
- `SegmentPacketBuildError`
- `SegmentPacketBuilder`
- `SegmentPacketInfo`

**Key Imports:**
- `core.bypass.attacks.base`
- `core.packet_builder`
- `dataclasses`
- `socket`
- `struct`


### `core\bypass\attacks\telemetry\metrics_exporter.py`

Validation module with 0 functions and 5 classes for data validation and verification

**Classes:**
- `JSONExporter`
- `MetricsAggregator`
- `MetricsExporter`
- `MetricsFilter`
- `PrometheusExporter`

**Key Imports:**
- `abc`
- `metrics_collector`


### `core\bypass\attacks\validation\attack_validator.py`

Validation module with 0 functions and 4 classes for data validation and verification

**Classes:**
- `AttackValidator`
- `ValidationLevel`
- `ValidationReport`
- `ValidationResult`

**Key Imports:**
- `asyncio`
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`


### `core\bypass\engine\parameter_preservation_validator.py`

Validation module with 2 functions and 1 classes for data validation and verification

**Functions:**
- `ensure_complete_strategy()`
- `validate_strategy_parameters()`

**Classes:**
- `ParameterPreservationValidator`


### `core\bypass\engines\engine_validator.py`

Validation module with 5 functions and 4 classes for data validation and verification

**Functions:**
- `check_permissions()`
- `get_engine_validator()`
- `validate_dependencies()`
- `validate_engine_type()`
- `validate_parameters()`

**Classes:**
- `EngineValidator`
- `ValidationIssue`
- `ValidationResult`
- `ValidationSeverity`

**Key Imports:**
- `core.bypass.engines.base`
- `core.bypass.engines.engine_type_detector`
- `dataclasses`
- `enum`
- `platform`


### `core\bypass\engines\health_check.py`

Validation module with 1 functions and 4 classes for data validation and verification

**Functions:**
- `perform_startup_health_check()`

**Classes:**
- `EngineHealthCheck`
- `HealthCheckResult`
- `HealthStatus`
- `SystemHealthReport`

**Key Imports:**
- `dataclasses`
- `enum`
- `socket`


### `core\bypass\filtering\feature_flags.py`

Validation module with 5 functions and 6 classes for data validation and verification

**Functions:**
- `get_feature_flags()`
- `is_custom_sni_enabled()`
- `is_domain_based_filtering_enabled()`
- `is_runtime_filtering_enabled()`
- `is_runtime_ip_resolution_enabled()`

**Classes:**
- `EnumEncoder`
- `FeatureConfig`
- `FeatureFlagManager`
- `FeatureStatus`
- `RolloutMetrics`
- `RolloutStage`

**Key Imports:**
- `dataclasses`
- `enum`


### `core\bypass\filtering\runtime_filter.py`

Validation module with 0 functions and 1 classes for data validation and verification

**Classes:**
- `RuntimePacketFilter`

**Key Imports:**
- `cache`
- `config`
- `domain_matcher`
- `host_extractor`
- `sni_extractor`


### `core\bypass\packet\validation.py`

Validation module with 4 functions and 0 classes for data validation and verification

**Functions:**
- `detect_sequence_overlap()`
- `suggest_safe_offset()`
- `validate_packet_sequences()`
- `validate_seq_offset()`


### `core\bypass\safety\safety_validator.py`

Validation module with 0 functions and 5 classes for data validation and verification

**Classes:**
- `SafetyValidator`
- `ValidationCheck`
- `ValidationLevel`
- `ValidationReport`
- `ValidationResult`

**Key Imports:**
- `core.bypass.attacks.attack_definition`
- `core.bypass.attacks.base`
- `dataclasses`
- `enum`
- `threading`


### `core\bypass\validation\dpi_effectiveness_validator.py`

Validation module with 2 functions and 6 classes for data validation and verification

**Functions:**
- `get_global_validator()`
- `validate_attack_effectiveness()`

**Classes:**
- `DPIEffectivenessValidator`
- `DPISystemType`
- `DPITestTarget`
- `EffectivenessLevel`
- `EffectivenessResult`
- `ValidationReport`

**Key Imports:**
- `concurrent.futures`
- `dataclasses`
- `enum`
- `socket`
- `statistics`


### `core\bypass\validation\validator.py`

Validation module with 0 functions and 2 classes for data validation and verification

**Classes:**
- `StrategyResultValidator`
- `ValidationResult`

**Key Imports:**
- `core.validation.edge_case_handler`
- `core.validation.http_response_classifier`
- `dataclasses`


### `core\cli_payload\strategy_conflict_checker.py`

Validation module with 6 functions and 0 classes for data validation and verification

**Functions:**
- `check_parent_domain_during_testing()`
- `check_parent_domain_exists()`
- `find_strategy_conflicts()`
- `load_domain_rules()`
- `main()`
- `print_strategy_conflicts()`


### `core\cli_validation_integration.py`

Validation module with 6 functions and 0 classes for data validation and verification

**Functions:**
- `check_strategy_syntax()`
- `format_strategy_validation_output()`
- `report_validation_errors_to_user()`
- `validate_and_report_strategies()`
- `validate_generated_strategies()`
- `validate_strategy_string()`

**Key Imports:**
- `core.cli_validation_orchestrator`


### `core\config\strategy_validator.py`

Validation module with 1 functions and 3 classes for data validation and verification

**Functions:**
- `validate_configuration_file()`

**Classes:**
- `StrategyValidator`
- `ValidationIssue`
- `ValidationResult`

**Key Imports:**
- `dataclasses`
- `strategy_config_manager`


### `core\domain_filter.py`

Validation module with 0 functions and 4 classes for data validation and verification

**Classes:**
- `DomainFilter`
- `FilterMode`
- `FilterRule`
- `FilterStats`

**Key Imports:**
- `core.bypass.engine.sni_domain_extractor`
- `core.bypass.filtering.sni_extractor`
- `dataclasses`
- `enum`


### `core\duplicate_analysis\refactoring_validator.py`

Validation module with 0 functions and 6 classes for data validation and verification

**Classes:**
- `DependencyIssue`
- `RefactoringValidator`
- `RiskWarning`
- `TestPlan`
- `ValidationReport`
- `ValidationResult`

**Key Imports:**
- `ast`
- `dataclasses`
- `enum`
- `interfaces`
- `refactoring_planner`


### `core\fingerprint\analyzer_adapters.py`

Validation module with 3 functions and 10 classes for data validation and verification

**Functions:**
- `check_analyzer_availability()`
- `create_analyzer_adapter()`
- `get_available_analyzers()`

**Classes:**
- `AdvancedTCPProberAdapter`
- `AdvancedTLSProberAdapter`
- `BaseAnalyzerAdapter`
- `BehavioralProberAdapter`
- `DNSAnalyzerAdapter`
- `ECHDetectorAdapter`
- `HTTPAnalyzerAdapter`
- `MLAnalyzerAdapter`
- `RealEffectivenessTesterAdapter`
- `TCPAnalyzerAdapter`

**Key Imports:**
- `unified_models`


### `core\packet_filter_methods.py`

Validation module with 0 functions and 3 classes for data validation and verification

**Classes:**
- `PacketFilterIntegration`
- `PacketFilterMethods`
- `PacketInfo`

**Key Imports:**
- `core.bypass.engine.sni_domain_extractor`
- `core.domain_filter`
- `dataclasses`
- `struct`


### `core\packet_modification_validator.py`

Validation module with 0 functions and 2 classes for data validation and verification

**Classes:**
- `ModificationReport`
- `PacketModificationValidator`

**Key Imports:**
- `dataclasses`


### `core\packet_validator.py`

Validation module with 2 functions and 5 classes for data validation and verification

**Functions:**
- `generate_diff_report()`
- `validate_pcap()`

**Classes:**
- `PacketData`
- `PacketValidator`
- `ValidationDetail`
- `ValidationResult`
- `ValidationSeverity`

**Key Imports:**
- `dataclasses`
- `enum`
- `socket`
- `struct`


### `core\payload\validator.py`

Validation module with 0 functions and 2 classes for data validation and verification

**Classes:**
- `PayloadValidator`
- `ValidationResult`

**Key Imports:**
- `dataclasses`
- `types`


### `core\pcap\cleanup_manager.py`

Validation module with 3 functions and 1 classes for data validation and verification

**Functions:**
- `get_global_cleanup_manager()`
- `start_global_cleanup()`
- `stop_global_cleanup()`

**Classes:**
- `PCAPCleanupManager`

**Key Imports:**
- `threading`


### `core\pcap\discovery_pcap_filter.py`

Validation module with 0 functions and 2 classes for data validation and verification

**Classes:**
- `DiscoveryPCAPFilter`
- `PCAPFilterStats`

**Key Imports:**
- `core.bypass.filtering.sni_extractor`
- `core.domain_filter`
- `dataclasses`


### `core\pcap_content_validator.py`

Validation module with 1 functions and 3 classes for data validation and verification

**Functions:**
- `validate_pcap_file()`

**Classes:**
- `PCAPContentValidator`
- `PCAPValidationResult`
- `ValidationIssue`

**Key Imports:**
- `dataclasses`


### `core\retransmission_detector.py`

Validation module with 1 functions and 1 classes for data validation and verification

**Functions:**
- `check_retransmissions_in_strategy_test()`

**Classes:**
- `RetransmissionDetector`


### `core\shared_ip_sni_filter.py`

Validation module with 1 functions and 3 classes for data validation and verification

**Functions:**
- `create_shared_ip_sni_filter()`

**Classes:**
- `SharedIPFilterStats`
- `SharedIPSNIFilter`
- `SharedIPScenario`

**Key Imports:**
- `core.bypass.filtering.sni_extractor`
- `core.domain_filter`
- `dataclasses`


### `core\simple_packet_validator.py`

Validation module with 1 functions and 1 classes for data validation and verification

**Functions:**
- `quick_validate()`

**Classes:**
- `SimplePacketValidator`

**Key Imports:**
- `socket`
- `struct`


### `core\success_validator.py`

Validation module with 1 functions and 1 classes for data validation and verification

**Functions:**
- `validate_bypass_success()`

**Classes:**
- `RealSuccessValidator`

**Key Imports:**
- `socket`
- `ssl`
- `urllib.parse`


### `core\validation\compliance_checker.py`

Validation module with 0 functions and 2 classes for data validation and verification

**Classes:**
- `ComplianceChecker`
- `ComplianceReport`

**Key Imports:**
- `attack_detector`
- `dataclasses`
- `pcap_validator`
- `strategy.loader`


### `core\validation\pcap_validator.py`

Validation module with 0 functions and 2 classes for data validation and verification

**Classes:**
- `PCAPValidator`
- `TCPStream`

**Key Imports:**
- `attack_detector`
- `clienthello_parser`
- `dataclasses`
- `struct`


### `core\validation\performance_cache.py`

Validation module with 1 functions and 3 classes for data validation and verification

**Functions:**
- `create_performance_optimized_validator()`

**Classes:**
- `CacheEntry`
- `PerformanceOptimizedValidator`
- `ValidationCache`

**Key Imports:**
- `core.bypass.validation.validator`
- `core.validation.unified_validation_system`
- `dataclasses`
- `hashlib`
- `threading`


### `core\validation\result_validator.py`

Validation module with 1 functions and 3 classes for data validation and verification

**Functions:**
- `create_result_validator()`

**Classes:**
- `IResultValidator`
- `ResultValidator`
- `ValidationThresholds`

**Key Imports:**
- `abc`
- `core.unified_engine_models`
- `dataclasses`


### `core\validation\strategy_validator.py`

Validation module with 0 functions and 1 classes for data validation and verification

**Classes:**
- `StrategyValidator`

**Key Imports:**
- `core.test_result_models`
- `core.validation.strategy_name_normalizer`


### `core\validation\tls_version_checker.py`

Validation module with 0 functions and 1 classes for data validation and verification

**Classes:**
- `TLSVersionChecker`

**Key Imports:**
- `struct`


### `core\validation_utilities.py`

Validation module with 1 functions and 7 classes for data validation and verification

**Functions:**
- `create_comprehensive_validation_report()`

**Classes:**
- `CLIServiceParityValidationResult`
- `CLIServiceParityValidator`
- `DomainFilterValidationResult`
- `DomainFilterValidator`
- `SNIExtractionValidationResult`
- `SNIExtractionValidator`
- `ValidationLogger`

**Key Imports:**
- `dataclasses`
- `struct`


### `core\windivert_filter.py`

Validation module with 0 functions and 1 classes for data validation and verification

**Classes:**
- `WinDivertFilterGenerator`


### `deep_compare_testing_vs_production.py`

Validation module with 5 functions and 0 classes for data validation and verification

**Functions:**
- `analyze_tcp_stream()`
- `compare_ja3_fingerprints()`
- `compare_results()`
- `compare_with_compliance_checker()`
- `find_nnmclub_streams()`

**Key Imports:**
- `scapy.all`


### `demo_attack_validation.py`

Validation module with 10 functions and 0 classes for data validation and verification

**Functions:**
- `check_requirements()`
- `demo_parity_validation()`
- `demo_pcap_analysis()`
- `demo_quick_check()`
- `demo_real_validation()`
- `main()`
- `print_header()`
- `print_step()`
- `show_example_results()`
- `show_workflow()`


### `demo_validation_utilities.py`

Validation module with 6 functions and 0 classes for data validation and verification

**Functions:**
- `demo_cli_service_parity_validation()`
- `demo_comprehensive_validation_report()`
- `demo_domain_filter_validation()`
- `demo_sni_extraction_validation()`
- `demo_validation_logging()`
- `main()`

**Key Imports:**
- `core.validation_utilities`
- `unittest.mock`


### `gui_app_qt.py`

Validation module with 1 functions and 0 classes for data validation and verification

**Functions:**
- `check_admin()`


### `packet_modification_validator.py`

Validation module with 0 functions and 2 classes for data validation and verification

**Classes:**
- `ModificationReport`
- `PacketModificationValidator`

**Key Imports:**
- `dataclasses`


### `pcap_inspect.py`

Validation module with 10 functions and 1 classes for data validation and verification

**Functions:**
- `analyze_flow_pair()`
- `detect_injection_pair()`
- `extract_pktinfo()`
- `inspect_pcap()`
- `is_tls_clienthello()`
- `load_flows()`
- `ones_complement_sum()`
- `parse_sni()`
- `tcp_checksum()`
- `tcp_checksum_ok()`

**Classes:**
- `AttackValidator`

**Key Imports:**
- `scapy.all`
- `struct`


### `retransmission_root_cause_analyzer.py`

Validation module with 16 functions and 0 classes for data validation and verification

**Functions:**
- `analyze_retransmission_causes()`
- `analyze_retransmission_patterns()`
- `analyze_segmentation_differences()`
- `analyze_timing_differences()`
- `check_performance_issues()`
- `check_windivert_issues()`
- `extract_packet_delays()`
- `extract_packet_sequences()`
- `extract_retransmissions()`
- `extract_segment_info()`
- `extract_segment_sizes()`
- `extract_send_errors()`
- `extract_timing_metrics()`
- `generate_fix_recommendations()`
- `main()`
- `read_log_safe()`


### `run_metrics_tests.py`

Validation module with 1 functions and 0 classes for data validation and verification

**Functions:**
- `run_async_tests()`

**Key Imports:**
- `asyncio`
- `core.fingerprint.test_metrics_collector`
- `unittest`


### `setup.py`

Validation module with 7 functions and 0 classes for data validation and verification

**Functions:**
- `action_find_strategy()`
- `action_show_help()`
- `action_start_service()`
- `check_files()`
- `is_admin()`
- `run_command()`
- `show_main_menu()`

**Key Imports:**
- `core.signature_manager`
- `ctypes`
- `platform`
- `subprocess`


### `tools\manage_domain_filtering.py`

Validation module with 7 functions and 0 classes for data validation and verification

**Functions:**
- `check_status()`
- `create_rollback_point()`
- `disable_domain_filtering()`
- `enable_domain_filtering()`
- `main()`
- `set_environment_variable()`
- `setup_logging()`

**Key Imports:**
- `argparse`


### `tools\validate_domain_rules.py`

Validation module with 1 functions and 5 classes for data validation and verification

**Functions:**
- `main()`

**Classes:**
- `DomainHierarchyTester`
- `DomainRulesValidator`
- `PerformanceResult`
- `PerformanceTester`
- `ValidationResult`

**Key Imports:**
- `argparse`
- `dataclasses`
- `string`


### `tools\validate_migration_deployment.py`

Validation module with 3 functions and 4 classes for data validation and verification

**Functions:**
- `main()`
- `print_results()`
- `run_validation_suite()`

**Classes:**
- `FeatureFlagValidator`
- `MigrationValidator`
- `MonitoringValidator`
- `ValidationResult`

**Key Imports:**
- `argparse`
- `core.bypass.filtering.feature_flags`
- `core.bypass.filtering.migration`
- `core.bypass.filtering.rollout_monitor`


### `windivert_filter.py`

Validation module with 0 functions and 1 classes for data validation and verification

**Classes:**
- `WinDivertFilterGenerator`

**Key Imports:**
- `ipaddress`



## Quality Metrics

**Total Functions Analyzed:** 1367
**Total Classes Analyzed:** 2819

### Quality by Category


## Enhancement Summary

**Total Modules Analyzed:** 998
**Modules with Duplicates:** 0
**Modules with Dead Code:** 0
**Modules with Quality Metrics:** 0

### Recommendations

1. **High Priority**: Address high-confidence duplicate groups to reduce code duplication
2. **Medium Priority**: Review dead code candidates and remove confirmed unused code
3. **Low Priority**: Improve maintainability of modules with low quality scores
4. **Ongoing**: Monitor universalization candidates for potential refactoring opportunities

---

*Enhanced analysis generated on 2025-12-24 16:03:18*
*This analysis extends the base MODULE_REGISTRY.md with duplicate detection, dead code analysis, and quality metrics.*