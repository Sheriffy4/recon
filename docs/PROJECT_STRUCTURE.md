# Структура проекта Recon

Этот документ описывает структуру проекта Recon - инструмента для обхода DPI блокировок.
Документ автоматически сгенерирован анализатором структуры проекта.

## Быстрая навигация

- [Entry Points (Точки входа)](#entry-points-точки-входа)
- [Конфигурационные файлы](#конфигурационные-файлы)
- [Структура директорий](#структура-директорий)
- [Основные компоненты](#основные-компоненты)

## Entry Points (Точки входа)

Основные исполняемые файлы проекта:

- **_service.py** - Сервисный режим работы
- **abs_twimg_analysis_and_fix.py** - Исполняемый скрипт
- **adaptive_bypass_service.py** - Сервисный режим работы
- **adaptive_strategy_finder.py** - Исполняемый скрипт
- **aggressive_strategy_tester.py** - Тестовый скрипт
- **alternative_capture_solution.py** - Захват и анализ трафика
- **analyze_last_flow.py** - Исполняемый скрипт
- **analyze_pcap_simple.py** - Исполняемый скрипт
- **attack_handlers_stub.py** - Исполняемый скрипт
- **attack_parity_cli.py** - Интерфейс командной строки
- **attack_parity_validator.py** - Исполняемый скрипт
- **attack_recipe_validator_enhanced.py** - Исполняемый скрипт
- **attack_validation_example.py** - Исполняемый скрипт
- **automated_validation.py** - Исполняемый скрипт
- **build_release.py** - Сборка проекта
- **build_windows_app.py** - Сборка проекта
- **bypass_problem_investigator.py** - Обход блокировок
- **check_ipv6_support.py** - Исполняемый скрипт
- **check_pcap_domains.py** - Исполняемый скрипт
- **cleanup_project.py** - Исполняемый скрипт
- **clear_cache_and_verify.py** - Исполняемый скрипт
- **clear_recovery_history.py** - Исполняемый скрипт
- **cli.py** - Интерфейс командной строки
- **cli_analysis_report_generator.py** - Интерфейс командной строки
- **cli_integrated_monitor.py** - Интерфейс командной строки
- **cli_mode_analysis_reporter.py** - Интерфейс командной строки
- **cli_mode_tester.py** - Интерфейс командной строки
- **cli_monitor.py** - Интерфейс командной строки
- **cli_service_mode_comparator.py** - Интерфейс командной строки
- **cli_strategy_tester.py** - Интерфейс командной строки
- **compare_log_pcap.py** - Исполняемый скрипт
- **compare_test_vs_bypass_pcap.py** - Тестовый скрипт
- **comprehensive_discrepancy_analyzer.py** - Исполняемый скрипт
- **convert_strategies_to_domain_rules.py** - Исполняемый скрипт
- **copy_cli_logic_to_service.py** - Интерфейс командной строки
- **core\adaptive_state_manager.py** - Исполняемый скрипт
- **core\attack_mapping.py** - Исполняемый скрипт
- **core\attack_parity\cli.py** - Интерфейс командной строки
- **core\blocked_domain_detector.py** - Исполняемый скрипт
- **core\bypass\analytics\demo_analytics_system.py** - Исполняемый скрипт
- **core\bypass\attacks\audit\registration_audit.py** - Исполняемый скрипт
- **core\bypass\attacks\audit\run_audit.py** - Исполняемый скрипт
- **core\bypass\attacks\standardized_registration_examples.py** - Исполняемый скрипт
- **core\bypass\compatibility\demo_compatibility_layer.py** - Исполняемый скрипт
- **core\bypass\config\demo_config_migration.py** - Исполняемый скрипт
- **core\bypass\engine\service_wrapper.py** - Сервисный режим работы
- **core\bypass\engines\health_check.py** - Исполняемый скрипт
- **core\bypass\modes\demo_mode_controller.py** - Исполняемый скрипт
- **core\bypass\performance\demo_performance_optimization.py** - Исполняемый скрипт
- **core\bypass\protocols\demo_multi_port_integration.py** - Исполняемый скрипт
- **core\bypass\safety\demo_safety_framework.py** - Исполняемый скрипт
- **core\bypass\sharing\demo_sharing_system.py** - Исполняемый скрипт
- **core\bypass\strategies\pool_management_minimal.py** - Исполняемый скрипт
- **core\bypass\strategies\strategy_application.py** - Исполняемый скрипт
- **core\bypass\strategies\subdomain_handler.py** - Исполняемый скрипт
- **core\bypass\techniques\primitives_audit.py** - Исполняемый скрипт
- **core\bypass\validation\demo_reliability_validation.py** - Исполняемый скрипт
- **core\calibration\enhanced_strategy_calibrator.py** - Исполняемый скрипт
- **core\calibration\search_space_optimizer.py** - Исполняемый скрипт
- **core\cli_payload\segment_attack_cli.py** - Интерфейс командной строки
- **core\cli_payload\strategy_conflict_checker.py** - Исполняемый скрипт
- **core\config\config_migration_tool.py** - Исполняемый скрипт
- **core\config\demo_enhanced_config.py** - Исполняемый скрипт
- **core\config\strategy_validator.py** - Исполняемый скрипт
- **core\demo_modern_integration.py** - Исполняемый скрипт
- **core\discovery_combination_integration.py** - Исполняемый скрипт
- **core\discovery_config.py** - Исполняемый скрипт
- **core\discovery_controller.py** - Исполняемый скрипт
- **core\discovery_logging.py** - Исполняемый скрипт
- **core\fingerprint\advanced_fingerprinter_demo.py** - Исполняемый скрипт
- **core\fingerprint\compatibility.py** - Исполняемый скрипт
- **core\fingerprint\compatibility_demo.py** - Исполняемый скрипт
- **core\fingerprint\config.py** - Исполняемый скрипт
- **core\fingerprint\config_demo.py** - Исполняемый скрипт
- **core\fingerprint\diagnostics.py** - Исполняемый скрипт
- **core\fingerprint\dns_analyzer_demo.py** - Исполняемый скрипт
- **core\fingerprint\dpi_classifier.py** - Исполняемый скрипт
- **core\fingerprint\dpi_fingerprint_service.py** - Сервисный режим работы
- **core\fingerprint\dpi_monitor_demo.py** - Мониторинг и диагностика
- **core\fingerprint\enhanced_dpi_analyzer.py** - Исполняемый скрипт
- **core\fingerprint\enhanced_dpi_detector.py** - Исполняемый скрипт
- **core\fingerprint\final_integration.py** - Исполняемый скрипт
- **core\fingerprint\fingerprint_accuracy_validator.py** - Исполняемый скрипт
- **core\fingerprint\ml_classifier_demo.py** - Исполняемый скрипт
- **core\fingerprint\online_learning_demo.py** - Исполняемый скрипт
- **core\fingerprint\tcp_analyzer_demo.py** - Исполняемый скрипт
- **core\fingerprint\training_demo.py** - Исполняемый скрипт
- **core\hybrid_engine_fingerprinting_demo.py** - Исполняемый скрипт
- **core\monitoring\adaptive_strategy_monitor.py** - Мониторинг и диагностика
- **core\monitoring\monitoring_integration.py** - Мониторинг и диагностика
- **core\monitoring\real_time_monitor.py** - Мониторинг и диагностика
- **core\packet\attack_optimizer.py** - Исполняемый скрипт
- **core\packet\demo_final.py** - Исполняемый скрипт
- **core\packet\demo_migration.py** - Исполняемый скрипт
- **core\packet\pcap_analyzer.py** - Исполняемый скрипт
- **core\packet\performance_benchmark.py** - Исполняемый скрипт
- **core\pcap_analysis\adaptive_engine_integration.py** - Исполняемый скрипт
- **core\pcap_analysis\analysis_cache.py** - Исполняемый скрипт
- **core\pcap_analysis\analysis_cache_fixed.py** - Исполняемый скрипт
- **core\pcap_analysis\automated_workflow.py** - Исполняемый скрипт
- **core\pcap_analysis\cli.py** - Интерфейс командной строки
- **core\pcap_analysis\deployment\production_config.py** - Исполняемый скрипт
- **core\pcap_analysis\deployment\production_deployment.py** - Исполняемый скрипт
- **core\pcap_analysis\intelligent_pcap_analyzer.py** - Исполняемый скрипт
- **core\pcap_analysis\memory_optimizer.py** - Исполняемый скрипт
- **core\pcap_analysis\monitoring\health_monitor.py** - Мониторинг и диагностика
- **core\pcap_analysis\parallel_processor.py** - Исполняемый скрипт
- **core\pcap_analysis\pcap_strategy_generator.py** - Исполняемый скрипт
- **core\pcap_analysis\performance_integration.py** - Исполняемый скрипт
- **core\pcap_analysis\sequence_analysis_demo.py** - Исполняемый скрипт
- **core\pcap_analysis\strategy_integration_example.py** - Исполняемый скрипт
- **core\pcap_analysis\streaming_processor.py** - Исполняемый скрипт
- **core\pcap_analysis\system_validation.py** - Исполняемый скрипт
- **core\pcap_analysis\workflow_cli.py** - Интерфейс командной строки
- **core\pcap_analysis\workflow_config_manager.py** - Исполняемый скрипт
- **core\pcap_analysis\workflow_integration.py** - Исполняемый скрипт
- **core\pcap_analysis\workflow_scheduler.py** - Исполняемый скрипт
- **core\pcap_analysis_cli.py** - Интерфейс командной строки
- **core\refactoring\file_scanner.py** - Исполняемый скрипт
- **core\refactoring\llm_context_generator.py** - Исполняемый скрипт
- **core\refactoring\safe_remover.py** - Исполняемый скрипт
- **core\refactoring\structure_analyzer.py** - Исполняемый скрипт
- **core\results_collector.py** - Исполняемый скрипт
- **core\strategy\domain_strategy_resolver.py** - Исполняемый скрипт
- **core\strategy\enhanced_rst_analyzer.py** - Исполняемый скрипт
- **core\strategy\intelligent_combination_generator.py** - Исполняемый скрипт
- **core\strategy\intelligent_strategy_generator.py** - Исполняемый скрипт
- **core\strategy\intent_attack_mapper.py** - Исполняемый скрипт
- **core\strategy\smart_attack_combinator.py** - Исполняемый скрипт
- **core\strategy\strategy_generator.py** - Исполняемый скрипт
- **core\strategy\strategy_intent_engine.py** - Исполняемый скрипт
- **core\strategy\strategy_parameter_optimizer.py** - Исполняемый скрипт
- **core\strategy\strategy_rule_engine.py** - Исполняемый скрипт
- **core\strategy\strategy_rule_engine_fixed.py** - Исполняемый скрипт
- **core\strategy\unified_strategy_saver.py** - Исполняемый скрипт
- **core\strategy_combinator.py** - Исполняемый скрипт
- **core\strategy_comparator.py** - Исполняемый скрипт
- **core\strategy_diversifier.py** - Исполняемый скрипт
- **core\strategy_integration_helper.py** - Исполняемый скрипт
- **core\strategy_interpreter.py** - Исполняемый скрипт
- **core\strategy_rule_engine.py** - Исполняемый скрипт
- **core\strategy_selector_demo.py** - Исполняемый скрипт
- **core\validation\results_validation_system.py** - Исполняемый скрипт
- **create_clean_strategy.py** - Исполняемый скрипт
- **create_icon.py** - Исполняемый скрипт
- **create_real_tls_clienthello.py** - Интерфейс командной строки
- **create_shortcut.py** - Исполняемый скрипт
- **deep_analyze_test_connection.py** - Тестовый скрипт
- **deep_attack_analysis.py** - Исполняемый скрипт
- **deep_compare_testing_vs_production.py** - Тестовый скрипт
- **deep_pcap_analysis.py** - Исполняемый скрипт
- **deep_pcap_analyzer.py** - Исполняемый скрипт
- **deep_pcap_compare.py** - Исполняемый скрипт
- **deep_strategy_analysis.py** - Исполняемый скрипт
- **deep_strategy_comparison_analyzer.py** - Исполняемый скрипт
- **demo_attack_validation.py** - Исполняемый скрипт
- **demo_validation_utilities.py** - Исполняемый скрипт
- **deployment\full_deployment.py** - Исполняемый скрипт
- **deployment\production_deployment_manager.py** - Исполняемый скрипт
- **deployment\service_mode_deployment.py** - Сервисный режим работы
- **detailed_attack_analysis.py** - Исполняемый скрипт
- **doctor.py** - Диагностика проблем
- **doctor_simple.py** - Диагностика проблем
- **dpi_attack_verification.py** - Исполняемый скрипт
- **dpi_deep_analysis.py** - Исполняемый скрипт
- **emergency_rollback.py** - Исполняемый скрипт
- **enhanced_cli.py** - Интерфейс командной строки
- **enhanced_domain_strategy_analyzer.py** - Исполняемый скрипт
- **enhanced_find_rst_triggers.py** - Исполняемый скрипт
- **enhanced_find_rst_triggers_standalone.py** - Исполняемый скрипт
- **enhanced_strategy_generation_fix.py** - Исполняемый скрипт
- **enhanced_strategy_generator.py** - Исполняемый скрипт
- **examples\comprehensive_logging_demo.py** - Исполняемый скрипт
- **examples\demo_dns_attacks.py** - Исполняемый скрипт
- **examples\demo_http_attacks.py** - Исполняемый скрипт
- **examples\demo_timing_attacks.py** - Исполняемый скрипт
- **examples\demo_tls_evasion.py** - Исполняемый скрипт
- **examples\discovery_config_example.py** - Исполняемый скрипт
- **examples\domain_unification_demo.py** - Исполняемый скрипт
- **examples\engine_dry_run_example.py** - Исполняемый скрипт
- **examples\faked_disorder_attack_example.py** - Исполняемый скрипт
- **examples\fingerprinting_demo.py** - Исполняемый скрипт
- **examples\lazy_loading_example.py** - Исполняемый скрипт
- **examples\metrics_endpoint_example.py** - Исполняемый скрипт
- **examples\migration_examples_before_after.py** - Исполняемый скрипт
- **examples\multisplit_attack_example.py** - Исполняемый скрипт
- **examples\native_engine_segments_example.py** - Исполняемый скрипт
- **examples\online_analysis_demo.py** - Исполняемый скрипт
- **examples\packet_construction_transmission_example.py** - Исполняемый скрипт
- **examples\performance_optimization_demo.py** - Исполняемый скрипт
- **examples\production_monitoring_example.py** - Мониторинг и диагностика
- **examples\reference_attacks_showcase.py** - Исполняемый скрипт
- **examples\segment_diagnostics_example.py** - Исполняемый скрипт
- **examples\segment_execution_stats_example.py** - Исполняемый скрипт
- **examples\segment_packet_builder_example.py** - Сборка проекта
- **examples\segment_performance_optimization_example.py** - Исполняемый скрипт
- **examples\segments_usage_example.py** - Исполняемый скрипт
- **examples\tcp_session_context_example.py** - Исполняемый скрипт
- **examples\tls_version_diagnostics_demo.py** - Исполняемый скрипт
- **examples\unified_validation_demo.py** - Исполняемый скрипт
- **extract_working_strategy.py** - Исполняемый скрипт
- **fast_strategy_tester.py** - Тестовый скрипт
- **find_rst_triggers.py** - Исполняемый скрипт
- **flow_based_pcap_analyzer.py** - Исполняемый скрипт
- **force_adaptive_analysis.py** - Исполняемый скрипт
- **generate_clienthello_report.py** - Интерфейс командной строки
- **generate_module_registry.py** - Исполняемый скрипт
- **generate_project_structure.py** - Исполняемый скрипт
- **generate_service_analysis_report.py** - Сервисный режим работы
- **get_ips.py** - Исполняемый скрипт
- **global_refactoring_orchestrator.py** - Исполняемый скрипт
- **gui\improved_main_window.py** - Исполняемый скрипт
- **gui\main_window.py** - Исполняемый скрипт
- **gui_app.py** - Графический интерфейс пользователя
- **gui_app_qt.py** - Графический интерфейс пользователя
- **improved_attack_validation.py** - Исполняемый скрипт
- **improved_log_parser.py** - Исполняемый скрипт
- **improved_timeout_handler.py** - Исполняемый скрипт
- **infrastructure_setup.py** - Установка и настройка
- **install_pydivert.py** - Установка и настройка
- **intelligent_bypass_monitor.py** - Мониторинг и диагностика
- **investigate_cli_auto_domain_filtering.py** - Интерфейс командной строки
- **investigate_sni_extraction_issues.py** - Исполняемый скрипт
- **load_all_attacks.py** - Исполняемый скрипт
- **log_pcap_comparison_tool.py** - Исполняемый скрипт
- **log_pcap_validator.py** - Исполняемый скрипт
- **manual_badseq_pcap_verification.py** - Исполняемый скрипт
- **migrate_domain_rules.py** - Исполняемый скрипт
- **migrate_domain_rules_add_attacks.py** - Исполняемый скрипт
- **minimal_service.py** - Сервисный режим работы
- **ml\fingerprint_aware_strategy_demo.py** - Исполняемый скрипт
- **monitor.py** - Мониторинг и диагностика
- **monitor_attack_performance.py** - Мониторинг и диагностика
- **monitor_deployment.py** - Мониторинг и диагностика
- **monitor_service_logs.py** - Сервисный режим работы
- **monitoring\post_deployment_log_monitor.py** - Мониторинг и диагностика
- **monitoring\production_monitoring_system.py** - Мониторинг и диагностика
- **multi_domain_bypass_tester.py** - Тестовый скрипт
- **network_behavior_analyzer.py** - Исполняемый скрипт
- **patch_attack_validation.py** - Исполняемый скрипт
- **pcap_attack_analyzer.py** - Исполняемый скрипт
- **pcap_inspect.py** - Исполняемый скрипт
- **pcap_monitor.py** - Мониторинг и диагностика
- **pcap_strategy_analyzer.py** - Исполняемый скрипт
- **pcap_to_json_analyzer.py** - Исполняемый скрипт
- **performance_monitor_script.py** - Мониторинг и диагностика
- **profile_baseline_manager.py** - Исполняемый скрипт
- **profile_cli_validation.py** - Интерфейс командной строки
- **project.py** - Исполняемый скрипт
- **quick_attack_check.py** - Исполняемый скрипт
- **quick_pcap_analysis.py** - Исполняемый скрипт
- **quick_pcap_check.py** - Исполняемый скрипт
- **real_attack_validation.py** - Исполняемый скрипт
- **recon_service.py** - Сервисный режим работы
- **refactoring_reporter.py** - Исполняемый скрипт
- **refactoring_validator.py** - Исполняемый скрипт
- **reload_modules.py** - Исполняемый скрипт
- **restart_service_with_new_config.py** - Сервисный режим работы
- **retransmission_root_cause_analyzer.py** - Исполняемый скрипт
- **run_dashboard.py** - Исполняемый скрипт
- **run_metrics_tests.py** - Тестовый скрипт
- **run_performance_profiling.py** - Исполняемый скрипт
- **run_service_log_pcap_comparison.py** - Сервисный режим работы
- **run_service_mode_tests.py** - Сервисный режим работы
- **run_validation_tests.py** - Тестовый скрипт
- **run_web_dashboard.py** - Исполняемый скрипт
- **runtime_attack_patcher.py** - Исполняемый скрипт
- **service_strategy_tester.py** - Сервисный режим работы
- **setup.py** - Установка и настройка
- **setup_advanced.py** - Установка и настройка
- **setup_hosts_bypass.py** - Установка и настройка
- **show_all_domains_in_pcap.py** - Исполняемый скрипт
- **simple_cli.py** - Интерфейс командной строки
- **simple_pcap_analysis.py** - Исполняемый скрипт
- **simple_service.py** - Сервисный режим работы
- **start_adaptive_monitoring.py** - Мониторинг и диагностика
- **start_and_monitor_service.py** - Сервисный режим работы
- **start_service_utf8.py** - Сервисный режим работы
- **strategy_mismatch_root_cause_analyzer.py** - Исполняемый скрипт
- **strategy_sync_tool.py** - Исполняемый скрипт
- **subdomain_detector.py** - Исполняемый скрипт
- **tools\analyze_disorder_pcap.py** - Исполняемый скрипт
- **tools\analyze_seqovl_pcap.py** - Исполняемый скрипт
- **tools\audit_attack_application.py** - Исполняемый скрипт
- **tools\audit_disorder_attack.py** - Исполняемый скрипт
- **tools\audit_fake_attack.py** - Исполняемый скрипт
- **tools\audit_multisplit_attack.py** - Исполняемый скрипт
- **tools\audit_seqovl_attack.py** - Исполняемый скрипт
- **tools\capture_disorder_pcap.py** - Захват и анализ трафика
- **tools\capture_seqovl_pcap.py** - Захват и анализ трафика
- **tools\check_domain_config_syntax.py** - Исполняемый скрипт
- **tools\deduplicate_pcap.py** - Исполняемый скрипт
- **tools\extract_insights.py** - Исполняемый скрипт
- **tools\extract_recon_insights.py** - Исполняемый скрипт
- **tools\extract_run_insights.py** - Исполняемый скрипт
- **tools\health_check.py** - Исполняемый скрипт
- **tools\manage_domain_filtering.py** - Исполняемый скрипт
- **tools\manage_feature_flags.py** - Исполняемый скрипт
- **tools\migrate_filtering_config.py** - Исполняемый скрипт
- **tools\migrate_to_domain_rules.py** - Исполняемый скрипт
- **tools\migration_validation_tool.py** - Исполняемый скрипт
- **tools\mode_validator.py** - Исполняемый скрипт
- **tools\pcap_compare.py** - Исполняемый скрипт
- **tools\remove_frame_delta_duplicates.py** - Исполняемый скрипт
- **tools\smart_pcap_dedup.py** - Исполняемый скрипт
- **tools\strategy_bruteforce.py** - Исполняемый скрипт
- **tools\strategy_diff.py** - Исполняемый скрипт
- **tools\validate_domain_rules.py** - Исполняемый скрипт
- **tools\validate_migration_deployment.py** - Исполняемый скрипт
- **tools\verify_bypass_pcap.py** - Обход блокировок
- **tools\view_metrics.py** - Исполняемый скрипт
- **trace_deps.py** - Исполняемый скрипт
- **unify_attack_execution.py** - Исполняемый скрипт
- **unify_attack_execution_final.py** - Исполняемый скрипт
- **utils\strategy_normalizer.py** - Исполняемый скрипт
- **web\bypass_integration.py** - Обход блокировок
- **web\demo_web_integration.py** - Исполняемый скрипт
- **working_adaptive_monitor.py** - Мониторинг и диагностика

## Конфигурационные файлы

Файлы конфигурации проекта:

### .CONF файлы

- **zapret_tls_sni.conf** - Общая конфигурация приложения

### .INI файлы

- **pytest.ini** - Конфигурация тестирования

### .JSON файлы

- **aiohttp_config.json** - Общая конфигурация приложения
- **baselines\baseline_v1.json** - Общая конфигурация приложения
- **baselines\current_baseline.json** - Общая конфигурация приложения
- **baselines\my_baseline_v1.json** - Общая конфигурация приложения
- **baselines\tcp_tls_baseline.json** - Общая конфигурация приложения
- **baselines\x_com_with_fingerprint.json** - Общая конфигурация приложения
- **best_strategy.json** - Конфигурация обхода блокировок
- **bypass_configs\shadowsocks_client.json** - Общая конфигурация приложения
- **bypass_configs\v2ray_client.json** - Общая конфигурация приложения
- **config\combination_attacks.json** - Общая конфигурация приложения
- **config\doh_config.json** - Общая конфигурация приложения
- **config\domain_filter.json** - Общая конфигурация приложения
- **config\dpi_strategy_config.json** - Конфигурация обхода блокировок
- **config\engine_config.json** - Общая конфигурация приложения
- **config\engine_config_development.json** - Общая конфигурация приложения
- **config\engine_config_production.json** - Общая конфигурация приложения
- **config\enhanced_strategies_v3.json** - Общая конфигурация приложения
- **config\feature_flags.json** - Общая конфигурация приложения
- **core\bypass\strategies\subdomain_config.json** - Общая конфигурация приложения
- **core\config\examples\enhanced_config_v3.json** - Общая конфигурация приложения
- **core\config\examples\legacy_config_v2.json** - Общая конфигурация приложения
- **core\pcap_analysis\batch_config_example.json** - Общая конфигурация приложения
- **core\pcap_analysis\example_config.json** - Общая конфигурация приложения
- **core\recon\data\attack_registry.json** - Общая конфигурация приложения
- **data\adaptive_knowledge.json** - Общая конфигурация приложения
- **data\attack_registry.json** - Общая конфигурация приложения
- **data\payloads\bundled\index.json** - Общая конфигурация приложения
- **data\probe_cache.json** - Общая конфигурация приложения
- **data\reasoning_logs\reasoning_mail.ru_20251214_220759.json** - Общая конфигурация приложения
- **data\reasoning_logs\reasoning_mail.ru_20251215_012518.json** - Общая конфигурация приложения
- **data\reasoning_logs\reasoning_mail.ru_20251215_013005.json** - Общая конфигурация приложения
- **data\reasoning_logs\reasoning_nnmclub.to_20251214_223939.json** - Общая конфигурация приложения
- **data\reasoning_logs\reasoning_nnmclub.to_20251214_224947.json** - Общая конфигурация приложения
- **data\reasoning_logs\reasoning_nnmclub.to_20251215_012121.json** - Общая конфигурация приложения
- **data\reasoning_logs\summary_mail.ru_20251214_220759.json** - Общая конфигурация приложения
- **data\reasoning_logs\summary_mail.ru_20251215_012518.json** - Общая конфигурация приложения
- **data\reasoning_logs\summary_mail.ru_20251215_013005.json** - Общая конфигурация приложения
- **data\reasoning_logs\summary_nnmclub.to_20251214_223939.json** - Общая конфигурация приложения
- **data\reasoning_logs\summary_nnmclub.to_20251214_224947.json** - Общая конфигурация приложения
- **data\reasoning_logs\summary_nnmclub.to_20251215_012121.json** - Общая конфигурация приложения
- **data\test_reasoning_logs\reasoning_test.com_20251214_192023.json** - Конфигурация тестирования
- **data\test_reasoning_logs\reasoning_test.com_20251214_192039.json** - Конфигурация тестирования
- **data\test_reasoning_logs\summary_test.com_20251214_192039.json** - Конфигурация тестирования
- **data\validation_reports\validation_results_mail_ru_20251214_220824.json** - Конфигурация валидации
- **data\validation_reports\validation_results_mail_ru_20251214_220831.json** - Конфигурация валидации
- **data\validation_reports\validation_results_mail_ru_20251214_220837.json** - Конфигурация валидации
- **data\validation_reports\validation_results_mail_ru_20251215_012604.json** - Конфигурация валидации
- **data\validation_reports\validation_results_mail_ru_20251215_012610.json** - Конфигурация валидации
- **data\validation_reports\validation_results_mail_ru_20251215_012616.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251214_224001.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251214_224017.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251214_224033.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251214_225024.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251214_225040.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251214_225056.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251215_012158.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251215_012214.json** - Конфигурация валидации
- **data\validation_reports\validation_results_nnmclub_to_20251215_012230.json** - Конфигурация валидации
- **demo_baselines\current_baseline.json** - Общая конфигурация приложения
- **demo_baselines\demo_baseline.json** - Общая конфигурация приложения
- **doh_cache.json** - Общая конфигурация приложения
- **domain_rules.json** - Общая конфигурация приложения
- **domain_strategies.json** - Общая конфигурация приложения
- **dpi_fingerprints.json** - Общая конфигурация приложения
- **dpi_signatures.json** - Общая конфигурация приложения
- **examples\advanced_domain_patterns.json** - Общая конфигурация приложения
- **examples\basic_runtime_filtering.json** - Общая конфигурация приложения
- **examples\custom_sni_configuration.json** - Общая конфигурация приложения
- **examples\performance_optimized.json** - Общая конфигурация приложения
- **gui_settings.json** - Конфигурация интерфейса
- **knowledge\pattern_rules.json** - Общая конфигурация приложения
- **metrics\attack_parity_metrics.json** - Конфигурация мониторинга
- **monitoring_config.json** - Конфигурация мониторинга
- **negative_knowledge.json** - Общая конфигурация приложения
- **optimized_fingerprinting_config.json** - Общая конфигурация приложения
- **packets.json** - Общая конфигурация приложения
- **pool_config.json** - Конфигурация пулов соединений
- **real_data_validation\real_data_validation_report_20251020_122856.json** - Конфигурация валидации
- **real_data_validation\real_data_validation_report_20251020_123449.json** - Конфигурация валидации
- **recon_summary.json** - Общая конфигурация приложения
- **service_test_results\service_log_pcap_comparison_20251217_172057.json** - Конфигурация логирования
- **service_test_results\service_test_results_20251217_171552.json** - Конфигурация тестирования
- **service_test_results\service_test_results_20251217_171916.json** - Конфигурация тестирования
- **strategies_enhanced.json** - Общая конфигурация приложения
- **subdomain_config.json** - Общая конфигурация приложения
- **suggested_parameter_mappings.json** - Общая конфигурация приложения
- **timeout_config.json** - Конфигурация таймаутов
- **trusted_sources.json** - Общая конфигурация приложения
- **validation_config.json** - Конфигурация валидации

### .TOML файлы

- **pyproject.toml** - Конфигурация Python проекта

### .YAML файлы

- **.pre-commit-config.yaml** - Системная конфигурация
- **bypass_configs\clash.yaml** - Общая конфигурация приложения
- **core\pcap_analysis\deployment\kubernetes\configmap.yaml** - Общая конфигурация приложения
- **core\pcap_analysis\deployment\kubernetes\deployment.yaml** - Общая конфигурация приложения
- **core\pcap_analysis\deployment\kubernetes\namespace.yaml** - Общая конфигурация приложения
- **core\pcap_analysis\deployment\kubernetes\pvc.yaml** - Общая конфигурация приложения
- **core\pcap_analysis\deployment\kubernetes\service.yaml** - Общая конфигурация приложения
- **flet_build.yaml** - Конфигурация интерфейса
- **specs\attacks\disorder.yaml** - Общая конфигурация приложения
- **specs\attacks\fake.yaml** - Общая конфигурация приложения
- **specs\attacks\fakeddisorder.yaml** - Общая конфигурация приложения
- **specs\attacks\multidisorder.yaml** - Общая конфигурация приложения
- **specs\attacks\multisplit.yaml** - Общая конфигурация приложения
- **specs\attacks\quic_bypass.yaml** - Конфигурация интерфейса
- **specs\attacks\seqovl.yaml** - Общая конфигурация приложения
- **specs\attacks\simple_fragment.yaml** - Общая конфигурация приложения
- **specs\attacks\split.yaml** - Общая конфигурация приложения
- **specs\attacks\stun_bypass.yaml** - Конфигурация обхода блокировок
- **specs\attacks\tcp_options_modification.yaml** - Общая конфигурация приложения
- **specs\attacks\udp_fragmentation.yaml** - Общая конфигурация приложения
- **specs\attacks\window_manipulation.yaml** - Общая конфигурация приложения

### .YML файлы

- **core\pcap_analysis\deployment\docker-compose.yml** - Конфигурация Docker

## Структура директорий

Описание основных директорий проекта:

### Корневая директория

**Назначение:** Тесты и тестирование
**Файлов:** 248
**Тип:** Python пакет
**Основные типы файлов:** .py, .txt, .json
**Поддиректории:** .kiro, attack_validation, baselines, bypass_configs, cli_test_results, config, core, data, demo_baselines, deployment, docs, examples, gui, knowledge, logs, metrics, ml, monitoring, pcap, pcap_failures, platform, real_data_validation, recon_dpi_tool.egg-info, recon_pcap, reports, service_test_results, specs, state_backups, temp, temp_pcap, tests, tools, tunnels, utils, validation_results, web, workflow_configs

### .kiro

**Назначение:** Пустая директория
**Файлов:** 0
**Поддиректории:** specs

### .kiro\specs

**Назначение:** Пустая директория
**Файлов:** 0
**Поддиректории:** attack-application-parity, attack-recipe-consistency, auto-strategy-discovery, cli-auto-mode-fixes, dpi-strategy-fix, duplicate-functionality-analysis, enhanced-strategy-generation, fake-payload-generation, false-positive-validation-fix, global-refactoring, log-pcap-validation, pcap-validator-combo-detection, site-accessibility-testing-fix, strategy-application-bugs, strategy-conversion-logging-cleanup, strategy-optimization, strategy-testing-production-parity, unified-attack-dispatcher, unified-engine-refactoring, url-parameter-bypass

### .kiro\specs\attack-application-parity

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\attack-recipe-consistency

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\auto-strategy-discovery

**Назначение:** Документация
**Файлов:** 5
**Основные типы файлов:** .md

### .kiro\specs\cli-auto-mode-fixes

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\dpi-strategy-fix

**Назначение:** Документация
**Файлов:** 1
**Основные типы файлов:** .md

### .kiro\specs\duplicate-functionality-analysis

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\enhanced-strategy-generation

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\fake-payload-generation

**Назначение:** Документация
**Файлов:** 4
**Основные типы файлов:** .md

### .kiro\specs\false-positive-validation-fix

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\global-refactoring

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\log-pcap-validation

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\pcap-validator-combo-detection

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\site-accessibility-testing-fix

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\strategy-application-bugs

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\strategy-conversion-logging-cleanup

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\strategy-optimization

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\strategy-testing-production-parity

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\unified-attack-dispatcher

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\unified-engine-refactoring

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### .kiro\specs\url-parameter-bypass

**Назначение:** Документация
**Файлов:** 3
**Основные типы файлов:** .md

### attack_validation

**Назначение:** Пустая директория
**Файлов:** 0

### baselines

**Назначение:** Конфигурационные файлы
**Файлов:** 5
**Основные типы файлов:** .json
**Поддиректории:** archive

### baselines\archive

**Назначение:** Пустая директория
**Файлов:** 0

### bypass_configs

**Назначение:** Конфигурационные файлы
**Файлов:** 3
**Основные типы файлов:** .json, .yaml

### cli_test_results

**Назначение:** Пустая директория
**Файлов:** 0

### config

**Назначение:** Конфигурационные файлы
**Файлов:** 9
**Основные типы файлов:** .json

### core

**Назначение:** Основной код приложения
**Файлов:** 93
**Тип:** Python пакет
**Основные типы файлов:** .py
**Поддиректории:** async, async_compat, async_utils, attack_parity, bypass, caching, calibration, cli_payload, config, di, diagnostics, dns, effectiveness, fingerprint, infrastructure, integration, intelligence, knowledge, learning, logging, metrics, monitoring, net, optimization, optimizer, orchestration, packet, payload, pcap, pcap_analysis, performance, protocols, recon, refactoring, reporting, session, state_management, strategy, telemetry, validation, verification, workflow

### core\async

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\async_compat

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\async_utils

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\attack_parity

**Назначение:** Смешанные файлы проекта
**Файлов:** 13
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass

**Назначение:** Обход блокировок
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py
**Поддиректории:** analytics, attacks, compatibility, config, diagnostics, engine, engines, filtering, flow, hybrid, integration, modes, monitoring, packet, performance, pipeline, protocols, safety, sharing, sni, strategies, techniques, telemetry, validation

### core\bypass\analytics

**Назначение:** Смешанные файлы проекта
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks

**Назначение:** Атаки и обход блокировок
**Файлов:** 27
**Тип:** Python пакет
**Основные типы файлов:** .py
**Поддиректории:** audit, base_classes, combo, compatibility, dns, http, ip, obfuscation, payload, performance, tcp, telemetry, timing, tls, tunneling, udp, validation

### core\bypass\attacks\audit

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\base_classes

**Назначение:** Смешанные файлы проекта
**Файлов:** 7
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\combo

**Назначение:** Смешанные файлы проекта
**Файлов:** 16
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\compatibility

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Основные типы файлов:** .py

### core\bypass\attacks\dns

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\http

**Назначение:** Смешанные файлы проекта
**Файлов:** 6
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\ip

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\obfuscation

**Назначение:** Смешанные файлы проекта
**Файлов:** 7
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\payload

**Назначение:** Смешанные файлы проекта
**Файлов:** 6
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\performance

**Назначение:** Смешанные файлы проекта
**Файлов:** 6
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\tcp

**Назначение:** Смешанные файлы проекта
**Файлов:** 9
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\telemetry

**Назначение:** Смешанные файлы проекта
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\timing

**Назначение:** Смешанные файлы проекта
**Файлов:** 5
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\tls

**Назначение:** Смешанные файлы проекта
**Файлов:** 10
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\tunneling

**Назначение:** Смешанные файлы проекта
**Файлов:** 5
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\udp

**Назначение:** Смешанные файлы проекта
**Файлов:** 5
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\attacks\validation

**Назначение:** Валидация и проверки
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\compatibility

**Назначение:** Смешанные файлы проекта
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\config

**Назначение:** Конфигурационные файлы
**Файлов:** 7
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\diagnostics

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\engine

**Назначение:** Смешанные файлы проекта
**Файлов:** 24
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\engines

**Назначение:** Смешанные файлы проекта
**Файлов:** 19
**Тип:** Python пакет
**Основные типы файлов:** .py, .txt

### core\bypass\filtering

**Назначение:** Смешанные файлы проекта
**Файлов:** 14
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\flow

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\hybrid

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\integration

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\modes

**Назначение:** Смешанные файлы проекта
**Файлов:** 6
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\monitoring

**Назначение:** Мониторинг и метрики
**Файлов:** 1
**Основные типы файлов:** .py

### core\bypass\packet

**Назначение:** Смешанные файлы проекта
**Файлов:** 6
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\performance

**Назначение:** Смешанные файлы проекта
**Файлов:** 9
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\pipeline

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\protocols

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\safety

**Назначение:** Смешанные файлы проекта
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\sharing

**Назначение:** Смешанные файлы проекта
**Файлов:** 7
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\sni

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\strategies

**Назначение:** Стратегии обхода
**Файлов:** 19
**Тип:** Python пакет
**Основные типы файлов:** .py, .json

### core\bypass\techniques

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Основные типы файлов:** .py

### core\bypass\telemetry

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\bypass\validation

**Назначение:** Валидация и проверки
**Файлов:** 4
**Основные типы файлов:** .py

### core\caching

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\calibration

**Назначение:** Смешанные файлы проекта
**Файлов:** 5
**Основные типы файлов:** .py

### core\cli_payload

**Назначение:** Смешанные файлы проекта
**Файлов:** 10
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\config

**Назначение:** Конфигурационные файлы
**Файлов:** 6
**Тип:** Python пакет
**Основные типы файлов:** .py
**Поддиректории:** examples

### core\config\examples

**Назначение:** Конфигурационные файлы
**Файлов:** 2
**Основные типы файлов:** .json

### core\di

**Назначение:** Смешанные файлы проекта
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\diagnostics

**Назначение:** Смешанные файлы проекта
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\dns

**Назначение:** Смешанные файлы проекта
**Файлов:** 5
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\effectiveness

**Назначение:** Смешанные файлы проекта
**Файлов:** 1
**Основные типы файлов:** .py

### core\fingerprint

**Назначение:** Смешанные файлы проекта
**Файлов:** 51
**Тип:** Python пакет
**Основные типы файлов:** .py
**Поддиректории:** training_data

### core\fingerprint\training_data

**Назначение:** Пустая директория
**Файлов:** 0

### core\infrastructure

**Назначение:** Смешанные файлы проекта
**Файлов:** 5
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\integration

**Назначение:** Смешанные файлы проекта
**Файлов:** 25
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\intelligence

**Назначение:** Смешанные файлы проекта
**Файлов:** 1
**Основные типы файлов:** .py

### core\knowledge

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\learning

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\logging

**Назначение:** Логи и журналирование
**Файлов:** 7
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\metrics

**Назначение:** Мониторинг и метрики
**Файлов:** 5
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\monitoring

**Назначение:** Мониторинг и метрики
**Файлов:** 19
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\net

**Назначение:** Сетевые операции
**Файлов:** 9
**Основные типы файлов:** .py

### core\optimization

**Назначение:** Смешанные файлы проекта
**Файлов:** 10
**Основные типы файлов:** .py

### core\optimizer

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Основные типы файлов:** .py

### core\orchestration

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\packet

**Назначение:** Смешанные файлы проекта
**Файлов:** 16
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\payload

**Назначение:** Смешанные файлы проекта
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\pcap

**Назначение:** Захват и анализ сетевого трафика
**Файлов:** 17
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\pcap_analysis

**Назначение:** Смешанные файлы проекта
**Файлов:** 51
**Тип:** Python пакет
**Основные типы файлов:** .py, .json
**Поддиректории:** deployment, monitoring

### core\pcap_analysis\deployment

**Назначение:** Развертывание и деплой
**Файлов:** 7
**Основные типы файлов:** .py, .yml, 
**Поддиректории:** kubernetes

### core\pcap_analysis\deployment\kubernetes

**Назначение:** Конфигурационные файлы
**Файлов:** 5
**Основные типы файлов:** .yaml

### core\pcap_analysis\monitoring

**Назначение:** Мониторинг и метрики
**Файлов:** 2
**Основные типы файлов:** .py

### core\performance

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\protocols

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\recon

**Назначение:** Пустая директория
**Файлов:** 0
**Поддиректории:** data

### core\recon\data

**Назначение:** Данные и датасеты
**Файлов:** 1
**Основные типы файлов:** .json

### core\refactoring

**Назначение:** Рефакторинг и реорганизация кода
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\reporting

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\session

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Основные типы файлов:** .py

### core\state_management

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\strategy

**Назначение:** Стратегии обхода
**Файлов:** 22
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\telemetry

**Назначение:** Смешанные файлы проекта
**Файлов:** 3
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\validation

**Назначение:** Валидация и проверки
**Файлов:** 18
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\verification

**Назначение:** Смешанные файлы проекта
**Файлов:** 2
**Тип:** Python пакет
**Основные типы файлов:** .py

### core\workflow

**Назначение:** Смешанные файлы проекта
**Файлов:** 1
**Основные типы файлов:** .py

### data

**Назначение:** Данные и датасеты
**Файлов:** 4
**Основные типы файлов:** .json, .db
**Поддиректории:** operation_logs, payloads, reasoning_logs, test_reasoning_logs, validation_reports

### data\operation_logs

**Назначение:** Пустая директория
**Файлов:** 0

### data\payloads

**Назначение:** Документация
**Файлов:** 2
**Основные типы файлов:** .md
**Поддиректории:** bundled, captured

### data\payloads\bundled

**Назначение:** Смешанные файлы проекта
**Файлов:** 25
**Основные типы файлов:** .bin, .json

### data\payloads\captured

**Назначение:** Смешанные файлы проекта
**Файлов:** 1
**Основные типы файлов:** .bin

### data\reasoning_logs

**Назначение:** Конфигурационные файлы
**Файлов:** 12
**Основные типы файлов:** .json

### data\test_reasoning_logs

**Назначение:** Конфигурационные файлы
**Файлов:** 3
**Основные типы файлов:** .json

### data\validation_reports

**Назначение:** Конфигурационные файлы
**Файлов:** 30
**Основные типы файлов:** .txt, .json

### demo_baselines

**Назначение:** Конфигурационные файлы
**Файлов:** 2
**Основные типы файлов:** .json
**Поддиректории:** archive

### demo_baselines\archive

**Назначение:** Пустая директория
**Файлов:** 0

### deployment

**Назначение:** Развертывание и деплой
**Файлов:** 3
**Основные типы файлов:** .py
**Поддиректории:** service_results

### deployment\service_results

**Назначение:** Пустая директория
**Файлов:** 0

### docs

**Назначение:** Документация
**Файлов:** 4
**Основные типы файлов:** .md

### examples

**Назначение:** Смешанные файлы проекта
**Файлов:** 33
**Основные типы файлов:** .py, .json, .md

### gui

**Назначение:** Пользовательский интерфейс
**Файлов:** 8
**Тип:** Python пакет
**Основные типы файлов:** .py, .md

### knowledge

**Назначение:** Конфигурационные файлы
**Файлов:** 1
**Основные типы файлов:** .json

### logs

**Назначение:** Логи и журналирование
**Файлов:** 0

### metrics

**Назначение:** Мониторинг и метрики
**Файлов:** 1
**Основные типы файлов:** .json

### ml

**Назначение:** Смешанные файлы проекта
**Файлов:** 9
**Тип:** Python пакет
**Основные типы файлов:** .py

### monitoring

**Назначение:** Мониторинг и метрики
**Файлов:** 4
**Основные типы файлов:** .py

### pcap

**Назначение:** Захват и анализ сетевого трафика
**Файлов:** 0

### pcap_failures

**Назначение:** Пустая директория
**Файлов:** 0

### platform

**Назначение:** Смешанные файлы проекта
**Файлов:** 1
**Основные типы файлов:** .py

### real_data_validation

**Назначение:** Конфигурационные файлы
**Файлов:** 2
**Основные типы файлов:** .json

### recon_dpi_tool.egg-info

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Основные типы файлов:** .txt, 

### recon_pcap

**Назначение:** Пустая директория
**Файлов:** 0

### reports

**Назначение:** Пустая директория
**Файлов:** 0

### service_test_results

**Назначение:** Смешанные файлы проекта
**Файлов:** 12
**Основные типы файлов:** .txt, .json

### specs

**Назначение:** Пустая директория
**Файлов:** 0
**Поддиректории:** attacks

### specs\attacks

**Назначение:** Атаки и обход блокировок
**Файлов:** 13
**Основные типы файлов:** .yaml

### state_backups

**Назначение:** Пустая директория
**Файлов:** 0

### temp

**Назначение:** Временные файлы
**Файлов:** 0

### temp_pcap

**Назначение:** Пустая директория
**Файлов:** 0

### tests

**Назначение:** Тесты и тестирование
**Файлов:** 0

### tools

**Назначение:** Смешанные файлы проекта
**Файлов:** 31
**Основные типы файлов:** .py, .md

### tunnels

**Назначение:** Смешанные файлы проекта
**Файлов:** 4
**Тип:** Python пакет
**Основные типы файлов:** .py, .txt

### utils

**Назначение:** Вспомогательные утилиты
**Файлов:** 1
**Основные типы файлов:** .py

### validation_results

**Назначение:** Пустая директория
**Файлов:** 0

### web

**Назначение:** Смешанные файлы проекта
**Файлов:** 6
**Основные типы файлов:** .py
**Поддиректории:** static

### web\static

**Назначение:** Смешанные файлы проекта
**Файлов:** 1
**Основные типы файлов:** 

### workflow_configs

**Назначение:** Пустая директория
**Файлов:** 0

## Основные компоненты

Ключевые компоненты проекта по функциональности:

### Основной код

- **core** - Основной код приложения

### Тестирование

- **.** - Тесты и тестирование
- **tests** - Тесты и тестирование

### Конфигурация

- **baselines** - Конфигурационные файлы
- **bypass_configs** - Конфигурационные файлы
- **config** - Конфигурационные файлы
- **core\bypass\config** - Конфигурационные файлы
- **core\config** - Конфигурационные файлы
- **core\config\examples** - Конфигурационные файлы
- **core\pcap_analysis\deployment\kubernetes** - Конфигурационные файлы
- **data\reasoning_logs** - Конфигурационные файлы
- **data\test_reasoning_logs** - Конфигурационные файлы
- **data\validation_reports** - Конфигурационные файлы
- **demo_baselines** - Конфигурационные файлы
- **knowledge** - Конфигурационные файлы
- **real_data_validation** - Конфигурационные файлы

### Документация

- **.kiro\specs\attack-application-parity** - Документация
- **.kiro\specs\attack-recipe-consistency** - Документация
- **.kiro\specs\auto-strategy-discovery** - Документация
- **.kiro\specs\cli-auto-mode-fixes** - Документация
- **.kiro\specs\dpi-strategy-fix** - Документация
- **.kiro\specs\duplicate-functionality-analysis** - Документация
- **.kiro\specs\enhanced-strategy-generation** - Документация
- **.kiro\specs\fake-payload-generation** - Документация
- **.kiro\specs\false-positive-validation-fix** - Документация
- **.kiro\specs\global-refactoring** - Документация
- **.kiro\specs\log-pcap-validation** - Документация
- **.kiro\specs\pcap-validator-combo-detection** - Документация
- **.kiro\specs\site-accessibility-testing-fix** - Документация
- **.kiro\specs\strategy-application-bugs** - Документация
- **.kiro\specs\strategy-conversion-logging-cleanup** - Документация
- **.kiro\specs\strategy-optimization** - Документация
- **.kiro\specs\strategy-testing-production-parity** - Документация
- **.kiro\specs\unified-attack-dispatcher** - Документация
- **.kiro\specs\unified-engine-refactoring** - Документация
- **.kiro\specs\url-parameter-bypass** - Документация
- **data\payloads** - Документация
- **docs** - Документация

### Интерфейсы

- **gui** - Пользовательский интерфейс

### Сетевые операции

- **core\net** - Сетевые операции
- **core\pcap** - Захват и анализ сетевого трафика
- **pcap** - Захват и анализ сетевого трафика

### Обход блокировок

- **core\bypass** - Обход блокировок
- **core\bypass\attacks** - Атаки и обход блокировок
- **core\bypass\strategies** - Стратегии обхода
- **core\strategy** - Стратегии обхода
- **specs\attacks** - Атаки и обход блокировок

### Мониторинг

- **core\bypass\monitoring** - Мониторинг и метрики
- **core\metrics** - Мониторинг и метрики
- **core\monitoring** - Мониторинг и метрики
- **core\pcap_analysis\monitoring** - Мониторинг и метрики
- **metrics** - Мониторинг и метрики
- **monitoring** - Мониторинг и метрики

### Утилиты

- **utils** - Вспомогательные утилиты

### Временные файлы

- **temp** - Временные файлы

### Прочее

- **.kiro** - Пустая директория
- **.kiro\specs** - Пустая директория
- **attack_validation** - Пустая директория
- **baselines\archive** - Пустая директория
- **cli_test_results** - Пустая директория
- **core\async** - Смешанные файлы проекта
- **core\async_compat** - Смешанные файлы проекта
- **core\async_utils** - Смешанные файлы проекта
- **core\attack_parity** - Смешанные файлы проекта
- **core\bypass\analytics** - Смешанные файлы проекта
- **core\bypass\attacks\audit** - Смешанные файлы проекта
- **core\bypass\attacks\base_classes** - Смешанные файлы проекта
- **core\bypass\attacks\combo** - Смешанные файлы проекта
- **core\bypass\attacks\compatibility** - Смешанные файлы проекта
- **core\bypass\attacks\dns** - Смешанные файлы проекта
- **core\bypass\attacks\http** - Смешанные файлы проекта
- **core\bypass\attacks\ip** - Смешанные файлы проекта
- **core\bypass\attacks\obfuscation** - Смешанные файлы проекта
- **core\bypass\attacks\payload** - Смешанные файлы проекта
- **core\bypass\attacks\performance** - Смешанные файлы проекта
- **core\bypass\attacks\tcp** - Смешанные файлы проекта
- **core\bypass\attacks\telemetry** - Смешанные файлы проекта
- **core\bypass\attacks\timing** - Смешанные файлы проекта
- **core\bypass\attacks\tls** - Смешанные файлы проекта
- **core\bypass\attacks\tunneling** - Смешанные файлы проекта
- **core\bypass\attacks\udp** - Смешанные файлы проекта
- **core\bypass\attacks\validation** - Валидация и проверки
- **core\bypass\compatibility** - Смешанные файлы проекта
- **core\bypass\diagnostics** - Смешанные файлы проекта
- **core\bypass\engine** - Смешанные файлы проекта
- **core\bypass\engines** - Смешанные файлы проекта
- **core\bypass\filtering** - Смешанные файлы проекта
- **core\bypass\flow** - Смешанные файлы проекта
- **core\bypass\hybrid** - Смешанные файлы проекта
- **core\bypass\integration** - Смешанные файлы проекта
- **core\bypass\modes** - Смешанные файлы проекта
- **core\bypass\packet** - Смешанные файлы проекта
- **core\bypass\performance** - Смешанные файлы проекта
- **core\bypass\pipeline** - Смешанные файлы проекта
- **core\bypass\protocols** - Смешанные файлы проекта
- **core\bypass\safety** - Смешанные файлы проекта
- **core\bypass\sharing** - Смешанные файлы проекта
- **core\bypass\sni** - Смешанные файлы проекта
- **core\bypass\techniques** - Смешанные файлы проекта
- **core\bypass\telemetry** - Смешанные файлы проекта
- **core\bypass\validation** - Валидация и проверки
- **core\caching** - Смешанные файлы проекта
- **core\calibration** - Смешанные файлы проекта
- **core\cli_payload** - Смешанные файлы проекта
- **core\di** - Смешанные файлы проекта
- **core\diagnostics** - Смешанные файлы проекта
- **core\dns** - Смешанные файлы проекта
- **core\effectiveness** - Смешанные файлы проекта
- **core\fingerprint** - Смешанные файлы проекта
- **core\fingerprint\training_data** - Пустая директория
- **core\infrastructure** - Смешанные файлы проекта
- **core\integration** - Смешанные файлы проекта
- **core\intelligence** - Смешанные файлы проекта
- **core\knowledge** - Смешанные файлы проекта
- **core\learning** - Смешанные файлы проекта
- **core\logging** - Логи и журналирование
- **core\optimization** - Смешанные файлы проекта
- **core\optimizer** - Смешанные файлы проекта
- **core\orchestration** - Смешанные файлы проекта
- **core\packet** - Смешанные файлы проекта
- **core\payload** - Смешанные файлы проекта
- **core\pcap_analysis** - Смешанные файлы проекта
- **core\pcap_analysis\deployment** - Развертывание и деплой
- **core\performance** - Смешанные файлы проекта
- **core\protocols** - Смешанные файлы проекта
- **core\recon** - Пустая директория
- **core\recon\data** - Данные и датасеты
- **core\refactoring** - Рефакторинг и реорганизация кода
- **core\reporting** - Смешанные файлы проекта
- **core\session** - Смешанные файлы проекта
- **core\state_management** - Смешанные файлы проекта
- **core\telemetry** - Смешанные файлы проекта
- **core\validation** - Валидация и проверки
- **core\verification** - Смешанные файлы проекта
- **core\workflow** - Смешанные файлы проекта
- **data** - Данные и датасеты
- **data\operation_logs** - Пустая директория
- **data\payloads\bundled** - Смешанные файлы проекта
- **data\payloads\captured** - Смешанные файлы проекта
- **demo_baselines\archive** - Пустая директория
- **deployment** - Развертывание и деплой
- **deployment\service_results** - Пустая директория
- **examples** - Смешанные файлы проекта
- **logs** - Логи и журналирование
- **ml** - Смешанные файлы проекта
- **pcap_failures** - Пустая директория
- **platform** - Смешанные файлы проекта
- **recon_dpi_tool.egg-info** - Смешанные файлы проекта
- **recon_pcap** - Пустая директория
- **reports** - Пустая директория
- **service_test_results** - Смешанные файлы проекта
- **specs** - Пустая директория
- **state_backups** - Пустая директория
- **temp_pcap** - Пустая директория
- **tools** - Смешанные файлы проекта
- **tunnels** - Смешанные файлы проекта
- **validation_results** - Пустая директория
- **web** - Смешанные файлы проекта
- **web\static** - Смешанные файлы проекта
- **workflow_configs** - Пустая директория

## Как использовать этот документ

1. **Для разработчиков:** Используйте этот документ для понимания архитектуры проекта
2. **Для новых участников:** Начните с изучения Entry Points и основных компонентов
3. **Для рефакторинга:** Проверяйте назначение директорий перед перемещением кода
4. **Для LLM:** Всегда сверяйтесь с этим документом перед созданием нового функционала

---
*Документ сгенерирован автоматически: recon project structure analyzer*