# Implementation Plan: Attack System Refactoring

## Phase 1: Analysis and Preparation

- [x] 1. Analyze codebase and identify all duplicates




  - [x] 1.1 Scan for all disorder attack implementations


    - Search for `apply_fakeddisorder`, `apply_disorder`, `apply_multidisorder` across codebase
    - Document location and differences of each implementation
    - _Requirements: 1.1, 1.2_
  
  - [x] 1.2 Identify all registry files


    - List all files containing "Registry" classes
    - Document functionality of each registry
    - _Requirements: 1.1, 4.1_
  
  - [x] 1.3 Create duplicate mapping document


    - Map each duplicate to its canonical version
    - Document unique functionality in duplicates
    - Create `DUPLICATE_MAPPING.md` in spec directory
    - _Requirements: 1.3, 2.1_
  
  - [x] 1.4 Analyze attack registration conflicts


    - Identify attacks registered multiple times
    - Document registration order and priority issues
    - _Requirements: 1.5, 5.1_

- [x] 2. Create baseline performance report




  - [x] 2.1 Run existing performance tests



    - Execute all attack performance tests
    - Collect execution time metrics
    - _Requirements: 9.6_
  
  - [x] 2.2 Generate baseline report



    - Create `baseline_performance.json` with current metrics
    - Include attack execution times, success rates, memory usage
    - _Requirements: 9.6_
  
  - [x] 2.3 Document current behavior


    - Record how each attack currently behaves
    - Document parameter handling quirks
    - _Requirements: 9.1, 9.4_

## Phase 2: Registry Consolidation

- [-] 3. Enhance primary attack registry



  - [x] 3.1 Add priority system to AttackRegistry


    - Implement `RegistrationPriority` enum (CORE, HIGH, NORMAL, LOW)
    - Update `register_attack()` to accept priority parameter
    - Add priority comparison logic
    - _Requirements: 4.6, 5.1_
  
  - [x] 3.2 Implement deduplication logic


    - Add `_handle_duplicate_registration()` method
    - Implement priority-based conflict resolution
    - Add detailed logging for duplicate attempts
    - _Requirements: 5.1, 5.2, 5.4_
  
  - [x] 3.3 Add alias tracking to AttackEntry


    - Add `is_alias_of` field to AttackEntry dataclass
    - Update alias registration to populate this field
    - _Requirements: 5.3_
  
  - [x] 3.4 Add promotion mechanism


    - Implement `promote_implementation()` method in registry
    - Add `promotion_history` field to AttackEntry
    - Add validation for promotion requests
    - _Requirements: 2.6, 11.2_
  
  - [-] 3.5 Implement lazy loading support


    - Add module path storage for unloaded attacks
    - Implement on-demand module import
    - Add configuration option for eager vs lazy loading
    - _Requirements: Performance optimization_

- [ ] 4. Migrate functionality from other registries
  - [ ] 4.1 Extract unique functions from registry.py
    - Identify functions not in attack_registry.py
    - Copy unique functionality to attack_registry.py
    - Add tests for migrated functions
    - _Requirements: 4.1, 4.2_
  
  - [ ] 4.2 Extract unique functions from modern_registry.py
    - Identify modern registry-specific features
    - Integrate into unified registry
    - _Requirements: 4.1, 4.2_
  
  - [ ] 4.3 Update all imports to use unified registry
    - Search for imports of old registries
    - Replace with attack_registry imports
    - Add deprecation warnings to old registry files
    - _Requirements: 6.1, 6.4_

- [ ] 5. Remove old registry files
  - [ ] 5.1 Delete core/bypass/attacks/registry.py
    - Verify no remaining imports
    - Remove file
    - _Requirements: 4.1, 3.5_
  
  - [ ] 5.2 Delete core/bypass/attacks/modern_registry.py
    - Verify no remaining imports
    - Remove file
    - _Requirements: 4.1, 3.5_
  
  - [ ] 5.3 Delete core/bypass/techniques/registry.py
    - Verify no remaining imports
    - Remove file
    - _Requirements: 4.1, 3.5_

## Phase 3: Attack Dispatcher Enhancement

- [ ] 6. Implement unified AttackContext
  - [ ] 6.1 Create AttackContext dataclass
    - Define fields: payload, dst_ip, dst_port, protocol, connection_id, metadata
    - Add validation methods
    - Create in `core/bypass/attacks/base.py`
    - _Requirements: 11.5_
  
  - [ ] 6.2 Update attack handlers to use AttackContext
    - Modify handler signatures to accept AttackContext
    - Update all attack implementations
    - _Requirements: 11.5_

- [ ] 7. Implement parameter normalization
  - [ ] 7.1 Create ParameterNormalizer class
    - Implement `normalize()` method
    - Add rules for split_pos → positions conversion
    - Handle list/int/str parameter variations
    - Create in `core/bypass/engine/attack_dispatcher.py`
    - _Requirements: 11.5_
  
  - [ ] 7.2 Add normalization rules for all attack types
    - Define normalization for fakeddisorder parameters
    - Define normalization for disorder family parameters
    - Define normalization for split/multisplit parameters
    - _Requirements: 11.5_
  
  - [ ] 7.3 Integrate normalizer into AttackDispatcher
    - Call normalizer before passing params to handlers
    - Add logging for parameter transformations
    - _Requirements: 11.5_

- [ ] 8. Enhance AttackDispatcher
  - [ ] 8.1 Add strategy resolution
    - Implement `resolve_strategy()` method
    - Parse zapret-style strategies (e.g., "fake,disorder")
    - Map to canonical attack names
    - _Requirements: 11.5_
  
  - [ ] 8.2 Integrate with unified registry
    - Use registry for attack handler lookup
    - Handle alias resolution
    - Add error handling for unknown attacks
    - _Requirements: 6.1, 6.2_
  
  - [ ] 8.3 Add comprehensive logging
    - Log attack dispatch requests
    - Log parameter normalization
    - Log handler execution
    - _Requirements: Monitoring_

## Phase 4: Primitives Enhancement

- [ ] 9. Add shared helper functions to primitives
  - [ ] 9.1 Implement `_split_payload()` helper
    - Create shared payload splitting logic
    - Add validation for split positions
    - Use in all disorder family attacks
    - _Requirements: 11.1_
  
  - [ ] 9.2 Implement `_create_segment_options()` helper
    - Create shared segment options builder
    - Handle fooling methods consistently
    - Use in all attacks
    - _Requirements: 11.1_
  
  - [ ] 9.3 Implement `_normalize_positions()` helper
    - Convert various position formats to List[int]
    - Handle special values (sni, cipher, midsld)
    - _Requirements: 11.5_

- [ ] 10. Optimize canonical attack implementations
  - [ ] 10.1 Update fakeddisorder implementation
    - Ensure fake packet contains full payload
    - Use optimized default parameters (ttl=3, split_pos=3)
    - Add comprehensive docstring explaining optimization
    - _Requirements: 11.2, 11.4_
  
  - [ ] 10.2 Update seqovl implementation
    - Fix sequence overlap calculation
    - Ensure real packet remains intact
    - Add validation for overlap_size
    - _Requirements: 11.3_
  
  - [ ] 10.3 Update disorder implementation
    - Use shared helpers
    - Optimize for common use cases
    - _Requirements: 11.1_
  
  - [ ] 10.4 Update multidisorder implementation
    - Use shared helpers
    - Optimize position generation
    - _Requirements: 11.1_
  
  - [ ] 10.5 Update multisplit implementation
    - Use shared helpers
    - Optimize for single position case
    - _Requirements: 11.1_

- [ ] 11. Add implementation promotion support
  - [ ] 11.1 Implement `promote_implementation()` in BypassTechniques
    - Add method to promote external implementations
    - Integrate with registry promotion mechanism
    - Add validation and testing requirements
    - _Requirements: 2.6, 11.2_

## Phase 5: Duplicate Removal

- [ ] 12. Analyze and merge unique functionality
  - [ ] 12.1 Review fake_disorder_attack.py variants
    - Compare all three versions (original, fixed, current)
    - Extract unique optimizations from each
    - Document which features to keep
    - _Requirements: 3.2, 3.3_
  
  - [ ] 12.2 Merge unique features into primitives
    - Add any missing optimizations to canonical fakeddisorder
    - Ensure all effective techniques are preserved
    - _Requirements: 3.3, 9.2_
  
  - [ ] 12.3 Create tests for merged features
    - Write specific tests for each merged feature
    - Ensure no functionality is lost
    - _Requirements: 3.6, 9.1_

- [ ] 13. Remove duplicate attack files
  - [ ] 13.1 Delete core/bypass/attacks/tcp/fake_disorder_attack_original.py
    - Verify functionality merged into primitives
    - Update any imports
    - Remove file
    - _Requirements: 3.1, 3.4_
  
  - [ ] 13.2 Delete core/bypass/attacks/tcp/fake_disorder_attack_fixed.py
    - Verify functionality merged into primitives
    - Update any imports
    - Remove file
    - _Requirements: 3.1, 3.4_
  
  - [ ] 13.3 Delete core/bypass/attacks/tcp/fake_disorder_attack.py
    - Verify functionality merged into primitives
    - Update any imports
    - Remove file
    - _Requirements: 3.1, 3.4_
  
  - [ ] 13.4 Delete core/bypass/attacks/reference/faked_disorder_attack.py
    - Verify this is truly a duplicate
    - Remove file
    - _Requirements: 3.1, 3.4_

- [ ] 14. Update import structure
  - [ ] 14.1 Update core/bypass/attacks/__init__.py
    - Remove imports of deleted files
    - Ensure primitives are properly registered
    - Add clear comments about canonical implementations
    - _Requirements: 6.1, 6.2_
  
  - [ ] 14.2 Search and update all attack imports
    - Find all imports of deleted attack files
    - Replace with primitives imports or registry lookups
    - _Requirements: 6.4_
  
  - [ ] 14.3 Verify no broken imports remain
    - Run import checker across codebase
    - Fix any remaining broken imports
    - _Requirements: 3.5_

## Phase 6: Testing and Validation

- [ ] 15. Update existing tests
  - [ ] 15.1 Update tests/test_attack_registry.py
    - Add tests for priority system
    - Add tests for deduplication logic
    - Add tests for promotion mechanism
    - _Requirements: 10.1, 10.2_
  
  - [ ] 15.2 Update tests/test_attack_dispatcher.py
    - Add tests for parameter normalization
    - Add tests for strategy resolution
    - Add tests for AttackContext
    - _Requirements: 10.1, 10.2_
  
  - [ ] 15.3 Create tests/test_attack_primitives.py
    - Test all canonical implementations
    - Test shared helper functions
    - Test parameter handling
    - _Requirements: 10.1, 10.2_
  
  - [ ] 15.4 Create tests/test_attack_deduplication.py
    - Test duplicate registration scenarios
    - Test priority conflict resolution
    - Test alias handling
    - _Requirements: 10.1, 10.2_

- [ ] 16. Run comprehensive test suite
  - [ ] 16.1 Run all unit tests
    - Execute pytest on all test files
    - Verify 100% pass rate
    - _Requirements: 10.5_
  
  - [ ] 16.2 Run integration tests
    - Test full attack execution flow
    - Test registry initialization
    - Test dispatcher integration
    - _Requirements: 10.5_
  
  - [ ] 16.3 Run performance tests
    - Execute attack performance benchmarks
    - Compare with baseline report
    - Investigate any regressions > 5%
    - _Requirements: 9.6_

- [ ] 17. Validate attack functionality
  - [ ] 17.1 Test all disorder family attacks
    - Execute disorder, disorder2, multidisorder, fakeddisorder
    - Verify correct segment generation
    - Verify parameter handling
    - _Requirements: 9.1, 9.4_
  
  - [ ] 17.2 Test all split family attacks
    - Execute split, multisplit
    - Verify correct segment generation
    - _Requirements: 9.1, 9.4_
  
  - [ ] 17.3 Test seqovl and fake attacks
    - Verify overlap calculation
    - Verify fake packet generation
    - _Requirements: 9.1, 9.4_
  
  - [ ] 17.4 Test with real-world scenarios
    - Test against known DPI systems
    - Verify effectiveness is maintained
    - _Requirements: 9.4, 9.5_

- [ ] 18. Performance validation
  - [ ] 18.1 Generate new performance report
    - Run same benchmarks as baseline
    - Create `refactored_performance.json`
    - _Requirements: 9.6_
  
  - [ ] 18.2 Compare performance metrics
    - Calculate performance delta for each attack
    - Identify any regressions
    - Document improvements
    - _Requirements: 9.6_
  
  - [ ] 18.3 Investigate and fix regressions
    - For any regression > 5%, investigate cause
    - Optimize or revert changes as needed
    - Re-test after fixes
    - _Requirements: 9.6_

## Phase 7: Documentation

- [ ] 19. Create migration guide
  - [ ] 19.1 Document import changes
    - Create before/after examples for all changed imports
    - Provide search/replace patterns
    - _Requirements: 8.1, 8.2_
  
  - [ ] 19.2 Document attack name changes
    - Create mapping table of old → new names
    - Document any renamed attacks
    - _Requirements: 8.3_
  
  - [ ] 19.3 Document parameter changes
    - Explain parameter normalization
    - Provide examples of old vs new parameter formats
    - _Requirements: 8.2, 11.5_
  
  - [ ] 19.4 Explain canonical implementation choices
    - Document why primitives.py is canonical
    - Explain rationale for each choice
    - _Requirements: 8.4_
  
  - [ ] 19.5 Provide code examples
    - Show how to use new registry
    - Show how to use AttackDispatcher
    - Show how to register new attacks
    - _Requirements: 8.5_

- [ ] 20. Update API documentation
  - [ ] 20.1 Update docs/API_REFERENCE.md
    - Document new registry API
    - Document AttackDispatcher API
    - Document AttackContext
    - _Requirements: 8.1_
  
  - [ ] 20.2 Update docs/ADDING_NEW_ATTACKS.md
    - Explain new registration process
    - Document priority system
    - Explain parameter normalization requirements
    - _Requirements: 8.1_
  
  - [ ] 20.3 Update docs/ARCHITECTURE.md
    - Document new architecture
    - Update component diagrams
    - Explain design decisions
    - _Requirements: 8.1_

- [ ] 21. Create refactoring summary
  - [ ] 21.1 Document all changes made
    - List all files modified
    - List all files deleted
    - List all new files created
    - _Requirements: 8.1_
  
  - [ ] 21.2 Document performance improvements
    - Summarize performance comparison
    - Highlight key improvements
    - _Requirements: 8.1_
  
  - [ ] 21.3 Document functionality preserved
    - Confirm all attacks still work
    - Confirm no features lost
    - _Requirements: 8.1, 9.5_

## Phase 8: Final Validation and Cleanup

- [ ] 22. Final testing
  - [ ] 22.1 Run full test suite one more time
    - Execute all tests
    - Verify 100% pass rate
    - _Requirements: 10.5_
  
  - [ ] 22.2 Manual testing of critical paths
    - Test attack registration
    - Test attack execution
    - Test error handling
    - _Requirements: 7.1, 7.4_
  
  - [ ] 22.3 Verify backward compatibility
    - Test deprecated import paths
    - Verify deprecation warnings work
    - _Requirements: 6.3_

- [ ] 23. Code cleanup
  - [ ] 23.1 Remove commented-out code
    - Clean up any debug code
    - Remove old commented implementations
    - _Requirements: Code quality_
  
  - [ ] 23.2 Update all docstrings
    - Ensure all functions have docstrings
    - Update docstrings for changed functions
    - _Requirements: Code quality_
  
  - [ ] 23.3 Run code formatter
    - Format all modified files
    - Ensure consistent style
    - _Requirements: Code quality_
  
  - [ ] 23.4 Run linter
    - Fix any linting issues
    - Ensure code quality standards met
    - _Requirements: Code quality_

- [ ] 24. Final validation
  - [ ] 24.1 Verify all requirements met
    - Check each requirement from requirements.md
    - Confirm all acceptance criteria satisfied
    - _Requirements: All_
  
  - [ ] 24.2 Verify all success criteria met
    - Check functional requirements
    - Check performance requirements
    - Check quality requirements
    - _Requirements: Success criteria_
  
  - [ ] 24.3 Create final report
    - Summarize refactoring results
    - Document metrics and improvements
    - List any known issues or limitations
    - _Requirements: 8.1_

## Post-Implementation Tasks (Optional)

- [ ]* 25. Implement lazy loading
  - [ ]* 25.1 Add lazy loading configuration
    - Add config option for lazy vs eager loading
    - _Requirements: Future enhancement_
  
  - [ ]* 25.2 Implement lazy module loader
    - Create module loader that imports on demand
    - _Requirements: Future enhancement_
  
  - [ ]* 25.3 Test lazy loading performance
    - Measure startup time improvement
    - _Requirements: Future enhancement_

- [ ]* 26. Create promotion workflow
  - [ ]* 26.1 Create promotion request template
    - Define required information for promotion
    - _Requirements: Future enhancement_
  
  - [ ]* 26.2 Create automated promotion tests
    - Test framework for comparing implementations
    - _Requirements: Future enhancement_
  
  - [ ]* 26.3 Document promotion process
    - Create guide for promoting implementations
    - _Requirements: Future enhancement_
