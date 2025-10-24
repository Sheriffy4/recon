# Requirements Document

## Introduction

Система атак DPI обхода содержит множественные дубликаты реализаций атак, что приводит к проблемам с регистрацией, конфликтам имен и сложности поддержки. Необходимо провести рефакторинг для создания единой, каноничной системы атак с правильной регистрацией и без дублирования кода.

## Glossary

- **Attack**: Техника обхода DPI (Deep Packet Inspection)
- **Registry**: Централизованный реестр для регистрации и управления атаками
- **Primitives**: Базовые примитивные техники обхода в `core/bypass/techniques/primitives.py`
- **Duplicate**: Множественные реализации одной и той же атаки в разных файлах
- **Canonical Implementation**: Единственная правильная реализация атаки, которая должна использоваться
- **Attack Registration**: Процесс добавления атаки в реестр для использования системой
- **Disorder Attack**: Семейство атак, изменяющих порядок TCP сегментов (disorder, disorder2, multidisorder, fakeddisorder)

## Requirements

### Requirement 1: Identify All Attack Duplicates

**User Story:** As a developer, I want to identify all duplicate attack implementations across the codebase, so that I can understand the scope of the refactoring work.

#### Acceptance Criteria

1. WHEN the system scans the codebase, THE System SHALL identify all files containing disorder attack implementations
2. WHEN duplicate attacks are found, THE System SHALL create a mapping of canonical vs duplicate implementations
3. WHEN the analysis is complete, THE System SHALL generate a report listing all duplicates with their locations
4. WHERE multiple versions exist, THE System SHALL identify which implementation is canonical based on expert guidance (primitives.py)
5. WHEN analyzing attack files, THE System SHALL detect registration conflicts where attacks register under the same name

### Requirement 2: Establish Canonical Attack Implementations

**User Story:** As a system architect, I want to establish a single canonical implementation for each attack type, so that there is no ambiguity about which code to use.

#### Acceptance Criteria

1. WHEN determining canonical implementations, THE System SHALL prioritize implementations in `core/bypass/techniques/primitives.py` as specified by the expert
2. WHEN multiple disorder variants exist, THE System SHALL preserve the following canonical attacks: disorder, disorder2, multidisorder, fakeddisorder, multisplit, split, seqovl, fake
3. WHERE an attack exists in both primitives and attack modules, THE System SHALL use the primitives version as canonical
4. WHEN establishing canonical implementations, THE System SHALL document the rationale for each choice
5. WHEN canonical implementations are identified, THE System SHALL mark all other versions as deprecated
6. WHEN a canonical implementation is chosen, THE System SHALL ensure it is the most effective and compatible version by cross-referencing performance data from recon_summary.json and analysis_report.json

### Requirement 3: Remove Duplicate Attack Files

**User Story:** As a developer, I want duplicate attack files removed from the codebase, so that there is only one implementation to maintain.

#### Acceptance Criteria

1. WHEN duplicate files are identified, THE System SHALL safely remove files marked as non-canonical
2. WHEN removing duplicates, THE System SHALL preserve any unique functionality not present in the canonical version
3. IF unique functionality exists in a duplicate, THEN THE System SHALL merge it into the canonical implementation before removal
4. WHEN files are removed, THE System SHALL update all import statements that referenced the removed files
5. WHEN removal is complete, THE System SHALL verify that no broken imports remain in the codebase
6. WHEN merging functionality from a duplicate file, THE System SHALL create a separate test case that specifically validates the merged feature

### Requirement 4: Consolidate Attack Registry System

**User Story:** As a system architect, I want a single, unified attack registry, so that attack registration is consistent and predictable.

#### Acceptance Criteria

1. WHEN multiple registry files exist (attack_registry.py, registry.py, modern_registry.py), THE System SHALL consolidate them into a single registry module
2. WHEN consolidating registries, THE System SHALL preserve all registration functionality from each registry
3. WHEN the unified registry is created, THE System SHALL ensure it supports both decorator-based and function-based registration
4. WHERE registry conflicts exist, THE System SHALL implement deduplication logic to prevent double registration
5. WHEN the registry is finalized, THE System SHALL provide clear documentation on how to register new attacks
6. WHEN the unified registry is created, THE System SHALL provide a clear priority mechanism for attack registration, where core attacks (from primitives.py) have higher priority than external or experimental ones

### Requirement 5: Implement Attack Registration Deduplication

**User Story:** As a developer, I want the registry to prevent duplicate registrations, so that attacks are not registered multiple times under the same name.

#### Acceptance Criteria

1. WHEN an attack is registered, THE Registry SHALL check if an attack with the same name already exists
2. IF an attack name already exists, THEN THE Registry SHALL log a warning and skip the duplicate registration
3. WHEN checking for duplicates, THE Registry SHALL compare both primary names and aliases
4. WHEN a duplicate is detected, THE Registry SHALL provide detailed information about both the existing and attempted registration
5. WHEN registration is complete, THE Registry SHALL maintain a single entry per unique attack type

### Requirement 6: Update Attack Import Structure

**User Story:** As a developer, I want a clean import structure for attacks, so that I can easily import and use any attack without confusion.

#### Acceptance Criteria

1. WHEN importing attacks, THE System SHALL provide a single canonical import path for each attack
2. WHEN the import structure is updated, THE System SHALL create a centralized `__init__.py` that exports all canonical attacks
3. WHERE backward compatibility is needed, THE System SHALL provide import aliases for deprecated paths
4. WHEN imports are restructured, THE System SHALL update all existing code to use the new canonical imports
5. WHEN the structure is finalized, THE System SHALL document the correct import patterns for each attack type

### Requirement 7: Validate Attack Registration Integrity

**User Story:** As a QA engineer, I want to validate that all attacks are correctly registered without duplicates, so that the system works reliably.

#### Acceptance Criteria

1. WHEN the system starts, THE Registry SHALL validate that all expected attacks are registered
2. WHEN validation runs, THE System SHALL check for duplicate registrations and report any found
3. WHEN checking attack handlers, THE System SHALL verify that each registered attack has a valid handler function
4. WHERE registration issues are found, THE System SHALL provide detailed error messages with remediation steps
5. WHEN validation is complete, THE System SHALL log a summary of all registered attacks and their metadata

### Requirement 8: Create Attack Migration Guide

**User Story:** As a developer, I want documentation on how to migrate from old attack imports to new ones, so that I can update my code correctly.

#### Acceptance Criteria

1. WHEN the refactoring is complete, THE System SHALL provide a migration guide documenting all changes
2. WHEN documenting changes, THE Guide SHALL include before/after examples for each affected import
3. WHERE attacks were renamed or moved, THE Guide SHALL provide a mapping table of old to new names
4. WHEN describing the new structure, THE Guide SHALL explain the rationale behind the canonical implementation choices
5. WHEN the guide is published, THE System SHALL include code examples demonstrating correct usage of the new structure

### Requirement 9: Preserve Attack Functionality

**User Story:** As a system user, I want all existing attack functionality to continue working after the refactoring, so that no capabilities are lost.

#### Acceptance Criteria

1. WHEN refactoring attacks, THE System SHALL preserve all parameters and configuration options from existing implementations
2. WHEN consolidating implementations, THE System SHALL ensure that all attack variants (disorder, disorder2, etc.) remain available
3. WHERE functionality differs between implementations, THE System SHALL preserve the most complete and correct version
4. WHEN testing after refactoring, THE System SHALL verify that all attacks produce the same results as before
5. WHEN the refactoring is complete, THE System SHALL run comprehensive tests to validate that no functionality was lost
6. WHEN validating functionality, THE System SHALL create a baseline performance report before refactoring and compare it with a new report after refactoring to ensure no performance degradation

### Requirement 10: Update Attack Tests

**User Story:** As a QA engineer, I want attack tests updated to reflect the new structure, so that testing continues to validate the system correctly.

#### Acceptance Criteria

1. WHEN tests reference old attack paths, THE System SHALL update them to use the new canonical imports
2. WHEN updating tests, THE System SHALL ensure that all attack variants are covered by test cases
3. WHERE duplicate tests exist for the same attack, THE System SHALL consolidate them into a single comprehensive test
4. WHEN tests are updated, THE System SHALL verify that test coverage remains at or above previous levels
5. WHEN all tests are updated, THE System SHALL run the full test suite to ensure all tests pass

### Requirement 11: Unify and Optimize Attack Logic

**User Story:** As a system architect, I want to unify the internal logic of similar attacks (like the disorder family), so that they are consistent, predictable, and use the most effective known parameters as defaults.

#### Acceptance Criteria

1. WHEN refactoring disorder family attacks (disorder, disorder2, multidisorder, fakeddisorder), THE System SHALL ensure they all derive from a common base or use a shared helper function for payload splitting and segment creation
2. WHEN defining the canonical fakeddisorder implementation, THE System SHALL ensure the fake packet always contains the full payload by default, as this is critical for sites like x.com
3. WHEN defining the canonical seqovl implementation, THE System SHALL ensure it correctly calculates sequence overlap based on split_pos and overlap_size parameters, keeping the real packet intact
4. WHEN establishing default parameters for canonical attacks, THE System SHALL use values known for high effectiveness (e.g., ttl=3, split_pos=3 for fakeddisorder, fooling=['badsum', 'badseq'])
5. WHEN the attack logic is unified, THE System SHALL create a clear mapping in the documentation explaining how high-level zapret-style parameters (--dpi-desync=fake,disorder) translate into the execution of a specific canonical attack with specific parameters
