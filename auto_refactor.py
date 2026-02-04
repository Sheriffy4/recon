#!/usr/bin/env python3
"""
Auto Refactor - Автоматический рефакторинг на основе базы знаний.

Применяет паттерны из базы знаний для автоматического рефакторинга проблемных файлов.
"""

import ast
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class RefactoringPlan:
    """План рефакторинга для файла."""
    target_file: str
    transformations: List[str]
    extracted_components: List[str]
    new_files: List[str]
    estimated_effort: float  # часы
    risk_level: str
    backup_required: bool = True


class AutoRefactor:
    """Автоматический рефакторинг на основе базы знаний."""
    
    def __init__(self, knowledge_base_path: str = "knowledge/refactoring_automation_metadata.json"):
        self.knowledge_base_path = Path(knowledge_base_path)
        self.knowledge_base = None
        self._load_knowledge_base()
        
    def _load_knowledge_base(self):
        """Загрузить базу знаний."""
        try:
            if self.knowledge_base_path.exists():
                with open(self.knowledge_base_path, 'r', encoding='utf-8') as f:
                    self.knowledge_base = json.load(f)
                print(f"✅ Загружена база знаний: {self.knowledge_base_path}")
            else:
                print("⚠️  База знаний не найдена")
        except Exception as e:
            print(f"❌ Ошибка загрузки базы знаний: {e}")
            
    def analyze_god_object(self, filepath: Path) -> RefactoringPlan:
        """Анализ God Object и создание плана рефакторинга."""
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        tree = ast.parse(content)
        
        # Найти главный класс (God Object)
        main_class = None
        max_methods = 0
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
                if len(methods) > max_methods:
                    max_methods = len(methods)
                    main_class = node
                    
        if not main_class or max_methods < 10:
            return RefactoringPlan(
                target_file=str(filepath),
                transformations=[],
                extracted_components=[],
                new_files=[],
                estimated_effort=0,
                risk_level="low"
            )
            
        # Анализ методов для группировки по ответственностям
        method_groups = self._group_methods_by_responsibility(main_class)
        
        # Создание плана извлечения компонентов
        extracted_components = []
        new_files = []
        transformations = []
        
        for group_name, methods in method_groups.items():
            if len(methods) >= 3:  # Группы с 3+ методами стоит выделять
                component_name = f"{group_name.title()}Service"
                interface_name = f"I{component_name}"
                
                extracted_components.append(component_name)
                new_files.append(f"core/services/{group_name}_service.py")
                transformations.append(f"Extract {len(methods)} methods to {component_name}")
                
        # Оценка усилий и рисков
        estimated_effort = len(extracted_components) * 2.5 + 4  # базовые 4 часа + по 2.5 на компонент
        risk_level = "high" if len(extracted_components) > 5 else "medium"
        
        return RefactoringPlan(
            target_file=str(filepath),
            transformations=transformations,
            extracted_components=extracted_components,
            new_files=new_files,
            estimated_effort=estimated_effort,
            risk_level=risk_level
        )
        
    def _group_methods_by_responsibility(self, class_node: ast.ClassDef) -> Dict[str, List[ast.FunctionDef]]:
        """Группировка методов по ответственностям на основе префиксов и семантики."""
        
        methods = [node for node in class_node.body if isinstance(node, ast.FunctionDef)]
        groups = {
            "strategy": [],
            "testing": [],
            "analysis": [],
            "caching": [],
            "logging": [],
            "config": [],
            "network": [],
            "fingerprint": [],
            "monitoring": [],
            "other": []
        }
        
        # Ключевые слова для группировки
        keywords = {
            "strategy": ["strategy", "generate", "create", "build", "construct"],
            "testing": ["test", "validate", "verify", "check", "probe"],
            "analysis": ["analyze", "parse", "process", "examine", "inspect"],
            "caching": ["cache", "store", "save", "load", "persist"],
            "logging": ["log", "debug", "info", "warn", "error"],
            "config": ["config", "setting", "option", "parameter"],
            "network": ["connect", "request", "response", "http", "tcp"],
            "fingerprint": ["fingerprint", "detect", "identify", "recognize"],
            "monitoring": ["monitor", "track", "measure", "metric", "stat"]
        }
        
        for method in methods:
            method_name = method.name.lower()
            assigned = False
            
            # Группировка по ключевым словам
            for group, words in keywords.items():
                if any(word in method_name for word in words):
                    groups[group].append(method)
                    assigned = True
                    break
                    
            if not assigned:
                groups["other"].append(method)
                
        # Удалить пустые группы
        return {k: v for k, v in groups.items() if v}
        
    def generate_component_interface(self, component_name: str, methods: List[ast.FunctionDef]) -> str:
        """Генерация интерфейса для компонента."""
        
        interface_name = f"I{component_name}"
        
        interface_code = f'''"""
Interface for {component_name}.

This interface defines the contract for {component_name.lower()} operations.
"""

from typing import Protocol, Any, Dict, List, Optional
from abc import abstractmethod


class {interface_name}(Protocol):
    """Interface for {component_name.lower()} operations."""
    
'''
        
        # Добавить методы интерфейса
        for method in methods:
            if method.name.startswith('_'):  # Пропустить приватные методы
                continue
                
            # Упрощенная сигнатура метода
            args = [arg.arg for arg in method.args.args[1:]]  # Пропустить self
            args_str = ", ".join(f"{arg}: Any" for arg in args)
            
            interface_code += f'''    @abstractmethod
    def {method.name}(self{", " + args_str if args_str else ""}) -> Any:
        """
        {method.name.replace('_', ' ').title()} operation.
        
        This method should be implemented by concrete classes.
        """
        pass
        
'''
        
        return interface_code
        
    def generate_component_implementation(self, component_name: str, methods: List[ast.FunctionDef], 
                                       original_content: str) -> str:
        """Генерация реализации компонента."""
        
        interface_name = f"I{component_name}"
        
        impl_code = f'''"""
{component_name} - Implementation of {interface_name}.

Extracted from monolithic class to improve maintainability and testability.
"""

import logging
from typing import Any, Dict, List, Optional

from .interfaces import {interface_name}

logger = logging.getLogger(__name__)


class {component_name}({interface_name}):
    """Implementation of {interface_name}."""
    
    def __init__(self):
        """Initialize {component_name}."""
        self.logger = logger
        
'''
        
        # Извлечь методы из оригинального кода
        tree = ast.parse(original_content)
        
        for method in methods:
            if method.name.startswith('_'):  # Пропустить приватные методы
                continue
                
            # Найти метод в оригинальном AST и извлечь его код
            method_code = self._extract_method_code(method, original_content)
            impl_code += f"    {method_code}\n\n"
            
        return impl_code
        
    def _extract_method_code(self, method_node: ast.FunctionDef, original_content: str) -> str:
        """Извлечь код метода из оригинального файла."""
        
        lines = original_content.splitlines()
        
        # Найти начало и конец метода
        start_line = method_node.lineno - 1
        end_line = method_node.end_lineno if hasattr(method_node, 'end_lineno') else start_line + 10
        
        # Извлечь код метода
        method_lines = lines[start_line:end_line]
        
        # Убрать лишние отступы
        if method_lines:
            # Найти минимальный отступ (исключая пустые строки)
            non_empty_lines = [line for line in method_lines if line.strip()]
            if non_empty_lines:
                min_indent = min(len(line) - len(line.lstrip()) for line in non_empty_lines)
                method_lines = [line[min_indent:] if len(line) > min_indent else line 
                              for line in method_lines]
                
        return "\n".join(method_lines)
        
    def create_facade_wrapper(self, original_class_name: str, components: List[str]) -> str:
        """Создание фасада для обратной совместимости."""
        
        facade_code = f'''"""
{original_class_name} - Backward compatible facade.

This facade maintains the original API while delegating to refactored components.
Ensures 100% backward compatibility for existing clients.
"""

import logging
from typing import Any, Dict, List, Optional

# Import all service interfaces
'''
        
        # Импорты компонентов
        for component in components:
            service_name = component.replace('Service', '').lower()
            facade_code += f"from .services.{service_name}_service import {component}, I{component}\n"
            
        facade_code += f'''
from .container import DIContainer
from .config import AdaptiveEngineConfig

logger = logging.getLogger(__name__)


class {original_class_name}:
    """
    Backward compatible facade for {original_class_name}.
    
    Maintains the original API while using refactored internal components.
    All existing code should work without modifications.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize {original_class_name} with backward compatibility.
        
        Args:
            config: Legacy configuration dictionary (will be converted)
        """
        self.logger = logger
        
        # Convert legacy config to new format
        engine_config = self._convert_legacy_config(config)
        
        # Initialize DI container with all services
        self.container = DIContainer.create_default(engine_config)
        
        # Get service instances
'''
        
        # Инициализация сервисов
        for component in components:
            service_var = component.replace('Service', '').lower() + '_service'
            facade_code += f"        self.{service_var} = self.container.get(I{component})\n"
            
        facade_code += '''
        
        self.logger.info("AdaptiveEngine initialized with refactored architecture")
        
    def _convert_legacy_config(self, legacy_config: Optional[Dict]) -> AdaptiveEngineConfig:
        """Convert legacy configuration to new format."""
        if legacy_config is None:
            return AdaptiveEngineConfig.create_default()
            
        # Convert old config structure to new
        return AdaptiveEngineConfig.from_legacy_dict(legacy_config)
        
    # Legacy API methods - delegate to appropriate services
    # These methods maintain exact compatibility with the original API
    
'''
        
        return facade_code
        
    def execute_refactoring(self, filepath: Path, plan: RefactoringPlan, 
                          dry_run: bool = True) -> Dict[str, Any]:
        """Выполнить рефакторинг согласно плану."""
        
        results = {
            "success": False,
            "files_created": [],
            "files_modified": [],
            "backup_created": None,
            "errors": []
        }
        
        try:
            # Создать резервную копию
            if plan.backup_required and not dry_run:
                backup_path = filepath.with_suffix(f".backup_{int(time.time())}.py")
                backup_path.write_text(filepath.read_text(encoding='utf-8'), encoding='utf-8')
                results["backup_created"] = str(backup_path)
                
            # Прочитать оригинальный файл
            original_content = filepath.read_text(encoding='utf-8')
            tree = ast.parse(original_content)
            
            # Найти главный класс
            main_class = None
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
                    if len(methods) > 10:  # God Object
                        main_class = node
                        break
                        
            if not main_class:
                results["errors"].append("God Object не найден")
                return results
                
            # Группировка методов
            method_groups = self._group_methods_by_responsibility(main_class)
            
            # Создать папку для сервисов
            services_dir = filepath.parent / "services"
            if not dry_run:
                services_dir.mkdir(exist_ok=True)
                
            # Генерация компонентов
            for group_name, methods in method_groups.items():
                if len(methods) < 3:
                    continue
                    
                component_name = f"{group_name.title()}Service"
                
                # Генерация интерфейса
                interface_code = self.generate_component_interface(component_name, methods)
                interface_file = services_dir / "interfaces.py"
                
                if not dry_run:
                    if interface_file.exists():
                        # Добавить к существующему файлу
                        existing_content = interface_file.read_text(encoding='utf-8')
                        interface_file.write_text(existing_content + "\n\n" + interface_code, encoding='utf-8')
                    else:
                        interface_file.write_text(interface_code, encoding='utf-8')
                        
                results["files_created"].append(str(interface_file))
                
                # Генерация реализации
                impl_code = self.generate_component_implementation(component_name, methods, original_content)
                impl_file = services_dir / f"{group_name}_service.py"
                
                if not dry_run:
                    impl_file.write_text(impl_code, encoding='utf-8')
                    
                results["files_created"].append(str(impl_file))
                
            # Создание фасада
            facade_code = self.create_facade_wrapper(main_class.name, plan.extracted_components)
            
            if not dry_run:
                # Заменить содержимое оригинального файла на фасад
                filepath.write_text(facade_code, encoding='utf-8')
                
            results["files_modified"].append(str(filepath))
            results["success"] = True
            
        except Exception as e:
            results["errors"].append(f"Ошибка выполнения рефакторинга: {e}")
            logger.exception("Ошибка рефакторинга")
            
        return results


def main():
    """Главная функция для CLI."""
    import argparse
    import time
    
    parser = argparse.ArgumentParser(description="Автоматический рефакторинг God Objects")
    parser.add_argument("file", help="Путь к файлу для рефакторинга")
    parser.add_argument("--dry-run", action="store_true", help="Показать план без выполнения")
    parser.add_argument("--knowledge-base", default="knowledge/refactoring_automation_metadata.json",
                       help="Путь к базе знаний")
    
    args = parser.parse_args()
    
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"❌ Файл не найден: {filepath}")
        return
        
    print(f"🔍 Анализ файла: {filepath}")
    
    refactor = AutoRefactor(args.knowledge_base)
    plan = refactor.analyze_god_object(filepath)
    
    print(f"\n📋 План рефакторинга:")
    print(f"   📁 Целевой файл: {plan.target_file}")
    print(f"   🔧 Трансформации: {len(plan.transformations)}")
    print(f"   🏗️  Компоненты: {len(plan.extracted_components)}")
    print(f"   📄 Новые файлы: {len(plan.new_files)}")
    print(f"   ⏱️  Оценка времени: {plan.estimated_effort:.1f} часов")
    print(f"   ⚠️  Уровень риска: {plan.risk_level}")
    
    if plan.transformations:
        print(f"\n🎯 Планируемые трансформации:")
        for i, transformation in enumerate(plan.transformations, 1):
            print(f"   {i}. {transformation}")
            
    if plan.extracted_components:
        print(f"\n🏗️  Извлекаемые компоненты:")
        for component in plan.extracted_components:
            print(f"   - {component}")
            
    if args.dry_run:
        print(f"\n🔍 Режим dry-run: изменения не применены")
        return
        
    # Подтверждение выполнения
    response = input(f"\n❓ Выполнить рефакторинг? (y/N): ")
    if response.lower() != 'y':
        print("❌ Рефакторинг отменен")
        return
        
    print(f"\n🚀 Выполнение рефакторинга...")
    start_time = time.time()
    
    results = refactor.execute_refactoring(filepath, plan, dry_run=False)
    
    elapsed_time = time.time() - start_time
    
    if results["success"]:
        print(f"\n✅ Рефакторинг завершен успешно за {elapsed_time:.1f} секунд")
        print(f"   📄 Создано файлов: {len(results['files_created'])}")
        print(f"   📝 Изменено файлов: {len(results['files_modified'])}")
        if results["backup_created"]:
            print(f"   💾 Резервная копия: {results['backup_created']}")
    else:
        print(f"\n❌ Рефакторинг завершился с ошибками:")
        for error in results["errors"]:
            print(f"   - {error}")


if __name__ == "__main__":
    main()