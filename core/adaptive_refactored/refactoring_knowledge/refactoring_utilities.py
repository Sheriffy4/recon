"""
Reusable Refactoring Components and Utilities.

This module provides reusable components and utilities that can be used
to automate common refactoring operations based on the patterns learned
from the adaptive engine refactoring.
"""

import ast
import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from pathlib import Path
from abc import ABC, abstractmethod
import textwrap


logger = logging.getLogger(__name__)


@dataclass
class RefactoringResult:
    """Result of a refactoring operation."""

    success: bool
    files_created: List[str]
    files_modified: List[str]
    files_deleted: List[str]
    error_message: Optional[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class RefactoringUtility(ABC):
    """Base class for refactoring utilities."""

    @abstractmethod
    def can_apply(self, file_path: str, **kwargs) -> bool:
        """Check if this utility can be applied to the given file."""
        pass

    @abstractmethod
    def apply(self, file_path: str, **kwargs) -> RefactoringResult:
        """Apply the refactoring to the given file."""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Get a description of what this utility does."""
        pass


class ComponentExtractor(RefactoringUtility):
    """Utility for extracting components from monolithic classes."""

    def __init__(self):
        self.interface_template = '''"""
{interface_description}
"""
from typing import Protocol
{additional_imports}

class {interface_name}(Protocol):
    """Interface for {component_description}."""
    
{interface_methods}
'''

        self.implementation_template = '''"""
{implementation_description}
"""
{imports}

class {class_name}({interface_name}):
    """Implementation of {interface_name}."""
    
    def __init__(self{constructor_params}):
        {constructor_body}
        
{methods}
'''

    def can_apply(self, file_path: str, **kwargs) -> bool:
        """Check if component extraction can be applied."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            # Find classes
            classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

            if not classes:
                return False

            # Check if any class is large enough to warrant extraction
            for cls in classes:
                methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)]
                if len(methods) > 5 and len(content.split("\n")) > 500:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking if component extraction can be applied: {e}")
            return False

    def apply(self, file_path: str, **kwargs) -> RefactoringResult:
        """Extract components from a monolithic class."""
        try:
            component_name = kwargs.get("component_name", "ExtractedComponent")
            methods_to_extract = kwargs.get("methods", [])
            target_directory = kwargs.get("target_directory", Path(file_path).parent)

            if not methods_to_extract:
                return RefactoringResult(
                    success=False,
                    files_created=[],
                    files_modified=[],
                    files_deleted=[],
                    error_message="No methods specified for extraction",
                )

            # Read original file
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            # Extract the component
            interface_code, implementation_code = self._extract_component(
                tree, content, component_name, methods_to_extract
            )

            # Write interface file
            interface_path = Path(target_directory) / f"i_{component_name.lower()}.py"
            with open(interface_path, "w", encoding="utf-8") as f:
                f.write(interface_code)

            # Write implementation file
            impl_path = Path(target_directory) / f"{component_name.lower()}.py"
            with open(impl_path, "w", encoding="utf-8") as f:
                f.write(implementation_code)

            # Modify original file to use the extracted component
            modified_content = self._modify_original_file(
                content, component_name, methods_to_extract
            )
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(modified_content)

            return RefactoringResult(
                success=True,
                files_created=[str(interface_path), str(impl_path)],
                files_modified=[file_path],
                files_deleted=[],
                warnings=["Please review extracted component boundaries and update tests"],
            )

        except Exception as e:
            logger.error(f"Error applying component extraction: {e}")
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=str(e),
            )

    def _extract_component(
        self, tree: ast.AST, content: str, component_name: str, methods_to_extract: List[str]
    ) -> Tuple[str, str]:
        """Extract component interface and implementation."""

        # Find the class and methods
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        if not classes:
            raise ValueError("No classes found in file")

        main_class = classes[0]  # Assume first class is the main one

        # Extract method signatures for interface
        interface_methods = []
        implementation_methods = []

        for node in main_class.body:
            if isinstance(node, ast.FunctionDef) and node.name in methods_to_extract:
                # Create interface method signature
                interface_method = self._create_interface_method(node)
                interface_methods.append(interface_method)

                # Extract implementation method
                impl_method = self._extract_method_implementation(node, content)
                implementation_methods.append(impl_method)

        # Generate interface code
        interface_code = self.interface_template.format(
            interface_description=f"Interface for {component_name} component.",
            interface_name=f"I{component_name}",
            component_description=component_name.lower(),
            additional_imports="",
            interface_methods="\n".join(interface_methods),
        )

        # Generate implementation code
        implementation_code = self.implementation_template.format(
            implementation_description=f"Implementation of {component_name} component.",
            imports=f"from .i_{component_name.lower()} import I{component_name}",
            class_name=component_name,
            interface_name=f"I{component_name}",
            constructor_params="",
            constructor_body="pass",
            methods="\n".join(implementation_methods),
        )

        return interface_code, implementation_code

    def _create_interface_method(self, method_node: ast.FunctionDef) -> str:
        """Create interface method signature from AST node."""
        # Extract method signature
        args = []
        for arg in method_node.args.args[1:]:  # Skip 'self'
            args.append(arg.arg)

        args_str = ", ".join(args)
        if args_str:
            args_str = ", " + args_str

        # Create method signature
        method_sig = f"    def {method_node.name}(self{args_str}) -> Any:"
        method_doc = f'        """Method {method_node.name}."""'
        method_body = "        pass"

        return f"{method_sig}\n{method_doc}\n{method_body}\n"

    def _extract_method_implementation(self, method_node: ast.FunctionDef, content: str) -> str:
        """Extract method implementation from content."""
        lines = content.split("\n")

        # Find method start and end lines
        start_line = method_node.lineno - 1
        end_line = method_node.end_lineno if hasattr(method_node, "end_lineno") else start_line + 10

        # Extract method lines
        method_lines = lines[start_line:end_line]

        # Join and return
        return "\n".join(method_lines) + "\n"

    def _modify_original_file(
        self, content: str, component_name: str, methods_to_extract: List[str]
    ) -> str:
        """Modify original file to use extracted component."""
        lines = content.split("\n")

        # Add import for the component
        import_line = f"from .{component_name.lower()} import {component_name}, I{component_name}"

        # Find where to insert import (after existing imports)
        insert_index = 0
        for i, line in enumerate(lines):
            if line.strip().startswith(("import ", "from ")):
                insert_index = i + 1
            elif line.strip() and not line.strip().startswith("#"):
                break

        lines.insert(insert_index, import_line)

        # Add component as dependency in constructor
        # This is simplified - in reality would need more sophisticated AST manipulation

        # Remove extracted methods (simplified)
        filtered_lines = []
        skip_lines = False

        for line in lines:
            # Simple heuristic to skip extracted methods
            if any(f"def {method}" in line for method in methods_to_extract):
                skip_lines = True
            elif line.strip().startswith("def ") and skip_lines:
                skip_lines = False
                filtered_lines.append(line)
            elif not skip_lines:
                filtered_lines.append(line)

        return "\n".join(filtered_lines)

    def get_description(self) -> str:
        """Get description of component extractor."""
        return (
            "Extracts components from monolithic classes following single responsibility principle"
        )


class ConfigurationSplitter(RefactoringUtility):
    """Utility for splitting monolithic configuration classes."""

    def __init__(self):
        self.domain_config_template = '''"""
{domain_name} configuration.
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class {class_name}:
    """{domain_name} configuration settings."""
    
{fields}
'''

        self.main_config_template = '''"""
Main configuration that composes domain-specific configurations.
"""
from dataclasses import dataclass
{imports}

@dataclass
class {main_class_name}:
    """Main configuration composed of domain-specific configs."""
    
{domain_fields}
'''

    def can_apply(self, file_path: str, **kwargs) -> bool:
        """Check if configuration splitting can be applied."""
        try:
            if "config" not in file_path.lower():
                return False

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Check if file has dataclass with many fields
            if "@dataclass" in content and content.count(":") > 10:
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking if config splitting can be applied: {e}")
            return False

    def apply(self, file_path: str, **kwargs) -> RefactoringResult:
        """Split monolithic configuration into domain-specific configs."""
        try:
            domains = kwargs.get("domains", {})  # domain_name -> field_names
            target_directory = kwargs.get("target_directory", Path(file_path).parent)

            if not domains:
                return RefactoringResult(
                    success=False,
                    files_created=[],
                    files_modified=[],
                    files_deleted=[],
                    error_message="No domains specified for configuration split",
                )

            # Read original file
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse configuration fields
            config_fields = self._parse_config_fields(content)

            created_files = []
            imports = []
            domain_fields = []

            # Create domain-specific config files
            for domain_name, field_names in domains.items():
                domain_fields_code = []

                for field_name in field_names:
                    if field_name in config_fields:
                        domain_fields_code.append(f"    {config_fields[field_name]}")

                class_name = f"{domain_name.title()}Config"

                domain_config_code = self.domain_config_template.format(
                    domain_name=domain_name.title(),
                    class_name=class_name,
                    fields="\n".join(domain_fields_code),
                )

                # Write domain config file
                domain_file_path = Path(target_directory) / f"{domain_name}_config.py"
                with open(domain_file_path, "w", encoding="utf-8") as f:
                    f.write(domain_config_code)

                created_files.append(str(domain_file_path))
                imports.append(f"from .{domain_name}_config import {class_name}")
                domain_fields.append(f"    {domain_name}: {class_name}")

            # Create main config file
            main_config_code = self.main_config_template.format(
                main_class_name="MainConfig",
                imports="\n".join(imports),
                domain_fields="\n".join(domain_fields),
            )

            # Write main config file
            main_config_path = Path(target_directory) / "main_config.py"
            with open(main_config_path, "w", encoding="utf-8") as f:
                f.write(main_config_code)

            created_files.append(str(main_config_path))

            return RefactoringResult(
                success=True,
                files_created=created_files,
                files_modified=[],
                files_deleted=[],
                warnings=["Please update imports and usage of the original configuration"],
            )

        except Exception as e:
            logger.error(f"Error applying configuration splitting: {e}")
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=str(e),
            )

    def _parse_config_fields(self, content: str) -> Dict[str, str]:
        """Parse configuration fields from content."""
        fields = {}
        lines = content.split("\n")

        in_dataclass = False
        for line in lines:
            stripped = line.strip()

            if "@dataclass" in stripped:
                in_dataclass = True
                continue

            if in_dataclass and stripped.startswith("class "):
                continue

            if in_dataclass and ":" in stripped and "=" in stripped:
                # This is a field definition
                field_match = re.match(r"\s*(\w+):\s*(.+)", stripped)
                if field_match:
                    field_name = field_match.group(1)
                    field_definition = field_match.group(2)
                    fields[field_name] = f"{field_name}: {field_definition}"

        return fields

    def get_description(self) -> str:
        """Get description of configuration splitter."""
        return "Splits monolithic configuration classes into domain-specific configurations"


class DependencyInjectionIntroducer(RefactoringUtility):
    """Utility for introducing dependency injection patterns."""

    def __init__(self):
        self.interface_template = '''"""
Interface for {service_name}.
"""
from typing import Protocol
{additional_imports}

class I{service_name}(Protocol):
    """Interface for {service_name} service."""
    
{interface_methods}
'''

        self.container_template = '''"""
Dependency injection container.
"""
from typing import Dict, Any, TypeVar, Type, Callable
import inspect

T = TypeVar('T')

class DIContainer:
    """Simple dependency injection container."""
    
    def __init__(self):
        self._services: Dict[Type, Any] = {}
        self._singletons: Dict[Type, Any] = {}
        self._factories: Dict[Type, Callable] = {}
        
    def register_singleton(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a singleton service."""
        self._services[interface] = implementation
        
    def register_transient(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a transient service."""
        self._services[interface] = implementation
        
    def register_factory(self, interface: Type[T], factory: Callable[[], T]) -> None:
        """Register a factory for creating services."""
        self._factories[interface] = factory
        
    def get(self, interface: Type[T]) -> T:
        """Get a service instance."""
        if interface in self._singletons:
            return self._singletons[interface]
            
        if interface in self._factories:
            instance = self._factories[interface]()
            self._singletons[interface] = instance
            return instance
            
        if interface in self._services:
            implementation = self._services[interface]
            
            # Create instance with dependency injection
            constructor = implementation.__init__
            sig = inspect.signature(constructor)
            
            kwargs = {}
            for param_name, param in sig.parameters.items():
                if param_name == 'self':
                    continue
                    
                if param.annotation != inspect.Parameter.empty:
                    dependency = self.get(param.annotation)
                    kwargs[param_name] = dependency
                    
            instance = implementation(**kwargs)
            
            # Cache as singleton if registered as such
            if interface in self._services:
                self._singletons[interface] = instance
                
            return instance
            
        raise ValueError(f"Service {interface} not registered")
        
    @classmethod
    def create_default(cls, config: Any = None) -> 'DIContainer':
        """Create container with default registrations."""
        container = cls()
        # Default registrations would go here
        return container
'''

    def can_apply(self, file_path: str, **kwargs) -> bool:
        """Check if dependency injection can be applied."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Check for classes that create their own dependencies
            if re.search(r"self\.\w+\s*=\s*\w+\(", content):
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking if DI can be applied: {e}")
            return False

    def apply(self, file_path: str, **kwargs) -> RefactoringResult:
        """Introduce dependency injection patterns."""
        try:
            services = kwargs.get("services", [])  # List of service names
            target_directory = kwargs.get("target_directory", Path(file_path).parent)

            created_files = []

            # Create interfaces for services
            for service_name in services:
                interface_code = self._create_service_interface(service_name)
                interface_path = Path(target_directory) / f"i_{service_name.lower()}.py"

                with open(interface_path, "w", encoding="utf-8") as f:
                    f.write(interface_code)

                created_files.append(str(interface_path))

            # Create DI container
            container_path = Path(target_directory) / "container.py"
            with open(container_path, "w", encoding="utf-8") as f:
                f.write(self.container_template)

            created_files.append(str(container_path))

            # Modify original file to use DI
            self._modify_for_di(file_path, services)

            return RefactoringResult(
                success=True,
                files_created=created_files,
                files_modified=[file_path],
                files_deleted=[],
                warnings=["Please review constructor parameters and update service registrations"],
            )

        except Exception as e:
            logger.error(f"Error applying dependency injection: {e}")
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=str(e),
            )

    def _create_service_interface(self, service_name: str) -> str:
        """Create interface for a service."""
        # This is simplified - would need more sophisticated analysis
        interface_methods = [
            "    def process(self, data: Any) -> Any:",
            '        """Process data."""',
            "        pass",
        ]

        return self.interface_template.format(
            service_name=service_name,
            additional_imports="from typing import Any",
            interface_methods="\n".join(interface_methods),
        )

    def _modify_for_di(self, file_path: str, services: List[str]) -> None:
        """Modify file to use dependency injection."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Add imports
        imports_to_add = []
        for service in services:
            imports_to_add.append(f"from .i_{service.lower()} import I{service}")

        # Simple modification - in reality would need AST manipulation
        lines = content.split("\n")

        # Find import section
        import_index = 0
        for i, line in enumerate(lines):
            if line.strip().startswith(("import ", "from ")):
                import_index = i + 1

        # Insert new imports
        for import_line in imports_to_add:
            lines.insert(import_index, import_line)
            import_index += 1

        # Write back
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def get_description(self) -> str:
        """Get description of DI introducer."""
        return "Introduces dependency injection patterns with interfaces and container"


class FacadeCreator(RefactoringUtility):
    """Utility for creating facade patterns for backward compatibility."""

    def __init__(self):
        self.facade_template = '''"""
Facade for backward compatibility.
"""
from typing import Any, Dict, Optional
{imports}

class {facade_class_name}:
    """Facade that maintains backward compatibility while using new architecture."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize facade with backward-compatible configuration."""
        # Convert old config format to new
        engine_config = self._convert_config(config)
        
        # Initialize with DI container
        self.container = DIContainer.create_default(engine_config)
{service_initializations}
        
{facade_methods}
        
    def _convert_config(self, old_config: Optional[Dict]) -> Any:
        """Convert old configuration format to new structure."""
        if old_config is None:
            old_config = {}
            
        # Configuration conversion logic would go here
        return old_config
'''

    def can_apply(self, file_path: str, **kwargs) -> bool:
        """Check if facade creation can be applied."""
        # Facade is typically applied after major refactoring
        return kwargs.get("major_refactoring_completed", False)

    def apply(self, file_path: str, **kwargs) -> RefactoringResult:
        """Create facade for backward compatibility."""
        try:
            facade_class_name = kwargs.get("facade_class_name", "BackwardCompatibleFacade")
            services = kwargs.get("services", [])
            methods = kwargs.get("methods", [])
            target_directory = kwargs.get("target_directory", Path(file_path).parent)

            # Generate service initializations
            service_inits = []
            imports = ["from .container import DIContainer"]

            for service in services:
                service_inits.append(
                    f"        self.{service.lower()}_service = self.container.get(I{service}Service)"
                )
                imports.append(f"from .i_{service.lower()}_service import I{service}Service")

            # Generate facade methods
            facade_methods = []
            for method in methods:
                method_code = self._create_facade_method(method, services)
                facade_methods.append(method_code)

            # Create facade code
            facade_code = self.facade_template.format(
                facade_class_name=facade_class_name,
                imports="\n".join(imports),
                service_initializations="\n".join(service_inits),
                facade_methods="\n".join(facade_methods),
            )

            # Write facade file
            facade_path = Path(target_directory) / f"{facade_class_name.lower()}.py"
            with open(facade_path, "w", encoding="utf-8") as f:
                f.write(facade_code)

            return RefactoringResult(
                success=True,
                files_created=[str(facade_path)],
                files_modified=[],
                files_deleted=[],
                warnings=[
                    "Please review facade method implementations and test backward compatibility"
                ],
            )

        except Exception as e:
            logger.error(f"Error creating facade: {e}")
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=str(e),
            )

    def _create_facade_method(self, method_name: str, services: List[str]) -> str:
        """Create a facade method that delegates to internal services."""
        # Simplified method creation
        method_code = f'''    def {method_name}(self, *args, **kwargs) -> Any:
        """Facade method for {method_name}."""
        # Delegate to appropriate internal service
        # This would contain the actual delegation logic
        pass
'''
        return method_code

    def get_description(self) -> str:
        """Get description of facade creator."""
        return "Creates facade pattern for maintaining backward compatibility"


class RefactoringUtilityRegistry:
    """Registry of available refactoring utilities."""

    def __init__(self):
        self.utilities: Dict[str, RefactoringUtility] = {}
        self._register_default_utilities()

    def _register_default_utilities(self):
        """Register default refactoring utilities."""
        self.register("component_extractor", ComponentExtractor())
        self.register("configuration_splitter", ConfigurationSplitter())
        self.register("dependency_injection", DependencyInjectionIntroducer())
        self.register("facade_creator", FacadeCreator())

    def register(self, name: str, utility: RefactoringUtility):
        """Register a refactoring utility."""
        self.utilities[name] = utility
        logger.info(f"Registered refactoring utility: {name}")

    def get_utility(self, name: str) -> Optional[RefactoringUtility]:
        """Get a refactoring utility by name."""
        return self.utilities.get(name)

    def get_applicable_utilities(
        self, file_path: str, **kwargs
    ) -> List[Tuple[str, RefactoringUtility]]:
        """Get utilities that can be applied to the given file."""
        applicable = []

        for name, utility in self.utilities.items():
            if utility.can_apply(file_path, **kwargs):
                applicable.append((name, utility))

        return applicable

    def list_utilities(self) -> Dict[str, str]:
        """List all registered utilities with their descriptions."""
        return {name: utility.get_description() for name, utility in self.utilities.items()}


# Global registry instance
_utility_registry: Optional[RefactoringUtilityRegistry] = None


def get_utility_registry() -> RefactoringUtilityRegistry:
    """Get the global utility registry."""
    global _utility_registry
    if _utility_registry is None:
        _utility_registry = RefactoringUtilityRegistry()
    return _utility_registry


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Demonstrate the utilities
    registry = get_utility_registry()

    logger.info("Available refactoring utilities:")
    for name, description in registry.list_utilities().items():
        logger.info(f"  {name}: {description}")
