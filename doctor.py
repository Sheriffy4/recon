#!/usr/bin/env python3
"""
Doctor Script - Санитарная проверка проекта

Проверяет все модули проекта на наличие ошибок импорта,
циклических зависимостей и других проблем.
"""

import sys
import importlib
from pathlib import Path
from typing import List, Dict, Set, Tuple
import ast


class DoctorReport:
    """Отчет о проверке проекта."""

    def __init__(self):
        self.import_errors: List[Tuple[str, str]] = []
        self.circular_dependencies: List[List[str]] = []
        self.syntax_errors: List[Tuple[str, str]] = []
        self.missing_files: List[str] = []
        self.successful_imports: List[str] = []

    def add_import_error(self, module: str, error: str):
        self.import_errors.append((module, error))

    def add_circular_dependency(self, cycle: List[str]):
        self.circular_dependencies.append(cycle)

    def add_syntax_error(self, file_path: str, error: str):
        self.syntax_errors.append((file_path, error))

    def add_missing_file(self, file_path: str):
        self.missing_files.append(file_path)

    def add_successful_import(self, module: str):
        self.successful_imports.append(module)

    def print_report(self):
        """Печатает детальный отчет."""
        print("=" * 80)
        print("🏥 DOCTOR REPORT - Санитарная проверка проекта")
        print("=" * 80)

        # Успешные импорты
        print(f"\n✅ Успешные импорты: {len(self.successful_imports)}")
        if self.successful_imports:
            for module in sorted(self.successful_imports):
                print(f"   ✓ {module}")

        # Ошибки импорта
        if self.import_errors:
            print(f"\n❌ Ошибки импорта: {len(self.import_errors)}")
            for module, error in self.import_errors:
                print(f"   ✗ {module}: {error}")

        # Синтаксические ошибки
        if self.syntax_errors:
            print(f"\n🔥 Синтаксические ошибки: {len(self.syntax_errors)}")
            for file_path, error in self.syntax_errors:
                print(f"   ✗ {file_path}: {error}")

        # Циклические зависимости
        if self.circular_dependencies:
            print(f"\n🔄 Циклические зависимости: {len(self.circular_dependencies)}")
            for i, cycle in enumerate(self.circular_dependencies, 1):
                print(f"   {i}. {' → '.join(cycle)} → {cycle[0]}")

        # Отсутствующие файлы
        if self.missing_files:
            print(f"\n📁 Отсутствующие файлы: {len(self.missing_files)}")
            for file_path in self.missing_files:
                print(f"   ✗ {file_path}")

        # Итоговая оценка
        total_issues = (
            len(self.import_errors)
            + len(self.syntax_errors)
            + len(self.circular_dependencies)
            + len(self.missing_files)
        )

        print("\n" + "=" * 80)
        if total_issues == 0:
            print("🎉 ПРОЕКТ ЗДОРОВ! Все проверки пройдены успешно.")
        else:
            print(f"⚠️  НАЙДЕНО ПРОБЛЕМ: {total_issues}")
            print("   Рекомендуется исправить проблемы перед продолжением разработки.")
        print("=" * 80)


class ProjectDoctor:
    """Основной класс для проверки проекта."""

    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.report = DoctorReport()
        self.dependency_graph: Dict[str, Set[str]] = {}

    def find_python_files(self) -> List[Path]:
        """Находит все Python файлы в проекте."""
        python_files = []

        # Исключаем определенные директории
        exclude_dirs = {
            "__pycache__",
            ".git",
            ".pytest_cache",
            "venv",
            "env",
            ".venv",
            "node_modules",
            ".kiro",
            "build",
            "dist",
        }

        for path in self.project_root.rglob("*.py"):
            # Проверяем, что файл не в исключенной директории
            if not any(part in exclude_dirs for part in path.parts):
                python_files.append(path)

        return python_files

    def check_syntax(self, file_path: Path) -> bool:
        """Проверяет синтаксис Python файла."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            ast.parse(source)
            return True
        except SyntaxError as e:
            self.report.add_syntax_error(str(file_path), str(e))
            return False
        except Exception as e:
            self.report.add_syntax_error(str(file_path), f"Unexpected error: {e}")
            return False

    def path_to_module(self, file_path: Path) -> str:
        """Конвертирует путь к файлу в имя модуля."""
        try:
            relative_path = file_path.relative_to(self.project_root)
            module_parts = list(relative_path.parts[:-1])  # Убираем имя файла

            # Добавляем имя файла без расширения
            file_name = relative_path.stem
            if file_name != "__init__":
                module_parts.append(file_name)

            return ".".join(module_parts)
        except ValueError:
            return str(file_path)

    def extract_imports(self, file_path: Path) -> Set[str]:
        """Извлекает импорты из Python файла."""
        imports = set()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split(".")[0])

        except Exception:
            # Если не можем парсить, пропускаем
            pass

        return imports

    def build_dependency_graph(self, python_files: List[Path]):
        """Строит граф зависимостей между модулями."""
        for file_path in python_files:
            module_name = self.path_to_module(file_path)
            imports = self.extract_imports(file_path)

            # Фильтруем только локальные импорты (начинающиеся с core, ml, tests)
            local_imports = {
                imp
                for imp in imports
                if imp.startswith(("core", "ml", "tests", "recon"))
            }

            self.dependency_graph[module_name] = local_imports

    def find_circular_dependencies(self):
        """Находит циклические зависимости в графе."""
        visited = set()
        rec_stack = set()

        def dfs(node: str, path: List[str]) -> bool:
            if node in rec_stack:
                # Найден цикл
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                self.report.add_circular_dependency(cycle)
                return True

            if node in visited:
                return False

            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in self.dependency_graph.get(node, set()):
                if dfs(neighbor, path):
                    return True

            rec_stack.remove(node)
            path.pop()
            return False

        for node in self.dependency_graph:
            if node not in visited:
                dfs(node, [])

    def test_imports(self, python_files: List[Path]):
        """Тестирует импорт всех модулей."""
        # Добавляем корень проекта в sys.path
        if str(self.project_root) not in sys.path:
            sys.path.insert(0, str(self.project_root))

        for file_path in python_files:
            module_name = self.path_to_module(file_path)

            if not module_name:  # Пропускаем файлы без модульного имени
                continue

            try:
                # Пытаемся импортировать модуль
                importlib.import_module(module_name)
                self.report.add_successful_import(module_name)

            except ImportError as e:
                self.report.add_import_error(module_name, str(e))
            except Exception as e:
                self.report.add_import_error(module_name, f"Unexpected error: {e}")

    def check_critical_files(self):
        """Проверяет наличие критически важных файлов."""
        critical_files = [
            "cli.py",
            "recon_service.py",
            "core/__init__.py",
            "core/di/container.py",
            "core/di/factory.py",
            "core/di/cli_provider.py",
            "core/bypass/engines/packet_processing_engine.py",
            "core/fingerprint/advanced_fingerprint_engine.py",
            "core/integration/attack_adapter.py",
            "core/integration/closed_loop_manager.py",
            "core/packet_builder.py",
            "core/interfaces/core_interfaces.py",
            "core/interfaces/service_interfaces.py",
        ]

        for file_path in critical_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                self.report.add_missing_file(file_path)

    def check_di_architecture(self):
        """Проверяет корректность DI архитектуры."""
        print("🏗️  Проверка DI архитектуры...")

        # Проверяем, что ключевые классы используют DI
        di_classes_to_check = [
            (
                "core/bypass/engines/packet_processing_engine.py",
                "PacketProcessingEngine",
                ["attack_adapter", "fingerprint_engine", "diagnostic_system"],
            ),
            (
                "core/integration/closed_loop_manager.py",
                "ClosedLoopManager",
                [
                    "fingerprint_engine",
                    "strategy_generator",
                    "effectiveness_tester",
                    "learning_memory",
                    "attack_adapter",
                    "strategy_saver",
                ],
            ),
            (
                "core/fingerprint/advanced_fingerprint_engine.py",
                "UltimateAdvancedFingerprintEngine",
                ["prober", "classifier", "attack_adapter"],
            ),
        ]

        for file_path, class_name, expected_deps in di_classes_to_check:
            full_path = self.project_root / file_path
            if full_path.exists():
                self._check_class_di_compliance(full_path, class_name, expected_deps)

    def _check_class_di_compliance(
        self, file_path: Path, class_name: str, expected_deps: List[str]
    ):
        """Проверяет, что класс соответствует принципам DI."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    # Ищем метод __init__
                    for method in node.body:
                        if (
                            isinstance(method, ast.FunctionDef)
                            and method.name == "__init__"
                        ):
                            # Проверяем аргументы конструктора
                            args = [
                                arg.arg for arg in method.args.args if arg.arg != "self"
                            ]

                            missing_deps = []
                            for dep in expected_deps:
                                if dep not in args:
                                    missing_deps.append(dep)

                            if missing_deps:
                                error_msg = f"Missing DI dependencies: {', '.join(missing_deps)}"
                                self.report.add_import_error(
                                    f"{class_name} (DI)", error_msg
                                )
                            else:
                                self.report.add_successful_import(
                                    f"{class_name} (DI compliant)"
                                )
                            break
                    break

        except Exception as e:
            self.report.add_import_error(f"{class_name} (DI check)", str(e))

    def check_interface_implementations(self):
        """Проверяет, что классы правильно реализуют интерфейсы."""
        print("🔌 Проверка реализации интерфейсов...")

        # Проверяем PacketBuilder
        packet_builder_path = self.project_root / "core/packet_builder.py"
        if packet_builder_path.exists():
            self._check_interface_implementation(
                packet_builder_path,
                "PacketBuilder",
                "IPacketBuilder",
                [
                    "create_tcp_packet",
                    "create_udp_packet",
                    "create_syn_packet",
                    "fragment_packet",
                    "calculate_checksum",
                    "assemble_tcp_packet",
                ],
            )

    def _check_interface_implementation(
        self,
        file_path: Path,
        class_name: str,
        interface_name: str,
        required_methods: List[str],
    ):
        """Проверяет, что класс реализует все методы интерфейса."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    # Получаем все методы класса
                    class_methods = []
                    for method in node.body:
                        if isinstance(method, ast.FunctionDef):
                            class_methods.append(method.name)

                    # Проверяем наличие всех требуемых методов
                    missing_methods = []
                    for method in required_methods:
                        if method not in class_methods:
                            missing_methods.append(method)

                    if missing_methods:
                        error_msg = (
                            f"Missing interface methods: {', '.join(missing_methods)}"
                        )
                        self.report.add_import_error(
                            f"{class_name} ({interface_name})", error_msg
                        )
                    else:
                        self.report.add_successful_import(
                            f"{class_name} implements {interface_name}"
                        )
                    break

        except Exception as e:
            self.report.add_import_error(f"{class_name} (interface check)", str(e))

    def check_deprecated_patterns(self):
        """Проверяет использование устаревших паттернов."""
        print("🗑️  Проверка устаревших паттернов...")

        deprecated_patterns = [
            ("EnhancedPacketBuilder", "Use unified PacketBuilder instead"),
            ("PacketFactory", "Use unified PacketBuilder instead"),
            (
                "create_engine.*attack_adapter=None",
                "attack_adapter should be injected via DI",
            ),
            (
                "__init__.*=.*None.*#.*DI",
                "Dependencies should be required, not optional",
            ),
        ]

        python_files = self.find_python_files()

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                for pattern, message in deprecated_patterns:
                    if pattern in content:
                        relative_path = file_path.relative_to(self.project_root)
                        self.report.add_import_error(
                            f"Deprecated pattern in {relative_path}",
                            f"{pattern}: {message}",
                        )

            except Exception:
                continue

    def run_full_check(self):
        """Запускает полную проверку проекта."""
        print("🏥 Запуск санитарной проверки проекта...")
        print(f"📁 Корень проекта: {self.project_root}")

        # 1. Находим все Python файлы
        print("🔍 Поиск Python файлов...")
        python_files = self.find_python_files()
        print(f"   Найдено файлов: {len(python_files)}")

        # 2. Проверяем синтаксис
        print("📝 Проверка синтаксиса...")
        syntax_ok_files = []
        for file_path in python_files:
            if self.check_syntax(file_path):
                syntax_ok_files.append(file_path)
        print(f"   Файлов с корректным синтаксисом: {len(syntax_ok_files)}")

        # 3. Строим граф зависимостей
        print("🔗 Анализ зависимостей...")
        self.build_dependency_graph(syntax_ok_files)

        # 4. Ищем циклические зависимости
        print("🔄 Поиск циклических зависимостей...")
        self.find_circular_dependencies()

        # 5. Проверяем критические файлы
        print("📋 Проверка критических файлов...")
        self.check_critical_files()

        # 6. Проверяем DI архитектуру
        self.check_di_architecture()

        # 7. Проверяем реализацию интерфейсов
        self.check_interface_implementations()

        # 8. Проверяем устаревшие паттерны
        self.check_deprecated_patterns()

        # 9. Тестируем импорты
        print("📦 Тестирование импортов...")
        self.test_imports(syntax_ok_files)

        # 10. Выводим отчет
        self.report.print_report()


def main():
    """Главная функция."""
    project_root = "."
    if len(sys.argv) > 1:
        project_root = sys.argv[1]

    doctor = ProjectDoctor(project_root)
    doctor.run_full_check()


if __name__ == "__main__":
    main()
