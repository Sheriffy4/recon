#!/usr/bin/env python3
"""
Refactoring Results Validator

Валидатор результатов глобального рефакторинга.
Проверяет что все документы созданы и ссылки между ними работают.
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
import re


@dataclass
class ValidationResult:
    """Результат валидации."""
    check_name: str
    success: bool
    message: str
    details: Dict[str, Any] = None


class RefactoringValidator:
    """Валидатор результатов рефакторинга."""
    
    def __init__(self, project_root: Path = None):
        """
        Инициализация валидатора.
        
        Args:
            project_root: Корневая директория проекта
        """
        self.project_root = project_root or Path.cwd()
        self.expected_docs = [
            'PROJECT_STRUCTURE.md',
            'MODULE_REGISTRY.md', 
            'LLM_CONTEXT.md'
        ]
    
    def validate_all(self) -> List[ValidationResult]:
        """
        Выполняет все проверки валидации.
        
        Returns:
            Список результатов валидации
        """
        results = []
        
        # Проверяем существование документов
        results.append(self._check_documents_exist())
        
        # Проверяем ссылки между документами
        results.append(self._check_document_links())
        
        # Проверяем содержимое PROJECT_STRUCTURE.md
        results.append(self._check_project_structure_content())
        
        # Проверяем содержимое MODULE_REGISTRY.md
        results.append(self._check_module_registry_content())
        
        # Проверяем содержимое LLM_CONTEXT.md
        results.append(self._check_llm_context_content())
        
        # Проверяем папку _to_delete
        results.append(self._check_cleanup_results())
        
        return results
    
    def _check_documents_exist(self) -> ValidationResult:
        """Проверяет существование всех ожидаемых документов."""
        missing_docs = []
        existing_docs = []
        
        for doc_name in self.expected_docs:
            doc_path = self.project_root / doc_name
            if doc_path.exists():
                existing_docs.append(doc_name)
            else:
                missing_docs.append(doc_name)
        
        if missing_docs:
            return ValidationResult(
                check_name="Существование документов",
                success=False,
                message=f"Отсутствуют документы: {', '.join(missing_docs)}",
                details={
                    'missing': missing_docs,
                    'existing': existing_docs
                }
            )
        
        return ValidationResult(
            check_name="Существование документов",
            success=True,
            message=f"Все {len(self.expected_docs)} документа найдены",
            details={'existing': existing_docs}
        )
    
    def _check_document_links(self) -> ValidationResult:
        """Проверяет ссылки между документами."""
        broken_links = []
        working_links = []
        
        # Проверяем ссылки в LLM_CONTEXT.md
        llm_context_path = self.project_root / 'LLM_CONTEXT.md'
        if llm_context_path.exists():
            content = llm_context_path.read_text(encoding='utf-8')
            
            # Ищем ссылки на другие документы
            for doc_name in ['PROJECT_STRUCTURE.md', 'MODULE_REGISTRY.md']:
                if doc_name in content:
                    target_path = self.project_root / doc_name
                    if target_path.exists():
                        working_links.append(f"LLM_CONTEXT.md -> {doc_name}")
                    else:
                        broken_links.append(f"LLM_CONTEXT.md -> {doc_name}")
        
        if broken_links:
            return ValidationResult(
                check_name="Ссылки между документами",
                success=False,
                message=f"Найдены битые ссылки: {', '.join(broken_links)}",
                details={
                    'broken': broken_links,
                    'working': working_links
                }
            )
        
        return ValidationResult(
            check_name="Ссылки между документами",
            success=True,
            message=f"Все ссылки работают ({len(working_links)} проверено)",
            details={'working': working_links}
        )
    
    def _check_project_structure_content(self) -> ValidationResult:
        """Проверяет содержимое PROJECT_STRUCTURE.md."""
        doc_path = self.project_root / 'PROJECT_STRUCTURE.md'
        
        if not doc_path.exists():
            return ValidationResult(
                check_name="Содержимое PROJECT_STRUCTURE.md",
                success=False,
                message="Файл PROJECT_STRUCTURE.md не найден"
            )
        
        content = doc_path.read_text(encoding='utf-8')
        
        # Проверяем наличие основных разделов (более гибкие паттерны)
        required_patterns = [
            (r'#.*[Сс]труктур.*[Пп]роект', 'Project Structure header'),
            (r'Entry Points?|Точки входа', 'Entry Points section'),
            (r'[Кк]онфигурац.*файл|Configuration Files?', 'Configuration Files section')
        ]
        missing_sections = []
        
        for pattern, description in required_patterns:
            if not re.search(pattern, content, re.IGNORECASE):
                missing_sections.append(description)
        
        if missing_sections:
            return ValidationResult(
                check_name="Содержимое PROJECT_STRUCTURE.md",
                success=False,
                message=f"Отсутствуют разделы: {', '.join(missing_sections)}",
                details={'missing_sections': missing_sections}
            )
        
        return ValidationResult(
            check_name="Содержимое PROJECT_STRUCTURE.md",
            success=True,
            message="Все необходимые разделы присутствуют",
            details={'content_length': len(content)}
        )
    
    def _check_module_registry_content(self) -> ValidationResult:
        """Проверяет содержимое MODULE_REGISTRY.md."""
        doc_path = self.project_root / 'MODULE_REGISTRY.md'
        
        if not doc_path.exists():
            return ValidationResult(
                check_name="Содержимое MODULE_REGISTRY.md",
                success=False,
                message="Файл MODULE_REGISTRY.md не найден"
            )
        
        content = doc_path.read_text(encoding='utf-8')
        
        # Проверяем наличие основных разделов (более гибкие паттерны)
        required_patterns = [
            (r'#.*[Мм]одул.*[Рр]еестр|Module Registry', 'Module Registry header'),
            (r'[Кк]атегори|Categories', 'Categories section'),
            (r'[Мм]одул|Modules', 'Modules section')
        ]
        missing_sections = []
        
        for pattern, description in required_patterns:
            if not re.search(pattern, content, re.IGNORECASE):
                missing_sections.append(description)
        
        # Подсчитываем количество модулей (более гибкие паттерны)
        module_patterns = [
            r'^##\s+.*\.py',  # ## module.py
            r'^\*\*.*\.py\*\*',  # **module.py**
            r'###\s+.*\.py'  # ### module.py
        ]
        
        module_count = 0
        for pattern in module_patterns:
            matches = re.findall(pattern, content, re.MULTILINE)
            module_count += len(matches)
        
        if missing_sections:
            return ValidationResult(
                check_name="Содержимое MODULE_REGISTRY.md",
                success=False,
                message=f"Отсутствуют разделы: {', '.join(missing_sections)}",
                details={'missing_sections': missing_sections, 'module_count': module_count}
            )
        
        return ValidationResult(
            check_name="Содержимое MODULE_REGISTRY.md",
            success=True,
            message=f"Все разделы присутствуют, найдено {module_count} модулей",
            details={'module_count': module_count, 'content_length': len(content)}
        )
    
    def _check_llm_context_content(self) -> ValidationResult:
        """Проверяет содержимое LLM_CONTEXT.md."""
        doc_path = self.project_root / 'LLM_CONTEXT.md'
        
        if not doc_path.exists():
            return ValidationResult(
                check_name="Содержимое LLM_CONTEXT.md",
                success=False,
                message="Файл LLM_CONTEXT.md не найден"
            )
        
        content = doc_path.read_text(encoding='utf-8')
        
        # Проверяем наличие основных правил (более гибкие паттерны)
        required_patterns = [
            (r'MODULE_REGISTRY\.md', 'MODULE_REGISTRY.md reference'),
            (r'PROJECT_STRUCTURE\.md', 'PROJECT_STRUCTURE.md reference'),
            (r'перед созданием.*функционал|before creating.*functionality', 'check before creating functionality rule'),
            (r'где размещать.*код|where to place.*code', 'where to place code rule')
        ]
        
        missing_rules = []
        for pattern, description in required_patterns:
            if not re.search(pattern, content, re.IGNORECASE):
                missing_rules.append(description)
        
        if missing_rules:
            return ValidationResult(
                check_name="Содержимое LLM_CONTEXT.md",
                success=False,
                message=f"Отсутствуют правила: {', '.join(missing_rules)}",
                details={'missing_rules': missing_rules}
            )
        
        return ValidationResult(
            check_name="Содержимое LLM_CONTEXT.md",
            success=True,
            message="Все необходимые правила присутствуют",
            details={'content_length': len(content)}
        )
    
    def _check_cleanup_results(self) -> ValidationResult:
        """Проверяет результаты очистки мусора."""
        to_delete_path = self.project_root / '_to_delete'
        
        if not to_delete_path.exists():
            return ValidationResult(
                check_name="Результаты очистки",
                success=False,
                message="Папка _to_delete не найдена - очистка не выполнялась"
            )
        
        # Подсчитываем файлы в папке _to_delete
        moved_files = list(to_delete_path.rglob('*'))
        moved_files = [f for f in moved_files if f.is_file()]
        
        return ValidationResult(
            check_name="Результаты очистки",
            success=True,
            message=f"Папка _to_delete содержит {len(moved_files)} перемещенных файлов",
            details={'moved_files_count': len(moved_files)}
        )
    
    def print_results(self, results: List[ValidationResult]) -> bool:
        """
        Выводит результаты валидации.
        
        Args:
            results: Список результатов валидации
            
        Returns:
            True если все проверки прошли успешно
        """
        print("="*60)
        print("РЕЗУЛЬТАТЫ ВАЛИДАЦИИ РЕФАКТОРИНГА")
        print("="*60)
        
        success_count = 0
        total_count = len(results)
        
        for result in results:
            status = "✅" if result.success else "❌"
            print(f"{status} {result.check_name}")
            print(f"   {result.message}")
            
            if result.details:
                for key, value in result.details.items():
                    print(f"   {key}: {value}")
            
            if result.success:
                success_count += 1
            
            print()
        
        overall_success = success_count == total_count
        
        print("="*60)
        if overall_success:
            print("🎉 ВСЕ ПРОВЕРКИ ПРОШЛИ УСПЕШНО!")
            print(f"Успешно: {success_count}/{total_count}")
        else:
            print("❌ НАЙДЕНЫ ПРОБЛЕМЫ")
            print(f"Успешно: {success_count}/{total_count}")
            print(f"Ошибок: {total_count - success_count}")
        
        return overall_success


def main():
    """Главная функция для запуска валидатора."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Валидатор результатов глобального рефакторинга"
    )
    
    parser.add_argument(
        '--project-root',
        type=Path,
        help='Путь к корневой директории проекта (по умолчанию текущая директория)'
    )
    
    args = parser.parse_args()
    
    try:
        validator = RefactoringValidator(project_root=args.project_root)
        results = validator.validate_all()
        success = validator.print_results(results)
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"❌ Ошибка валидации: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()