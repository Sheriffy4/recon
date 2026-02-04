#!/usr/bin/env python3
"""
Project Analyzer - Анализатор проекта для рекомендаций по рефакторингу.

Анализирует код проекта и предоставляет рекомендации на основе накопленных знаний.
"""

import ast
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict
from datetime import datetime
import logging

# Импорты из нашей системы знаний
try:
    from core.adaptive_refactored.refactoring_knowledge.automation_metadata import (
        get_automation_generator, RefactoringAutomationMetadata
    )
    from core.adaptive_refactored.refactoring_knowledge.decision_trees import (
        CodeMetrics, RefactoringContext
    )
except ImportError:
    print("⚠️  Модули анализа не найдены, используем упрощенную версию")


@dataclass
class FileAnalysis:
    """Анализ отдельного файла."""
    filepath: str
    lines_count: int
    classes_count: int
    methods_count: int
    complexity_score: float
    responsibilities_count: int
    dependencies_count: int
    test_coverage: float
    issues: List[str]
    recommendations: List[str]


@dataclass
class ProjectAnalysis:
    """Анализ всего проекта."""
    total_files: int
    total_lines: int
    large_files: List[str]  # Файлы > 500 строк
    complex_files: List[str]  # Файлы с высокой сложностью
    god_objects: List[str]  # Классы с множественными ответственностями
    refactoring_candidates: List[FileAnalysis]
    overall_recommendations: List[str]
    automation_potential: float


class ProjectAnalyzer:
    """Анализатор проекта для рекомендаций по рефакторингу."""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.knowledge_base = None
        self._load_knowledge_base()
        
    def _load_knowledge_base(self):
        """Загрузить базу знаний."""
        try:
            generator = get_automation_generator()
            knowledge_file = self.project_root / "knowledge" / "refactoring_automation_metadata.json"
            if knowledge_file.exists():
                self.knowledge_base = generator.load_metadata(str(knowledge_file))
                print(f"✅ Загружена база знаний: {knowledge_file}")
            else:
                print("⚠️  База знаний не найдена, используем базовый анализ")
        except Exception as e:
            print(f"⚠️  Ошибка загрузки базы знаний: {e}")
            
    def analyze_file(self, filepath: Path) -> FileAnalysis:
        """Анализ отдельного Python файла."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Парсинг AST
            tree = ast.parse(content)
            
            # Базовые метрики
            lines_count = len(content.splitlines())
            classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
            methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
            
            # Анализ сложности (упрощенный)
            complexity_score = self._calculate_complexity(tree)
            
            # Анализ ответственностей (по количеству методов в классах)
            responsibilities_count = self._count_responsibilities(classes)
            
            # Анализ зависимостей (по импортам)
            dependencies_count = len([node for node in ast.walk(tree) 
                                    if isinstance(node, (ast.Import, ast.ImportFrom))])
            
            # Определение проблем
            issues = []
            recommendations = []
            
            if lines_count > 1000:
                issues.append(f"Большой файл: {lines_count} строк")
                recommendations.append("Рассмотрите разделение на несколько модулей")
                
            if complexity_score > 20:
                issues.append(f"Высокая сложность: {complexity_score}")
                recommendations.append("Извлеките методы в отдельные компоненты")
                
            if responsibilities_count > 5:
                issues.append(f"Множественные ответственности: {responsibilities_count}")
                recommendations.append("Примените паттерн Single Responsibility Principle")
                
            # Проверка на God Object
            for cls in classes:
                class_methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)]
                if len(class_methods) > 15:
                    issues.append(f"God Object: класс {cls.name} имеет {len(class_methods)} методов")
                    recommendations.append(f"Разделите класс {cls.name} на несколько компонентов")
            
            return FileAnalysis(
                filepath=str(filepath.relative_to(self.project_root)),
                lines_count=lines_count,
                classes_count=len(classes),
                methods_count=len(methods),
                complexity_score=complexity_score,
                responsibilities_count=responsibilities_count,
                dependencies_count=dependencies_count,
                test_coverage=0.0,  # Требует дополнительного анализа
                issues=issues,
                recommendations=recommendations
            )
            
        except Exception as e:
            print(f"❌ Ошибка анализа файла {filepath}: {e}")
            return FileAnalysis(
                filepath=str(filepath.relative_to(self.project_root)),
                lines_count=0, classes_count=0, methods_count=0,
                complexity_score=0, responsibilities_count=0,
                dependencies_count=0, test_coverage=0.0,
                issues=[f"Ошибка анализа: {e}"], recommendations=[]
            )
            
    def _calculate_complexity(self, tree: ast.AST) -> float:
        """Упрощенный расчет цикломатической сложности."""
        complexity = 1  # Базовая сложность
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.Try):
                complexity += len(node.handlers)
            elif isinstance(node, (ast.And, ast.Or)):
                complexity += 1
                
        return complexity
        
    def _count_responsibilities(self, classes: List[ast.ClassDef]) -> int:
        """Подсчет ответственностей на основе методов классов."""
        if not classes:
            return 1
            
        max_responsibilities = 0
        for cls in classes:
            methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)]
            # Группируем методы по префиксам для определения ответственностей
            prefixes = set()
            for method in methods:
                if '_' in method.name:
                    prefix = method.name.split('_')[0]
                    prefixes.add(prefix)
                    
            responsibilities = max(len(prefixes), len(methods) // 5)  # Эвристика
            max_responsibilities = max(max_responsibilities, responsibilities)
            
        return max_responsibilities
        
    def analyze_project(self, include_patterns: List[str] = None, 
                       exclude_patterns: List[str] = None) -> ProjectAnalysis:
        """Анализ всего проекта."""
        
        if include_patterns is None:
            include_patterns = ["**/*.py"]
        if exclude_patterns is None:
            exclude_patterns = ["**/test_*.py", "**/*_test.py", "**/__pycache__/**", 
                              "**/.*", "**/build/**", "**/dist/**"]
            
        print("🔍 Анализ проекта...")
        
        # Найти все Python файлы
        python_files = []
        for pattern in include_patterns:
            python_files.extend(self.project_root.glob(pattern))
            
        # Исключить файлы по паттернам
        filtered_files = []
        for file_path in python_files:
            should_exclude = False
            for exclude_pattern in exclude_patterns:
                if file_path.match(exclude_pattern):
                    should_exclude = True
                    break
            if not should_exclude and file_path.is_file():
                filtered_files.append(file_path)
                
        print(f"📁 Найдено {len(filtered_files)} Python файлов для анализа")
        
        # Анализ каждого файла
        file_analyses = []
        large_files = []
        complex_files = []
        god_objects = []
        total_lines = 0
        
        for i, file_path in enumerate(filtered_files):
            if i % 10 == 0:
                print(f"📊 Проанализировано {i}/{len(filtered_files)} файлов...")
                
            analysis = self.analyze_file(file_path)
            file_analyses.append(analysis)
            total_lines += analysis.lines_count
            
            # Категоризация проблемных файлов
            if analysis.lines_count > 500:
                large_files.append(analysis.filepath)
            if analysis.complexity_score > 15:
                complex_files.append(analysis.filepath)
            if "God Object" in str(analysis.issues):
                god_objects.append(analysis.filepath)
                
        # Определение кандидатов на рефакторинг
        refactoring_candidates = [
            analysis for analysis in file_analyses
            if len(analysis.issues) > 0 and analysis.lines_count > 100
        ]
        
        # Сортировка по приоритету (больше проблем = выше приоритет)
        refactoring_candidates.sort(
            key=lambda x: len(x.issues) * x.lines_count, reverse=True
        )
        
        # Общие рекомендации
        overall_recommendations = self._generate_overall_recommendations(
            file_analyses, large_files, complex_files, god_objects
        )
        
        # Расчет потенциала автоматизации
        automation_potential = self._calculate_automation_potential(refactoring_candidates)
        
        return ProjectAnalysis(
            total_files=len(filtered_files),
            total_lines=total_lines,
            large_files=large_files,
            complex_files=complex_files,
            god_objects=god_objects,
            refactoring_candidates=refactoring_candidates[:10],  # Топ 10
            overall_recommendations=overall_recommendations,
            automation_potential=automation_potential
        )
        
    def _generate_overall_recommendations(self, file_analyses: List[FileAnalysis],
                                        large_files: List[str], complex_files: List[str],
                                        god_objects: List[str]) -> List[str]:
        """Генерация общих рекомендаций для проекта."""
        recommendations = []
        
        if len(large_files) > 5:
            recommendations.append(
                f"🔧 Найдено {len(large_files)} больших файлов. "
                "Рекомендуется применить паттерн 'Split Monolithic Configuration'"
            )
            
        if len(complex_files) > 3:
            recommendations.append(
                f"🎯 Найдено {len(complex_files)} сложных файлов. "
                "Рекомендуется применить паттерн 'Extract Method to Component Class'"
            )
            
        if len(god_objects) > 0:
            recommendations.append(
                f"⚠️  Найдено {len(god_objects)} God Objects. "
                "Критически важно применить рефакторинг с использованием DI паттернов"
            )
            
        # Рекомендации на основе базы знаний
        if self.knowledge_base:
            total_issues = sum(len(analysis.issues) for analysis in file_analyses)
            if total_issues > 20:
                recommendations.append(
                    "💡 На основе базы знаний: рекомендуется создать Facade "
                    "для сохранения обратной совместимости при крупном рефакторинге"
                )
                
        return recommendations
        
    def _calculate_automation_potential(self, candidates: List[FileAnalysis]) -> float:
        """Расчет потенциала автоматизации рефакторинга."""
        if not candidates:
            return 0.0
            
        # Базовый потенциал на основе типов проблем
        automation_scores = []
        
        for candidate in candidates:
            score = 0.0
            
            # Проблемы, которые легко автоматизировать
            for issue in candidate.issues:
                if "Большой файл" in issue:
                    score += 0.8  # Разделение файлов легко автоматизировать
                elif "Высокая сложность" in issue:
                    score += 0.6  # Извлечение методов частично автоматизируемо
                elif "God Object" in issue:
                    score += 0.4  # Требует больше ручной работы
                elif "Множественные ответственности" in issue:
                    score += 0.7  # Разделение ответственностей автоматизируемо
                    
            automation_scores.append(min(score, 1.0))
            
        return sum(automation_scores) / len(automation_scores) if automation_scores else 0.0
        
    def generate_report(self, analysis: ProjectAnalysis, output_file: str = None) -> str:
        """Генерация отчета по анализу."""
        
        report = f"""
# 📊 Отчет по анализу проекта

**Дата анализа**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Всего файлов**: {analysis.total_files}
**Всего строк кода**: {analysis.total_lines:,}
**Потенциал автоматизации**: {analysis.automation_potential:.1%}

## 🎯 Приоритетные кандидаты на рефакторинг

"""
        
        for i, candidate in enumerate(analysis.refactoring_candidates, 1):
            report += f"""
### {i}. `{candidate.filepath}`
- **Строк кода**: {candidate.lines_count}
- **Классов**: {candidate.classes_count}
- **Методов**: {candidate.methods_count}
- **Сложность**: {candidate.complexity_score}
- **Проблемы**: {len(candidate.issues)}

**Выявленные проблемы**:
"""
            for issue in candidate.issues:
                report += f"- ❌ {issue}\n"
                
            report += "\n**Рекомендации**:\n"
            for rec in candidate.recommendations:
                report += f"- ✅ {rec}\n"
                
        report += f"""

## 📈 Общая статистика

- **Больших файлов (>500 строк)**: {len(analysis.large_files)}
- **Сложных файлов**: {len(analysis.complex_files)}
- **God Objects**: {len(analysis.god_objects)}

## 💡 Общие рекомендации

"""
        
        for rec in analysis.overall_recommendations:
            report += f"- {rec}\n"
            
        if analysis.large_files:
            report += f"""

## 📁 Большие файлы требующие внимания

"""
            for file_path in analysis.large_files[:5]:  # Топ 5
                report += f"- `{file_path}`\n"
                
        if analysis.god_objects:
            report += f"""

## ⚠️  God Objects (критический приоритет)

"""
            for file_path in analysis.god_objects:
                report += f"- `{file_path}`\n"
                
        report += f"""

## 🚀 Следующие шаги

1. **Начните с God Objects** - они имеют наибольший потенциал улучшения
2. **Примените паттерны из базы знаний**:
   - Extract Method to Component Class
   - Constructor Injection with Interfaces  
   - Split Monolithic Configuration
3. **Используйте автоматизацию** где возможно (потенциал: {analysis.automation_potential:.1%})
4. **Создайте тесты** перед рефакторингом для безопасности

## 🔧 Команды для применения

```bash
# Получить рекомендации для конкретного типа проблем
python knowledge_manager.py recommend large_monolithic_classes
python knowledge_manager.py recommend god_objects

# Применить автоматический рефакторинг (когда будет готов)
python auto_refactor.py --file path/to/file.py --pattern extract_method_to_component
```

---
*Отчет сгенерирован автоматически на основе анализа кода и базы знаний рефакторинга*
"""
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"📄 Отчет сохранен в {output_file}")
            
        return report


def main():
    """Главная функция для CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Анализ проекта для рекомендаций по рефакторингу")
    parser.add_argument("--project", "-p", default=".", help="Путь к проекту (по умолчанию: текущая папка)")
    parser.add_argument("--output", "-o", help="Файл для сохранения отчета")
    parser.add_argument("--include", nargs="*", default=["**/*.py"], help="Паттерны файлов для включения")
    parser.add_argument("--exclude", nargs="*", 
                       default=["**/test_*.py", "**/*_test.py", "**/__pycache__/**"], 
                       help="Паттерны файлов для исключения")
    parser.add_argument("--top", "-t", type=int, default=5, help="Количество топ кандидатов для показа")
    
    args = parser.parse_args()
    
    print(f"🔍 Анализ проекта: {args.project}")
    
    analyzer = ProjectAnalyzer(args.project)
    analysis = analyzer.analyze_project(args.include, args.exclude)
    
    # Показать краткую сводку
    print(f"\n📊 Результаты анализа:")
    print(f"   📁 Всего файлов: {analysis.total_files}")
    print(f"   📝 Всего строк: {analysis.total_lines:,}")
    print(f"   🎯 Кандидатов на рефакторинг: {len(analysis.refactoring_candidates)}")
    print(f"   🤖 Потенциал автоматизации: {analysis.automation_potential:.1%}")
    
    if analysis.refactoring_candidates:
        print(f"\n🔥 Топ {min(args.top, len(analysis.refactoring_candidates))} приоритетных файлов:")
        for i, candidate in enumerate(analysis.refactoring_candidates[:args.top], 1):
            print(f"   {i}. {candidate.filepath} ({candidate.lines_count} строк, {len(candidate.issues)} проблем)")
            
    # Генерация полного отчета
    report = analyzer.generate_report(analysis, args.output)
    
    if not args.output:
        print("\n" + "="*80)
        print(report)


if __name__ == "__main__":
    main()