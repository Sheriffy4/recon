#!/usr/bin/env python3
"""
File Analyzer - Детальный анализ отдельного файла с рекомендациями.

Анализирует конкретный файл и предоставляет детальные рекомендации по рефакторингу.
"""

import ast
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime


@dataclass
class MethodInfo:
    """Информация о методе."""
    name: str
    line_start: int
    line_end: int
    complexity: int
    parameters_count: int
    calls_count: int
    is_public: bool
    responsibility_group: str


@dataclass
class ClassInfo:
    """Информация о классе."""
    name: str
    line_start: int
    line_end: int
    methods: List[MethodInfo]
    responsibilities_count: int
    is_god_object: bool
    
    @property
    def public_methods_count(self) -> int:
        return len([m for m in self.methods if m.is_public])
        
    @property
    def total_complexity(self) -> int:
        return sum(m.complexity for m in self.methods)


@dataclass
class FileAnalysisResult:
    """Результат анализа файла."""
    filepath: str
    lines_count: int
    classes: List[ClassInfo]
    imports_count: int
    complexity_score: int
    issues: List[str]
    recommendations: List[str]
    refactoring_priority: int  # 1-10, где 10 = критический
    automation_potential: float  # 0.0-1.0


class FileAnalyzer:
    """Анализатор отдельного файла."""
    
    def __init__(self):
        self.responsibility_keywords = {
            "strategy": ["strategy", "generate", "create", "build", "construct", "produce"],
            "testing": ["test", "validate", "verify", "check", "probe", "assert"],
            "analysis": ["analyze", "parse", "process", "examine", "inspect", "scan"],
            "caching": ["cache", "store", "save", "load", "persist", "retrieve"],
            "logging": ["log", "debug", "info", "warn", "error", "trace"],
            "config": ["config", "setting", "option", "parameter", "preference"],
            "network": ["connect", "request", "response", "http", "tcp", "socket"],
            "fingerprint": ["fingerprint", "detect", "identify", "recognize", "signature"],
            "monitoring": ["monitor", "track", "measure", "metric", "stat", "observe"],
            "validation": ["validate", "sanitize", "normalize", "clean", "format"],
            "transformation": ["transform", "convert", "modify", "change", "update"],
            "coordination": ["coordinate", "orchestrate", "manage", "control", "handle"]
        }
        
    def analyze_file(self, filepath: Path) -> FileAnalysisResult:
        """Полный анализ файла."""
        
        try:
            content = filepath.read_text(encoding='utf-8')
            tree = ast.parse(content)
            lines = content.splitlines()
            
            # Базовые метрики
            lines_count = len(lines)
            imports_count = len([node for node in ast.walk(tree) 
                               if isinstance(node, (ast.Import, ast.ImportFrom))])
            
            # Анализ классов
            classes = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = self._analyze_class(node, lines)
                    classes.append(class_info)
                    
            # Общая сложность
            complexity_score = sum(cls.total_complexity for cls in classes)
            
            # Выявление проблем
            issues = self._identify_issues(lines_count, classes, complexity_score)
            
            # Генерация рекомендаций
            recommendations = self._generate_recommendations(classes, issues)
            
            # Приоритет рефакторинга
            priority = self._calculate_priority(lines_count, classes, len(issues))
            
            # Потенциал автоматизации
            automation_potential = self._calculate_automation_potential(classes, issues)
            
            return FileAnalysisResult(
                filepath=str(filepath),
                lines_count=lines_count,
                classes=classes,
                imports_count=imports_count,
                complexity_score=complexity_score,
                issues=issues,
                recommendations=recommendations,
                refactoring_priority=priority,
                automation_potential=automation_potential
            )
            
        except Exception as e:
            return FileAnalysisResult(
                filepath=str(filepath),
                lines_count=0,
                classes=[],
                imports_count=0,
                complexity_score=0,
                issues=[f"Ошибка анализа: {e}"],
                recommendations=["Исправьте синтаксические ошибки"],
                refactoring_priority=1,
                automation_potential=0.0
            )
            
    def _analyze_class(self, class_node: ast.ClassDef, lines: List[str]) -> ClassInfo:
        """Анализ отдельного класса."""
        
        methods = []
        for node in class_node.body:
            if isinstance(node, ast.FunctionDef):
                method_info = self._analyze_method(node, lines)
                methods.append(method_info)
                
        # Подсчет ответственностей
        responsibilities = set(m.responsibility_group for m in methods)
        responsibilities_count = len(responsibilities)
        
        # Определение God Object
        is_god_object = (len(methods) > 15 or 
                        responsibilities_count > 5 or
                        sum(m.complexity for m in methods) > 100)
        
        return ClassInfo(
            name=class_node.name,
            line_start=class_node.lineno,
            line_end=getattr(class_node, 'end_lineno', class_node.lineno + 10),
            methods=methods,
            responsibilities_count=responsibilities_count,
            is_god_object=is_god_object
        )
        
    def _analyze_method(self, method_node: ast.FunctionDef, lines: List[str]) -> MethodInfo:
        """Анализ отдельного метода."""
        
        # Сложность (упрощенная цикломатическая)
        complexity = self._calculate_method_complexity(method_node)
        
        # Количество параметров
        parameters_count = len(method_node.args.args) - 1  # Исключить self
        
        # Количество вызовов функций
        calls_count = len([node for node in ast.walk(method_node) 
                          if isinstance(node, ast.Call)])
        
        # Публичный/приватный
        is_public = not method_node.name.startswith('_')
        
        # Группа ответственности
        responsibility_group = self._determine_responsibility(method_node.name)
        
        return MethodInfo(
            name=method_node.name,
            line_start=method_node.lineno,
            line_end=getattr(method_node, 'end_lineno', method_node.lineno + 5),
            complexity=complexity,
            parameters_count=parameters_count,
            calls_count=calls_count,
            is_public=is_public,
            responsibility_group=responsibility_group
        )
        
    def _calculate_method_complexity(self, method_node: ast.FunctionDef) -> int:
        """Расчет цикломатической сложности метода."""
        
        complexity = 1  # Базовая сложность
        
        for node in ast.walk(method_node):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.Try):
                complexity += len(node.handlers)
            elif isinstance(node, (ast.And, ast.Or)):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
                
        return complexity
        
    def _determine_responsibility(self, method_name: str) -> str:
        """Определение группы ответственности метода."""
        
        method_lower = method_name.lower()
        
        for group, keywords in self.responsibility_keywords.items():
            if any(keyword in method_lower for keyword in keywords):
                return group
                
        return "other"
        
    def _identify_issues(self, lines_count: int, classes: List[ClassInfo], 
                        complexity_score: int) -> List[str]:
        """Выявление проблем в файле."""
        
        issues = []
        
        # Проблемы размера файла
        if lines_count > 1000:
            issues.append(f"🔴 Очень большой файл: {lines_count} строк (рекомендуется <500)")
        elif lines_count > 500:
            issues.append(f"🟡 Большой файл: {lines_count} строк (рекомендуется <500)")
            
        # Проблемы сложности
        if complexity_score > 200:
            issues.append(f"🔴 Критическая сложность: {complexity_score} (рекомендуется <50)")
        elif complexity_score > 100:
            issues.append(f"🟡 Высокая сложность: {complexity_score} (рекомендуется <50)")
            
        # Проблемы классов
        god_objects = [cls for cls in classes if cls.is_god_object]
        if god_objects:
            for god_obj in god_objects:
                issues.append(f"🔴 God Object: класс '{god_obj.name}' имеет {god_obj.public_methods_count} публичных методов и {god_obj.responsibilities_count} ответственностей")
                
        # Проблемы методов
        complex_methods = []
        for cls in classes:
            for method in cls.methods:
                if method.complexity > 10:
                    complex_methods.append(f"{cls.name}.{method.name}")
                    
        if complex_methods:
            issues.append(f"🟡 Сложные методы ({len(complex_methods)}): {', '.join(complex_methods[:3])}{'...' if len(complex_methods) > 3 else ''}")
            
        return issues
        
    def _generate_recommendations(self, classes: List[ClassInfo], issues: List[str]) -> List[str]:
        """Генерация рекомендаций по рефакторингу."""
        
        recommendations = []
        
        # Рекомендации для God Objects
        god_objects = [cls for cls in classes if cls.is_god_object]
        if god_objects:
            recommendations.append("🎯 Применить паттерн 'Extract Method to Component Class' для разделения God Objects")
            recommendations.append("🏗️ Создать интерфейсы для каждой группы ответственностей")
            recommendations.append("💉 Использовать Constructor Injection для связывания компонентов")
            
        # Рекомендации по размеру файла
        if any("большой файл" in issue.lower() for issue in issues):
            recommendations.append("📁 Разделить файл на несколько модулей по доменам")
            recommendations.append("🔧 Применить паттерн 'Split Monolithic Configuration'")
            
        # Рекомендации по сложности
        if any("сложность" in issue.lower() for issue in issues):
            recommendations.append("🎭 Извлечь сложные методы в отдельные классы")
            recommendations.append("🔄 Применить паттерн Strategy для упрощения условной логики")
            
        # Рекомендации по тестированию
        if god_objects or any("сложность" in issue.lower() for issue in issues):
            recommendations.append("🧪 Создать unit тесты для каждого извлеченного компонента")
            recommendations.append("🔬 Применить property-based тестирование для проверки инвариантов")
            
        # Рекомендации по автоматизации
        automation_potential = self._calculate_automation_potential(classes, issues)
        if automation_potential > 0.7:
            recommendations.append(f"🤖 Высокий потенциал автоматизации ({automation_potential:.1%}) - можно использовать auto_refactor.py")
        elif automation_potential > 0.4:
            recommendations.append(f"⚙️ Средний потенциал автоматизации ({automation_potential:.1%}) - частичная автоматизация возможна")
            
        return recommendations
        
    def _calculate_priority(self, lines_count: int, classes: List[ClassInfo], issues_count: int) -> int:
        """Расчет приоритета рефакторинга (1-10)."""
        
        priority = 1
        
        # Размер файла
        if lines_count > 2000:
            priority += 3
        elif lines_count > 1000:
            priority += 2
        elif lines_count > 500:
            priority += 1
            
        # God Objects
        god_objects_count = len([cls for cls in classes if cls.is_god_object])
        priority += min(god_objects_count * 2, 4)
        
        # Количество проблем
        priority += min(issues_count, 3)
        
        return min(priority, 10)
        
    def _calculate_automation_potential(self, classes: List[ClassInfo], issues: List[str]) -> float:
        """Расчет потенциала автоматизации (0.0-1.0)."""
        
        potential = 0.0
        
        # God Objects легко автоматизировать
        god_objects = [cls for cls in classes if cls.is_god_object]
        if god_objects:
            potential += 0.4
            
        # Большие файлы можно разделить автоматически
        if any("большой файл" in issue.lower() for issue in issues):
            potential += 0.3
            
        # Высокая сложность частично автоматизируема
        if any("сложность" in issue.lower() for issue in issues):
            potential += 0.2
            
        # Множественные ответственности хорошо автоматизируются
        multi_responsibility_classes = [cls for cls in classes if cls.responsibilities_count > 3]
        if multi_responsibility_classes:
            potential += 0.3
            
        return min(potential, 1.0)
        
    def generate_detailed_report(self, result: FileAnalysisResult) -> str:
        """Генерация детального отчета."""
        
        report = f"""
# 🔍 Детальный анализ файла

**Файл**: `{result.filepath}`
**Дата анализа**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Общие метрики

| Метрика | Значение | Статус |
|---------|----------|--------|
| Строк кода | {result.lines_count:,} | {'🔴' if result.lines_count > 1000 else '🟡' if result.lines_count > 500 else '🟢'} |
| Классов | {len(result.classes)} | {'🔴' if len(result.classes) > 5 else '🟢'} |
| Импортов | {result.imports_count} | {'🟡' if result.imports_count > 20 else '🟢'} |
| Сложность | {result.complexity_score} | {'🔴' if result.complexity_score > 200 else '🟡' if result.complexity_score > 100 else '🟢'} |
| Приоритет рефакторинга | {result.refactoring_priority}/10 | {'🔴' if result.refactoring_priority > 7 else '🟡' if result.refactoring_priority > 4 else '🟢'} |
| Потенциал автоматизации | {result.automation_potential:.1%} | {'🟢' if result.automation_potential > 0.7 else '🟡' if result.automation_potential > 0.4 else '🔴'} |

## 🎯 Анализ классов

"""
        
        for cls in result.classes:
            status = "🔴 God Object" if cls.is_god_object else "🟢 Нормальный"
            
            report += f"""
### `{cls.name}` {status}

- **Строки**: {cls.line_start}-{cls.line_end}
- **Методов**: {len(cls.methods)} (публичных: {cls.public_methods_count})
- **Ответственностей**: {cls.responsibilities_count}
- **Сложность**: {cls.total_complexity}

**Группы методов по ответственностям**:
"""
            
            # Группировка методов по ответственностям
            responsibility_groups = defaultdict(list)
            for method in cls.methods:
                responsibility_groups[method.responsibility_group].append(method)
                
            for group, methods in responsibility_groups.items():
                report += f"- **{group.title()}**: {len(methods)} методов\n"
                
        report += f"""

## ⚠️ Выявленные проблемы

"""
        
        for issue in result.issues:
            report += f"- {issue}\n"
            
        report += f"""

## 💡 Рекомендации по рефакторингу

"""
        
        for rec in result.recommendations:
            report += f"- {rec}\n"
            
        # Конкретный план действий
        if result.refactoring_priority > 6:
            report += f"""

## 🚀 План действий (высокий приоритет)

### Этап 1: Подготовка
1. Создать резервную копию файла
2. Убедиться в наличии тестов (если нет - создать базовые)
3. Зафиксировать текущее состояние в git

### Этап 2: Автоматический рефакторинг
```bash
# Анализ и план
python auto_refactor.py "{result.filepath}" --dry-run

# Выполнение (если потенциал автоматизации > 70%)
python auto_refactor.py "{result.filepath}"
```

### Этап 3: Ручная доработка
1. Проверить корректность извлеченных интерфейсов
2. Добавить недостающую документацию
3. Оптимизировать DI конфигурацию
4. Создать comprehensive тесты

### Этап 4: Валидация
1. Запустить все существующие тесты
2. Проверить производительность
3. Валидировать обратную совместимость
"""
        
        report += f"""

---
*Отчет сгенерирован автоматически на основе AST анализа и базы знаний рефакторинга*
"""
        
        return report


def main():
    """Главная функция для CLI."""
    import argparse
    from datetime import datetime
    
    parser = argparse.ArgumentParser(description="Детальный анализ файла для рефакторинга")
    parser.add_argument("file", help="Путь к файлу для анализа")
    parser.add_argument("--output", "-o", help="Файл для сохранения отчета")
    parser.add_argument("--json", action="store_true", help="Вывод в JSON формате")
    
    args = parser.parse_args()
    
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"❌ Файл не найден: {filepath}")
        return
        
    print(f"🔍 Анализ файла: {filepath}")
    
    analyzer = FileAnalyzer()
    result = analyzer.analyze_file(filepath)
    
    if args.json:
        # JSON вывод для программного использования
        import json
        from dataclasses import asdict
        output = asdict(result)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
        else:
            print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        # Человеко-читаемый отчет
        report = analyzer.generate_detailed_report(result)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"📄 Отчет сохранен в {args.output}")
        else:
            print(report)
            
    # Краткая сводка в консоль
    print(f"\n📊 Краткая сводка:")
    print(f"   📏 Размер: {result.lines_count:,} строк")
    print(f"   🏗️ Классов: {len(result.classes)}")
    print(f"   🔥 Приоритет: {result.refactoring_priority}/10")
    print(f"   🤖 Автоматизация: {result.automation_potential:.1%}")
    
    if result.refactoring_priority > 6:
        print(f"\n🚨 ВЫСОКИЙ ПРИОРИТЕТ РЕФАКТОРИНГА!")
        print(f"   Рекомендуется немедленное вмешательство")


if __name__ == "__main__":
    main()