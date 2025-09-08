#!/usr/bin/env python3
"""
Анализатор проекта - определяет рабочие и нерабочие модули
"""

import os
import sys
import ast
import importlib.util
from pathlib import Path
from typing import Dict, List, Set, Tuple
import json

class ProjectAnalyzer:
    """Анализатор структуры и функциональности проекта."""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.python_files: List[Path] = []
        self.modules_info: Dict[str, Dict] = {}
        self.working_modules: Set[str] = set()
        self.broken_modules: Set[str] = set()
        self.standalone_scripts: List[str] = []
        
    def scan_python_files(self):
        """Сканирует все Python файлы в проекте."""
        print("🔍 Сканирование Python файлов...")
        
        for file_path in self.project_root.rglob("*.py"):
            # Пропускаем виртуальные окружения и кэш
            if any(part in file_path.parts for part in ['.venv', '__pycache__', '.git']):
                continue
            
            self.python_files.append(file_path)
        
        print(f"📁 Найдено {len(self.python_files)} Python файлов")
        return self.python_files
    
    def analyze_file(self, file_path: Path) -> Dict:
        """Анализирует отдельный Python файл."""
        info = {
            'path': str(file_path),
            'relative_path': str(file_path.relative_to(self.project_root)),
            'size': file_path.stat().st_size,
            'imports': [],
            'functions': [],
            'classes': [],
            'has_main': False,
            'is_executable': False,
            'errors': [],
            'description': ''
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Проверяем на исполняемость
            if '__name__ == "__main__"' in content:
                info['has_main'] = True
                info['is_executable'] = True
            
            # Парсим AST
            try:
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            info['imports'].append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            info['imports'].append(node.module)
                    elif isinstance(node, ast.FunctionDef):
                        info['functions'].append(node.name)
                    elif isinstance(node, ast.ClassDef):
                        info['classes'].append(node.name)
                
                # Извлекаем описание из docstring
                if (isinstance(tree.body[0], ast.Expr) and 
                    isinstance(tree.body[0].value, ast.Constant) and
                    isinstance(tree.body[0].value.value, str)):
                    info['description'] = tree.body[0].value.value.strip()
                    
            except SyntaxError as e:
                info['errors'].append(f"Syntax error: {e}")
            
        except Exception as e:
            info['errors'].append(f"Read error: {e}")
        
        return info
    
    def test_module_import(self, file_path: Path) -> bool:
        """Тестирует возможность импорта модуля."""
        try:
            # Получаем относительный путь для импорта
            rel_path = file_path.relative_to(self.project_root)
            
            # Преобразуем путь в модуль
            module_parts = list(rel_path.parts[:-1])  # Убираем .py
            if rel_path.stem != '__init__':
                module_parts.append(rel_path.stem)
            
            module_name = '.'.join(module_parts)
            
            if not module_name:
                return False
            
            # Пытаемся импортировать
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return True
            
        except Exception:
            pass
        
        return False
    
    def categorize_modules(self):
        """Категоризирует модули по функциональности."""
        categories = {
            'cli_tools': [],
            'core_engines': [],
            'analyzers': [],
            'tests': [],
            'utilities': [],
            'configs': [],
            'documentation': [],
            'deprecated': [],
            'broken': []
        }
        
        for file_path, info in self.modules_info.items():
            rel_path = info['relative_path']
            
            # CLI инструменты
            if ('cli' in rel_path.lower() or 
                info['has_main'] or
                'main' in info['functions'] or
                any('argparse' in imp for imp in info['imports'])):
                categories['cli_tools'].append(rel_path)
            
            # Основные движки
            elif ('engine' in rel_path.lower() or 
                  'bypass' in rel_path.lower() or
                  'core' in rel_path.lower()):
                categories['core_engines'].append(rel_path)
            
            # Анализаторы
            elif ('analyzer' in rel_path.lower() or 
                  'pcap' in rel_path.lower() or
                  'analyze' in rel_path.lower()):
                categories['analyzers'].append(rel_path)
            
            # Тесты
            elif ('test' in rel_path.lower() or 
                  'demo' in rel_path.lower()):
                categories['tests'].append(rel_path)
            
            # Утилиты
            elif ('util' in rel_path.lower() or 
                  'helper' in rel_path.lower() or
                  'tool' in rel_path.lower()):
                categories['utilities'].append(rel_path)
            
            # Конфигурации
            elif ('config' in rel_path.lower() or 
                  'setup' in rel_path.lower() or
                  rel_path.endswith('.json')):
                categories['configs'].append(rel_path)
            
            # Документация
            elif rel_path.endswith('.md'):
                categories['documentation'].append(rel_path)
            
            # Сломанные модули
            elif info['errors']:
                categories['broken'].append(rel_path)
            
            # Остальное - утилиты
            else:
                categories['utilities'].append(rel_path)
        
        return categories
    
    def find_standalone_functionality(self):
        """Находит функциональность, которую можно запускать отдельно."""
        standalone = []
        
        for file_path, info in self.modules_info.items():
            if info['is_executable'] and not info['errors']:
                # Определяем тип функциональности
                rel_path = info['relative_path']
                
                functionality = {
                    'file': rel_path,
                    'description': info['description'] or 'Нет описания',
                    'functions': len(info['functions']),
                    'classes': len(info['classes']),
                    'type': 'unknown'
                }
                
                # Определяем тип по названию и содержимому
                if 'cli' in rel_path.lower():
                    functionality['type'] = 'CLI Tool'
                elif 'test' in rel_path.lower():
                    functionality['type'] = 'Test Script'
                elif 'analyze' in rel_path.lower():
                    functionality['type'] = 'Analyzer'
                elif 'setup' in rel_path.lower():
                    functionality['type'] = 'Setup Script'
                elif 'monitor' in rel_path.lower():
                    functionality['type'] = 'Monitor'
                elif 'detector' in rel_path.lower():
                    functionality['type'] = 'Detector'
                else:
                    functionality['type'] = 'Utility'
                
                standalone.append(functionality)
        
        return standalone
    
    def analyze_project(self):
        """Полный анализ проекта."""
        print("🚀 Запуск полного анализа проекта")
        print("=" * 50)
        
        # 1. Сканируем файлы
        self.scan_python_files()
        
        # 2. Анализируем каждый файл
        print("\n📊 Анализ файлов...")
        for file_path in self.python_files:
            info = self.analyze_file(file_path)
            self.modules_info[str(file_path)] = info
            
            # Тестируем импорт
            if self.test_module_import(file_path):
                self.working_modules.add(str(file_path))
            else:
                self.broken_modules.add(str(file_path))
        
        # 3. Категоризируем модули
        categories = self.categorize_modules()
        
        # 4. Находим standalone функциональность
        standalone = self.find_standalone_functionality()
        
        return {
            'total_files': len(self.python_files),
            'working_modules': len(self.working_modules),
            'broken_modules': len(self.broken_modules),
            'categories': categories,
            'standalone_functionality': standalone
        }
    
    def generate_report(self, results: Dict):
        """Генерирует отчет анализа."""
        print(f"\n📋 ОТЧЕТ АНАЛИЗА ПРОЕКТА")
        print("=" * 50)
        
        print(f"📁 Всего Python файлов: {results['total_files']}")
        print(f"✅ Рабочих модулей: {results['working_modules']}")
        print(f"❌ Сломанных модулей: {results['broken_modules']}")
        
        print(f"\n📂 КАТЕГОРИИ МОДУЛЕЙ:")
        for category, files in results['categories'].items():
            if files:
                print(f"\n{category.upper().replace('_', ' ')} ({len(files)}):")
                for file in files[:5]:  # Показываем первые 5
                    print(f"  • {file}")
                if len(files) > 5:
                    print(f"  ... и еще {len(files) - 5}")
        
        print(f"\n🚀 STANDALONE ФУНКЦИОНАЛЬНОСТЬ ({len(results['standalone_functionality'])}):")
        for func in results['standalone_functionality']:
            print(f"\n• {func['file']} ({func['type']})")
            print(f"  Описание: {func['description'][:80]}...")
            print(f"  Функций: {func['functions']}, Классов: {func['classes']}")
        
        return results
    
    def save_report(self, results: Dict, filename: str = "project_analysis.json"):
        """Сохраняет отчет в JSON файл."""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Отчет сохранен в {filename}")


def main():
    """Главная функция."""
    analyzer = ProjectAnalyzer()
    results = analyzer.analyze_project()
    analyzer.generate_report(results)
    analyzer.save_report(results)


if __name__ == '__main__':
    main()