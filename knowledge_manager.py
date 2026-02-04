#!/usr/bin/env python3
"""
Knowledge Base Manager

Утилита для управления базой знаний рефакторинга.
Позволяет добавлять новые файлы знаний, обновлять индекс и анализировать накопленный опыт.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


class KnowledgeManager:
    """Менеджер базы знаний рефакторинга."""
    
    def __init__(self, knowledge_dir: str = "knowledge"):
        self.knowledge_dir = Path(knowledge_dir)
        self.index_file = self.knowledge_dir / "knowledge_index.json"
        
    def add_refactoring_metadata(self, metadata_file: str, project_name: str = None) -> None:
        """Добавить новый файл метаданных рефакторинга в базу знаний."""
        
        # Загрузить метаданные
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
            
        # Определить имя проекта
        if not project_name:
            project_name = metadata.get('project_name', 'Unknown Project')
            
        # Создать запись для индекса
        knowledge_entry = {
            "filename": Path(metadata_file).name,
            "type": "refactoring_metadata",
            "project_name": project_name,
            "date_created": metadata.get('refactoring_date', datetime.now().strftime('%Y-%m-%d')),
            "transformation_rules_count": len(metadata.get('transformation_rules', [])),
            "di_patterns_count": len(metadata.get('di_patterns', [])),
            "interface_templates_count": len(metadata.get('interface_templates', [])),
            "testing_strategies_count": len(metadata.get('testing_strategies', [])),
            "automation_potential_score": metadata.get('automation_potential_score', 0.0),
            "reusability_score": metadata.get('reusability_score', 0.0),
            "key_metrics": metadata.get('overall_success_metrics', {}),
            "applicable_contexts": metadata.get('applicable_contexts', [])
        }
        
        # Обновить индекс
        self._update_index(knowledge_entry)
        
        print(f"✅ Добавлен файл знаний: {metadata_file}")
        print(f"📊 Проект: {project_name}")
        print(f"🎯 Потенциал автоматизации: {knowledge_entry['automation_potential_score']}")
        
    def _update_index(self, new_entry: Dict[str, Any]) -> None:
        """Обновить индексный файл базы знаний."""
        
        # Загрузить существующий индекс или создать новый
        if self.index_file.exists():
            with open(self.index_file, 'r', encoding='utf-8') as f:
                index = json.load(f)
        else:
            index = {
                "knowledge_base_version": "1.0",
                "last_updated": "",
                "total_refactoring_projects": 0,
                "knowledge_files": [],
                "statistics": {
                    "total_transformation_rules": 0,
                    "total_di_patterns": 0,
                    "total_interface_templates": 0,
                    "total_testing_strategies": 0,
                    "average_automation_confidence": 0.0,
                    "average_reusability_score": 0.0
                }
            }
            
        # Проверить, не существует ли уже такой файл
        existing_files = [f['filename'] for f in index['knowledge_files']]
        if new_entry['filename'] in existing_files:
            # Обновить существующую запись
            for i, entry in enumerate(index['knowledge_files']):
                if entry['filename'] == new_entry['filename']:
                    index['knowledge_files'][i] = new_entry
                    break
        else:
            # Добавить новую запись
            index['knowledge_files'].append(new_entry)
            index['total_refactoring_projects'] += 1
            
        # Обновить статистику
        self._recalculate_statistics(index)
        
        # Обновить временную метку
        index['last_updated'] = datetime.now().isoformat()
        
        # Сохранить индекс
        with open(self.index_file, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2, ensure_ascii=False)
            
    def _recalculate_statistics(self, index: Dict[str, Any]) -> None:
        """Пересчитать статистику базы знаний."""
        
        refactoring_files = [f for f in index['knowledge_files'] if f['type'] == 'refactoring_metadata']
        
        if not refactoring_files:
            return
            
        # Суммарная статистика
        total_rules = sum(f.get('transformation_rules_count', 0) for f in refactoring_files)
        total_di = sum(f.get('di_patterns_count', 0) for f in refactoring_files)
        total_interfaces = sum(f.get('interface_templates_count', 0) for f in refactoring_files)
        total_testing = sum(f.get('testing_strategies_count', 0) for f in refactoring_files)
        
        # Средние значения
        avg_automation = sum(f.get('automation_potential_score', 0) for f in refactoring_files) / len(refactoring_files)
        avg_reusability = sum(f.get('reusability_score', 0) for f in refactoring_files) / len(refactoring_files)
        
        index['statistics'] = {
            "total_transformation_rules": total_rules,
            "total_di_patterns": total_di,
            "total_interface_templates": total_interfaces,
            "total_testing_strategies": total_testing,
            "average_automation_confidence": round(avg_automation, 2),
            "average_reusability_score": round(avg_reusability, 2)
        }
        
    def list_knowledge(self) -> None:
        """Показать список всех файлов знаний."""
        
        if not self.index_file.exists():
            print("❌ База знаний не найдена")
            return
            
        with open(self.index_file, 'r', encoding='utf-8') as f:
            index = json.load(f)
            
        print(f"📚 База знаний рефакторинга")
        print(f"📅 Последнее обновление: {index['last_updated']}")
        print(f"📊 Всего проектов: {index['total_refactoring_projects']}")
        print()
        
        for file_info in index['knowledge_files']:
            if file_info['type'] == 'refactoring_metadata':
                print(f"🔧 {file_info['project_name']}")
                print(f"   📁 {file_info['filename']}")
                print(f"   📅 {file_info['date_created']}")
                print(f"   🎯 Автоматизация: {file_info['automation_potential_score']}")
                print(f"   🔄 Переиспользование: {file_info['reusability_score']}")
                print()
                
        stats = index['statistics']
        print(f"📈 Общая статистика:")
        print(f"   🔧 Правил трансформации: {stats['total_transformation_rules']}")
        print(f"   💉 DI паттернов: {stats['total_di_patterns']}")
        print(f"   🎭 Шаблонов интерфейсов: {stats['total_interface_templates']}")
        print(f"   🧪 Стратегий тестирования: {stats['total_testing_strategies']}")
        print(f"   🎯 Средняя автоматизация: {stats['average_automation_confidence']}")
        
    def get_recommendations(self, context: str) -> List[str]:
        """Получить рекомендации на основе контекста."""
        
        if not self.index_file.exists():
            return []
            
        with open(self.index_file, 'r', encoding='utf-8') as f:
            index = json.load(f)
            
        recommendations = []
        
        for file_info in index['knowledge_files']:
            if file_info['type'] == 'refactoring_metadata':
                applicable_contexts = file_info.get('applicable_contexts', [])
                if context in applicable_contexts:
                    recommendations.append(f"Используйте паттерны из {file_info['project_name']} "
                                        f"(автоматизация: {file_info['automation_potential_score']})")
                    
        return recommendations


def main():
    """Главная функция для CLI интерфейса."""
    import sys
    
    manager = KnowledgeManager()
    
    if len(sys.argv) < 2:
        print("Использование:")
        print("  python knowledge_manager.py list                    # Показать все знания")
        print("  python knowledge_manager.py add <file> [project]    # Добавить файл знаний")
        print("  python knowledge_manager.py recommend <context>     # Получить рекомендации")
        return
        
    command = sys.argv[1]
    
    if command == "list":
        manager.list_knowledge()
    elif command == "add" and len(sys.argv) >= 3:
        metadata_file = sys.argv[2]
        project_name = sys.argv[3] if len(sys.argv) > 3 else None
        manager.add_refactoring_metadata(metadata_file, project_name)
    elif command == "recommend" and len(sys.argv) >= 3:
        context = sys.argv[2]
        recommendations = manager.get_recommendations(context)
        if recommendations:
            print("💡 Рекомендации:")
            for rec in recommendations:
                print(f"   {rec}")
        else:
            print(f"❌ Нет рекомендаций для контекста: {context}")
    else:
        print("❌ Неизвестная команда")


if __name__ == "__main__":
    main()