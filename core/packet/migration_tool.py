"""
Инструмент для миграции кода со Scapy на побайтовую обработку пакетов.
"""

import ast
import re
import os
import shutil
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime


class ScapyMigrationTool:
    """Инструмент для автоматической миграции кода со Scapy."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.scapy_usage_stats = {}
        
        # Паттерны для обнаружения Scapy
        self.scapy_patterns = {
            'imports': [
                r'from\s+scapy\.',
                r'import\s+scapy',
                r'from\s+scapy\s+import',
            ],
            'functions': [
                r'send\s*\(',
                r'sr1\s*\(',
                r'sniff\s*\(',
                r'wrpcap\s*\(',
                r'rdpcap\s*\(',
            ],
            'classes': [
                r'IP\s*\(',
                r'TCP\s*\(',
                r'UDP\s*\(',
                r'ICMP\s*\(',
            ]
        }
    
    def detect_scapy_usage(self, code: str) -> Dict[str, Any]:
        """Обнаруживает использование Scapy в коде."""
        try:
            usage = {
                'has_scapy': False,
                'imports': [],
                'functions': [],
                'classes': [],
                'complexity': 'low'
            }
            
            # Проверка импортов
            for pattern in self.scapy_patterns['imports']:
                matches = re.findall(pattern, code, re.IGNORECASE)
                if matches:
                    usage['has_scapy'] = True
                    usage['imports'].extend(['scapy'])
            
            # Проверка функций
            for pattern in self.scapy_patterns['functions']:
                matches = re.findall(pattern, code)
                if matches:
                    usage['has_scapy'] = True
                    func_name = pattern.replace(r'\s*\(', '').replace('\\', '')
                    usage['functions'].append(func_name)
            
            # Проверка классов
            for pattern in self.scapy_patterns['classes']:
                matches = re.findall(pattern, code)
                if matches:
                    usage['has_scapy'] = True
                    class_name = pattern.replace(r'\s*\(', '').replace('\\', '')
                    usage['classes'].append(class_name)
            
            # Определение сложности
            total_usage = len(usage['imports']) + len(usage['functions']) + len(usage['classes'])
            if total_usage > 10:
                usage['complexity'] = 'high'
            elif total_usage > 5:
                usage['complexity'] = 'medium'
            
            return usage
            
        except Exception as e:
            self.logger.error(f"Error detecting Scapy usage: {e}")
            return {'has_scapy': False, 'imports': [], 'functions': [], 'classes': [], 'complexity': 'unknown'}
    
    def generate_migration_plan(self, code: str) -> Dict[str, Any]:
        """Генерирует план миграции для кода."""
        usage = self.detect_scapy_usage(code)
        
        plan = {
            'steps': [],
            'estimated_time': 'unknown',
            'complexity': usage['complexity'],
            'recommendations': []
        }
        
        if not usage['has_scapy']:
            plan['steps'] = ['Код не использует Scapy - миграция не требуется']
            return plan
        
        # Базовые шаги миграции
        plan['steps'] = [
            'Создать резервную копию исходного кода',
            'Заменить импорты Scapy на recon.core.packet',
            'Конвертировать создание пакетов на побайтовую обработку',
            'Заменить функции отправки пакетов',
            'Обновить функции парсинга пакетов',
            'Провести тестирование конвертированного кода',
            'Валидировать результаты миграции'
        ]
        
        # Дополнительные шаги в зависимости от сложности
        if usage['complexity'] == 'high':
            plan['steps'].insert(2, 'Использовать слой совместимости для сложных случаев')
            plan['estimated_time'] = '4-8 часов'
        elif usage['complexity'] == 'medium':
            plan['estimated_time'] = '2-4 часа'
        else:
            plan['estimated_time'] = '1-2 часа'
        
        # Рекомендации
        if 'IP' in usage['classes']:
            plan['recommendations'].append('Заменить IP() на RawPacketEngine.build_ip_packet()')
        if 'TCP' in usage['classes']:
            plan['recommendations'].append('Заменить TCP() на RawPacketEngine.build_tcp_packet()')
        if 'send' in usage['functions']:
            plan['recommendations'].append('Заменить send() на RawPacketEngine.inject_packet()')
        
        return plan
    
    def convert_scapy_code(self, code: str) -> str:
        """Конвертирует Scapy код в побайтовую обработку."""
        try:
            converted = code
            
            # Замена импортов
            converted = re.sub(
                r'from\s+scapy\.all\s+import.*',
                'from recon.core.packet import RawPacketEngine, ScapyCompatibilityLayer',
                converted
            )
            
            converted = re.sub(
                r'import\s+scapy.*',
                'from recon.core.packet import RawPacketEngine, ScapyCompatibilityLayer',
                converted
            )
            
            # Добавление инициализации движка
            if 'RawPacketEngine' in converted:
                init_code = '\n# Инициализация движка побайтовой обработки\nengine = RawPacketEngine()\n'
                converted = init_code + converted
            
            # Замена создания пакетов (упрощенная версия)
            converted = re.sub(
                r'IP\s*\(',
                'engine.build_ip_packet(',
                converted
            )
            
            converted = re.sub(
                r'TCP\s*\(',
                'engine.build_tcp_packet(',
                converted
            )
            
            # Замена функций отправки
            converted = re.sub(
                r'send\s*\(',
                'await engine.inject_packet(',
                converted
            )
            
            return converted
            
        except Exception as e:
            self.logger.error(f"Error converting Scapy code: {e}")
            return code
    
    def backup_scapy_code(self, filename: str, code: str) -> str:
        """Создает резервную копию Scapy кода."""
        try:
            backup_dir = self.config.get('backup_directory', './scapy_backups')
            os.makedirs(backup_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{filename}.backup_{timestamp}"
            backup_path = os.path.join(backup_dir, backup_filename)
            
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(code)
            
            self.logger.info(f"Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return ""
    
    async def validate_migration(self, original_data: bytes, migrated_data: bytes) -> bool:
        """Валидирует результаты миграции."""
        try:
            # Простая валидация - сравнение размеров и базовых характеристик
            if len(original_data) == 0 or len(migrated_data) == 0:
                return False
            
            # Проверка, что данные похожи (допустимая разница до 20%)
            size_diff = abs(len(original_data) - len(migrated_data)) / len(original_data)
            if size_diff > 0.2:
                return False
            
            # Дополнительные проверки можно добавить здесь
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating migration: {e}")
            return False
    
    def generate_migration_report(self) -> Dict[str, Any]:
        """Генерирует отчет о миграции."""
        try:
            report = {
                'migration_summary': self.scapy_usage_stats,
                'timestamp': datetime.now().isoformat(),
                'recommendations': [],
                'next_steps': []
            }
            
            # Вычисление статистики
            if self.scapy_usage_stats:
                total_files = self.scapy_usage_stats.get('total_files', 0)
                converted_files = self.scapy_usage_stats.get('converted_files', 0)
                
                if total_files > 0:
                    conversion_rate = (converted_files / total_files) * 100
                    report['migration_summary']['conversion_rate'] = conversion_rate
                    
                    if conversion_rate >= 90:
                        report['recommendations'].append('Миграция практически завершена')
                    elif conversion_rate >= 70:
                        report['recommendations'].append('Хороший прогресс миграции')
                    else:
                        report['recommendations'].append('Требуется дополнительная работа по миграции')
            
            # Следующие шаги
            report['next_steps'] = [
                'Провести полное тестирование мигрированного кода',
                'Оптимизировать производительность критических участков',
                'Обновить документацию',
                'Обучить команду новому API'
            ]
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating migration report: {e}")
            return {'error': str(e)}
    
    def analyze_packet_structure(self, packet) -> Dict[str, Any]:
        """Анализирует структуру пакета."""
        try:
            structure = {
                'type': getattr(packet, 'name', 'unknown'),
                'fields': {},
                'size': 0
            }
            
            # Извлечение полей пакета
            if hasattr(packet, 'fields'):
                structure['fields'] = packet.fields
            
            # Размер пакета
            if hasattr(packet, '__len__'):
                structure['size'] = len(packet)
            
            return structure
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet structure: {e}")
            return {'type': 'unknown', 'fields': {}, 'size': 0}
    
    async def convert_scapy_packet(self, scapy_packet) -> Optional['RawPacket']:
        """Конвертирует Scapy пакет в побайтовый формат."""
        try:
            from .raw_packet_engine import RawPacketEngine
            
            engine = RawPacketEngine()
            
            # Получаем байты из Scapy пакета
            if hasattr(scapy_packet, '__bytes__'):
                packet_bytes = scapy_packet.__bytes__()
            else:
                packet_bytes = bytes(scapy_packet)
            
            # Парсим в побайтовый формат
            raw_packet = await engine.parse_packet(packet_bytes)
            return raw_packet
            
        except Exception as e:
            self.logger.error(f"Error converting Scapy packet: {e}")
            return None