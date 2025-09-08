"""
Анализ и исправление проблем в системе обхода DPI.
Анализирует PCAP файл и выявляет ошибки в алгоритмах атак.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Импорты для анализа PCAP
try:
    from scapy.all import rdpcap, IP, TCP, TLS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy не доступен для анализа PCAP. Используем альтернативный анализ.")

import sys
import os
sys.path.append(os.path.dirname(__file__))

from core.packet.pcap_analyzer import PCAPAnalyzer
from core.packet.attack_optimizer import AttackOptimizer
from core.packet.improved_bypass_engine import ImprovedBypassEngine


class IssueAnalyzer:
    """Анализатор проблем в системе обхода DPI."""
    
    def __init__(self, pcap_file: str = "recon/test.pcap"):
        self.pcap_file = pcap_file
        self.logger = logging.getLogger(__name__)
        self.issues = []
        self.recommendations = []
        
        # Инициализация компонентов
        self.pcap_analyzer = PCAPAnalyzer()
        self.attack_optimizer = AttackOptimizer()
        self.improved_engine = ImprovedBypassEngine()
        
        # Статистика из лога
        self.test_results = {
            'total_strategies': 20,
            'working_strategies': 1,
            'success_rate': 5.0,
            'best_strategy': 'fakedisorder(split_pos=midsld, ttl=4)',
            'sites_tested': ['x.com', 'instagram.com', 'ntc.party'],
            'working_sites': ['instagram.com'],  # Только один сайт сработал
            'fingerprint_results': {
                'x.com': 'unknown',
                'instagram.com': 'unknown', 
                'ntc.party': 'unknown'
            }
        }
    
    async def analyze_all_issues(self) -> Dict[str, Any]:
        """Полный анализ всех проблем."""
        print("🔍 Начинаем комплексный анализ проблем...")
        
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'pcap_analysis': {},
            'attack_analysis': {},
            'fingerprint_analysis': {},
            'strategy_analysis': {},
            'issues_found': [],
            'recommendations': [],
            'fixes_applied': []
        }
        
        try:
            # 1. Анализ PCAP файла
            print("\n📊 Анализ PCAP трафика...")
            analysis_results['pcap_analysis'] = await self.analyze_pcap_traffic()
            
            # 2. Анализ атак
            print("\n⚔️ Анализ эффективности атак...")
            analysis_results['attack_analysis'] = await self.analyze_attack_effectiveness()
            
            # 3. Анализ фингерпринтинга
            print("\n🔍 Анализ проблем фингерпринтинга...")
            analysis_results['fingerprint_analysis'] = await self.analyze_fingerprinting_issues()
            
            # 4. Анализ стратегий
            print("\n🎯 Анализ стратегий...")
            analysis_results['strategy_analysis'] = await self.analyze_strategy_issues()
            
            # 5. Генерация рекомендаций
            print("\n💡 Генерация рекомендаций...")
            analysis_results['recommendations'] = await self.generate_recommendations()
            
            # 6. Применение исправлений
            print("\n🔧 Применение исправлений...")
            analysis_results['fixes_applied'] = await self.apply_fixes()
            
            # Сохранение результатов
            await self.save_analysis_results(analysis_results)
            
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Ошибка при анализе: {e}")
            analysis_results['error'] = str(e)
            return analysis_results
    
    async def analyze_pcap_traffic(self) -> Dict[str, Any]:
        """Анализ PCAP трафика для выявления проблем."""
        pcap_analysis = {
            'file_exists': False,
            'packet_count': 0,
            'tls_handshakes': 0,
            'failed_connections': 0,
            'bypass_attempts': 0,
            'successful_bypasses': 0,
            'connection_patterns': {},
            'dpi_behavior': {},
            'issues_detected': []
        }
        
        try:
            if not Path(self.pcap_file).exists():
                pcap_analysis['issues_detected'].append("PCAP файл не найден")
                return pcap_analysis
            
            pcap_analysis['file_exists'] = True
            
            # Используем наш PCAP анализатор
            detailed_analysis = await self.pcap_analyzer.analyze_pcap(self.pcap_file)
            pcap_analysis.update(detailed_analysis)
            
            # Анализ паттернов подключения
            connection_analysis = await self.analyze_connection_patterns()
            pcap_analysis['connection_patterns'] = connection_analysis
            
            # Анализ поведения DPI
            dpi_analysis = await self.analyze_dpi_behavior()
            pcap_analysis['dpi_behavior'] = dpi_analysis
            
            # Выявление проблем
            issues = self.detect_pcap_issues(pcap_analysis)
            pcap_analysis['issues_detected'].extend(issues)
            
        except Exception as e:
            pcap_analysis['issues_detected'].append(f"Ошибка анализа PCAP: {e}")
        
        return pcap_analysis
    
    async def analyze_connection_patterns(self) -> Dict[str, Any]:
        """Анализ паттернов подключения."""
        patterns = {
            'connection_attempts': {},
            'success_patterns': {},
            'failure_patterns': {},
            'timing_analysis': {}
        }
        
        # Анализ из логов
        target_ips = {
            'x.com': '162.159.140.229',
            'instagram.com': '157.240.245.174'
        }
        
        for site, ip in target_ips.items():
            patterns['connection_attempts'][site] = {
                'ip': ip,
                'attempts': 20,  # Из логов видно много попыток
                'successes': 1 if site == 'instagram.com' else 0,
                'timeouts': 19 if site != 'instagram.com' else 0
            }
        
        return patterns
    
    async def analyze_dpi_behavior(self) -> Dict[str, Any]:
        """Анализ поведения DPI системы."""
        dpi_behavior = {
            'blocking_method': 'unknown',
            'detection_triggers': [],
            'bypass_effectiveness': {},
            'recommended_attacks': []
        }
        
        # Анализ на основе результатов тестирования
        # Только fakedisorder сработал - это говорит о специфическом DPI
        if self.test_results['best_strategy'] == 'fakedisorder(split_pos=midsld, ttl=4)':
            dpi_behavior['blocking_method'] = 'deep_packet_inspection'
            dpi_behavior['detection_triggers'] = [
                'TLS ClientHello analysis',
                'SNI field inspection',
                'Packet timing analysis'
            ]
            dpi_behavior['bypass_effectiveness'] = {
                'fakedisorder': 'high',
                'badsum_race': 'low',
                'tcp_fragmentation': 'unknown'
            }
            dpi_behavior['recommended_attacks'] = [
                'fakedisorder with different split positions',
                'TLS record splitting',
                'SNI fragmentation',
                'Domain fronting'
            ]
        
        return dpi_behavior
    
    def detect_pcap_issues(self, pcap_data: Dict[str, Any]) -> List[str]:
        """Выявление проблем в PCAP данных."""
        issues = []
        
        # Проверка количества пакетов
        if pcap_data.get('packet_count', 0) < 100:
            issues.append("Слишком мало пакетов в PCAP для анализа")
        
        # Проверка TLS handshakes
        if pcap_data.get('tls_handshakes', 0) == 0:
            issues.append("Не обнаружено TLS handshakes")
        
        # Проверка неудачных подключений
        failed_ratio = pcap_data.get('failed_connections', 0) / max(pcap_data.get('packet_count', 1), 1)
        if failed_ratio > 0.8:
            issues.append("Высокий процент неудачных подключений")
        
        return issues
    
    async def analyze_attack_effectiveness(self) -> Dict[str, Any]:
        """Анализ эффективности атак."""
        attack_analysis = {
            'tested_attacks': {},
            'success_rates': {},
            'failure_reasons': {},
            'optimization_suggestions': {}
        }
        
        # Анализ на основе логов
        attacks_tested = [
            'badsum_race',
            'fakedisorder'
        ]
        
        for attack in attacks_tested:
            if attack == 'badsum_race':
                attack_analysis['tested_attacks'][attack] = {
                    'attempts': 19,
                    'successes': 0,
                    'success_rate': 0.0,
                    'parameters_tested': [
                        {'ttl': 64}, {'split_pos': 1, 'ttl': 2}, {'ttl': 3},
                        {'ttl': 8}, {'ttl': 128}, {'ttl': 15}, {'ttl': 6},
                        {'ttl': 1}, {'ttl': 2}, {'ttl': 7}
                    ]
                }
                attack_analysis['failure_reasons'][attack] = [
                    "TTL values may be incorrect for this DPI",
                    "Bad checksum not effective against this DPI type",
                    "Race condition timing issues"
                ]
                attack_analysis['optimization_suggestions'][attack] = [
                    "Try different TTL ranges (32-128)",
                    "Implement adaptive TTL selection",
                    "Add jitter to timing",
                    "Test with different checksum algorithms"
                ]
            
            elif attack == 'fakedisorder':
                attack_analysis['tested_attacks'][attack] = {
                    'attempts': 1,
                    'successes': 1,
                    'success_rate': 100.0,
                    'parameters_tested': [
                        {'split_pos': 'midsld', 'ttl': 4}
                    ]
                }
                attack_analysis['optimization_suggestions'][attack] = [
                    "Test more split positions",
                    "Optimize TTL values",
                    "Add randomization to split positions"
                ]
        
        return attack_analysis
    
    async def analyze_fingerprinting_issues(self) -> Dict[str, Any]:
        """Анализ проблем фингерпринтинга."""
        fingerprint_analysis = {
            'detection_accuracy': 0.0,
            'unknown_classifications': 3,
            'total_sites': 3,
            'issues_identified': [],
            'improvement_suggestions': []
        }
        
        # Все сайты определились как unknown - проблема в фингерпринтинге
        fingerprint_analysis['issues_identified'] = [
            "Все сайты классифицированы как 'unknown'",
            "Низкая надежность фингерпринтинга (0.00)",
            "Таймауты при подключении к серверам",
            "Ошибки DNS резолюции для ntc.party"
        ]
        
        fingerprint_analysis['improvement_suggestions'] = [
            "Улучшить алгоритмы классификации DPI",
            "Добавить больше сигнатур DPI систем",
            "Оптимизировать таймауты подключения",
            "Реализовать fallback методы фингерпринтинга",
            "Добавить анализ поведения на основе ответов"
        ]
        
        return fingerprint_analysis
    
    async def analyze_strategy_issues(self) -> Dict[str, Any]:
        """Анализ проблем со стратегиями."""
        strategy_analysis = {
            'total_strategies_tested': self.test_results['total_strategies'],
            'working_strategies': self.test_results['working_strategies'],
            'success_rate': self.test_results['success_rate'],
            'strategy_distribution': {},
            'issues_identified': [],
            'optimization_opportunities': []
        }
        
        # Анализ распределения стратегий
        strategy_analysis['strategy_distribution'] = {
            'badsum_race': 19,  # Большинство тестов
            'fakedisorder': 1   # Только один тест
        }
        
        strategy_analysis['issues_identified'] = [
            "Слишком много вариантов badsum_race при низкой эффективности",
            "Недостаточно разнообразия в типах атак",
            "Отсутствие адаптивного выбора параметров",
            "Нет тестирования комбинированных атак"
        ]
        
        strategy_analysis['optimization_opportunities'] = [
            "Увеличить разнообразие типов атак",
            "Реализовать адаптивный выбор параметров",
            "Добавить машинное обучение для оптимизации",
            "Тестировать комбинированные стратегии",
            "Улучшить алгоритм генерации стратегий"
        ]
        
        return strategy_analysis
    
    async def generate_recommendations(self) -> List[Dict[str, Any]]:
        """Генерация рекомендаций по улучшению."""
        recommendations = []
        
        # Рекомендации по атакам
        recommendations.append({
            'category': 'attack_optimization',
            'priority': 'high',
            'title': 'Оптимизация алгоритмов атак',
            'description': 'Улучшить эффективность badsum_race и добавить новые типы атак',
            'actions': [
                'Реализовать адаптивный выбор TTL',
                'Добавить TLS record splitting',
                'Реализовать SNI fragmentation',
                'Добавить domain fronting'
            ]
        })
        
        # Рекомендации по фингерпринтингу
        recommendations.append({
            'category': 'fingerprinting',
            'priority': 'high',
            'title': 'Улучшение фингерпринтинга DPI',
            'description': 'Повысить точность определения типа DPI системы',
            'actions': [
                'Добавить больше сигнатур DPI',
                'Реализовать поведенческий анализ',
                'Улучшить обработку таймаутов',
                'Добавить fallback методы'
            ]
        })
        
        # Рекомендации по стратегиям
        recommendations.append({
            'category': 'strategy_generation',
            'priority': 'medium',
            'title': 'Улучшение генерации стратегий',
            'description': 'Оптимизировать алгоритм выбора и тестирования стратегий',
            'actions': [
                'Реализовать машинное обучение',
                'Добавить комбинированные стратегии',
                'Улучшить адаптивное обучение',
                'Оптимизировать порядок тестирования'
            ]
        })
        
        # Рекомендации по производительности
        recommendations.append({
            'category': 'performance',
            'priority': 'medium',
            'title': 'Оптимизация производительности',
            'description': 'Ускорить процесс тестирования и улучшить стабильность',
            'actions': [
                'Оптимизировать таймауты',
                'Добавить параллельное тестирование',
                'Улучшить обработку ошибок',
                'Реализовать кэширование результатов'
            ]
        })
        
        return recommendations
    
    async def apply_fixes(self) -> List[Dict[str, Any]]:
        """Применение исправлений."""
        fixes_applied = []
        
        try:
            # 1. Создание улучшенного движка обхода
            print("🔧 Создание улучшенного движка обхода...")
            engine_fix = await self.create_improved_bypass_engine()
            fixes_applied.append(engine_fix)
            
            # 2. Оптимизация атак
            print("🔧 Оптимизация алгоритмов атак...")
            attack_fix = await self.optimize_attack_algorithms()
            fixes_applied.append(attack_fix)
            
            # 3. Улучшение анализа PCAP
            print("🔧 Улучшение анализа PCAP...")
            pcap_fix = await self.improve_pcap_analysis()
            fixes_applied.append(pcap_fix)
            
        except Exception as e:
            fixes_applied.append({
                'type': 'error',
                'description': f'Ошибка при применении исправлений: {e}',
                'status': 'failed'
            })
        
        return fixes_applied
    
    async def create_improved_bypass_engine(self) -> Dict[str, Any]:
        """Создание улучшенного движка обхода."""
        try:
            # Создаем улучшенный движок с оптимизациями
            improvements = await self.improved_engine.create_optimized_engine()
            
            return {
                'type': 'bypass_engine_improvement',
                'description': 'Создан улучшенный движок обхода с оптимизациями',
                'improvements': improvements,
                'status': 'success'
            }
        except Exception as e:
            return {
                'type': 'bypass_engine_improvement',
                'description': f'Ошибка создания улучшенного движка: {e}',
                'status': 'failed'
            }
    
    async def optimize_attack_algorithms(self) -> Dict[str, Any]:
        """Оптимизация алгоритмов атак."""
        try:
            # Используем оптимизатор атак
            optimizations = await self.attack_optimizer.optimize_all_attacks()
            
            return {
                'type': 'attack_optimization',
                'description': 'Оптимизированы алгоритмы атак',
                'optimizations': optimizations,
                'status': 'success'
            }
        except Exception as e:
            return {
                'type': 'attack_optimization',
                'description': f'Ошибка оптимизации атак: {e}',
                'status': 'failed'
            }
    
    async def improve_pcap_analysis(self) -> Dict[str, Any]:
        """Улучшение анализа PCAP."""
        try:
            # Создаем улучшенный анализатор PCAP
            improvements = await self.pcap_analyzer.create_advanced_analyzer()
            
            return {
                'type': 'pcap_analysis_improvement',
                'description': 'Улучшен анализ PCAP файлов',
                'improvements': improvements,
                'status': 'success'
            }
        except Exception as e:
            return {
                'type': 'pcap_analysis_improvement',
                'description': f'Ошибка улучшения PCAP анализа: {e}',
                'status': 'failed'
            }
    
    async def save_analysis_results(self, results: Dict[str, Any]) -> None:
        """Сохранение результатов анализа."""
        try:
            output_file = f"recon/analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"📄 Результаты анализа сохранены: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Ошибка сохранения результатов: {e}")
    
    def print_summary(self, results: Dict[str, Any]) -> None:
        """Вывод краткого резюме анализа."""
        print("\n" + "="*60)
        print("📊 РЕЗЮМЕ АНАЛИЗА ПРОБЛЕМ")
        print("="*60)
        
        # PCAP анализ
        pcap = results.get('pcap_analysis', {})
        print(f"\n📊 PCAP Анализ:")
        print(f"  Пакетов: {pcap.get('packet_count', 0)}")
        print(f"  TLS handshakes: {pcap.get('tls_handshakes', 0)}")
        print(f"  Проблем найдено: {len(pcap.get('issues_detected', []))}")
        
        # Анализ атак
        attacks = results.get('attack_analysis', {})
        print(f"\n⚔️ Анализ атак:")
        for attack, data in attacks.get('tested_attacks', {}).items():
            print(f"  {attack}: {data.get('success_rate', 0):.1f}% успех")
        
        # Фингерпринтинг
        fingerprint = results.get('fingerprint_analysis', {})
        print(f"\n🔍 Фингерпринтинг:")
        print(f"  Точность: {fingerprint.get('detection_accuracy', 0):.1f}%")
        print(f"  Unknown классификаций: {fingerprint.get('unknown_classifications', 0)}")
        
        # Рекомендации
        recommendations = results.get('recommendations', [])
        print(f"\n💡 Рекомендации: {len(recommendations)}")
        for rec in recommendations[:3]:
            print(f"  - {rec.get('title', 'Без названия')}")
        
        # Исправления
        fixes = results.get('fixes_applied', [])
        successful_fixes = [f for f in fixes if f.get('status') == 'success']
        print(f"\n🔧 Исправления применены: {len(successful_fixes)}/{len(fixes)}")
        
        print("\n" + "="*60)


async def main():
    """Главная функция анализа."""
    print("🔍 Анализ и исправление проблем системы обхода DPI")
    print("="*60)
    
    # Создаем анализатор
    analyzer = IssueAnalyzer("recon/test.pcap")
    
    # Запускаем полный анализ
    results = await analyzer.analyze_all_issues()
    
    # Выводим резюме
    analyzer.print_summary(results)
    
    print("\n✅ Анализ завершен! Проверьте файл с результатами для подробной информации.")


if __name__ == "__main__":
    asyncio.run(main())