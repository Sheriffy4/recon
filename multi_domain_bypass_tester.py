#!/usr/bin/env python3
"""
Тестер bypass на множественных доменах для сравнения эффективности
"""

import subprocess
import time
import requests
import json
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

class MultiDomainBypassTester:
    """Тестер bypass на множественных доменах"""
    
    def __init__(self):
        # Расширенный список доменов для тестирования
        self.test_domains = {
            'blocked_torrents': [
                'nnmclub.to',
                'rutracker.org', 
                'kinozal.tv',
                'torrentfreak.com'
            ],
            'blocked_social': [
                'twitter.com',
                'facebook.com',
                'instagram.com'
            ],
            'blocked_video': [
                'youtube.com',
                'vimeo.com'
            ],
            'control_group': [
                'google.com',
                'github.com',
                'stackoverflow.com'
            ]
        }
    
    def test_domain_accessibility(self, domain, timeout=8):
        """Тестирует доступность домена"""
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat()
        }
        
        # Прямой тест
        try:
            start_time = time.time()
            response = requests.get(f"https://{domain}", 
                                  timeout=timeout, verify=False,
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            duration = time.time() - start_time
            
            results['direct'] = {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'duration': duration,
                'blocked': False
            }
        except requests.exceptions.Timeout:
            results['direct'] = {
                'success': False,
                'blocked': True,
                'error': 'timeout'
            }
        except Exception as e:
            results['direct'] = {
                'success': False,
                'blocked': True,
                'error': str(e)
            }
        
        return results
    
    def test_domain_with_bypass(self, domain, timeout=12):
        """Тестирует домен с bypass через service"""
        service_process = None
        try:
            # Запускаем service
            service_process = subprocess.Popen([
                'python', 'simple_service.py'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(3)  # Время на запуск
            
            # Тестируем с bypass
            start_time = time.time()
            response = requests.get(f"https://{domain}", 
                                  timeout=timeout, verify=False,
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            duration = time.time() - start_time
            
            return {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'duration': duration,
                'bypassed': True
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'bypassed': False,
                'error': 'timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'bypassed': False,
                'error': str(e)
            }
        finally:
            if service_process:
                service_process.terminate()
                service_process.wait(timeout=3)
    
    def test_domain_comprehensive(self, domain):
        """Комплексное тестирование домена"""
        print(f"   🎯 Тестирование {domain}...")
        
        # Прямой тест
        direct_result = self.test_domain_accessibility(domain)
        
        # Тест с bypass
        bypass_result = self.test_domain_with_bypass(domain)
        
        # Определяем статус
        is_blocked = direct_result['direct'].get('blocked', True)
        bypass_works = bypass_result.get('success', False)
        
        if not is_blocked:
            status = "🟢 Доступен"
            effectiveness = 1.0
        elif bypass_works:
            status = "🟡 Bypass работает"
            effectiveness = 1.0
        else:
            status = "🔴 Заблокирован"
            effectiveness = 0.0
        
        print(f"      {status}")
        
        return {
            'domain': domain,
            'direct': direct_result['direct'],
            'bypass': bypass_result,
            'is_blocked': is_blocked,
            'bypass_works': bypass_works,
            'effectiveness': effectiveness,
            'status': status
        }
    
    def test_all_domains(self):
        """Тестирует все домены"""
        print("🌐 Комплексное тестирование доменов...")
        
        all_results = {}
        
        for category, domains in self.test_domains.items():
            print(f"\n📂 Категория: {category}")
            category_results = {}
            
            for domain in domains:
                try:
                    result = self.test_domain_comprehensive(domain)
                    category_results[domain] = result
                except Exception as e:
                    print(f"      ❌ Ошибка тестирования {domain}: {e}")
                    category_results[domain] = {
                        'domain': domain,
                        'error': str(e),
                        'effectiveness': 0.0
                    }
                
                # Небольшая пауза между тестами
                time.sleep(2)
            
            all_results[category] = category_results
        
        return all_results
    
    def analyze_bypass_patterns(self, results):
        """Анализирует паттерны работы bypass"""
        print("📊 Анализ паттернов bypass...")
        
        analysis = {
            'total_domains': 0,
            'blocked_domains': 0,
            'bypass_working': 0,
            'categories': {},
            'effectiveness_by_category': {}
        }
        
        for category, domains in results.items():
            category_stats = {
                'total': len(domains),
                'blocked': 0,
                'bypass_works': 0,
                'effectiveness': 0.0
            }
            
            effectiveness_scores = []
            
            for domain, result in domains.items():
                analysis['total_domains'] += 1
                
                if result.get('is_blocked', True):
                    analysis['blocked_domains'] += 1
                    category_stats['blocked'] += 1
                
                if result.get('bypass_works', False):
                    analysis['bypass_working'] += 1
                    category_stats['bypass_works'] += 1
                
                effectiveness_scores.append(result.get('effectiveness', 0.0))
            
            # Средняя эффективность по категории
            if effectiveness_scores:
                category_stats['effectiveness'] = sum(effectiveness_scores) / len(effectiveness_scores)
            
            analysis['categories'][category] = category_stats
            analysis['effectiveness_by_category'][category] = category_stats['effectiveness']
        
        # Общая эффективность
        if analysis['blocked_domains'] > 0:
            analysis['overall_bypass_rate'] = analysis['bypass_working'] / analysis['blocked_domains']
        else:
            analysis['overall_bypass_rate'] = 1.0  # Если нет заблокированных доменов
        
        return analysis
    
    def identify_working_strategies(self):
        """Определяет работающие стратегии на основе логов"""
        print("🔍 Поиск работающих стратегий...")
        
        # Анализируем последние логи service
        log_files = list(Path("logs").glob("*service*.log"))
        if not log_files:
            return {"error": "Нет логов service для анализа"}
        
        latest_log = max(log_files, key=lambda x: x.stat().st_mtime)
        
        try:
            # Try different encodings
            encodings = ['utf-8', 'cp1251', 'latin-1']
            content = None
            
            for encoding in encodings:
                try:
                    with open(latest_log, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                return {"error": "Не удалось прочитать лог файл"}
            
            # Ищем успешные стратегии
            successful_strategies = []
            failed_strategies = []
            
            lines = content.split('\n')
            for line in lines:
                line_lower = line.lower()
                
                # Ищем индикаторы успеха/неудачи
                if any(word in line_lower for word in ['success', 'working', 'bypass']):
                    if any(attack in line_lower for attack in ['split', 'disorder', 'fake', 'multisplit']):
                        successful_strategies.append(line.strip())
                
                if any(word in line_lower for word in ['failed', 'error', 'timeout']):
                    if any(attack in line_lower for attack in ['split', 'disorder', 'fake', 'multisplit']):
                        failed_strategies.append(line.strip())
            
            return {
                'log_file': str(latest_log),
                'successful_strategies': successful_strategies[:10],  # Первые 10
                'failed_strategies': failed_strategies[:10],
                'total_success': len(successful_strategies),
                'total_failed': len(failed_strategies)
            }
            
        except Exception as e:
            return {"error": f"Ошибка анализа логов: {e}"}
    
    def generate_comprehensive_report(self, domain_results, pattern_analysis, strategy_analysis):
        """Генерирует комплексный отчет"""
        print("📋 Генерация комплексного отчета...")
        
        report = {
            'test_timestamp': datetime.now().isoformat(),
            'test_type': 'multi_domain_bypass_analysis',
            'domain_results': domain_results,
            'pattern_analysis': pattern_analysis,
            'strategy_analysis': strategy_analysis,
            'summary': {
                'total_domains_tested': pattern_analysis['total_domains'],
                'blocked_domains': pattern_analysis['blocked_domains'],
                'bypass_success_rate': pattern_analysis['overall_bypass_rate'],
                'most_effective_category': max(pattern_analysis['effectiveness_by_category'].items(), 
                                             key=lambda x: x[1])[0] if pattern_analysis['effectiveness_by_category'] else 'none',
                'least_effective_category': min(pattern_analysis['effectiveness_by_category'].items(), 
                                              key=lambda x: x[1])[0] if pattern_analysis['effectiveness_by_category'] else 'none'
            },
            'recommendations': self._generate_final_recommendations(pattern_analysis, strategy_analysis)
        }
        
        # Сохраняем отчет
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/multi_domain_bypass_analysis_{timestamp}.json"
        Path("reports").mkdir(exist_ok=True)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"   💾 Отчет сохранен: {report_file}")
        return report_file, report
    
    def _generate_final_recommendations(self, pattern_analysis, strategy_analysis):
        """Генерирует финальные рекомендации"""
        recommendations = []
        
        # Анализ общей эффективности
        bypass_rate = pattern_analysis['overall_bypass_rate']
        if bypass_rate < 0.3:
            recommendations.append("🔴 КРИТИЧНО: Очень низкая эффективность bypass (<30%)")
            recommendations.append("   → Требуется полный пересмотр стратегий и параметров")
        elif bypass_rate < 0.7:
            recommendations.append("🟡 ВНИМАНИЕ: Средняя эффективность bypass (<70%)")
            recommendations.append("   → Необходима оптимизация существующих стратегий")
        else:
            recommendations.append("🟢 ХОРОШО: Высокая эффективность bypass (>70%)")
        
        # Анализ по категориям
        for category, effectiveness in pattern_analysis['effectiveness_by_category'].items():
            if effectiveness < 0.5:
                recommendations.append(f"❌ Категория '{category}': низкая эффективность ({effectiveness:.1%})")
            else:
                recommendations.append(f"✅ Категория '{category}': хорошая эффективность ({effectiveness:.1%})")
        
        # Анализ стратегий
        if strategy_analysis.get('total_success', 0) == 0:
            recommendations.append("❌ Не найдено успешных стратегий в логах")
            recommendations.append("   → Проверить логирование и применение стратегий")
        
        return recommendations

def main():
    """Основная функция"""
    print("🎯 МНОГОДОМЕННОЕ ТЕСТИРОВАНИЕ BYPASS СИСТЕМЫ")
    print("=" * 60)
    
    tester = MultiDomainBypassTester()
    
    # 1. Тестирование всех доменов
    print("\n1️⃣ ТЕСТИРОВАНИЕ ДОМЕНОВ")
    domain_results = tester.test_all_domains()
    
    # 2. Анализ паттернов
    print("\n2️⃣ АНАЛИЗ ПАТТЕРНОВ")
    pattern_analysis = tester.analyze_bypass_patterns(domain_results)
    
    # 3. Поиск работающих стратегий
    print("\n3️⃣ АНАЛИЗ СТРАТЕГИЙ")
    strategy_analysis = tester.identify_working_strategies()
    
    # 4. Генерация отчета
    print("\n4️⃣ ГЕНЕРАЦИЯ ОТЧЕТА")
    report_file, report = tester.generate_comprehensive_report(
        domain_results, pattern_analysis, strategy_analysis
    )
    
    # Выводим итоги
    print(f"\n📊 ИТОГОВЫЕ РЕЗУЛЬТАТЫ:")
    print(f"Протестировано доменов: {pattern_analysis['total_domains']}")
    print(f"Заблокированных доменов: {pattern_analysis['blocked_domains']}")
    print(f"Bypass работает: {pattern_analysis['bypass_working']}")
    print(f"Общая эффективность: {pattern_analysis['overall_bypass_rate']:.1%}")
    
    print(f"\n📋 РЕКОМЕНДАЦИИ:")
    for rec in report['recommendations']:
        print(f"   {rec}")
    
    print(f"\n💾 Полный отчет: {report_file}")

if __name__ == "__main__":
    main()