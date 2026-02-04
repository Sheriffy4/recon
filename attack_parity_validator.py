#!/usr/bin/env python3
"""
Валидатор паритета атак между discovery и service режимами
Использует полную систему анализа логов и PCAP
"""

import os
import json
import sys
from pathlib import Path
from datetime import datetime
from core.attack_parity.analyzer import AttackParityAnalyzer
from core.attack_parity.report_generator import AttackParityReportGenerator

class AttackParityValidator:
    """Валидатор паритета атак"""
    
    def __init__(self):
        self.analyzer = AttackParityAnalyzer(timing_tolerance=0.1)
        self.report_generator = AttackParityReportGenerator()
        Path("reports").mkdir(exist_ok=True)
    
    def validate_parity_with_pcap(self, domain, discovery_log, service_log, discovery_pcap, service_pcap):
        """Полная валидация паритета с PCAP файлами"""
        
        print(f"\n🔍 ВАЛИДАЦИЯ ПАРИТЕТА: {domain}")
        print("=" * 50)
        
        # Проверяем наличие файлов
        files_to_check = {
            'Discovery Log': discovery_log,
            'Service Log': service_log,
            'Discovery PCAP': discovery_pcap,
            'Service PCAP': service_pcap
        }
        
        missing_files = []
        for name, file_path in files_to_check.items():
            if not os.path.exists(file_path):
                missing_files.append(f"{name}: {file_path}")
            else:
                size = os.path.getsize(file_path)
                print(f"✅ {name}: {size} байт")
        
        if missing_files:
            print(f"\n❌ Отсутствующие файлы:")
            for missing in missing_files:
                print(f"   {missing}")
            return None
        
        try:
            print(f"\n📊 Запуск анализа паритета...")
            
            # Выполняем полный анализ паритета
            result = self.analyzer.analyze_parity(
                discovery_log_path=discovery_log,
                service_log_path=service_log,
                discovery_pcap_path=discovery_pcap,
                service_pcap_path=service_pcap
            )
            
            # Генерируем отчет
            report = self.report_generator.generate_comprehensive_report(result)
            
            # Анализируем результаты
            analysis = self.analyze_parity_results(result)
            
            print(f"\n📈 РЕЗУЛЬТАТЫ АНАЛИЗА:")
            print(f"Semantic Accuracy: {result.semantic_accuracy:.2%}")
            print(f"Truth Consistency: {result.truth_consistency_score:.2%}")
            print(f"Parity Score: {result.parity_score:.2%}")
            print(f"Timing Alignment: {analysis['timing_quality']}")
            
            # Детальный анализ
            if hasattr(result, 'discrepancies') and result.discrepancies:
                print(f"\n⚠️  ОБНАРУЖЕННЫЕ РАСХОЖДЕНИЯ ({len(result.discrepancies)}):")
                for i, discrepancy in enumerate(result.discrepancies[:5], 1):
                    print(f"  {i}. {discrepancy.description}")
                if len(result.discrepancies) > 5:
                    print(f"  ... и еще {len(result.discrepancies) - 5}")
            
            # Сохраняем результаты
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = f"reports/parity_validation_{domain}_{timestamp}.json"
            
            result_data = {
                'domain': domain,
                'timestamp': timestamp,
                'files': files_to_check,
                'metrics': {
                    'semantic_accuracy': result.semantic_accuracy,
                    'truth_consistency': result.truth_consistency_score,
                    'parity_score': result.parity_score
                },
                'analysis': analysis,
                'report': report,
                'discrepancies': [
                    {
                        'description': d.description,
                        'severity': getattr(d, 'severity', 'unknown'),
                        'category': getattr(d, 'category', 'unknown')
                    } for d in (result.discrepancies if hasattr(result, 'discrepancies') else [])
                ]
            }
            
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n💾 Результаты сохранены: {result_file}")
            
            return result_data
            
        except Exception as e:
            print(f"❌ Ошибка анализа: {e}")
            return None
    
    def analyze_parity_results(self, result):
        """Анализирует результаты паритета"""
        analysis = {
            'overall_quality': 'unknown',
            'timing_quality': 'unknown',
            'semantic_quality': 'unknown',
            'recommendations': []
        }
        
        # Оценка семантического качества
        if result.semantic_accuracy >= 0.95:
            analysis['semantic_quality'] = 'excellent'
        elif result.semantic_accuracy >= 0.90:
            analysis['semantic_quality'] = 'good'
        elif result.semantic_accuracy >= 0.80:
            analysis['semantic_quality'] = 'acceptable'
        else:
            analysis['semantic_quality'] = 'poor'
            analysis['recommendations'].append("Проверьте корректность канонических определений атак")
        
        # Оценка временного качества
        if hasattr(result, 'timing_analysis'):
            avg_diff = getattr(result.timing_analysis, 'average_difference', 1000)
            if avg_diff < 0.1:
                analysis['timing_quality'] = 'excellent'
            elif avg_diff < 0.5:
                analysis['timing_quality'] = 'good'
            elif avg_diff < 1.0:
                analysis['timing_quality'] = 'acceptable'
            else:
                analysis['timing_quality'] = 'poor'
                analysis['recommendations'].append("Проверьте синхронизацию времени между режимами")
        
        # Общая оценка
        scores = [result.semantic_accuracy, result.truth_consistency_score, result.parity_score]
        avg_score = sum(scores) / len(scores)
        
        if avg_score >= 0.95:
            analysis['overall_quality'] = 'excellent'
        elif avg_score >= 0.85:
            analysis['overall_quality'] = 'good'
        elif avg_score >= 0.70:
            analysis['overall_quality'] = 'acceptable'
        else:
            analysis['overall_quality'] = 'poor'
        
        # Рекомендации
        if result.truth_consistency_score < 0.90:
            analysis['recommendations'].append("Проверьте соответствие логов и PCAP данных")
        
        if result.parity_score < 0.90:
            analysis['recommendations'].append("Исследуйте различия в поведении между режимами")
        
        return analysis
    
    def validate_domain_comprehensive(self, domain):
        """Комплексная валидация домена"""
        
        # Ищем файлы для анализа
        discovery_log = f"logs/{domain}_discovery.log"
        service_log = f"logs/{domain}_service.log"
        discovery_pcap = f"pcap/{domain}_discovery.pcap"
        service_pcap = f"pcap/{domain}_service.pcap"
        
        # Альтернативные имена файлов
        alt_discovery_log = f"logs/{domain}_quick_discovery.log"
        alt_service_log = f"logs/{domain}_quick_service.log"
        
        if not os.path.exists(discovery_log) and os.path.exists(alt_discovery_log):
            discovery_log = alt_discovery_log
        
        if not os.path.exists(service_log) and os.path.exists(alt_service_log):
            service_log = alt_service_log
        
        return self.validate_parity_with_pcap(
            domain, discovery_log, service_log, discovery_pcap, service_pcap
        )
    
    def batch_validate_domains(self, domains):
        """Пакетная валидация доменов"""
        
        print(f"\n🚀 ПАКЕТНАЯ ВАЛИДАЦИЯ {len(domains)} ДОМЕНОВ")
        print("=" * 60)
        
        results = {}
        
        for i, domain in enumerate(domains, 1):
            print(f"\n[{i}/{len(domains)}] Валидация {domain}")
            print("-" * 40)
            
            result = self.validate_domain_comprehensive(domain)
            results[domain] = result
        
        # Сводная статистика
        print(f"\n📊 СВОДНАЯ СТАТИСТИКА")
        print("=" * 40)
        
        quality_counts = {'excellent': 0, 'good': 0, 'acceptable': 0, 'poor': 0, 'failed': 0}
        
        for domain, result in results.items():
            if result is None:
                quality = 'failed'
                print(f"{domain:20} | FAILED")
            else:
                quality = result['analysis']['overall_quality']
                metrics = result['metrics']
                print(f"{domain:20} | {quality.upper():10} | "
                      f"S:{metrics['semantic_accuracy']:.2f} "
                      f"T:{metrics['truth_consistency']:.2f} "
                      f"P:{metrics['parity_score']:.2f}")
            
            quality_counts[quality] += 1
        
        print(f"\nРаспределение качества:")
        for quality, count in quality_counts.items():
            if count > 0:
                percentage = count / len(domains) * 100
                print(f"  {quality.capitalize():10}: {count:2} ({percentage:5.1f}%)")
        
        # Сохраняем сводный отчет
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = f"reports/batch_parity_validation_{timestamp}.json"
        
        summary_data = {
            'timestamp': timestamp,
            'domains': domains,
            'results': results,
            'statistics': quality_counts
        }
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Сводный отчет: {summary_file}")
        
        return results

def main():
    """Основная функция"""
    
    print("🔍 ВАЛИДАТОР ПАРИТЕТА АТАК")
    print("Версия: Полный анализ с PCAP")
    print("=" * 50)
    
    validator = AttackParityValidator()
    
    if len(sys.argv) > 1:
        # Валидация конкретного домена
        domain = sys.argv[1]
        result = validator.validate_domain_comprehensive(domain)
        
        if result:
            quality = result['analysis']['overall_quality']
            print(f"\n🎯 ИТОГОВАЯ ОЦЕНКА: {quality.upper()}")
            
            if result['analysis']['recommendations']:
                print(f"\n💡 РЕКОМЕНДАЦИИ:")
                for rec in result['analysis']['recommendations']:
                    print(f"  • {rec}")
        else:
            print(f"\n❌ Валидация {domain} не удалась")
    
    else:
        # Пакетная валидация
        domains = ["youtube.com", "nnmclub.to", "googlevideo.com"]
        
        print(f"Будут проанализированы домены: {', '.join(domains)}")
        print(f"Для анализа конкретного домена: python {sys.argv[0]} <domain>")
        
        input("\nНажмите Enter для продолжения или Ctrl+C для отмены...")
        
        results = validator.batch_validate_domains(domains)
        
        # Итоговая оценка
        successful = sum(1 for r in results.values() if r is not None)
        print(f"\n🎉 Успешно проанализировано: {successful}/{len(domains)} доменов")

if __name__ == "__main__":
    main()