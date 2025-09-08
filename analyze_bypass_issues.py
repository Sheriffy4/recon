#!/usr/bin/env python3
"""
Анализатор проблем с обходом блокировок

Этот скрипт анализирует результаты тестирования и PCAP файлы для выявления
причин низкой эффективности обхода блокировок.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    class Console:
        def print(self, *args, **kwargs):
            print(*args)

console = Console()


@dataclass
class BypassIssue:
    """Представляет проблему с обходом блокировки."""
    domain: str
    issue_type: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    recommendation: str
    technical_details: Optional[str] = None


class BypassIssueAnalyzer:
    """Анализатор проблем с обходом блокировок."""
    
    def __init__(self):
        """Инициализация анализатора."""
        self.issues: List[BypassIssue] = []
        self.report_data: Optional[Dict] = None
        self.pcap_data: Optional[Dict] = None
    
    def analyze_report(self, report_file: str) -> List[BypassIssue]:
        """Анализ JSON отчета для выявления проблем."""
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                self.report_data = json.load(f)
            
            console.print(f"[cyan]Анализ отчета: {report_file}[/cyan]")
            
            # Общая статистика
            total_sites = len(self.report_data.get('domains', {}))
            working_sites = sum(1 for domain_data in self.report_data.get('domains', {}).values() 
                              if domain_data.get('success_rate', 0) > 0)
            
            console.print(f"Общая статистика:")
            console.print(f"  Всего доменов: {total_sites}")
            console.print(f"  Работающих доменов: {working_sites}")
            console.print(f"  Процент успеха: {working_sites/total_sites*100:.1f}%")
            
            # Анализ проблемных доменов
            self._analyze_failed_domains()
            self._analyze_strategy_effectiveness()
            self._analyze_network_issues()
            self._analyze_dpi_detection()
            
            return self.issues
            
        except Exception as e:
            console.print(f"[red]Ошибка анализа отчета: {e}[/red]")
            return []
    
    def _analyze_failed_domains(self):
        """Анализ доменов, которые не работают."""
        domains = self.report_data.get('domains', {})
        
        failed_domains = []
        for domain, data in domains.items():
            if data.get('success_rate', 0) == 0:
                failed_domains.append(domain)
        
        if failed_domains:
            # Группировка по типам доменов
            twitter_domains = [d for d in failed_domains if 'x.com' in d or 'twimg.com' in d]
            facebook_domains = [d for d in failed_domains if 'facebook.com' in d or 'fbcdn.net' in d]
            instagram_domains = [d for d in failed_domains if 'instagram.com' in d or 'cdninstagram.com' in d]
            
            if twitter_domains:
                self.issues.append(BypassIssue(
                    domain=', '.join(twitter_domains),
                    issue_type='twitter_blocking',
                    severity='critical',
                    description=f'Все Twitter/X.com домены заблокированы ({len(twitter_domains)} доменов)',
                    recommendation='Использовать специализированные стратегии для Twitter: multisplit с высокими параметрами',
                    technical_details='Twitter использует продвинутую DPI систему, требующую multisplit стратегии'
                ))
            
            if facebook_domains:
                self.issues.append(BypassIssue(
                    domain=', '.join(facebook_domains),
                    issue_type='facebook_blocking',
                    severity='high',
                    description=f'Facebook домены заблокированы ({len(facebook_domains)} доменов)',
                    recommendation='Попробовать md5sig или badseq fooling методы',
                    technical_details='Facebook может использовать другие методы DPI анализа'
                ))
            
            if instagram_domains:
                self.issues.append(BypassIssue(
                    domain=', '.join(instagram_domains),
                    issue_type='instagram_blocking',
                    severity='high',
                    description=f'Instagram домены частично заблокированы',
                    recommendation='Использовать разные стратегии для основного домена и CDN',
                    technical_details='CDN домены могут требовать других параметров'
                ))
    
    def _analyze_strategy_effectiveness(self):
        """Анализ эффективности используемой стратегии."""
        best_strategy = self.report_data.get('best_strategy', {})
        strategy_name = best_strategy.get('strategy_dict', {}).get('name', 'unknown')
        success_rate = best_strategy.get('success_rate', 0)
        
        if strategy_name == 'seqovl' and success_rate < 0.5:
            self.issues.append(BypassIssue(
                domain='all',
                issue_type='outdated_strategy',
                severity='high',
                description=f'Используется устаревшая стратегия seqovl с низкой эффективностью ({success_rate:.1%})',
                recommendation='Перейти на современные стратегии: multisplit, fake_disorder, tcp_multidisorder',
                technical_details='seqovl стратегия менее эффективна против современных DPI систем'
            ))
        
        # Анализ параметров стратегии
        params = best_strategy.get('strategy_dict', {}).get('params', {})
        overlap_size = params.get('overlap_size', 0)
        split_pos = params.get('split_pos', 0)
        ttl = params.get('ttl', 0)
        
        if overlap_size == 1:
            self.issues.append(BypassIssue(
                domain='all',
                issue_type='suboptimal_parameters',
                severity='medium',
                description='Очень маленький overlap_size=1 может быть неэффективным',
                recommendation='Увеличить overlap_size до 15-30 для лучшего обхода',
                technical_details='Маленькое перекрытие может не обмануть DPI анализ'
            ))
        
        if ttl == 64:
            self.issues.append(BypassIssue(
                domain='all',
                issue_type='high_ttl',
                severity='medium',
                description='Высокий TTL=64 может снижать эффективность',
                recommendation='Использовать низкий TTL (3-6) для лучшего обхода',
                technical_details='Низкий TTL помогает пакетам "умереть" до DPI анализа'
            ))
    
    def _analyze_network_issues(self):
        """Анализ сетевых проблем."""
        domains = self.report_data.get('domains', {})
        
        # Проверка таймаутов
        timeout_domains = []
        for domain, data in domains.items():
            if data.get('avg_latency_ms', 0) == 0 and data.get('success_rate', 0) == 0:
                timeout_domains.append(domain)
        
        if len(timeout_domains) > len(domains) * 0.5:  # Более 50% доменов с таймаутами
            self.issues.append(BypassIssue(
                domain='multiple',
                issue_type='network_timeouts',
                severity='critical',
                description=f'Массовые таймауты подключений ({len(timeout_domains)} из {len(domains)} доменов)',
                recommendation='Проверить сетевое подключение и настройки firewall',
                technical_details='Возможно блокировка на уровне сети или проблемы с DNS'
            ))
        
        # Анализ высокой задержки
        high_latency_domains = []
        for domain, data in domains.items():
            latency = data.get('avg_latency_ms', 0)
            if latency > 400:  # Более 400ms
                high_latency_domains.append((domain, latency))
        
        if high_latency_domains:
            self.issues.append(BypassIssue(
                domain=', '.join([d[0] for d in high_latency_domains]),
                issue_type='high_latency',
                severity='medium',
                description=f'Высокая задержка подключений (>{max(d[1] for d in high_latency_domains):.0f}ms)',
                recommendation='Оптимизировать параметры стратегии или попробовать другие методы',
                technical_details='Высокая задержка может указывать на проблемы с обходом'
            ))
    
    def _analyze_dpi_detection(self):
        """Анализ обнаружения DPI системой."""
        # Проверка использования фингерпринтинга
        fingerprint_used = self.report_data.get('best_strategy', {}).get('fingerprint_used', False)
        
        if not fingerprint_used:
            self.issues.append(BypassIssue(
                domain='all',
                issue_type='no_fingerprinting',
                severity='medium',
                description='Фингерпринтинг DPI не использовался',
                recommendation='Включить фингерпринтинг для адаптивного выбора стратегий',
                technical_details='Фингерпринтинг помогает выбрать оптимальную стратегию для конкретной DPI системы'
            ))
        
        # Анализ паттернов блокировки
        domains = self.report_data.get('domains', {})
        
        # Проверка селективной блокировки
        twitter_success = sum(1 for d, data in domains.items() 
                            if ('x.com' in d or 'twimg.com' in d) and data.get('success_rate', 0) > 0)
        twitter_total = sum(1 for d in domains.keys() if 'x.com' in d or 'twimg.com' in d)
        
        if twitter_total > 0 and twitter_success == 0:
            self.issues.append(BypassIssue(
                domain='twitter/x.com',
                issue_type='selective_blocking',
                severity='critical',
                description='Полная блокировка всех Twitter/X.com доменов',
                recommendation='Использовать специализированные anti-Twitter стратегии или комбинированные атаки',
                technical_details='Возможно использование специализированных правил DPI для Twitter'
            ))
    
    def generate_recommendations(self) -> List[str]:
        """Генерация рекомендаций по улучшению обхода."""
        recommendations = []
        
        # Анализ текущих проблем
        critical_issues = [i for i in self.issues if i.severity == 'critical']
        high_issues = [i for i in self.issues if i.severity == 'high']
        
        if critical_issues:
            recommendations.append("🚨 КРИТИЧЕСКИЕ ПРОБЛЕМЫ:")
            for issue in critical_issues:
                recommendations.append(f"   • {issue.description}")
                recommendations.append(f"     Решение: {issue.recommendation}")
        
        if high_issues:
            recommendations.append("\n⚠️  ВАЖНЫЕ ПРОБЛЕМЫ:")
            for issue in high_issues:
                recommendations.append(f"   • {issue.description}")
                recommendations.append(f"     Решение: {issue.recommendation}")
        
        # Специфические рекомендации для улучшения
        recommendations.extend([
            "\n🔧 РЕКОМЕНДУЕМЫЕ СТРАТЕГИИ:",
            "   1. Для Twitter/X.com:",
            "      --dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum",
            "   2. Для Facebook:",
            "      --dpi-desync=fake,disorder --dpi-desync-split-pos=4 --dpi-desync-fooling=md5sig --dpi-desync-ttl=3",
            "   3. Для Instagram:",
            "      --dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=badseq",
            "\n🧪 ЭКСПЕРИМЕНТАЛЬНЫЕ ПОДХОДЫ:",
            "   • Попробовать tcp_multidisorder стратегию",
            "   • Использовать комбинированные атаки",
            "   • Включить фингерпринтинг DPI",
            "   • Тестировать с разными fooling методами (badseq, md5sig)",
            "\n⚡ ОПТИМИЗАЦИЯ ПАРАМЕТРОВ:",
            "   • Уменьшить TTL до 3-6",
            "   • Увеличить split_seqovl до 20-30", 
            "   • Использовать split_count=5-7 для multisplit",
            "   • Добавить repeats=2-3 для устойчивости"
        ])
        
        return recommendations
    
    def display_analysis(self):
        """Отображение результатов анализа."""
        if not self.report_data:
            console.print("[red]Нет данных для анализа[/red]")
            return
        
        # Заголовок
        console.print(Panel(
            f"[bold cyan]Анализ проблем обхода блокировок[/bold cyan]\n"
            f"Отчет: {self.report_data.get('timestamp', 'unknown')}\n"
            f"Стратегия: {self.report_data.get('best_strategy', {}).get('strategy', 'unknown')}",
            title="Диагностика обхода"
        ))
        
        # Статистика успеха
        domains = self.report_data.get('domains', {})
        success_stats = self._calculate_success_stats(domains)
        
        stats_table = Table(title="Статистика успеха по категориям")
        stats_table.add_column("Категория", style="cyan")
        stats_table.add_column("Успешно", style="green")
        stats_table.add_column("Всего", style="yellow")
        stats_table.add_column("Процент", style="magenta")
        
        for category, stats in success_stats.items():
            success_rate = stats['success'] / stats['total'] * 100 if stats['total'] > 0 else 0
            stats_table.add_row(
                category,
                str(stats['success']),
                str(stats['total']),
                f"{success_rate:.1f}%"
            )
        
        console.print(stats_table)
        
        # Проблемные домены
        failed_domains = [d for d, data in domains.items() if data.get('success_rate', 0) == 0]
        if failed_domains:
            console.print(f"\n[red]❌ Заблокированные домены ({len(failed_domains)}):[/red]")
            for domain in failed_domains:
                console.print(f"   • {domain}")
        
        # Работающие домены
        working_domains = [d for d, data in domains.items() if data.get('success_rate', 0) > 0]
        if working_domains:
            console.print(f"\n[green]✅ Работающие домены ({len(working_domains)}):[/green]")
            for domain in working_domains:
                latency = domains[domain].get('avg_latency_ms', 0)
                console.print(f"   • {domain} (задержка: {latency:.0f}ms)")
        
        # Отображение проблем
        if self.issues:
            console.print(f"\n[bold red]🔍 ВЫЯВЛЕННЫЕ ПРОБЛЕМЫ ({len(self.issues)}):[/bold red]")
            
            for issue in sorted(self.issues, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x.severity]):
                severity_colors = {
                    'critical': 'red',
                    'high': 'yellow', 
                    'medium': 'blue',
                    'low': 'white'
                }
                color = severity_colors.get(issue.severity, 'white')
                
                console.print(f"\n[{color}]🔸 {issue.issue_type.upper()} ({issue.severity})[/{color}]")
                console.print(f"   Домен(ы): {issue.domain}")
                console.print(f"   Проблема: {issue.description}")
                console.print(f"   Решение: {issue.recommendation}")
                if issue.technical_details:
                    console.print(f"   Детали: {issue.technical_details}")
        
        # Рекомендации
        recommendations = self.generate_recommendations()
        if recommendations:
            console.print(f"\n[bold green]💡 РЕКОМЕНДАЦИИ:[/bold green]")
            for rec in recommendations:
                console.print(rec)
    
    def _calculate_success_stats(self, domains: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
        """Подсчет статистики успеха по категориям доменов."""
        stats = {
            'Twitter/X.com': {'success': 0, 'total': 0},
            'Facebook': {'success': 0, 'total': 0},
            'Instagram': {'success': 0, 'total': 0},
            'YouTube': {'success': 0, 'total': 0},
            'Другие': {'success': 0, 'total': 0}
        }
        
        for domain, data in domains.items():
            success = 1 if data.get('success_rate', 0) > 0 else 0
            
            if 'x.com' in domain or 'twimg.com' in domain:
                stats['Twitter/X.com']['total'] += 1
                stats['Twitter/X.com']['success'] += success
            elif 'facebook.com' in domain or 'fbcdn.net' in domain:
                stats['Facebook']['total'] += 1
                stats['Facebook']['success'] += success
            elif 'instagram.com' in domain or 'cdninstagram.com' in domain:
                stats['Instagram']['total'] += 1
                stats['Instagram']['success'] += success
            elif 'youtube.com' in domain or 'ytimg.com' in domain or 'ggpht.com' in domain:
                stats['YouTube']['total'] += 1
                stats['YouTube']['success'] += success
            else:
                stats['Другие']['total'] += 1
                stats['Другие']['success'] += success
        
        return stats
    
    def suggest_alternative_strategies(self) -> List[str]:
        """Предложение альтернативных стратегий."""
        strategies = []
        
        # Анализ проблемных доменов
        domains = self.report_data.get('domains', {}) if self.report_data else {}
        
        twitter_failed = any('x.com' in d or 'twimg.com' in d for d, data in domains.items() 
                           if data.get('success_rate', 0) == 0)
        facebook_failed = any('facebook.com' in d or 'fbcdn.net' in d for d, data in domains.items() 
                            if data.get('success_rate', 0) == 0)
        
        if twitter_failed:
            strategies.extend([
                "# Специализированные стратегии для Twitter/X.com:",
                "python cli.py -d sites.txt --strategy \"--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4\"",
                "python cli.py -d sites.txt --strategy \"--dpi-desync=multidisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3 --dpi-desync-fooling=badseq\"",
                "python cli.py -d sites.txt --strategy \"--dpi-desync=fake,disorder --dpi-desync-split-pos=2 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=md5sig --dpi-desync-ttl=3\"",
            ])
        
        if facebook_failed:
            strategies.extend([
                "\n# Стратегии для Facebook:",
                "python cli.py -d sites.txt --strategy \"--dpi-desync=fake,disorder --dpi-desync-split-pos=4 --dpi-desync-fooling=md5sig --dpi-desync-ttl=3\"",
                "python cli.py -d sites.txt --strategy \"--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-split-seqovl=15 --dpi-desync-fooling=badseq --dpi-desync-ttl=5\"",
            ])
        
        strategies.extend([
            "\n# Экспериментальные стратегии:",
            "python cli.py -d sites.txt --strategy \"--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=2 --dpi-desync-fooling=badseq --dpi-desync-ttl=3\"",
            "python cli.py -d sites.txt --strategy \"--dpi-desync=multisplit --dpi-desync-split-count=8 --dpi-desync-split-seqovl=35 --dpi-desync-fooling=badsum --dpi-desync-repeats=4 --dpi-desync-ttl=2\"",
            "\n# Комбинированные подходы:",
            "python cli.py -d sites.txt --evolutionary --generations 5 --population 15",
            "python cli.py -d sites.txt --fingerprint --adaptive"
        ])
        
        return strategies


def analyze_pcap_traffic(pcap_file: str) -> Dict[str, Any]:
    """Анализ PCAP файла для выявления проблем с трафиком."""
    try:
        from scapy.all import rdpcap, IP, TCP, Raw
        
        console.print(f"[cyan]Анализ PCAP файла: {pcap_file}[/cyan]")
        
        packets = rdpcap(pcap_file)
        
        analysis = {
            'total_packets': len(packets),
            'tcp_packets': 0,
            'rst_packets': 0,
            'syn_packets': 0,
            'syn_ack_packets': 0,
            'connections': {},
            'blocked_connections': [],
            'successful_connections': []
        }
        
        for packet in packets:
            if TCP in packet and IP in packet:
                analysis['tcp_packets'] += 1
                
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                conn_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                
                if conn_id not in analysis['connections']:
                    analysis['connections'][conn_id] = {
                        'syn_sent': False,
                        'syn_ack_received': False,
                        'rst_received': False,
                        'data_sent': False
                    }
                
                conn = analysis['connections'][conn_id]
                
                # Анализ TCP флагов
                if packet[TCP].flags & 0x02:  # SYN
                    analysis['syn_packets'] += 1
                    conn['syn_sent'] = True
                
                if packet[TCP].flags & 0x12:  # SYN-ACK
                    analysis['syn_ack_packets'] += 1
                    conn['syn_ack_received'] = True
                
                if packet[TCP].flags & 0x04:  # RST
                    analysis['rst_packets'] += 1
                    conn['rst_received'] = True
                
                if Raw in packet:
                    conn['data_sent'] = True
        
        # Классификация соединений
        for conn_id, conn_data in analysis['connections'].items():
            if conn_data['rst_received']:
                analysis['blocked_connections'].append(conn_id)
            elif conn_data['syn_ack_received'] and conn_data['data_sent']:
                analysis['successful_connections'].append(conn_id)
        
        return analysis
        
    except ImportError:
        console.print("[yellow]Scapy не доступен для анализа PCAP[/yellow]")
        return {}
    except Exception as e:
        console.print(f"[red]Ошибка анализа PCAP: {e}[/red]")
        return {}


def main():
    """Главная функция анализатора."""
    if len(sys.argv) < 2:
        console.print("Использование: python analyze_bypass_issues.py <report.json> [pcap_file]")
        console.print("\nПример:")
        console.print("  python analyze_bypass_issues.py recon_report_20250901_170741.json out.pcap")
        sys.exit(1)
    
    report_file = sys.argv[1]
    pcap_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not Path(report_file).exists():
        console.print(f"[red]Файл отчета не найден: {report_file}[/red]")
        sys.exit(1)
    
    # Создание анализатора
    analyzer = BypassIssueAnalyzer()
    
    # Анализ отчета
    issues = analyzer.analyze_report(report_file)
    
    # Анализ PCAP если доступен
    if pcap_file and Path(pcap_file).exists():
        console.print(f"\n[cyan]Анализ сетевого трафика...[/cyan]")
        pcap_analysis = analyze_pcap_traffic(pcap_file)
        
        if pcap_analysis:
            console.print(f"\n[bold]Анализ трафика:[/bold]")
            console.print(f"  Всего пакетов: {pcap_analysis['total_packets']:,}")
            console.print(f"  TCP пакетов: {pcap_analysis['tcp_packets']:,}")
            console.print(f"  RST пакетов: {pcap_analysis['rst_packets']:,}")
            console.print(f"  Соединений: {len(pcap_analysis['connections']):,}")
            console.print(f"  Заблокированных: {len(pcap_analysis['blocked_connections']):,}")
            console.print(f"  Успешных: {len(pcap_analysis['successful_connections']):,}")
            
            # Анализ RST пакетов
            rst_rate = pcap_analysis['rst_packets'] / pcap_analysis['tcp_packets'] * 100 if pcap_analysis['tcp_packets'] > 0 else 0
            if rst_rate > 20:  # Более 20% RST пакетов
                console.print(f"\n[red]⚠️  Высокий процент RST пакетов ({rst_rate:.1f}%) - DPI активно блокирует соединения[/red]")
    
    # Отображение анализа
    analyzer.display_analysis()
    
    # Предложение альтернативных стратегий
    alternative_strategies = analyzer.suggest_alternative_strategies()
    if alternative_strategies:
        console.print(f"\n[bold yellow]🚀 АЛЬТЕРНАТИВНЫЕ СТРАТЕГИИ ДЛЯ ТЕСТИРОВАНИЯ:[/bold yellow]")
        for strategy in alternative_strategies:
            console.print(strategy)


if __name__ == '__main__':
    main()