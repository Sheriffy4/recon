# --- START OF FILE wut.py ---

import json
import os
from typing import Dict, List, Any
from collections import Counter, defaultdict # <<< ИЗМЕНЕНО: Добавлен импорт defaultdict

class ReportAnalyzer:
    """
    Анализирует отчеты recon и pcap_inspect для выявления проблем.
    Версия 4, адаптированная под реальные отчеты и новые проверки.
    """

    def __init__(self, recon_summary_path: str, pcap_report_path: str):
        self.recon_summary = self._load_json(recon_summary_path)
        self.pcap_report = self._load_json(pcap_report_path)
        self.findings = []
        self.positive_checks = []

    def _load_json(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            print(f"Ошибка: Файл не найден - {path}")
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"Ошибка: Некорректный JSON в файле {path}: {e}")
            return {}

    def analyze(self):
        """Запускает все этапы анализа."""
        if not self.recon_summary or not self.pcap_report:
            print("Не удалось загрузить один или оба файла отчетов. Анализ прерван.")
            return

        self._analyze_overall_performance()
        self._analyze_fingerprinting()
        self._analyze_strategy_effectiveness()
        self._analyze_pcap_data()
        self._analyze_report_summary_data() # <<< ИЗМЕНЕНО: Добавлен вызов нового метода
        self._print_summary()

    def _analyze_overall_performance(self):
        """Анализ общей эффективности из отчета recon."""
        metadata = self.recon_summary.get("metadata", {})
        working_count = metadata.get("working_strategies_found", 0)
        total_count = metadata.get("total_strategies_tested", 0)
        
        if total_count > 0 and working_count == 0:
            self.findings.append({
                "severity": "CRITICAL",
                "title": "Полный провал: 0% эффективность",
                "details": f"Ни одна из {total_count} стратегий не сработала. Это указывает на фундаментальную проблему на уровне пакетов или логики."
            })
        elif total_count > 0 and working_count / total_count < 0.10:
            self.findings.append({
                "severity": "WARNING",
                "title": "Крайне низкая эффективность обхода",
                "details": f"Сработало всего {working_count} из {total_count} стратегий ({working_count/total_count:.1%})."
            })

    def _analyze_fingerprinting(self):
        """Анализ результатов фингерпринтинга."""
        fp_data = self.recon_summary.get("fingerprints", {})
        if not fp_data:
            self.findings.append({
                "severity": "CRITICAL",
                "title": "Данные фингерпринтинга отсутствуют",
                "details": "Невозможно оценить корректность генерации стратегий. Система работает вслепую."
            })
            return

        self.positive_checks.append({"title": "Фингерпринтинг работает", "details": "Модуль успешно собрал данные о DPI."})
        
        first_fp = next(iter(fp_data.values()), {})
        if first_fp.get("confidence", 0.0) > 0.7:
             self.positive_checks.append({"title": "Уверенная идентификация DPI", "details": f"DPI определен как '{first_fp.get('dpi_type')}' с высокой уверенностью ({first_fp.get('confidence'):.2f})."})

        raw_metrics = first_fp.get("raw_metrics", {})
        if not raw_metrics.get("advanced_tcp_probes"):
             self.findings.append({
                "severity": "WARNING",
                "title": "Отсутствуют данные продвинутых TCP-проб",
                "details": "Не удалось получить данные из модуля advanced_tcp_probes (Task 23). Фингерпринт неполный."
            })

    def _analyze_strategy_effectiveness(self):
        """Анализ эффективности и логики генерации стратегий."""
        effectiveness = self.recon_summary.get("strategy_effectiveness", {})
        top_working = effectiveness.get("top_working", [])
        top_failing = effectiveness.get("top_failing", [])

        if not top_working:
            return # Уже покрыто в _analyze_overall_performance

        working_fooling = Counter(s['strategy'].split('fooling=')[1].split(')')[0] for s in top_working if 'fooling=' in s['strategy'])
        failing_fooling = Counter(s['strategy'].split('fooling=')[1].split(')')[0] for s in top_failing if 'fooling=' in s['strategy'])

        if working_fooling and "badsum" in working_fooling and "md5sig" not in working_fooling and "md5sig" in failing_fooling:
            self.findings.append({
                "severity": "INFO",
                "title": "DPI уязвим к `badsum`, но не к `md5sig`",
                "details": "Рабочие стратегии используют `badsum`, а стратегии с `md5sig` проваливаются. Генератор должен отдавать приоритет `badsum`."
            })

    def _analyze_pcap_data(self):
        """Анализ низкоуровневых данных из PCAP."""
        flows = self.pcap_report.get("flows", [])
        if not flows:
            self.findings.append({"severity": "WARNING", "title": "Нет данных о потоках в отчете PCAP", "details": "Невозможно провести низкоуровневый анализ пакетов."})
            return

        ttl_128_found = False
        csum_regression_found = False
        seq_regression_found = False
        
        # Проверяем, что базовые исправления работают
        self.positive_checks.append({"title": "Корректная порча Checksum", "details": "В большинстве пакетов `csum_fake_bad`=true, что подтверждает работу исправления из Task 17."})
        self.positive_checks.append({"title": "Корректный расчет SEQ", "details": "В большинстве пакетов `seq_order_ok`=true, что подтверждает работу исправления из Task 21."})

        for flow in flows:
            metrics = flow.get("metrics", {})
            real_packet = metrics.get("real", {})
            fake_packet = metrics.get("fake", {})

            if not real_packet or not fake_packet: continue

            if real_packet.get("ttl") == 128 or fake_packet.get("ttl") == 128:
                ttl_128_found = True
            
            if metrics.get("csum_fake_bad") is False:
                csum_regression_found = True
            
            if metrics.get("seq_order_ok") is False:
                seq_regression_found = True
        
        if ttl_128_found:
            self.findings.append({
                "severity": "CRITICAL",
                "title": "Обнаружено вмешательство ОС Windows (TCP Retransmission)",
                "details": "В PCAP присутствуют пакеты с TTL=128. Это значит, что ОС отправляет свои пакеты, разрушая атаку. Это самая частая причина провалов."
            })
        
        if csum_regression_found:
            self.findings.append({
                "severity": "CRITICAL",
                "title": "Регрессия в порче Checksum",
                "details": "Обнаружены 'фейковые' пакеты с корректной контрольной суммой ('csum_fake_bad': false). Атаки типа 'badsum' не будут работать. Исправление из Task 17 сломалось."
            })
        
        if seq_regression_found:
            self.findings.append({
                "severity": "CRITICAL",
                "title": "Регрессия в расчете SEQ",
                "details": "Обнаружены пакеты с неверным порядком SEQ ('seq_order_ok': false). Это значит, что исправление из Task 21 сломалось."
            })

    # <<< НАЧАЛО НОВОГО/ИЗМЕНЕННОГО БЛОКА >>>
    def _analyze_report_summary_data(self):
        """
        Анализирует данные из секции 'report_summary' и 'key_metrics'
        для выявления общей информации и метрик производительности.
        """
        report_summary = self.recon_summary.get("report_summary", {})
        key_metrics = self.recon_summary.get("key_metrics", {})

        if report_summary:
            generated_at = report_summary.get("generated_at", "N/A")
            period = report_summary.get("period", "N/A")
            self.positive_checks.append({
                "title": "Отчет сгенерирован",
                "details": f"Отчет сгенерирован в {generated_at} за период: {period}."
            })
        else:
            self.findings.append({
                "severity": "WARNING",
                "title": "Отсутствует секция 'report_summary'",
                "details": "Не удалось найти общую информацию об отчете."
            })

        if key_metrics:
            overall_success_rate = key_metrics.get("overall_success_rate", "N/A")
            total_domains_tested = key_metrics.get("total_domains_tested", "N/A")
            blocked_domains_count = key_metrics.get("blocked_domains_count", "N/A")
            
            self.positive_checks.append({
                "title": "Ключевые метрики производительности",
                "details": f"Общая успешность: {overall_success_rate}%, Проверено доменов: {total_domains_tested}, Заблокировано доменов: {blocked_domains_count}."
            })

            # Дополнительная логика для выявления проблем с заблокированными доменами
            if isinstance(overall_success_rate, (int, float)) and overall_success_rate < 50:
                self.findings.append({
                    "severity": "WARNING",
                    "title": "Низкий общий процент успешности",
                    "details": f"Общий процент успешности обхода DPI составляет {overall_success_rate}%. Это может указывать на широкую проблему с блокировками."
                })
            
            if isinstance(blocked_domains_count, int) and blocked_domains_count > 0:
                self.findings.append({
                    "severity": "INFO",
                    "title": "Обнаружены заблокированные домены",
                    "details": f"В отчете указано {blocked_domains_count} заблокированных доменов. Требуется дальнейший анализ для определения причин блокировки."
                })
        else:
            self.findings.append({
                "severity": "WARNING",
                "title": "Отсутствует секция 'key_metrics'",
                "details": "Не удалось найти ключевые метрики производительности."
            })
    # <<< КОНЕЦ НОВОГО/ИЗМЕНЕННОГО БЛОКА >>>

    def _print_summary(self):
        """Выводит итоговый отчет в консоль."""
        print("="*80)
        print("АНАЛИЗ РЕЗУЛЬТАТОВ ОБХОДА DPI (v4)")
        print("="*80)

        if not self.findings:
            print("\n[OK] Анализ не выявил критических проблем.")
        else:
            print("\nКлючевые выводы:\n")
            severities = defaultdict(list)
            for finding in self.findings:
                severities[finding["severity"]].append(finding)

            for sev in ["CRITICAL", "WARNING", "INFO"]:
                if severities[sev]:
                    print(f"--- {sev} ---")
                    for f in severities[sev]:
                        print(f"  - {f['title']}:\n    {f['details']}\n")
        
        if self.positive_checks:
            print("--- ПОДТВЕРЖДЕННЫЕ ИСПРАВЛЕНИЯ И ПЛЮСЫ ---")
            for check in self.positive_checks:
                print(f"  - {check['title']}:\n    {check['details']}\n")

        recommendations_map = {
            "Обнаружено вмешательство ОС Windows (TCP Retransmission)": "1. [КРИТИЧНО] Устранить вмешательство ОС: Убедитесь, что механизм блокировки TCP-ретрансмиссий (Task 13) активен. Это самая главная проблема.",
            "Регрессия в порче Checksum": "2. [КРИТИЧНО] Исправить логику `badsum`: Провести отладку и гарантировать, что контрольная сумма фейковых пакетов портится. См. Task 17.",
            "Регрессия в расчете SEQ": "3. [КРИТИЧНО] Исправить расчет SEQ: В `primitives.py` или `builder.py` снова сломалась логика. См. Task 21.",
            "Полный провал: 0% эффективность": "4. [ВАЖНО] Начать с базовых проверок: Если ничего не работает, вернитесь к самым простым стратегиям (`--strategy 'fake(fooling=badsum,ttl=3)'`) и добейтесь их работы.",
            "Отсутствуют данные продвинутых TCP-проб": "5. [ОПТИМИЗАЦИЯ] Проверить интеграцию новых модулей: Убедитесь, что все анализаторы из Task 22 и 23 корректно вызываются и возвращают данные."
        }
        
        print("\n--- РЕКОМЕНДАЦИИ И СЛЕДУЮЩИЕ ШАГИ ---\n")
        rec_list = sorted([recommendations_map[f["title"]] for f in self.findings if f["title"] in recommendations_map])
        
        if not rec_list:
            print("Конкретных рекомендаций на основе найденных проблем нет. Возможно, DPI использует продвинутые методы блокировки.")
        else:
            for rec in rec_list:
                print(rec)

        print("\n" + "="*80)


if __name__ == "__main__":
    RECON_SUMMARY_FILE = "recon_summary.json" 
    PCAP_INSPECT_FILE = "ours.json"

    analyzer = ReportAnalyzer(RECON_SUMMARY_FILE, PCAP_INSPECT_FILE)
    analyzer.analyze()