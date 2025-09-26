# find_rst_triggers.py

import argparse
import sys
import os

# Добавляем корень проекта в путь, чтобы найти модуль анализатора
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from core.pcap.rst_analyzer import RSTTriggerAnalyzer

def main():
    parser = argparse.ArgumentParser(
        description="Анализирует PCAP-файл и находит пакеты, которые спровоцировали TCP RST."
    )
    parser.add_argument("pcap_file", help="Путь к PCAP-файлу для анализа.")
    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"[ERROR] Файл не найден: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Анализируем файл: {args.pcap_file}...")
    analyzer = RSTTriggerAnalyzer(args.pcap_file)
    triggers = analyzer.analyze()
    analyzer.print_report(triggers)

if __name__ == "__main__":
    main()