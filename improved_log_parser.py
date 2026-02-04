#!/usr/bin/env python3
"""
Улучшенный парсер логов для реальных форматов CLI и Service режимов
"""

import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ParsedAttack:
    """Распарсенная атака из лога"""
    timestamp: datetime
    attack_type: str
    domain: Optional[str]
    ip: Optional[str]
    parameters: Dict[str, Any]
    segment_count: int
    raw_line: str
    line_number: int


class ImprovedLogParser:
    """Улучшенный парсер для реальных логов"""
    
    # Формат Service mode: "11:53:48 [INFO   ] BypassEngine: 🔦 Sending 3 bypass segments for fakeddisorder"
    SERVICE_ATTACK_PATTERN = re.compile(
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\s*\]\s+(?P<component>\w+):\s+'
        r'.*?Sending\s+(?P<segments>\d+)\s+bypass\s+segments\s+for\s+(?P<attack>[\w,]+)'
    )
    
    # Формат параметров: "split_pos': 3, 'fake_ttl': 3"
    PARAMETER_PATTERN = re.compile(
        r"'(?P<param_name>[\w_]+)':\s*(?P<param_value>\d+|true|false|'[^']*'|\[[^\]]*\])"
    )
    
    # Формат domain/IP: "domain=nnmclub.to" или "192.168.18.188:63536 -> 3.221.164.243:443"
    DOMAIN_PATTERN = re.compile(r'domain=(?P<domain>[\w\.-]+)')
    IP_PATTERN = re.compile(r'(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<src_port>\d+)\s*->\s*(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dst_port>\d+)')
    
    # Формат CLI mode может быть другим
    CLI_ATTACK_PATTERN = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3})'
        r'.*?'
        r'(?P<attack>split|multisplit|disorder|fake|smart_combo_\w+|fakeddisorder)'
    )
    
    def parse_service_log(self, log_path: str, date_str: str = None) -> List[ParsedAttack]:
        """
        Парсит Service mode лог
        
        Args:
            log_path: путь к файлу лога
            date_str: дата в формате "2025-12-17" (если не указана, используется сегодня)
        """
        if date_str is None:
            date_str = datetime.now().strftime("%Y-%m-%d")
        
        attacks = []
        
        # Читаем файл
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Ошибка чтения файла {log_path}: {e}")
            return attacks
        
        # Контекст для сбора информации
        current_domain = None
        current_ip = None
        current_params = {}
        
        for line_num, line in enumerate(lines, 1):
            # Ищем domain
            domain_match = self.DOMAIN_PATTERN.search(line)
            if domain_match:
                current_domain = domain_match.group('domain')
            
            # Ищем IP
            ip_match = self.IP_PATTERN.search(line)
            if ip_match:
                current_ip = ip_match.group('dst_ip')
            
            # Ищем параметры
            for param_match in self.PARAMETER_PATTERN.finditer(line):
                param_name = param_match.group('param_name')
                param_value = param_match.group('param_value')
                
                # Конвертируем значение
                if param_value.isdigit():
                    current_params[param_name] = int(param_value)
                elif param_value.lower() in ('true', 'false'):
                    current_params[param_name] = param_value.lower() == 'true'
                elif param_value.startswith("'") and param_value.endswith("'"):
                    current_params[param_name] = param_value[1:-1]
                elif param_value.startswith("[") and param_value.endswith("]"):
                    current_params[param_name] = param_value
                else:
                    current_params[param_name] = param_value
            
            # Ищем применение атаки
            attack_match = self.SERVICE_ATTACK_PATTERN.search(line)
            if attack_match:
                time_str = attack_match.group('time')
                segments = int(attack_match.group('segments'))
                attack_type = attack_match.group('attack')
                
                # Создаем timestamp
                try:
                    timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    timestamp = datetime.now()
                
                # Создаем запись об атаке
                attack = ParsedAttack(
                    timestamp=timestamp,
                    attack_type=attack_type,
                    domain=current_domain,
                    ip=current_ip,
                    parameters=current_params.copy(),
                    segment_count=segments,
                    raw_line=line.strip(),
                    line_number=line_num
                )
                
                attacks.append(attack)
                
                # Сбрасываем параметры после использования
                current_params = {}
        
        return attacks
    
    def parse_cli_log(self, log_path: str) -> List[ParsedAttack]:
        """Парсит CLI mode лог"""
        attacks = []
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Ошибка чтения файла {log_path}: {e}")
            return attacks
        
        current_domain = None
        current_ip = None
        current_params = {}
        
        for line_num, line in enumerate(lines, 1):
            # Ищем domain
            domain_match = self.DOMAIN_PATTERN.search(line)
            if domain_match:
                current_domain = domain_match.group('domain')
            
            # Ищем IP
            ip_match = self.IP_PATTERN.search(line)
            if ip_match:
                current_ip = ip_match.group('dst_ip')
            
            # Ищем параметры
            for param_match in self.PARAMETER_PATTERN.finditer(line):
                param_name = param_match.group('param_name')
                param_value = param_match.group('param_value')
                
                if param_value.isdigit():
                    current_params[param_name] = int(param_value)
                elif param_value.lower() in ('true', 'false'):
                    current_params[param_name] = param_value.lower() == 'true'
                else:
                    current_params[param_name] = param_value
            
            # Ищем применение атаки (может быть в разных форматах)
            # Формат 1: "Sending X bypass segments for attack"
            service_match = self.SERVICE_ATTACK_PATTERN.search(line)
            if service_match:
                time_str = service_match.group('time')
                segments = int(service_match.group('segments'))
                attack_type = service_match.group('attack')
                
                try:
                    # Пытаемся найти дату в предыдущих строках
                    date_str = datetime.now().strftime("%Y-%m-%d")
                    timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    timestamp = datetime.now()
                
                attack = ParsedAttack(
                    timestamp=timestamp,
                    attack_type=attack_type,
                    domain=current_domain,
                    ip=current_ip,
                    parameters=current_params.copy(),
                    segment_count=segments,
                    raw_line=line.strip(),
                    line_number=line_num
                )
                
                attacks.append(attack)
                current_params = {}
            
            # Формат 2: CLI-специфичный формат с полным timestamp
            cli_match = self.CLI_ATTACK_PATTERN.search(line)
            if cli_match and not service_match:
                timestamp_str = cli_match.group('timestamp')
                attack_type = cli_match.group('attack')
                
                try:
                    timestamp_str = timestamp_str.replace(',', '.')
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    try:
                        timestamp = datetime.strptime(timestamp_str[:19], '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        timestamp = datetime.now()
                
                attack = ParsedAttack(
                    timestamp=timestamp,
                    attack_type=attack_type,
                    domain=current_domain,
                    ip=current_ip,
                    parameters=current_params.copy(),
                    segment_count=1,  # Неизвестно
                    raw_line=line.strip(),
                    line_number=line_num
                )
                
                attacks.append(attack)
                current_params = {}
        
        return attacks
    
    def print_summary(self, attacks: List[ParsedAttack], title: str = "Parsed Attacks"):
        """Выводит сводку по распарсенным атакам"""
        print(f"\n{'='*80}")
        print(f"{title}")
        print(f"{'='*80}")
        print(f"Всего атак: {len(attacks)}")
        
        if not attacks:
            print("Атаки не найдены")
            return
        
        # Группируем по типам атак
        by_type = {}
        for attack in attacks:
            if attack.attack_type not in by_type:
                by_type[attack.attack_type] = []
            by_type[attack.attack_type].append(attack)
        
        print(f"\nПо типам атак:")
        for attack_type, atk_list in sorted(by_type.items()):
            print(f"  {attack_type}: {len(atk_list)} раз")
        
        # Показываем первые несколько примеров
        print(f"\nПримеры (первые 5):")
        for i, attack in enumerate(attacks[:5], 1):
            print(f"\n  {i}. {attack.attack_type} @ {attack.timestamp}")
            print(f"     Domain: {attack.domain}, IP: {attack.ip}")
            print(f"     Segments: {attack.segment_count}, Params: {attack.parameters}")
            print(f"     Line {attack.line_number}: {attack.raw_line[:100]}...")


def main():
    """Тестируем парсер на реальных логах"""
    parser = ImprovedLogParser()
    
    # Парсим Service mode лог
    print("Парсинг Service mode лога (log.txt)...")
    service_attacks = parser.parse_service_log('log.txt', date_str='2025-12-17')
    parser.print_summary(service_attacks, "SERVICE MODE ATTACKS")
    
    # Парсим CLI mode лог
    print("\n\nПарсинг CLI mode лога (log2.txt)...")
    cli_attacks = parser.parse_cli_log('log2.txt')
    parser.print_summary(cli_attacks, "CLI MODE ATTACKS")
    
    # Сравнение
    print(f"\n\n{'='*80}")
    print("СРАВНЕНИЕ")
    print(f"{'='*80}")
    print(f"Service mode: {len(service_attacks)} атак")
    print(f"CLI mode: {len(cli_attacks)} атак")
    
    if service_attacks and cli_attacks:
        # Сравниваем типы атак
        service_types = set(a.attack_type for a in service_attacks)
        cli_types = set(a.attack_type for a in cli_attacks)
        
        print(f"\nТипы атак в Service mode: {service_types}")
        print(f"Типы атак в CLI mode: {cli_types}")
        
        common = service_types & cli_types
        only_service = service_types - cli_types
        only_cli = cli_types - service_types
        
        if common:
            print(f"\nОбщие типы атак: {common}")
        if only_service:
            print(f"Только в Service mode: {only_service}")
        if only_cli:
            print(f"Только в CLI mode: {only_cli}")


if __name__ == '__main__':
    main()
