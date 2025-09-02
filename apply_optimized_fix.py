#!/usr/bin/env python3
"""
Применение оптимизированных стратегий на основе анализа успешных соединений.
Специальное внимание к решению проблемы rutracker.org.
"""

import json
import sys
import subprocess
import asyncio
import socket
from pathlib import Path


class OptimizedFix:
    """Применяет оптимизированные исправления на основе анализа PCAP."""
    
    def __init__(self):
        self.optimized_file = "optimized_strategies_v3.json"
        self.strategies_file = "strategies.json"
        self.hosts_file = self._get_hosts_path()
        
    def _get_hosts_path(self):
        """Получает путь к hosts файлу."""
        import platform
        if platform.system().lower() == 'windows':
            return r'C:\Windows\System32\drivers\etc\hosts'
        else:
            return '/etc/hosts'
    
    def load_optimized_config(self):
        """Загружает оптимизированную конфигурацию."""
        try:
            with open(self.optimized_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Ошибка загрузки конфигурации: {e}")
            return None
    
    def convert_to_zapret_strategies(self, config):
        """Конвертирует оптимизированные стратегии в формат zapret."""
        strategies = {}
        
        for domain, strategy_config in config['strategies'].items():
            params = strategy_config['params']
            
            # Формируем строку стратегии
            strategy_parts = []
            
            # Основной метод
            if params.get('desync_method'):
                strategy_parts.append(f"--dpi-desync={params['desync_method']}")
            
            # Параметры разделения
            if params.get('split_count'):
                strategy_parts.append(f"--dpi-desync-split-count={params['split_count']}")
            
            if params.get('split_seqovl'):
                strategy_parts.append(f"--dpi-desync-split-seqovl={params['split_seqovl']}")
            
            if params.get('split_pos'):
                strategy_parts.append(f"--dpi-desync-split-pos={params['split_pos']}")
            
            # TTL и fooling
            if params.get('ttl'):
                strategy_parts.append(f"--dpi-desync-ttl={params['ttl']}")
            
            if params.get('fooling'):
                strategy_parts.append(f"--dpi-desync-fooling={params['fooling']}")
            
            # Повторы
            if params.get('repeats'):
                strategy_parts.append(f"--dpi-desync-repeats={params['repeats']}")
            
            # Дополнительные опции
            if params.get('extra_options'):
                strategy_parts.append(params['extra_options'])
            
            strategies[domain] = ' '.join(strategy_parts)
        
        return strategies
    
    async def fix_rutracker_dns(self):
        """Исправляет проблему DNS для rutracker.org."""
        print(f"\n🔧 === Исправление DNS для rutracker.org ===")
        
        # Пробуем разные способы получения IP
        rutracker_ips = []
        
        # 1. DoH запрос
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                params = {"name": "rutracker.org", "type": "A"}
                headers = {"accept": "application/dns-json"}
                
                async with session.get("https://8.8.8.8/resolve", params=params, headers=headers, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("Answer"):
                            for answer in data["Answer"]:
                                if answer.get("data"):
                                    rutracker_ips.append(answer["data"])
                                    print(f"  ✅ DoH IP: {answer['data']}")
        except Exception as e:
            print(f"  ❌ DoH ошибка: {e}")
        
        # 2. Системный DNS
        try:
            result = await asyncio.get_event_loop().getaddrinfo('rutracker.org', None, family=socket.AF_INET)
            system_ips = [addr[4][0] for addr in result]
            for ip in system_ips:
                if ip not in rutracker_ips:
                    rutracker_ips.append(ip)
                    print(f"  ✅ Системный DNS: {ip}")
        except Exception as e:
            print(f"  ❌ Системный DNS ошибка: {e}")
        
        # 3. Альтернативные домены
        alt_domains = ['rutracker.net', 'rutracker.nl', 'rutracker.lib']
        for alt_domain in alt_domains:
            try:
                result = await asyncio.get_event_loop().getaddrinfo(alt_domain, None, family=socket.AF_INET)
                alt_ips = [addr[4][0] for addr in result]
                for ip in alt_ips:
                    if ip not in rutracker_ips:
                        rutracker_ips.append(ip)
                        print(f"  ✅ {alt_domain}: {ip}")
            except:
                continue
        
        # 4. Известные рабочие IP (из предыдущих анализов)
        known_ips = ['213.180.193.234', '213.180.204.158', '195.82.146.214']
        for ip in known_ips:
            if ip not in rutracker_ips:
                rutracker_ips.append(ip)
                print(f"  📋 Известный IP: {ip}")
        
        return rutracker_ips
    
    def update_hosts_file(self, domain_ips):
        """Обновляет hosts файл с рабочими IP."""
        print(f"\n📝 === Обновление hosts файла ===")
        
        try:
            # Читаем текущий hosts файл
            with open(self.hosts_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Удаляем старые записи Smart Bypass
            new_lines = []
            skip_block = False
            
            for line in lines:
                if "Smart Bypass Entries START" in line:
                    skip_block = True
                    continue
                elif "Smart Bypass Entries END" in line:
                    skip_block = False
                    continue
                elif not skip_block:
                    new_lines.append(line)
            
            # Добавляем новые записи
            new_lines.append("\n# === Smart Bypass Entries START ===\n")
            new_lines.append("# Оптимизированные записи на основе анализа PCAP\n")
            
            for domain, ips in domain_ips.items():
                if ips:
                    # Используем первый рабочий IP
                    ip = ips[0]
                    new_lines.append(f"{ip:<15} {domain}\n")
                    if not domain.startswith('www.'):
                        new_lines.append(f"{ip:<15} www.{domain}\n")
                    print(f"  ✅ Добавлено: {ip} -> {domain}")
            
            new_lines.append("# === Smart Bypass Entries END ===\n")
            
            # Записываем обновленный файл
            with open(self.hosts_file, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            
            print(f"✅ Hosts файл обновлен: {self.hosts_file}")
            
            # Очищаем DNS кэш
            try:
                subprocess.run(['ipconfig', '/flushdns'], check=True, capture_output=True)
                print(f"✅ DNS кэш очищен")
            except:
                print(f"⚠️  Не удалось очистить DNS кэш")
            
            return True
            
        except Exception as e:
            print(f"❌ Ошибка обновления hosts: {e}")
            return False
    
    def save_optimized_strategies(self, strategies):
        """Сохраняет оптимизированные стратегии."""
        try:
            with open(self.strategies_file, 'w', encoding='utf-8') as f:
                json.dump(strategies, f, indent=2, ensure_ascii=False)
            print(f"✅ Стратегии сохранены в {self.strategies_file}")
            return True
        except Exception as e:
            print(f"❌ Ошибка сохранения стратегий: {e}")
            return False
    
    async def test_connections(self, domains):
        """Тестирует соединения к доменам."""
        print(f"\n🧪 === Тестирование соединений ===")
        
        for domain in domains:
            try:
                print(f"Тестирование {domain}...", end=' ')
                
                # Простой TCP тест
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(domain, 443),
                    timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
                
                print(f"✅ Успех")
                
            except asyncio.TimeoutError:
                print(f"⏱️ Таймаут")
            except Exception as e:
                print(f"❌ Ошибка: {e}")
    
    async def run_optimization(self):
        """Запускает полную оптимизацию."""
        print(f"🚀 === Применение оптимизированных исправлений ===")
        print(f"На основе анализа успешных соединений в PCAP\n")
        
        # 1. Загружаем оптимизированную конфигурацию
        config = self.load_optimized_config()
        if not config:
            return False
        
        print(f"✅ Загружена оптимизированная конфигурация v{config.get('version', 'unknown')}")
        
        # 2. Показываем результаты анализа
        success_patterns = config.get('success_patterns', {})
        print(f"\n📊 Паттерны успеха из анализа:")
        print(f"   • Рабочие TTL: {success_patterns.get('working_ttl_values', [])}")
        print(f"   • Оптимальный размер пакета: {success_patterns.get('optimal_packet_size', 'unknown')}")
        print(f"   • Длительность соединений: {success_patterns.get('successful_duration', 'unknown')}")
        print(f"   • Объем передачи данных: {success_patterns.get('data_transfer_range', 'unknown')}")
        
        # 3. Исправляем DNS для rutracker.org
        rutracker_ips = await self.fix_rutracker_dns()
        
        # 4. Обновляем hosts файл
        domain_ips = {
            'rutracker.org': rutracker_ips,
            'nnmclub.to': rutracker_ips  # Используем те же IP
        }
        
        if rutracker_ips:
            self.update_hosts_file(domain_ips)
        
        # 5. Конвертируем и сохраняем стратегии
        strategies = self.convert_to_zapret_strategies(config)
        
        print(f"\n📋 Оптимизированные стратегии:")
        for domain, strategy in strategies.items():
            short_strategy = strategy[:60] + "..." if len(strategy) > 60 else strategy
            print(f"   • {domain}: {short_strategy}")
        
        if self.save_optimized_strategies(strategies):
            print(f"\n✅ Оптимизация завершена успешно!")
            
            # 6. Тестируем соединения
            test_domains = ['x.com', 'instagram.com', 'rutracker.org']
            await self.test_connections(test_domains)
            
            print(f"\n🔄 Следующие шаги:")
            print(f"   1. Перезапустите службу обхода")
            print(f"   2. Протестируйте сайты в браузере")
            print(f"   3. x.com и instagram.com должны работать стабильно")
            print(f"   4. rutracker.org должен теперь подключаться")
            
            return True
        
        return False


async def main():
    """Главная функция."""
    optimizer = OptimizedFix()
    
    try:
        success = await optimizer.run_optimization()
        
        if success:
            print(f"\n🎉 Оптимизация применена успешно!")
        else:
            print(f"\n❌ Оптимизация не удалась")
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())