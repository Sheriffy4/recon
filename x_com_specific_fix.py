#!/usr/bin/env python3
"""
Специальное исправление для x.com.
Анализирует почему x.com не открывается полностью и применяет целевые исправления.
"""

import asyncio
import aiohttp
import json
import subprocess
import sys
from pathlib import Path


class XComSpecificFix:
    """Специальные исправления для x.com."""
    
    def __init__(self):
        self.x_com_ips = []
        self.working_strategy = None
        
    async def get_all_x_com_ips(self):
        """Получает все возможные IP адреса для x.com."""
        print("🔍 === Поиск всех IP адресов x.com ===")
        
        ips = set()
        
        # 1. DoH через разные провайдеры
        doh_servers = [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/resolve", 
            "https://9.9.9.9/dns-query"
        ]
        
        async with aiohttp.ClientSession() as session:
            for server in doh_servers:
                try:
                    if "8.8.8.8" in server:
                        params = {"name": "x.com", "type": "A"}
                        headers = {"accept": "application/dns-json"}
                    else:
                        params = {"name": "x.com", "type": "A"}
                        headers = {"accept": "application/dns-json"}
                    
                    async with session.get(server, params=params, headers=headers, timeout=5) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get("Answer"):
                                for answer in data["Answer"]:
                                    if answer.get("data") and "." in answer["data"]:
                                        ip = answer["data"]
                                        ips.add(ip)
                                        server_name = server.split("//")[1].split("/")[0]
                                        print(f"  ✅ {server_name}: {ip}")
                except Exception as e:
                    server_name = server.split("//")[1].split("/")[0]
                    print(f"  ❌ {server_name}: {e}")
        
        # 2. Системный DNS
        try:
            import socket
            result = await asyncio.get_event_loop().getaddrinfo('x.com', None, family=socket.AF_INET)
            system_ips = [addr[4][0] for addr in result]
            for ip in system_ips:
                ips.add(ip)
                print(f"  ✅ Системный DNS: {ip}")
        except Exception as e:
            print(f"  ❌ Системный DNS: {e}")
        
        # 3. Альтернативные домены
        alt_domains = ['twitter.com', 'www.x.com', 'mobile.x.com']
        for domain in alt_domains:
            try:
                result = await asyncio.get_event_loop().getaddrinfo(domain, None, family=socket.AF_INET)
                alt_ips = [addr[4][0] for addr in result]
                for ip in alt_ips:
                    if ip not in ips:
                        ips.add(ip)
                        print(f"  ✅ {domain}: {ip}")
            except:
                continue
        
        self.x_com_ips = list(ips)
        print(f"\n📊 Найдено {len(self.x_com_ips)} уникальных IP для x.com")
        return self.x_com_ips
    
    async def test_x_com_strategies(self):
        """Тестирует различные стратегии специально для x.com."""
        print(f"\n🧪 === Тестирование стратегий для x.com ===")
        
        # Специальные стратегии для x.com на основе анализа
        test_strategies = {
            "current_working": "--dpi-desync=fake,disorder --dpi-desync-split-pos=8 --dpi-desync-ttl=4 --dpi-desync-fooling=badseq --dpi-desync-repeats=2",
            
            "aggressive_multisplit": "--dpi-desync=multisplit --dpi-desync-split-count=15 --dpi-desync-split-seqovl=100 --dpi-desync-ttl=2 --dpi-desync-fooling=badsum --dpi-desync-repeats=3",
            
            "ultra_split": "--dpi-desync=multisplit --dpi-desync-split-count=25 --dpi-desync-split-seqovl=150 --dpi-desync-ttl=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=5",
            
            "fake_combo": "--dpi-desync=fake,multisplit --dpi-desync-split-count=10 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum --dpi-desync-fake-tls=0x16030100",
            
            "disorder_combo": "--dpi-desync=disorder,multisplit --dpi-desync-split-count=8 --dpi-desync-split-pos=2 --dpi-desync-ttl=4 --dpi-desync-fooling=badseq",
            
            "triple_combo": "--dpi-desync=fake,disorder,multisplit --dpi-desync-split-count=12 --dpi-desync-split-pos=3 --dpi-desync-ttl=2 --dpi-desync-fooling=badsum --dpi-desync-repeats=4"
        }
        
        print(f"Тестируем {len(test_strategies)} специальных стратегий:")
        print(f"{'Стратегия':<20} {'Результат':<15} {'Описание'}")
        print("-" * 70)
        
        best_strategy = None
        best_score = 0
        
        for name, strategy in test_strategies.items():
            try:
                # Создаем временный файл стратегий
                temp_strategies = {"x.com": strategy}
                with open("temp_x_strategies.json", "w") as f:
                    json.dump(temp_strategies, f)
                
                # Тестируем через простой CLI
                result = subprocess.run([
                    sys.executable, "simple_cli.py", "check", "x.com"
                ], capture_output=True, text=True, timeout=10)
                
                if "ПОДОЗРИТЕЛЬНО" in result.stdout or "DoH" in result.stdout:
                    status = "🟡 Активен"
                    score = 70
                elif "ДОСТУПЕН" in result.stdout:
                    status = "✅ Успех"
                    score = 100
                else:
                    status = "❌ Неудача"
                    score = 0
                
                if score > best_score:
                    best_score = score
                    best_strategy = (name, strategy)
                
                description = test_strategies.get(name, "")[:30]
                print(f"{name:<20} {status:<15} {description}")
                
            except subprocess.TimeoutExpired:
                print(f"{name:<20} {'⏱️ Таймаут':<15}")
            except Exception as e:
                print(f"{name:<20} {'❌ Ошибка':<15} {str(e)[:20]}")
        
        if best_strategy:
            self.working_strategy = best_strategy
            print(f"\n🏆 Лучшая стратегия: {best_strategy[0]} (оценка: {best_score})")
        else:
            print(f"\n⚠️  Оптимальная стратегия не найдена")
        
        return best_strategy
    
    def create_x_com_hosts_entries(self):
        """Создает специальные записи hosts для x.com."""
        print(f"\n📝 === Создание записей hosts для x.com ===")
        
        if not self.x_com_ips:
            print("❌ IP адреса x.com не найдены")
            return []
        
        entries = []
        
        # Основные домены x.com
        main_domains = [
            "x.com",
            "www.x.com", 
            "mobile.x.com",
            "api.x.com",
            "twitter.com",
            "www.twitter.com",
            "mobile.twitter.com",
            "api.twitter.com"
        ]
        
        # Используем первый рабочий IP
        primary_ip = self.x_com_ips[0]
        
        for domain in main_domains:
            entries.append(f"{primary_ip:<15} {domain}")
        
        # CDN домены - используем другие IP если доступны
        cdn_domains = [
            "abs.twimg.com",
            "pbs.twimg.com", 
            "video.twimg.com",
            "ton.twimg.com",
            "cdn.syndication.twimg.com"
        ]
        
        cdn_ip = self.x_com_ips[1] if len(self.x_com_ips) > 1 else primary_ip
        
        for domain in cdn_domains:
            entries.append(f"{cdn_ip:<15} {domain}")
        
        print(f"✅ Создано {len(entries)} записей для x.com")
        return entries
    
    def apply_x_com_fix(self):
        """Применяет специальное исправление для x.com."""
        print(f"\n🎯 === Применение специального исправления x.com ===")
        
        fixes_applied = 0
        
        # 1. Обновляем стратегию
        if self.working_strategy:
            try:
                # Загружаем текущие стратегии
                with open("strategies.json", "r", encoding="utf-8") as f:
                    strategies = json.load(f)
                
                # Обновляем стратегию для x.com
                strategies["x.com"] = self.working_strategy[1]
                
                # Сохраняем
                with open("strategies.json", "w", encoding="utf-8") as f:
                    json.dump(strategies, f, indent=2, ensure_ascii=False)
                
                print(f"✅ Стратегия x.com обновлена на: {self.working_strategy[0]}")
                fixes_applied += 1
                
            except Exception as e:
                print(f"❌ Ошибка обновления стратегии: {e}")
        
        # 2. Добавляем специальные hosts записи
        x_hosts_entries = self.create_x_com_hosts_entries()
        if x_hosts_entries:
            try:
                # Добавляем в файл hosts
                hosts_path = r'C:\Windows\System32\drivers\etc\hosts' if sys.platform == 'win32' else '/etc/hosts'
                
                with open(hosts_path, "a", encoding="utf-8") as f:
                    f.write(f"\n# === X.com специальные записи ===\n")
                    for entry in x_hosts_entries:
                        f.write(f"{entry}\n")
                    f.write(f"# === Конец X.com записей ===\n")
                
                print(f"✅ Добавлено {len(x_hosts_entries)} специальных записей для x.com")
                fixes_applied += 1
                
                # Очищаем DNS кэш
                try:
                    subprocess.run(['ipconfig', '/flushdns'], check=True, capture_output=True)
                    print("✅ DNS кэш очищен")
                except:
                    pass
                
            except Exception as e:
                print(f"❌ Ошибка добавления hosts записей: {e}")
        
        return fixes_applied
    
    async def run_x_com_fix(self):
        """Запускает полное исправление для x.com."""
        print("🎯 === Специальное исправление для x.com ===")
        print("Цель: решить проблему с неполной загрузкой x.com\n")
        
        try:
            # 1. Получаем все IP
            await self.get_all_x_com_ips()
            
            # 2. Тестируем стратегии
            await self.test_x_com_strategies()
            
            # 3. Применяем исправления
            fixes_applied = self.apply_x_com_fix()
            
            print(f"\n📊 === Результаты исправления ===")
            print(f"Применено исправлений: {fixes_applied}/2")
            
            if fixes_applied >= 1:
                print(f"\n✅ Исправления применены!")
                print(f"\n🔄 Следующие шаги:")
                print(f"   1. Перезапустите службу обхода")
                print(f"   2. Очистите кэш браузера (Ctrl+Shift+Del)")
                print(f"   3. Откройте x.com в новой вкладке")
                print(f"   4. Попробуйте инкогнито режим")
                
                print(f"\n💡 Дополнительные советы:")
                print(f"   • Если x.com загружается частично - подождите 10-15 секунд")
                print(f"   • Попробуйте обновить страницу (F5)")
                print(f"   • Проверьте, что служба обхода активна")
                
                return True
            else:
                print(f"\n⚠️  Не все исправления применены")
                print(f"💡 Возможно требуются права администратора")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка исправления x.com: {e}")
            return False


async def main():
    """Главная функция."""
    fixer = XComSpecificFix()
    
    try:
        success = await fixer.run_x_com_fix()
        
        if success:
            print(f"\n🎉 Специальное исправление x.com завершено!")
        else:
            print(f"\n⚠️  Исправление завершено с предупреждениями")
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())