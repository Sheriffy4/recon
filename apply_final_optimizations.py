#!/usr/bin/env python3
"""
Финальное применение всех оптимизаций на основе комплексного анализа.
Применяет оптимизированные стратегии, обновляет hosts файл и настраивает службу.
"""

import json
import sys
import subprocess
import shutil
from pathlib import Path
import platform


class FinalOptimizationApplier:
    """Применяет финальные оптимизации системы обхода."""
    
    def __init__(self):
        self.hosts_path = self._get_hosts_path()
        self.backup_created = False
        
    def _get_hosts_path(self):
        """Получает путь к hosts файлу."""
        if platform.system().lower() == 'windows':
            return r'C:\Windows\System32\drivers\etc\hosts'
        else:
            return '/etc/hosts'
    
    def create_backups(self):
        """Создает резервные копии важных файлов."""
        print("💾 === Создание резервных копий ===")
        
        # Backup strategies.json
        if Path("strategies.json").exists():
            shutil.copy2("strategies.json", "strategies_backup_final.json")
            print("✅ Резервная копия strategies.json создана")
        
        # Backup hosts file
        try:
            if Path(self.hosts_path).exists():
                shutil.copy2(self.hosts_path, "hosts_backup_final.txt")
                print("✅ Резервная копия hosts файла создана")
                self.backup_created = True
        except Exception as e:
            print(f"⚠️  Не удалось создать резервную копию hosts: {e}")
    
    def apply_optimized_strategies(self):
        """Применяет оптимизированные стратегии."""
        print("\n⚙️ === Применение оптимизированных стратегий ===")
        
        try:
            # Загружаем оптимизированные стратегии
            with open("optimized_strategies_final.json", "r", encoding="utf-8") as f:
                optimized_strategies = json.load(f)
            
            # Сохраняем как основные стратегии
            with open("strategies.json", "w", encoding="utf-8") as f:
                json.dump(optimized_strategies, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Применено {len(optimized_strategies)} оптимизированных стратегий:")
            for domain, strategy in optimized_strategies.items():
                short_strategy = strategy[:50] + "..." if len(strategy) > 50 else strategy
                print(f"   • {domain}: {short_strategy}")
            
            return True
            
        except Exception as e:
            print(f"❌ Ошибка применения стратегий: {e}")
            return False
    
    def apply_hosts_entries(self):
        """Применяет записи hosts файла."""
        print("\n📝 === Обновление hosts файла ===")
        
        try:
            # Загружаем рекомендуемые записи
            with open("recommended_hosts_entries.txt", "r", encoding="utf-8") as f:
                recommended_lines = f.readlines()
            
            # Читаем текущий hosts файл
            with open(self.hosts_path, "r", encoding="utf-8") as f:
                current_lines = f.readlines()
            
            # Удаляем старые записи Smart Bypass
            new_lines = []
            skip_block = False
            
            for line in current_lines:
                if "Smart Bypass Entries START" in line:
                    skip_block = True
                    continue
                elif "Smart Bypass Entries END" in line:
                    skip_block = False
                    continue
                elif not skip_block:
                    new_lines.append(line)
            
            # Добавляем новые записи
            new_lines.append("\n")
            new_lines.extend(recommended_lines)
            
            # Записываем обновленный файл
            with open(self.hosts_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            
            # Подсчитываем добавленные записи
            added_entries = len([line for line in recommended_lines if not line.startswith("#") and line.strip()])
            
            print(f"✅ Добавлено {added_entries} записей в hosts файл")
            
            # Очищаем DNS кэш
            try:
                if platform.system().lower() == 'windows':
                    subprocess.run(['ipconfig', '/flushdns'], check=True, capture_output=True)
                    print("✅ DNS кэш очищен")
            except:
                print("⚠️  Не удалось очистить DNS кэш")
            
            return True
            
        except Exception as e:
            print(f"❌ Ошибка обновления hosts файла: {e}")
            print("💡 Попробуйте запустить от имени администратора")
            return False
    
    def show_optimization_summary(self):
        """Показывает сводку оптимизаций."""
        print("\n📊 === Сводка применённых оптимизаций ===")
        
        try:
            # Загружаем отчет
            with open("comprehensive_analysis_report.json", "r", encoding="utf-8") as f:
                report = json.load(f)
            
            # Показываем ключевые улучшения
            print("🔧 Применённые улучшения:")
            
            fixes = report.get("immediate_fixes", [])
            for i, fix in enumerate(fixes, 1):
                print(f"   {i}. ✅ {fix}")
            
            # Показываем конфигурацию службы
            config = report.get("service_config", {})
            print(f"\n⚙️  Оптимизированная конфигурация:")
            print(f"   • Стратегия: {config.get('primary_strategy', 'fake,disorder')}")
            print(f"   • TTL: {config.get('default_ttl', 4)}")
            print(f"   • Fooling: {config.get('default_fooling', 'badseq')}")
            print(f"   • Повторы: {config.get('default_repeats', 2)}")
            
        except Exception as e:
            print(f"⚠️  Не удалось загрузить отчет: {e}")
    
    def test_optimizations(self):
        """Тестирует применённые оптимизации."""
        print("\n🧪 === Тестирование оптимизаций ===")
        
        test_domains = ["x.com", "instagram.com", "rutracker.org"]
        
        for domain in test_domains:
            try:
                print(f"Тестирование {domain}...", end=" ")
                
                # Простой тест подключения
                result = subprocess.run([
                    sys.executable, "simple_cli.py", "check", domain
                ], capture_output=True, text=True, timeout=10)
                
                if "ПОДОЗРИТЕЛЬНО" in result.stdout or "DoH" in result.stdout:
                    print("🟡 Обнаружены различия DNS - обход активен")
                elif "ДОСТУПЕН" in result.stdout:
                    print("✅ Доступен")
                else:
                    print("⚠️  Требует проверки")
                    
            except subprocess.TimeoutExpired:
                print("⏱️ Таймаут")
            except Exception as e:
                print(f"❌ Ошибка: {e}")
    
    def generate_next_steps(self):
        """Генерирует следующие шаги для пользователя."""
        print(f"\n🚀 === Следующие шаги ===")
        
        print(f"1. 🔄 Перезапустите службу обхода:")
        print(f"   • Остановите текущую службу (Ctrl+C)")
        print(f"   • Запустите заново: python recon_service.py")
        
        print(f"\n2. 🌐 Протестируйте сайты в браузере:")
        print(f"   • x.com - должен загружаться полностью")
        print(f"   • instagram.com - должен работать стабильно")
        print(f"   • rutracker.org - должен открываться быстро")
        print(f"   • nnmclub.to - должен работать аналогично rutracker")
        
        print(f"\n3. 📊 Мониторинг результатов:")
        print(f"   • Если сайты не открываются - проверьте права администратора")
        print(f"   • Если x.com загружается частично - очистите кэш браузера")
        print(f"   • Если проблемы остаются - захватите новый PCAP для анализа")
        
        print(f"\n4. 🔧 Дополнительные инструменты:")
        print(f"   • python simple_cli.py test-multi x.com instagram.com rutracker.org")
        print(f"   • python comprehensive_bypass_analyzer.py (повторный анализ)")
        print(f"   • smart_bypass.bat (интерактивное меню)")
    
    def restore_backups(self):
        """Восстанавливает резервные копии в случае проблем."""
        print("\n🔄 === Восстановление резервных копий ===")
        
        try:
            # Восстанавливаем strategies.json
            if Path("strategies_backup_final.json").exists():
                shutil.copy2("strategies_backup_final.json", "strategies.json")
                print("✅ Стратегии восстановлены")
            
            # Восстанавливаем hosts файл
            if Path("hosts_backup_final.txt").exists() and self.backup_created:
                shutil.copy2("hosts_backup_final.txt", self.hosts_path)
                print("✅ Hosts файл восстановлен")
                
                # Очищаем DNS кэш
                try:
                    if platform.system().lower() == 'windows':
                        subprocess.run(['ipconfig', '/flushdns'], check=True, capture_output=True)
                        print("✅ DNS кэш очищен")
                except:
                    pass
            
            return True
            
        except Exception as e:
            print(f"❌ Ошибка восстановления: {e}")
            return False
    
    def run_final_optimization(self):
        """Запускает финальную оптимизацию."""
        print("🎯 === Финальная оптимизация системы обхода ===")
        print("На основе комплексного анализа PCAP, поддоменов и стратегий\n")
        
        success_steps = 0
        total_steps = 3
        
        try:
            # Шаг 1: Создание резервных копий
            self.create_backups()
            success_steps += 1
            
            # Шаг 2: Применение стратегий
            if self.apply_optimized_strategies():
                success_steps += 1
            else:
                raise Exception("Не удалось применить стратегии")
            
            # Шаг 3: Обновление hosts файла
            if self.apply_hosts_entries():
                success_steps += 1
            else:
                print("⚠️  Hosts файл не обновлен - возможно нужны права администратора")
            
            # Показываем результаты
            self.show_optimization_summary()
            self.test_optimizations()
            self.generate_next_steps()
            
            print(f"\n🎉 === Оптимизация завершена ===")
            print(f"Успешно выполнено: {success_steps}/{total_steps} шагов")
            
            if success_steps == total_steps:
                print("✅ Все оптимизации применены успешно!")
            else:
                print("⚠️  Некоторые оптимизации требуют дополнительных действий")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Ошибка оптимизации: {e}")
            
            # Предлагаем восстановление
            print(f"\n🔄 Восстановить резервные копии? (y/N): ", end="")
            try:
                response = input().strip().lower()
                if response in ['y', 'yes', 'да']:
                    self.restore_backups()
            except KeyboardInterrupt:
                print(f"\nОперация прервана")
            
            return False


def main():
    """Главная функция."""
    applier = FinalOptimizationApplier()
    
    # Проверяем наличие необходимых файлов
    required_files = [
        "optimized_strategies_final.json",
        "recommended_hosts_entries.txt",
        "comprehensive_analysis_report.json"
    ]
    
    missing_files = [f for f in required_files if not Path(f).exists()]
    
    if missing_files:
        print(f"❌ Отсутствуют необходимые файлы: {', '.join(missing_files)}")
        print(f"💡 Сначала запустите: python comprehensive_bypass_analyzer.py")
        return
    
    try:
        success = applier.run_final_optimization()
        
        if success:
            print(f"\n🚀 Система оптимизирована и готова к использованию!")
        else:
            print(f"\n⚠️  Оптимизация завершена с предупреждениями")
            
    except KeyboardInterrupt:
        print(f"\n⏹️ Оптимизация прервана пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")


if __name__ == "__main__":
    main()