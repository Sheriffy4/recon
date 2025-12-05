"""
Быстрая проверка PCAP файлов
"""

import os
import glob
import subprocess
import sys

def quick_check_pcaps(pcap_dir):
    """Быстрая проверка всех PCAP файлов"""
    
    print("\n" + "="*80)
    print("БЫСТРАЯ ПРОВЕРКА PCAP ФАЙЛОВ")
    print("="*80)
    
    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap")))
    
    if not pcap_files:
        print(f"\n❌ PCAP файлы не найдены в {pcap_dir}")
        return
    
    print(f"\nНайдено {len(pcap_files)} PCAP файлов")
    print("="*80)
    
    results = []
    
    for i, pcap_file in enumerate(pcap_files, 1):
        filename = os.path.basename(pcap_file)
        size = os.path.getsize(pcap_file)
        
        print(f"\n{i}. {filename} ({size} bytes)")
        
        # Запустить анализатор
        try:
            result = subprocess.run(
                ["python", "pcap_strategy_analyzer.py", pcap_file],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = result.stdout
            
            # Извлечь ключевую информацию
            strategy = "unknown"
            serverhello = "❌"
            clienthello_count = 0
            
            for line in output.split('\n'):
                if line.startswith("Strategy:"):
                    strategy = line.split(":", 1)[1].strip()
                elif line.startswith("ServerHello received:"):
                    serverhello = "✅" if "✅" in line else "❌"
                elif line.startswith("ClientHello packets:"):
                    try:
                        clienthello_count = int(line.split(":", 1)[1].strip())
                    except:
                        pass
            
            print(f"   Strategy: {strategy}")
            print(f"   ClientHello: {clienthello_count}")
            print(f"   ServerHello: {serverhello}")
            
            results.append({
                'file': filename,
                'strategy': strategy,
                'clienthello': clienthello_count,
                'serverhello': serverhello == "✅"
            })
            
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
            results.append({
                'file': filename,
                'strategy': 'error',
                'clienthello': 0,
                'serverhello': False
            })
    
    # Статистика
    print("\n" + "="*80)
    print("СТАТИСТИКА")
    print("="*80)
    
    with_strategy = sum(1 for r in results if r['strategy'] not in ['none', 'error', 'unknown'])
    with_serverhello = sum(1 for r in results if r['serverhello'])
    
    print(f"\nВсего файлов: {len(results)}")
    print(f"Со стратегией: {with_strategy}")
    print(f"С ServerHello: {with_serverhello}")
    
    if with_strategy > 0:
        print(f"\n✅ ХОРОШО: {with_strategy} тестов применили стратегии")
        print(f"📈 Процент успеха: {with_strategy/len(results)*100:.1f}%")
    else:
        print(f"\n⚠️ Ни один тест не применил стратегию")
    
    # Список стратегий
    strategies = {}
    for r in results:
        if r['strategy'] not in ['none', 'error', 'unknown']:
            strategies[r['strategy']] = strategies.get(r['strategy'], 0) + 1
    
    if strategies:
        print(f"\n📊 Найденные стратегии:")
        for strategy, count in sorted(strategies.items(), key=lambda x: x[1], reverse=True):
            print(f"   - {strategy}: {count}")

if __name__ == "__main__":
    pcap_dir = r"C:\Users\admin\AppData\Local\Temp\recon_pcap"
    
    if len(sys.argv) > 1:
        pcap_dir = sys.argv[1]
    
    if not os.path.exists(pcap_dir):
        print(f"❌ Директория не существует: {pcap_dir}")
        sys.exit(1)
    
    quick_check_pcaps(pcap_dir)
