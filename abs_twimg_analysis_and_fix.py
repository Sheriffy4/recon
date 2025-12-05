#!/usr/bin/env python3
"""
Анализ и исправление проблемы с abs-0.twimg.com

Проблема: Все стратегии приводят к TIMEOUT, DPI блокирует TLS handshake
Решение: Создание специализированных стратегий для Twitter CDN
"""

import json
import subprocess
import time
from typing import Dict, List, Tuple, Optional

class AbsTwimgFixer:
    def __init__(self):
        self.target_domain = "abs-0.twimg.com"
        self.target_url = f"https://{self.target_domain}"
        
        # Специализированные стратегии для Twitter CDN
        self.specialized_strategies = [
            # Стратегии для обхода TLS fingerprinting
            {
                "name": "tls_split_sni",
                "strategy": "--dpi-desync=fake,disorder --dpi-desync-split-tls=sni --dpi-desync-fooling=badseq --dpi-desync-ttl=1 --dpi-desync-repeats=3"
            },
            {
                "name": "tls_split_chello", 
                "strategy": "--dpi-desync=fake,disorder --dpi-desync-split-tls=chello --dpi-desync-fooling=badsum --dpi-desync-ttl=2 --dpi-desync-repeats=2"
            },
            {
                "name": "multisplit_low_ttl",
                "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=15 --dpi-desync-split-seqovl=50 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1 --dpi-desync-repeats=5"
            },
            {
                "name": "fake_tls_record",
                "strategy": "--dpi-desync=fake --dpi-desync-fake-tls=0x160301 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=4"
            },
            {
                "name": "disorder_with_fake_http",
                "strategy": "--dpi-desync=fake,disorder --dpi-desync-fake-http=0x47455420 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-ttl=2"
            },
            {
                "name": "multidisorder_aggressive",
                "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=1,3,5,10,20 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1 --dpi-desync-repeats=3"
            },
            {
                "name": "split_at_tls_version",
                "strategy": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-fake-tls=0x16030300"
            },
            {
                "name": "tcp_md5_bypass",
                "strategy": "--dpi-desync=fake,disorder --dpi-desync-split-pos=2 --dpi-desync-fooling=md5sig --dpi-desync-ttl=2 --dpi-desync-repeats=2"
            },
            {
                "name": "ipfrag_bypass",
                "strategy": "--dpi-desync=ipfrag2 --dpi-desync-fooling=badsum --dpi-desync-ttl=3"
            },
            {
                "name": "syndata_bypass",
                "strategy": "--dpi-desync=syndata --dpi-desync-fooling=badseq --dpi-desync-ttl=1"
            },
            # Комбинированные стратегии
            {
                "name": "combo_tls_http_split",
                "strategy": "--dpi-desync=fake,multisplit --dpi-desync-split-tls=sni --dpi-desync-split-http-req=method --dpi-desync-split-count=8 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1"
            },
            {
                "name": "aggressive_fragmentation",
                "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=20 --dpi-desync-split-seqovl=100 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=10"
            }
        ]
    
    def test_strategy(self, strategy: str, timeout: int = 15) -> Tuple[bool, float, str]:
        """Тестирует стратегию и возвращает результат"""
        try:
            start_time = time.time()
            
            # Команда для тестирования с zapret
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", str(timeout),
                "--connect-timeout", "10",
                self.target_url
            ]
            
            # Устанавливаем переменные окружения для zapret
            env = {
                "ZAPRET_BASE": "/opt/zapret",
                "ZAPRET_CONFIG": strategy
            }
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout + 5,
                env=env
            )
            
            elapsed = time.time() - start_time
            
            # Проверяем успешность
            if result.returncode == 0 and result.stdout.strip() in ["200", "301", "302"]:
                return True, elapsed * 1000, result.stdout.strip()
            else:
                return False, elapsed * 1000, f"Error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, timeout * 1000, "TIMEOUT"
        except Exception as e:
            return False, 0, f"Exception: {str(e)}"
    
    def test_all_strategies(self) -> List[Dict]:
        """Тестирует все специализированные стратегии"""
        results = []
        
        print(f"Тестирование {len(self.specialized_strategies)} специализированных стратегий для {self.target_domain}")
        print("=" * 80)
        
        for i, strategy_info in enumerate(self.specialized_strategies, 1):
            name = strategy_info["name"]
            strategy = strategy_info["strategy"]
            
            print(f"[{i}/{len(self.specialized_strategies)}] Тестирую: {name}")
            print(f"Стратегия: {strategy}")
            
            success, latency, response = self.test_strategy(strategy)
            
            result = {
                "name": name,
                "strategy": strategy,
                "success": success,
                "latency_ms": latency,
                "response": response,
                "timestamp": time.time()
            }
            
            results.append(result)
            
            status = "✅ УСПЕХ" if success else "❌ НЕУДАЧА"
            print(f"Результат: {status} ({latency:.1f}ms) - {response}")
            print("-" * 40)
            
            # Небольшая пауза между тестами
            time.sleep(2)
        
        return results
    
    def analyze_results(self, results: List[Dict]) -> Dict:
        """Анализирует результаты тестирования"""
        successful = [r for r in results if r["success"]]
        failed = [r for r in results if not r["success"]]
        
        analysis = {
            "total_tested": len(results),
            "successful_count": len(successful),
            "failed_count": len(failed),
            "success_rate": len(successful) / len(results) if results else 0,
            "successful_strategies": successful,
            "failed_strategies": failed
        }
        
        if successful:
            # Находим лучшую стратегию по латентности
            best_strategy = min(successful, key=lambda x: x["latency_ms"])
            analysis["best_strategy"] = best_strategy
            
            # Средняя латентность успешных стратегий
            avg_latency = sum(s["latency_ms"] for s in successful) / len(successful)
            analysis["avg_successful_latency"] = avg_latency
        
        return analysis
    
    def update_strategy_files(self, best_strategy: Dict):
        """Обновляет файлы стратегий с найденной рабочей стратегией"""
        try:
            # Обновляем strategies_enhanced.json
            with open("strategies_enhanced.json", "r") as f:
                strategies = json.load(f)
            
            strategies[self.target_domain] = best_strategy["strategy"]
            
            with open("strategies_enhanced.json", "w") as f:
                json.dump(strategies, f, indent=2, ensure_ascii=False)
            
            # Обновляем domain_strategies.json
            with open("domain_strategies.json", "r") as f:
                domain_strategies = json.load(f)
            
            domain_strategies["domain_strategies"][self.target_domain] = {
                "domain": self.target_domain,
                "strategy": best_strategy["strategy"],
                "success_rate": 1.0,
                "avg_latency_ms": best_strategy["latency_ms"],
                "last_tested": time.strftime("%Y-%m-%dT%H:%M:%S.%f"),
                "test_count": 1,
                "split_pos": None,
                "overlap_size": None,
                "fake_ttl_source": None,
                "fooling_modes": None
            }
            
            with open("domain_strategies.json", "w") as f:
                json.dump(domain_strategies, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Обновлены файлы стратегий с рабочей стратегией для {self.target_domain}")
            
        except Exception as e:
            print(f"❌ Ошибка при обновлении файлов стратегий: {e}")
    
    def generate_report(self, results: List[Dict], analysis: Dict):
        """Генерирует отчет о тестировании"""
        report = {
            "target_domain": self.target_domain,
            "test_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "analysis": analysis,
            "detailed_results": results
        }
        
        # Сохраняем отчет
        with open(f"abs_twimg_fix_report_{int(time.time())}.json", "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Выводим краткий отчет
        print("\n" + "=" * 80)
        print("ОТЧЕТ О ТЕСТИРОВАНИИ")
        print("=" * 80)
        print(f"Домен: {self.target_domain}")
        print(f"Всего протестировано стратегий: {analysis['total_tested']}")
        print(f"Успешных стратегий: {analysis['successful_count']}")
        print(f"Неудачных стратегий: {analysis['failed_count']}")
        print(f"Процент успеха: {analysis['success_rate']:.1%}")
        
        if analysis.get("best_strategy"):
            best = analysis["best_strategy"]
            print(f"\n🏆 ЛУЧШАЯ СТРАТЕГИЯ:")
            print(f"Название: {best['name']}")
            print(f"Стратегия: {best['strategy']}")
            print(f"Латентность: {best['latency_ms']:.1f}ms")
        else:
            print("\n❌ Рабочих стратегий не найдено")
            print("\nРЕКОМЕНДАЦИИ:")
            print("1. Проверьте сетевое подключение")
            print("2. Убедитесь, что zapret правильно настроен")
            print("3. Попробуйте другие методы обхода (VPN, прокси)")
            print("4. Возможно, требуется более глубокий анализ DPI")

def main():
    fixer = AbsTwimgFixer()
    
    print("🔧 Запуск диагностики и исправления проблемы с abs-0.twimg.com")
    print("=" * 80)
    
    # Тестируем все стратегии
    results = fixer.test_all_strategies()
    
    # Анализируем результаты
    analysis = fixer.analyze_results(results)
    
    # Если найдена рабочая стратегия, обновляем файлы
    if analysis.get("best_strategy"):
        fixer.update_strategy_files(analysis["best_strategy"])
    
    # Генерируем отчет
    fixer.generate_report(results, analysis)

if __name__ == "__main__":
    main()