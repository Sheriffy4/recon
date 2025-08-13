# recon/ml/zapret_strategy_generator.py
import re
import random

class ZapretStrategyGenerator:
    """Генератор стратегий в формате zapret команд, создающий рабочие комбинации."""
    
    # --- ИСПРАВЛЕНИЕ: Добавлены более агрессивные и проверенные стратегии ---
    PROVEN_WORKING = [
        # Комбинация фейка, сегментации и fooling
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
        # Атака с сегментацией по маркеру midsld и повторами фейка
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
        # Атака с множественной сегментацией и перекрытием
        "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
        # Атака с перестановкой сегментов и фейком
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3,10 --dpi-desync-fooling=badseq",
        # Новые агрессивные стратегии от эксперта
        "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3",
        "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum",
        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-repeats=3 --dpi-desync-fooling=badsum,badseq",
        "--dpi-desync=fake --dpi-desync-fake-tls=0x1603 --dpi-desync-ttl=2",
    ]
    
    def generate_strategies(self, fingerprint: dict = None, count: int = 20) -> list:
        """Генерирует список zapret стратегий."""
        strategies = set(self.PROVEN_WORKING)
        
        # Генерируем много вариаций для достижения нужного количества
        while len(strategies) < count:
            # Выбираем случайную базовую стратегию
            base = random.choice(self.PROVEN_WORKING)
            
            # Генерируем различные вариации
            variations = self._generate_variations(base)
            strategies.update(variations)
            
            # Если все еще мало стратегий, создаем новые комбинации
            if len(strategies) < count:
                new_strategies = self._generate_new_combinations()
                strategies.update(new_strategies)

        # --- ИСПРАВЛЕНИЕ: Добавляем стратегию, учитывающую fingerprint ---
        if fingerprint and fingerprint.get('dpi_type') == 'LIKELY_WINDOWS_BASED':
            strategies.add("--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=127")

        strategy_list = list(strategies)
        random.shuffle(strategy_list)
        return strategy_list[:count]
    
    def _generate_variations(self, base_strategy: str) -> set:
        """Генерирует вариации базовой стратегии."""
        variations = set()
        
        # Вариации TTL
        for ttl in [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 15, 20, 64, 127, 128]:
            if f"--dpi-desync-ttl=" in base_strategy:
                new_strategy = re.sub(r'--dpi-desync-ttl=\d+', f'--dpi-desync-ttl={ttl}', base_strategy)
            else:
                new_strategy = base_strategy + f" --dpi-desync-ttl={ttl}"
            variations.add(new_strategy)
        
        # Вариации split-pos
        for pos in [1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20, "midsld"]:
            if f"--dpi-desync-split-pos=" in base_strategy:
                new_strategy = re.sub(r'--dpi-desync-split-pos=[\w,]+', f'--dpi-desync-split-pos={pos}', base_strategy)
            else:
                new_strategy = base_strategy + f" --dpi-desync-split-pos={pos}"
            variations.add(new_strategy)
        
        # Вариации repeats
        for repeats in [1, 2, 3, 4, 5]:
            if f"--dpi-desync-repeats=" in base_strategy:
                new_strategy = re.sub(r'--dpi-desync-repeats=\d+', f'--dpi-desync-repeats={repeats}', base_strategy)
            else:
                new_strategy = base_strategy + f" --dpi-desync-repeats={repeats}"
            variations.add(new_strategy)
        
        return variations
    
    def _generate_new_combinations(self) -> set:
        """Генерирует новые комбинации стратегий."""
        new_strategies = set()
        
        # Базовые методы
        methods = [
            "fake", "fake,fakeddisorder", "fake,disorder2", "fake,multidisorder",
            "multisplit", "multidisorder", "disorder", "disorder2"
        ]
        
        # Fooling методы
        fooling_options = [
            "badsum", "badseq", "badsum,badseq", "md5sig", "datanoack"
        ]
        
        # Split позиции
        split_positions = [
            "1", "2", "3", "4", "5", "midsld", "1,5", "3,10", "1,5,10", "2,5,10"
        ]
        
        # TTL значения
        ttl_values = [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 127, 128]
        
        # Генерируем случайные комбинации
        for _ in range(50):  # Генерируем 50 новых комбинаций
            method = random.choice(methods)
            fooling = random.choice(fooling_options)
            split_pos = random.choice(split_positions)
            ttl = random.choice(ttl_values)
            
            strategy = f"--dpi-desync={method}"
            
            if "split" in method or "disorder" in method:
                strategy += f" --dpi-desync-split-pos={split_pos}"
            
            strategy += f" --dpi-desync-fooling={fooling}"
            strategy += f" --dpi-desync-ttl={ttl}"
            
            # Иногда добавляем repeats
            if random.random() < 0.3:
                repeats = random.randint(1, 5)
                strategy += f" --dpi-desync-repeats={repeats}"
            
            # Иногда добавляем fake-tls
            if "fake" in method and random.random() < 0.2:
                strategy += " --dpi-desync-fake-tls=0x1603"
            
            new_strategies.add(strategy)
        
        return new_strategies