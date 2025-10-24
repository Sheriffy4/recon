import random
from typing import List, Dict, Any, Optional


class NativeCandidateGenerator:
    """
    Простой нативный генератор стратегий:
    - базируется на KB (split_pos/overlap/fooling)
    - применяет ε-greedy (эксплуатация/исследование)
    - UCT-подобное ранжирование по успехам/латентности из телеметрии (упрощённо)
    """

    def __init__(self, epsilon: float = 0.2):
        self.epsilon = epsilon

    def generate(
        self,
        kb_recs: Optional[Dict[str, Any]] = None,
        telemetry_hint: Optional[Dict[str, Any]] = None,
        count: int = 6,
    ) -> List[Dict[str, Any]]:
        # Базовые значения из KB
        base = []
        split_pos = 76
        overlap = 336
        fool = ["badsum"]
        if kb_recs:
            split_pos = kb_recs.get("split_pos", split_pos)
            overlap = kb_recs.get("overlap_size", overlap)
            fm = kb_recs.get("fooling_methods")
            if fm:
                fool = fm if isinstance(fm, list) else [fm]

        # Эксплуатация вокруг KB
        base.extend(
            [
                {
                    "type": "fakeddisorder",
                    "params": {
                        "split_pos": split_pos,
                        "overlap_size": overlap,
                        "ttl": 1,
                        "fooling": fool,
                    },
                },
                {
                    "type": "multisplit",
                    "params": {"positions": [6, 14, 26], "ttl": 2, "fooling": fool},
                },
            ]
        )

        # Исследование (микро-вариации)
        exploratory = []
        while len(exploratory) + len(base) < count * 2:
            if random.random() < 0.5:
                s = max(2, split_pos + random.choice([-8, -4, 0, 4, 8]))
                o = max(8, min(overlap + random.choice([-64, -32, 0, 32, 64]), 1024))
                t = random.choice([1, 2, 3, 4])
                fl = fool[:]
                if random.random() < 0.3 and "badseq" not in fl:
                    fl.append("badseq")
                exploratory.append(
                    {
                        "type": "fakeddisorder",
                        "params": {
                            "split_pos": s,
                            "overlap_size": o,
                            "ttl": t,
                            "fooling": fl,
                        },
                    }
                )
            else:
                p0 = random.choice([4, 6, 8, 10])
                gap = random.choice([4, 6, 8, 10, 12])
                positions = [p0, p0 + gap, p0 + 2 * gap]
                exploratory.append(
                    {
                        "type": "multisplit",
                        "params": {
                            "positions": positions,
                            "ttl": random.choice([2, 3]),
                            "fooling": fool,
                        },
                    }
                )

        # ε-greedy: с вероятностью (1-ε) отдаём больше exploitation, с ε — exploration
        if random.random() < (1.0 - self.epsilon):
            pool = base + exploratory[: max(0, count - len(base))]
        else:
            pool = exploratory + base

        # Упрощённая UCT-подобная переоценка по телеметрии если доступна
        # Ожидаем в telemetry_hint ключи: success_by_type: {attack_type: rate}, avg_latency_by_type: {attack_type: ms}
        def score(c):
            a_type = c.get("type")
            succ = 0.0
            lat = 0.0
            if telemetry_hint:
                succ = float(telemetry_hint.get("success_by_type", {}).get(a_type, 0.0))
                lat = float(
                    telemetry_hint.get("avg_latency_by_type", {}).get(a_type, 0.0)
                )
            # Больше успеха и ниже задержка — выше score
            return succ - 0.0005 * lat

        pool.sort(key=score, reverse=True)

        # Возвращаем top-N
        return pool[:count]
