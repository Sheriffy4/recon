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

    def generate(self, kb_recs: Optional[Dict[str, Any]] = None,
                 telemetry_hint: Optional[Dict[str, Any]] = None,
                 count: int = 6) -> List[Dict[str, Any]]:
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

        # Эксплуатация: fakeddisorder и multisplit вокруг KB
        base.extend([
            {"type": "fakeddisorder", "params": {"split_pos": split_pos, "overlap_size": overlap, "ttl": 1, "fooling": fool}},
            {"type": "multisplit", "params": {"positions": [6, 14, 26], "ttl": 2, "fooling": fool}},
        ])

        # Исследование: вариации
        cand = []
        for _ in range(count - len(base)):
            if random.random() < 0.5:
                s = max(2, split_pos + random.choice([-8, -4, 0, 4, 8]))
                o = max(8, min(overlap + random.choice([-64, -32, 0, 32, 64]), 512))
                t = random.choice([1,2,3,4])
                fl = fool[:]
                if random.random() < 0.3:
                    if "badseq" not in fl: fl.append("badseq")
                cand.append({"type": "fakeddisorder", "params": {"split_pos": s, "overlap_size": o, "ttl": t, "fooling": fl}})
            else:
                positions = [6, 14, 26]
                gap = random.choice([4,6,8,10,12])
                positions = [positions[0], positions[0]+gap, positions[0]+2*gap]
                cand.append({"type": "multisplit", "params": {"positions": positions, "ttl": random.choice([2,3]), "fooling": fool}})
        return base + cand[:max(0, count - len(base))]
