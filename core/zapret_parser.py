# recon/core/zapret_parser.py
import re
import logging
from typing import Dict, Any

LOG = logging.getLogger("zapret_parser")


class ZapretStrategyParser:
    """
    Парсит полную строку стратегии zapret в структурированный словарь параметров.
    ИСПРАВЛЕНО: Финальная версия с корректной обработкой всех типов флагов.
    """

    def parse(self, strategy: str) -> Dict[str, Any]:
        """
        Парсит строку стратегии zapret в структурированный формат.
        """
        params = {
            "dpi_desync": [],
            "dpi_desync_fooling": [],
            "dpi_desync_ttl": None,
            "dpi_desync_autottl": None,
            "dpi_desync_split_pos": [],
            "dpi_desync_split_seqovl": None,
            "dpi_desync_repeats": 1,
            "dpi_desync_fake_tls": None,
            "dpi_desync_fake_tls_mod": [],
            "dpi_desync_fake_http": None,
            "dpi_desync_fake_syndata": None,
            "dpi_desync_badseq_increment": -10000,
            "dpi_desync_split_count": None,
            "wssize": None,
        }

        # --- ОБЩАЯ ЛОГИКА ПАРСИНГА ---

        # 1. Простые списки через запятую
        match = re.search(r"--dpi-desync=([^\s]+)", strategy)
        if match:
            params["dpi_desync"] = match.group(1).split(",")

        match = re.search(r"--dpi-desync-fooling=([^\s]+)", strategy)
        if match:
            params["dpi_desync_fooling"] = match.group(1).split(",")

        # 2. Числовые параметры (всегда имеют значение)
        num_params = {
            "ttl": "dpi_desync_ttl",
            "repeats": "dpi_desync_repeats",
            "split-seqovl": "dpi_desync_split_seqovl",
            "badseq-increment": "dpi_desync_badseq_increment",
            "split-count": "dpi_desync_split_count",
        }
        for param_name, key in num_params.items():
            match = re.search(rf"--dpi-desync-{param_name}=([-\d]+)", strategy)
            if match:
                try:
                    params[key] = int(match.group(1))
                except ValueError:
                    LOG.warning(f"Could not parse integer for {param_name}")

        # 3. Флаги, которые могут быть с значением или без (autottl, fake-tls и т.д.)
        flag_params = {
            "autottl": "dpi_desync_autottl",
            "fake-tls": "dpi_desync_fake_tls",
            "fake-http": "dpi_desync_fake_http",
            "fake-syndata": "dpi_desync_fake_syndata",
        }
        for param_name, key in flag_params.items():
            match = re.search(
                rf"--dpi-desync-{param_name}(?:=([^\s]+))?(?:\s|$)", strategy
            )
            if match:
                value = match.group(1)
                if value is not None:
                    try:
                        params[key] = int(value)
                    except ValueError:
                        params[key] = value
                else:
                    params[key] = 2 if key == "dpi_desync_autottl" else True

        # 4. Парсинг позиций для сплита
        match = re.search(r"--dpi-desync-split-pos=([^\s]+)", strategy)
        if match:
            positions_str = match.group(1).split(",")
            parsed_positions = []
            for pos in positions_str:
                if pos == "midsld":
                    parsed_positions.append({"type": "midsld"})
                elif pos.isdigit() or (pos.startswith("-") and pos[1:].isdigit()):
                    parsed_positions.append({"type": "absolute", "value": int(pos)})
            params["dpi_desync_split_pos"] = parsed_positions

        # 5. QUIC fragmentation parameters
        q_params = {
            "quic-frag": "quic_frag",
            "quic-fragment": "quic_fragment",
        }
        for param_name, key in q_params.items():
            match = re.search(rf"--{param_name}=([-\d]+)", strategy)
            if match:
                try:
                    # Use the key directly, not a new one
                    params[key] = int(match.group(1))
                except ValueError:
                    LOG.warning(f"Could not parse integer for {param_name}")

        return params
