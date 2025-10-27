import argparse
import json
import sys
import os
import ipaddress
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import PcapReader, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _recalculate_tcp_checksum(pkt):
    """
    Пересчет TCP checksum и сравнение с оригинальным.
    Возвращает: (original_checksum, is_valid)
    """
    if TCP not in pkt:
        return None, False

    pkt_copy = pkt.copy()
    try:
        del pkt_copy[TCP].chksum
    except Exception:
        pass

    if IP in pkt_copy:
        ip_bytes = bytes(pkt_copy[IP])
        recalculated_csum = IP(ip_bytes)[TCP].chksum
    elif IPv6 in pkt_copy:
        ipv6_bytes = bytes(pkt_copy[IPv6])
        recalculated_csum = IPv6(ipv6_bytes)[TCP].chksum
    else:
        return None, False

    original_csum = pkt[TCP].chksum
    if original_csum is None:
        return None, False

    return original_csum, (original_csum == recalculated_csum)


def packet_to_dict(pkt, pkt_num):
    """
    Конвертирует пакет Scapy в JSON-совместимый словарь. Только для IPv4/IPv6 TCP.
    """
    if not (IP in pkt or IPv6 in pkt):
        return None
    if TCP not in pkt:
        return None

    info = {
        "num": pkt_num,
        "timestamp": float(pkt.time),
        "len": len(pkt),
    }

    if IP in pkt:
        info.update({
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "ttl": pkt[IP].ttl,
            "ip_len": pkt[IP].len,
            "ip_id": pkt[IP].id,
        })
    elif IPv6 in pkt:
        info.update({
            "src_ip": pkt[IPv6].src,
            "dst_ip": pkt[IPv6].dst,
            "ttl": pkt[IPv6].hlim,
        })

    tcp_layer = pkt[TCP]
    original_csum, is_valid = _recalculate_tcp_checksum(pkt)

    payload_len = len(bytes(tcp_layer.payload)) if tcp_layer.payload is not None else 0

    info.update({
        "src_port": tcp_layer.sport,
        "dst_port": tcp_layer.dport,
        "seq": tcp_layer.seq,
        "ack": tcp_layer.ack,
        "flags": str(tcp_layer.flags),
        "window": tcp_layer.window,
        "payload_len": payload_len,
        "tcp_checksum": original_csum,
        "tcp_checksum_valid": is_valid,
    })

    if Raw in tcp_layer:
        try:
            info["payload_hex"] = tcp_layer[Raw].load.hex()
        except Exception:
            info["payload_hex"] = bytes(tcp_layer[Raw].load or b"").hex()

    return info


# ------------------------ Фильтры ------------------------

def _split_csv_tokens(values):
    tokens = []
    for v in values or []:
        for part in str(v).split(","):
            part = part.strip()
            if part:
                tokens.append(part)
    return tokens


def _parse_ip_filters(values):
    tokens = _split_csv_tokens(values)
    nets = []
    for token in tokens:
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError as e:
            raise ValueError(f"Некорректный IP/сеть '{token}': {e}")
    return nets


def _parse_port_filters(values):
    tokens = _split_csv_tokens(values)
    pf = {"exact": set(), "ranges": []}

    def _validate_port(p):
        if not (0 <= p <= 65535):
            raise ValueError(f"Порт вне диапазона [0,65535]: {p}")

    for token in tokens:
        if "-" in token:
            a, b = token.split("-", 1)
            try:
                start = int(a)
                end = int(b)
            except ValueError:
                raise ValueError(f"Некорректный диапазон портов '{token}'")
            _validate_port(start)
            _validate_port(end)
            if start > end:
                start, end = end, start
            pf["ranges"].append((start, end))
        else:
            try:
                p = int(token)
            except ValueError:
                raise ValueError(f"Некорректный порт '{token}'")
            _validate_port(p)
            pf["exact"].add(p)

    return pf


def _ip_in_networks(ip_str, networks):
    if not networks:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in networks:
        if ip_obj.version == net.version and ip_obj in net:
            return True
    return False


def _port_match(port, pf):
    if not pf or (not pf["exact"] and not pf["ranges"]):
        return True
    if port in pf["exact"]:
        return True
    for s, e in pf["ranges"]:
        if s <= port <= e:
            return True
    return False


def _build_filters_from_args(args):
    filters = {
        "ip_any": _parse_ip_filters(args.ip),
        "src_ip": _parse_ip_filters(args.src_ip),
        "dst_ip": _parse_ip_filters(args.dst_ip),
        "port_any": _parse_port_filters(args.port),
        "src_port": _parse_port_filters(args.src_port),
        "dst_port": _parse_port_filters(args.dst_port),
    }
    return filters


def _packet_matches_filters(pkt_dict, flt):
    if not flt:
        return True

    src_ip = pkt_dict["src_ip"]
    dst_ip = pkt_dict["dst_ip"]
    src_port = int(pkt_dict["src_port"])
    dst_port = int(pkt_dict["dst_port"])

    # IP-фильтры
    if flt.get("ip_any"):
        if not (_ip_in_networks(src_ip, flt["ip_any"]) or _ip_in_networks(dst_ip, flt["ip_any"])):
            return False
    if flt.get("src_ip"):
        if not _ip_in_networks(src_ip, flt["src_ip"]):
            return False
    if flt.get("dst_ip"):
        if not _ip_in_networks(dst_ip, flt["dst_ip"]):
            return False

    # Порт-фильтры
    if flt.get("port_any") and (flt["port_any"]["exact"] or flt["port_any"]["ranges"]):
        if not (_port_match(src_port, flt["port_any"]) or _port_match(dst_port, flt["port_any"])):
            return False
    if flt.get("src_port"):
        if not _port_match(src_port, flt["src_port"]):
            return False
    if flt.get("dst_port"):
        if not _port_match(dst_port, flt["dst_port"]):
            return False

    return True


def _filters_to_summary(flt):
    if not flt:
        return {}

    def pf_to_summary(pf):
        if not pf or (not pf["exact"] and not pf["ranges"]):
            return None
        return {
            "exact": sorted(int(p) for p in pf["exact"]),
            "ranges": [f"{a}-{b}" for a, b in pf["ranges"]],
        }

    summary = {}
    if flt.get("ip_any"):
        summary["ip_any"] = [str(n) for n in flt["ip_any"]]
    if flt.get("src_ip"):
        summary["src_ip"] = [str(n) for n in flt["src_ip"]]
    if flt.get("dst_ip"):
        summary["dst_ip"] = [str(n) for n in flt["dst_ip"]]
    if (s := pf_to_summary(flt.get("port_any"))):
        summary["port_any"] = s
    if (s := pf_to_summary(flt.get("src_port"))):
        summary["src_port"] = s
    if (s := pf_to_summary(flt.get("dst_port"))):
        summary["dst_port"] = s

    return summary


# ------------------------ Анализ PCAP ------------------------

def analyze_pcap(pcap_file, filters=None):
    """
    Анализ PCAP: группировка TCP-пакетов по двунаправленным потокам.
    Поддерживает фильтрацию по IP/сети и портам.
    """
    flows = defaultdict(list)
    reader = PcapReader(pcap_file)

    try:
        for i, pkt in enumerate(reader, start=1):
            pkt_dict = packet_to_dict(pkt, i)
            if not pkt_dict:
                continue

            if filters and not _packet_matches_filters(pkt_dict, filters):
                continue

            flow_key_part1 = f"{pkt_dict['src_ip']}:{pkt_dict['src_port']}"
            flow_key_part2 = f"{pkt_dict['dst_ip']}:{pkt_dict['dst_port']}"
            flow_key = tuple(sorted((flow_key_part1, flow_key_part2)))

            flows[flow_key].append(pkt_dict)
    finally:
        try:
            reader.close()
        except Exception:
            pass

    output_flows = {}
    for (end_a, end_b), packets in flows.items():
        output_flows[f"{end_a} <-> {end_b}"] = packets

    result = {
        "pcap_file": os.path.basename(pcap_file),
        "analysis_timestamp": datetime.now().astimezone().isoformat(),
        "total_flows": len(output_flows),
        "flows": output_flows,
    }

    if filters:
        result["filters"] = _filters_to_summary(filters)

    return result


def main():
    if not SCAPY_AVAILABLE:
        print("Ошибка: Scapy не установлен. Установите: pip install scapy", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Анализ PCAP и конвертация TCP-потоков в JSON. Поддержка фильтрации по IP/сети и порту."
    )
    parser.add_argument("pcap_file", help="Путь к входному PCAP-файлу.")
    parser.add_argument("-o", "--output", help="Путь к выходному JSON. Если не указан — вывод в stdout.")

    # Фильтры
    flt = parser.add_argument_group("Фильтры")
    flt.add_argument("--ip", action="append", default=[],
                     help="IP или CIDR для любого конца потока (можно несколько; поддерживается CSV). Пример: --ip 10.0.0.0/8 --ip 192.168.1.10")
    flt.add_argument("--src-ip", action="append", default=[],
                     help="IP или CIDR источника (можно несколько; поддерживается CSV).")
    flt.add_argument("--dst-ip", action="append", default=[],
                     help="IP или CIDR получателя (можно несколько; поддерживается CSV).")
    flt.add_argument("--port", action="append", default=[],
                     help="Порт(ы) или диапазоны для любого конца (можно несколько; CSV). Пример: --port 80,443,10000-10100")
    flt.add_argument("--src-port", action="append", default=[],
                     help="Порт(ы)/диапазоны источника (можно несколько; CSV).")
    flt.add_argument("--dst-port", action="append", default=[],
                     help="Порт(ы)/диапазоны получателя (можно несколько; CSV).")

    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"Ошибка: файл не найден: '{args.pcap_file}'", file=sys.stderr)
        sys.exit(1)

    try:
        filters = _build_filters_from_args(args)
        analysis_result = analyze_pcap(args.pcap_file, filters=filters)
        json_output = json.dumps(analysis_result, indent=2, ensure_ascii=False)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"Готово. Результат сохранён в '{args.output}'")
        else:
            print(json_output)

    except Exception as e:
        print(f"Ошибка при анализе: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
