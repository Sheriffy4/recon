#!/usr/bin/env python3
"""
Attack Recipe Validator - проверяет соответствие "рецепта" атаки реальным действиям.

Как рецепт омлета: если написано "3 яйца + соль + перец", то в сковороде должно быть именно это!

Шаги:
1. Читает лог и находит все [PACKET_SENT] записи для конкретного домена
2. Читает PCAP и фильтрует только пакеты к этому домену
3. Сопоставляет по timestamp, seq, dst_ip
4. Проверяет "рецепт" атаки - соответствуют ли параметры реальным пакетам
"""

import json
import re
import sys
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from scapy.all import rdpcap, IP, TCP
import time


@dataclass
class LoggedPacket:
    """Пакет из лога [PACKET_SENT]"""
    timestamp: float
    packet_type: str  # FAKE или REAL
    attack_type: str
    domain: str
    dst_ip: str
    dst_port: int
    seq: int
    ack: int
    ttl: int
    flags: int
    payload_len: int
    params: dict
    
    def __repr__(self):
        return f"LoggedPacket(type={self.packet_type}, domain={self.domain}, dst_ip={self.dst_ip})"