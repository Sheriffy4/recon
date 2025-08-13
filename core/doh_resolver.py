# recon/core/doh_resolver.py
import requests
import json
import socket
from typing import Optional
import logging

LOG = logging.getLogger("doh_resolver")

class DoHResolver:
    """DNS резолвер через DoH для обхода провайдерской фильтрации."""
    
    DOH_SERVERS = {
        'cloudflare': 'https://1.1.1.1/dns-query',
        'google': 'https://8.8.8.8/resolve',
        'quad9': 'https://9.9.9.9/dns-query'
    }
    
    def __init__(self, server='cloudflare'):
        self.server_url = self.DOH_SERVERS.get(server, self.DOH_SERVERS['cloudflare'])
        self.cache = {}
        
    def resolve(self, hostname: str) -> Optional[str]:
        """Резолвит hostname через DoH."""
        if hostname in self.cache:
            return self.cache[hostname]
            
        try:
            if 'google' in self.server_url:
                response = requests.get(
                    self.server_url,
                    params={'name': hostname, 'type': 'A'},
                    headers={'Accept': 'application/dns-json'},
                    timeout=5
                )
                data = response.json()
                if 'Answer' in data:
                    ip = data['Answer'][0]['data']
                    self.cache[hostname] = ip
                    LOG.info(f"Resolved {hostname} -> {ip} via DoH")
                    return ip
            else:
                response = requests.get(
                    self.server_url,
                    params={'name': hostname, 'type': 'A'},
                    headers={'accept': 'application/dns-json'},
                    timeout=5
                )
                data = response.json()
                if data.get('Answer'):
                    ip = data['Answer'][0]['data']
                    self.cache[hostname] = ip
                    LOG.info(f"Resolved {hostname} -> {ip} via DoH")
                    return ip
                    
        except Exception as e:
            LOG.error(f"DoH resolution failed for {hostname}: {e}")
            
        try:
            ip = socket.gethostbyname(hostname)
            LOG.warning(f"Used fallback system DNS for {hostname} -> {ip}")
            self.cache[hostname] = ip
            return ip
        except Exception:
            LOG.error(f"System DNS fallback failed for {hostname}")
            return None