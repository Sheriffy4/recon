# core/orchestrator.py
import asyncio
import logging
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass

LOG = logging.getLogger("AutonomousOrchestrator")

try:
    from core.hybrid_engine import HybridEngine
except Exception:
    HybridEngine = None

try:
    from core.strategy_synthesizer import StrategySynthesizer, AttackContext
except Exception:
    StrategySynthesizer = None
    AttackContext = None

try:
    from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
    from core.fingerprint.advanced_models import DPIFingerprint
except Exception:
    AdvancedFingerprinter = None
    FingerprintingConfig = None
    DPIFingerprint = None

try:
    from core.pcap.enhanced_packet_capturer import create_enhanced_capturer
except Exception:
    create_enhanced_capturer = None

try:
    from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase
except Exception:
    CdnAsnKnowledgeBase = None


@dataclass
class OrchestratorConfig:
    profile: str = "speedy"  # 'speedy' | 'robust'
    enable_autopcap: bool = True
    pcap_max_seconds: int = 10
    parallel: int = 10


class AutonomousStrategyOrchestrator:
    def __init__(self, cfg: Optional[OrchestratorConfig] = None, debug: bool = False):
        self.cfg = cfg or OrchestratorConfig()
        self.debug = debug
        self.engine = HybridEngine(debug=debug) if HybridEngine else None
        self.synth = StrategySynthesizer() if StrategySynthesizer else None
        self.kb = CdnAsnKnowledgeBase() if CdnAsnKnowledgeBase else None

        # Fingerprinter
        self.fp = None
        if AdvancedFingerprinter and FingerprintingConfig:
            fcfg = FingerprintingConfig(
                analysis_level='balanced',
                max_parallel_targets=self.cfg.parallel,
                enable_fail_fast=True
            )
            self.fp = AdvancedFingerprinter(config=fcfg)

    async def find_best_strategy_for_domain(self, domain: str, dns_cache: Dict[str, str], port: int = 443) -> Optional[Dict[str, Any]]:
        if not (self.engine and self.synth):
            LOG.error("Required components are not available")
            return None

        ip = dns_cache.get(domain)
        if not ip:
            LOG.warning(f"No IP for {domain}")
            return None

        # 1) Фингерпринтинг
        dpi_fp = None
        try:
            if self.fp:
                dpi_fp = await self.fp.fingerprint_target(domain, port=port)
        except Exception as e:
            LOG.debug(f"Fingerprint failed: {e}")

        # 2) KB профиль
        kb_profile = {}
        cdn = None
        asn = None
        try:
            if self.kb:
                kb_profile = self.kb.identify(ip) or {}
                cdn = kb_profile.get("cdn")
                asn = kb_profile.get("asn")
        except Exception:
            pass

        # 3) Синтез стратегии
        ctx = AttackContext(
            domain=domain,
            dst_ip=ip,
            port=port,
            fingerprint=dpi_fp,
            tls_clienthello=None,
            cdn=cdn,
            asn=asn,
            kb_profile=kb_profile
        )
        engine_task = self.synth.synthesize(ctx, profile=self.cfg.profile)

        # 4) Исполнение
        test_sites = [f"https://{domain}"]
        ips: Set[str] = {ip}
        capturer = None
        if self.cfg.enable_autopcap and create_enhanced_capturer:
            try:
                pcap_path = f"orchestrator_auto_{domain.replace('.', '_')}.pcap"
                capturer = create_enhanced_capturer(pcap_path, ips, port)
                capturer.start()
            except Exception:
                capturer = None

        try:
            # В HybridEngine ожидается либо zapret-строка, либо dict engine_task
            # Используем dict напрямую
            res_status, succ, total, avg_lat = await self.engine.execute_strategy_real_world(
                engine_task, test_sites, ips, dns_cache, port
            )
            LOG.info(f"Exec result for {domain}: {succ}/{total}, avg={avg_lat:.1f}ms")
        except Exception as e:
            LOG.error(f"Execution failed for {domain}: {e}")
            res_status, succ, total, avg_lat = ("ERROR", 0, 1, 0.0)

        # 5) Post‑фаза: авто‑PCAP + KB update
        if capturer:
            try:
                capturer.stop()
            except Exception:
                pass

        try:
            # Обновление KB: при успехе — повысить «confidence» best_fakeddisorder и т.п.
            if self.kb and succ > 0:
                # Простейший апдейт: сохраняем используемый task
                self.kb.update_with_success(domain, ip, engine_task, score=1.0)
            elif self.kb:
                self.kb.update_with_failure(domain, ip, engine_task)
        except Exception:
            pass

        return engine_task if succ > 0 else None
