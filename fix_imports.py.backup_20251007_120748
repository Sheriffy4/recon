import os
import sys

# The list of replacements to be made
# Order matters, more specific should come first.
REPLACEMENTS = [
    # Remove __package__ declarations
    ("__package__ = 'recon'", ""),
    # Specific recon imports
    ("from recon.core.", "from core."),
    ("import recon.core.", "import core."),
    ("from recon.tests.", "from tests."),
    ("import recon.tests.", "import tests."),
    ("from recon.base ", "from core.bypass.attacks.base "),
    ("from recon.attacks.base ", "from core.bypass.attacks.base "),
    ("from recon.ml.", "from ml."),
    ("from recon.dns.", "from core.dns."),
    ("from recon.fingerprint.", "from core.fingerprint."),
    ("from recon.integration.", "from core.integration."),
    ("from recon.net.", "from core.net."),
    ("from recon.cli", "from cli"),
    # Root level modules
    ("from recon.quic_handler", "from quic_handler"),
    ("from recon.signature_manager", "from signature_manager"),
    ("from recon.apply_bypass", "from apply_bypass"),
    ("from recon import config", "import config"),
    # Broken relative imports in tests
    ("from base import", "from core.bypass.attacks.base import"),
    ("from advanced_models import", "from core.fingerprint.advanced_models import"),
    ("from mode_controller import", "from core.bypass.modes.mode_controller import"),
    ("from online_learning import", "from core.fingerprint.online_learning import"),
    (
        "from reliability_validator import",
        "from core.bypass.validation.reliability_validator import",
    ),
    (
        "from social_media_handler import",
        "from core.bypass.strategies.social_media_handler import",
    ),
    (
        "from subdomain_handler import",
        "from core.bypass.strategies.subdomain_handler import",
    ),
    (
        "from tcp_fragmentation import",
        "from core.bypass.attacks.tcp_fragmentation import",
    ),
    ("from attack_catalog import", "from core.bypass.attacks.attack_catalog import"),
    ("import pool_management", "from core.bypass.strategies import pool_management"),
    # Imports from tests.*
    (
        "from tests.attack_definition import",
        "from core.bypass.attacks.attack_definition import",
    ),
    (
        "from tests.modern_registry import",
        "from core.bypass.attacks.modern_registry import",
    ),
    ("from tests.base import", "from core.bypass.attacks.base import"),
    ("from tests.bypass_api import", "from web.bypass_api import"),
    ("from tests.bypass_dashboard import", "from web.bypass_dashboard import"),
    ("from tests.bypass_integration import", "from web.bypass_integration import"),
    ("from tests.cache import", "from core.fingerprint.cache import"),
    (
        "from tests.tool_detector import",
        "from core.bypass.compatibility.tool_detector import",
    ),
    (
        "from tests.zapret_parser import",
        "from core.bypass.compatibility.zapret_parser import",
    ),
    (
        "from tests.goodbyedpi_parser import",
        "from core.bypass.compatibility.goodbyedpi_parser import",
    ),
    (
        "from tests.byebyedpi_parser import",
        "from core.bypass.compatibility.byebyedpi_parser import",
    ),
    (
        "from tests.syntax_converter import",
        "from core.bypass.compatibility.syntax_converter import",
    ),
    (
        "from tests.compatibility_bridge import",
        "from core.bypass.compatibility.compatibility_bridge import",
    ),
    ("from tests.config_models import", "from core.bypass.config.config_models import"),
    (
        "from tests.config_migrator import",
        "from core.bypass.config.config_migrator import",
    ),
    (
        "from tests.config_validator import",
        "from core.bypass.config.config_validator import",
    ),
    (
        "from tests.config_manager import",
        "from core.bypass.config.config_manager import",
    ),
    (
        "from tests.backup_manager import",
        "from core.bypass.config.backup_manager import",
    ),
    ("from tests.dns_analyzer import", "from core.fingerprint.dns_analyzer import"),
    (
        "from tests.dns_tunneling import",
        "from core.bypass.attacks.dns.dns_tunneling import",
    ),
    (
        "from tests.dpi_behavior_monitor import",
        "from core.fingerprint.dpi_behavior_monitor import",
    ),
    (
        "from tests.advanced_fingerprinter import",
        "from core.fingerprint.advanced_fingerprinter import",
    ),
    ("from tests.http_analyzer import", "from core.fingerprint.http_analyzer import"),
    (
        "from tests.metrics_collector import",
        "from core.fingerprint.metrics_collector import",
    ),
    ("from tests.ml_classifier import", "from core.fingerprint.ml_classifier import"),
    (
        "from tests.capability_detector import",
        "from core.bypass.modes.capability_detector import",
    ),
    (
        "from tests.mode_transition import",
        "from core.bypass.modes.mode_transition import",
    ),
    ("from tests.exceptions import", "from core.bypass.exceptions import"),
    ("from tests.hybrid_engine import", "from core.hybrid_engine import"),
    ("from tests.monitoring_system import", "from core.monitoring_system import"),
    (
        "from tests.bypass.attacks.modern_registry import",
        "from core.bypass.attacks.modern_registry import",
    ),
    (
        "from tests.bypass.strategies.pool_management import",
        "from core.bypass.strategies.pool_management import",
    ),
    (
        "from tests.bypass.modes.mode_controller import",
        "from core.bypass.modes.mode_controller import",
    ),
    (
        "from tests.bypass.validation.reliability_validator import",
        "from core.bypass.validation.reliability_validator import",
    ),
    (
        "from tests.multi_port_handler import",
        "from core.bypass.protocols.multi_port_handler import",
    ),
    (
        "from tests.performance_optimizer import",
        "from core.bypass.performance.performance_optimizer import",
    ),
    (
        "from tests.strategy_optimizer import",
        "from core.bypass.performance.strategy_optimizer import",
    ),
    (
        "from tests.production_monitor import",
        "from core.bypass.performance.production_monitor import",
    ),
    (
        "from tests.alerting_system import",
        "from core.bypass.performance.alerting_system import",
    ),
    (
        "from tests.performance_models import",
        "from core.bypass.performance.performance_models import",
    ),
    (
        "from tests.pool_management import",
        "from core.bypass.strategies.pool_management import",
    ),
    (
        "from tests.safety_controller import",
        "from core.bypass.safety.safety_controller import",
    ),
    (
        "from tests.resource_manager import",
        "from core.bypass.safety.resource_manager import",
    ),
    (
        "from tests.attack_sandbox import",
        "from core.bypass.safety.attack_sandbox import",
    ),
    (
        "from tests.emergency_stop import",
        "from core.bypass.safety.emergency_stop import",
    ),
    (
        "from tests.safety_validator import",
        "from core.bypass.safety.safety_validator import",
    ),
    (
        "from tests.sharing_models import",
        "from core.bypass.sharing.sharing_models import",
    ),
    (
        "from tests.strategy_validator import",
        "from core.bypass.sharing.strategy_validator import",
    ),
    (
        "from tests.community_database import",
        "from core.bypass.sharing.community_database import",
    ),
    (
        "from tests.update_manager import",
        "from core.bypass.sharing.update_manager import",
    ),
    (
        "from tests.sharing_manager import",
        "from core.bypass.sharing.sharing_manager import",
    ),
    (
        "from tests.strategy_application import",
        "from core.bypass.strategies.strategy_application import",
    ),
    ("from tests.tcp_analyzer import", "from core.fingerprint.tcp_analyzer import"),
    (
        "from tests.manipulation import",
        "from core.bypass.attacks.tcp.manipulation import",
    ),
    ("from tests.timing import", "from core.bypass.attacks.timing.base import"),
    ("from tests.fooling import", "from core.bypass.attacks.tcp.fooling import"),
    ("from tests.timing_base import", "from core.bypass.attacks.timing.base import"),
    (
        "from tests.jitter_injection import",
        "from core.bypass.attacks.timing.jitter_injection import",
    ),
    (
        "from tests.delay_evasion import",
        "from core.bypass.attacks.timing.delay_evasion import",
    ),
    (
        "from tests.burst_traffic import",
        "from core.bypass.attacks.timing.burst_traffic import",
    ),
    ("from tests.tls_evasion import", "from core.bypass.attacks.tls.evasion import"),
    ("from tests.training_data import", "from ml.training_data import"),
    ("from tests.model_trainer import", "from ml.model_trainer import"),
]


def get_all_python_files(scan_path):
    """Returns a list of all python files in the given path."""
    py_files = []
    excluded_dirs = [
        "__pycache__",
        ".git",
        ".idea",
        "venv",
        "env",
        "build",
        "dist",
        "eggs",
        ".eggs",
        "lib",
        "lib64",
        "parts",
        "sdist",
        "var",
        "wheels",
        "share/python-wheels",
        ".tox",
        ".nox",
        ".hypothesis",
        ".pytest_cache",
        "site",
    ]

    if os.path.isfile(scan_path) and scan_path.endswith(".py"):
        if os.path.basename(scan_path) != "fix_imports.py":
            return [scan_path]
        return []

    if os.path.isdir(scan_path):
        for root, dirs, files in os.walk(scan_path):
            # Exclude directories
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            for file in files:
                if file.endswith(".py"):
                    # ignore self
                    if file == "fix_imports.py":
                        continue
                    py_files.append(os.path.join(root, file))
    return py_files


def fix_imports_in_file(filepath):
    """Reads a file, applies replacements, and writes it back."""
    try:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(filepath, "r", encoding="latin-1") as f:
                content = f.read()

        original_content = content
        changed = False
        for old, new in REPLACEMENTS:
            if old in content:
                content = content.replace(old, new)
                changed = True

        if changed:
            print(f"Fixing imports in {filepath}")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

    except Exception as e:
        print(f"Could not process file {filepath}: {e}")
        return


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fix_imports.py <path_to_scan>")
        sys.exit(1)

    path_to_scan = sys.argv[1]
    if path_to_scan == "all":
        path_to_scan = "."

    all_files = get_all_python_files(path_to_scan)
    print(f"Found {len(all_files)} python files to check in {path_to_scan}.")
    for f in all_files:
        fix_imports_in_file(f)
    print("Import fixing script finished.")
