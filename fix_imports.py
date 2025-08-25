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
    ("from reliability_validator import", "from core.bypass.validation.reliability_validator import"),
    ("from social_media_handler import", "from core.bypass.strategies.social_media_handler import"),
    ("from subdomain_handler import", "from core.bypass.strategies.subdomain_handler import"),
    ("from tcp_fragmentation import", "from core.bypass.attacks.tcp_fragmentation import"),
    ("from attack_catalog import", "from core.bypass.attacks.attack_catalog import"),
    ("import pool_management", "from core.bypass.strategies import pool_management"),
]

def get_all_python_files(scan_path):
    """Returns a list of all python files in the given path."""
    py_files = []
    excluded_dirs = ['__pycache__', '.git', '.idea', 'venv', 'env', 'build', 'dist', 'eggs', '.eggs', 'lib', 'lib64', 'parts', 'sdist', 'var', 'wheels', 'share/python-wheels', '.tox', '.nox', '.hypothesis', '.pytest_cache', 'site']

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
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                content = f.read()
        except Exception as e:
            print(f"Could not read file {filepath}: {e}")
            return


    original_content = content
    changed = False
    for old, new in REPLACEMENTS:
        if old in content:
            content = content.replace(old, new)
            changed = True


    if changed:
        print(f"Fixing imports in {filepath}")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fix_imports.py <path_to_scan>")
        sys.exit(1)

    path_to_scan = sys.argv[1]
    if path_to_scan == 'all':
        path_to_scan = '.'

    all_files = get_all_python_files(path_to_scan)
    print(f"Found {len(all_files)} python files to check in {path_to_scan}.")
    for f in all_files:
        fix_imports_in_file(f)
    print("Import fixing script finished.")
