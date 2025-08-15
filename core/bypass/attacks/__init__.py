# recon/core/bypass/attacks/__init__.py

"""
Bypass attacks module.
Includes all attack implementations for the modernized bypass engine.
"""

# Import DNS attacks to trigger auto-registration
try:
    from .dns import dns_tunneling
except ImportError as e:
    print(f"Failed to import DNS attacks: {e}")

# Import other attack modules
try:
    from . import tcp_fragmentation
except ImportError:
    pass

try:
    from . import http_manipulation
except ImportError:
    pass

try:
    from .tls import tls_evasion
except ImportError:
    pass