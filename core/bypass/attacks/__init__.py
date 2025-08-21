# recon/core/bypass/attacks/__init__.py

"""
Bypass attacks module.
Includes all attack implementations for the modernized bypass engine.
"""
import importlib
import pkgutil

# Discover and import all attack modules dynamically
def import_submodules(package_name):
    """ Import all submodules of a module, recursively """
    package = importlib.import_module(package_name)
    for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + '.'):
        if not is_pkg:
            try:
                importlib.import_module(module_name)
            except ImportError as e:
                print(f"Failed to import attack module {module_name}: {e}")

# Import all attack modules to trigger auto-registration
import_submodules(__name__)
