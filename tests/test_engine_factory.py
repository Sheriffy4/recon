import unittest
import sys
from unittest import mock

# Add project root to path
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock pydivert before other imports
sys.modules["pydivert"] = mock.Mock()

from core.bypass.engine.factory import BypassEngineFactory
from core.bypass.engine.windows_engine import WindowsBypassEngine


class TestBypassEngineFactory(unittest.TestCase):

    @mock.patch("platform.system", return_value="Windows")
    def test_create_windows_engine_on_windows(self, mock_system):
        """Test that WindowsBypassEngine is created on Windows platform."""
        factory = BypassEngineFactory()
        engine = factory.create_engine(debug=False)
        self.assertIsInstance(engine, WindowsBypassEngine)

    @mock.patch("platform.system", return_value="Linux")
    def test_create_no_engine_on_linux(self, mock_system):
        """Test that no engine is created on an unsupported platform like Linux."""
        factory = BypassEngineFactory()
        engine = factory.create_engine(debug=False)
        self.assertIsNone(engine)

    @mock.patch("platform.system", return_value="Darwin")
    def test_create_no_engine_on_macos(self, mock_system):
        """Test that no engine is created on an unsupported platform like macOS."""
        factory = BypassEngineFactory()
        engine = factory.create_engine(debug=False)
        self.assertIsNone(engine)

    @mock.patch("platform.system", return_value="Linux")
    def test_force_windows_engine_override(self, mock_system):
        """Test that the engine_type override forces creation of WindowsBypassEngine."""
        factory = BypassEngineFactory()
        # Even though platform is mocked to Linux, the override should take precedence
        engine = factory.create_engine(debug=False, engine_type="windows")
        self.assertIsInstance(engine, WindowsBypassEngine)

    @mock.patch("platform.system", return_value="Windows")
    def test_force_unsupported_engine_override(self, mock_system):
        """Test that the engine_type override returns None for unsupported types."""
        factory = BypassEngineFactory()
        engine = factory.create_engine(debug=False, engine_type="linux")
        self.assertIsNone(engine)


if __name__ == "__main__":
    unittest.main()
