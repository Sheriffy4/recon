# recon/core/windivert_driver_fix.py
"""
WinDivert Driver Fix and Management

This module provides tools to diagnose and fix WinDivert driver issues
that prevent the DPI bypass system from starting.
"""

import sys
import logging
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

LOG = logging.getLogger("WinDivertDriverFix")


@dataclass
class DriverStatus:
    """WinDivert driver status information."""

    is_installed: bool
    is_running: bool
    files_present: bool
    version: Optional[str]
    error_message: Optional[str]
    recommendations: List[str]


class WinDivertDriverManager:
    """Manages WinDivert driver installation and status."""

    def __init__(self):
        self.logger = LOG
        self.required_files = ["WinDivert.dll", "WinDivert64.sys", "WinDivert32.sys"]

    def diagnose_driver_issues(self) -> DriverStatus:
        """
        Comprehensive diagnosis of WinDivert driver issues.

        Returns:
            DriverStatus with detailed information and recommendations
        """
        self.logger.info("🔍 Diagnosing WinDivert driver issues...")

        # Check if files are present
        files_present = self._check_driver_files()

        # Check service status
        is_installed, is_running, service_error = self._check_service_status()

        # Check PyDivert functionality
        pydivert_works, pydivert_error = self._test_pydivert_functionality()

        # Determine version
        version = self._get_driver_version()

        # Generate recommendations
        recommendations = self._generate_recommendations(
            files_present,
            is_installed,
            is_running,
            pydivert_works,
            service_error,
            pydivert_error,
        )

        error_message = None
        if service_error:
            error_message = f"Service error: {service_error}"
        elif pydivert_error:
            error_message = f"PyDivert error: {pydivert_error}"

        status = DriverStatus(
            is_installed=is_installed,
            is_running=is_running,
            files_present=files_present,
            version=version,
            error_message=error_message,
            recommendations=recommendations,
        )

        self._log_diagnosis_results(status)
        return status

    def _check_driver_files(self) -> bool:
        """Check if WinDivert driver files are present."""
        self.logger.debug("Checking WinDivert driver files...")

        # Check in current directory
        current_dir = Path.cwd()
        files_in_current = [current_dir / filename for filename in self.required_files]

        # Check in Python site-packages (where PyDivert might install them)
        try:
            import pydivert

            pydivert_dir = Path(pydivert.__file__).parent
            files_in_pydivert = [
                pydivert_dir / filename for filename in self.required_files
            ]
        except ImportError:
            files_in_pydivert = []

        # Check if any location has the files
        all_files = files_in_current + files_in_pydivert

        present_files = [f for f in all_files if f.exists()]

        self.logger.debug(f"Found {len(present_files)} driver files")
        for file in present_files:
            self.logger.debug(f"  ✓ {file}")

        # We need at least WinDivert.dll and one .sys file
        has_dll = any("WinDivert.dll" in str(f) for f in present_files)
        has_sys = any(".sys" in str(f) for f in present_files)

        return has_dll and has_sys

    def _check_service_status(self) -> Tuple[bool, bool, Optional[str]]:
        """
        Check WinDivert service status.

        Returns:
            Tuple of (is_installed, is_running, error_message)
        """
        self.logger.debug("Checking WinDivert service status...")

        try:
            # Try to query the service
            result = subprocess.run(
                ["sc", "query", "WinDivert"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                output = result.stdout.lower()
                is_installed = True
                is_running = "running" in output
                return is_installed, is_running, None
            else:
                # Service doesn't exist or other error
                error_msg = result.stderr.strip()
                if "does not exist" in error_msg.lower():
                    return False, False, "Service not installed"
                else:
                    return False, False, f"Service query failed: {error_msg}"

        except subprocess.TimeoutExpired:
            return False, False, "Service query timed out"
        except FileNotFoundError:
            return False, False, "sc.exe not found (not Windows?)"
        except Exception as e:
            return False, False, f"Unexpected error: {e}"

    def _test_pydivert_functionality(self) -> Tuple[bool, Optional[str]]:
        """
        Test if PyDivert can actually create a handle.

        Returns:
            Tuple of (works, error_message)
        """
        self.logger.debug("Testing PyDivert functionality...")

        try:
            import pydivert

            # Try to create a simple handle that won't capture anything
            with pydivert.WinDivert("false") as w:
                pass

            return True, None

        except ImportError:
            return False, "PyDivert not installed"
        except OSError as e:
            if e.winerror == 5:
                return False, "Access denied - need administrator privileges"
            elif e.winerror == 2:
                return False, "Driver files not found"
            elif e.winerror == 87:
                return False, "Invalid parameter - driver may be corrupted"
            else:
                return False, f"OS Error {e.winerror}: {e}"
        except Exception as e:
            return False, f"Unexpected error: {e}"

    def _get_driver_version(self) -> Optional[str]:
        """Get WinDivert driver version if available."""
        try:
            import pydivert

            return getattr(pydivert, "__version__", "unknown")
        except ImportError:
            return None

    def _generate_recommendations(
        self,
        files_present: bool,
        is_installed: bool,
        is_running: bool,
        pydivert_works: bool,
        service_error: Optional[str],
        pydivert_error: Optional[str],
    ) -> List[str]:
        """Generate specific recommendations based on diagnosis."""
        recommendations = []

        if not files_present:
            recommendations.append(
                "Install PyDivert with driver files: pip install pydivert"
            )
            recommendations.append(
                "Ensure WinDivert.dll and .sys files are in the application directory"
            )

        if not pydivert_works:
            if "administrator" in (pydivert_error or "").lower():
                recommendations.append("Run the application as Administrator")
            elif "not found" in (pydivert_error or "").lower():
                recommendations.append(
                    "Reinstall PyDivert: pip uninstall pydivert && pip install pydivert"
                )
            elif "invalid parameter" in (pydivert_error or "").lower():
                recommendations.append("Driver may be corrupted - reinstall PyDivert")
                recommendations.append(
                    "Try running: pip uninstall pydivert && pip install pydivert --force-reinstall"
                )

        if not is_installed and files_present:
            recommendations.append(
                "WinDivert service is not installed but files are present"
            )
            recommendations.append(
                "This is normal - WinDivert loads on-demand, not as a service"
            )

        # Add general troubleshooting steps
        if not pydivert_works:
            recommendations.append(
                "Check Windows Defender or antivirus - they may block WinDivert"
            )
            recommendations.append("Ensure Windows is up to date")
            recommendations.append(
                "Try restarting the application after making changes"
            )

        return recommendations

    def _log_diagnosis_results(self, status: DriverStatus) -> None:
        """Log detailed diagnosis results."""
        self.logger.info("🔍 WinDivert Driver Diagnosis Results:")
        self.logger.info(f"  Files Present: {'✅' if status.files_present else '❌'}")
        self.logger.info(
            f"  Service Installed: {'✅' if status.is_installed else '❌'}"
        )
        self.logger.info(f"  Service Running: {'✅' if status.is_running else '❌'}")

        if status.version:
            self.logger.info(f"  Version: {status.version}")

        if status.error_message:
            self.logger.error(f"  Error: {status.error_message}")

        if status.recommendations:
            self.logger.info("  Recommendations:")
            for i, rec in enumerate(status.recommendations, 1):
                self.logger.info(f"    {i}. {rec}")

    def attempt_driver_fix(self) -> bool:
        """
        Attempt to automatically fix common WinDivert driver issues.

        Returns:
            True if fix was successful, False otherwise
        """
        self.logger.info("🔧 Attempting to fix WinDivert driver issues...")

        status = self.diagnose_driver_issues()

        if not status.files_present:
            self.logger.info("Attempting to reinstall PyDivert...")
            if self._reinstall_pydivert():
                self.logger.info("✅ PyDivert reinstalled successfully")
                # Re-test
                works, error = self._test_pydivert_functionality()
                if works:
                    self.logger.info("✅ WinDivert is now working!")
                    return True
                else:
                    self.logger.error(f"❌ WinDivert still not working: {error}")
            else:
                self.logger.error("❌ Failed to reinstall PyDivert")

        return False

    def _reinstall_pydivert(self) -> bool:
        """Attempt to reinstall PyDivert."""
        try:
            # Uninstall first
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "pydivert", "-y"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Install again
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "pydivert",
                    "--force-reinstall",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            return result.returncode == 0

        except Exception as e:
            self.logger.error(f"Error during PyDivert reinstall: {e}")
            return False


def fix_windivert_driver_issues() -> bool:
    """
    Main function to diagnose and fix WinDivert driver issues.

    Returns:
        True if issues were resolved, False otherwise
    """
    manager = WinDivertDriverManager()

    # First, diagnose the issues
    status = manager.diagnose_driver_issues()

    # If PyDivert is working, no fix needed
    pydivert_works, _ = manager._test_pydivert_functionality()
    if pydivert_works:
        LOG.info("✅ WinDivert is working correctly - no fix needed")
        return True

    # Attempt automatic fix
    return manager.attempt_driver_fix()


if __name__ == "__main__":
    # Run diagnosis when executed directly
    import argparse

    parser = argparse.ArgumentParser(description="WinDivert Driver Fix")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.fix:
        success = fix_windivert_driver_issues()
        sys.exit(0 if success else 1)
    else:
        manager = WinDivertDriverManager()
        status = manager.diagnose_driver_issues()

        # Exit with appropriate code
        if not status.files_present:
            sys.exit(2)  # Files missing
        else:
            pydivert_works, _ = manager._test_pydivert_functionality()
            sys.exit(0 if pydivert_works else 1)
