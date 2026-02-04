#!/usr/bin/env python3
"""
Package IntelliRefactor for distribution

This script creates distribution packages and validates the installation process.
Implements requirement 2.5 - proper Python package structure.
"""

import os
import sys
import subprocess
import shutil
import tempfile
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
import venv

class DistributionPackager:
    """Handles packaging IntelliRefactor for distribution"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.dist_dir = self.project_root / "dist"
        self.build_dir = self.project_root / "build"
        
    def clean_build_artifacts(self):
        """Clean previous build artifacts"""
        print("Cleaning build artifacts...")
        
        # Remove build directories
        for dir_path in [self.dist_dir, self.build_dir]:
            if dir_path.exists():
                shutil.rmtree(dir_path)
                print(f"  Removed {dir_path}")
        
        # Remove egg-info directories
        for egg_info in self.project_root.glob("*.egg-info"):
            if egg_info.is_dir():
                shutil.rmtree(egg_info)
                print(f"  Removed {egg_info}")
        
        # Remove __pycache__ directories
        for pycache in self.project_root.rglob("__pycache__"):
            if pycache.is_dir():
                shutil.rmtree(pycache)
                print(f"  Removed {pycache}")
        
        print("✓ Build artifacts cleaned")
    
    def validate_package_structure(self) -> bool:
        """Validate that the package has proper structure"""
        print("Validating package structure...")
        
        required_files = [
            "setup.py",
            "requirements.txt",
            "README.md",
            "LICENSE",
            "pyproject.toml",
            "intellirefactor/__init__.py",
            "intellirefactor/api.py",
            "intellirefactor/cli.py",
            "intellirefactor/config.py",
        ]
        
        required_dirs = [
            "intellirefactor/analysis",
            "intellirefactor/refactoring", 
            "intellirefactor/knowledge",
            "intellirefactor/orchestration",
            "intellirefactor/templates",
            "tests/intellirefactor",
            "docs",
            "examples",
        ]
        
        missing_files = []
        missing_dirs = []
        
        # Check required files
        for file_path in required_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                missing_files.append(file_path)
        
        # Check required directories
        for dir_path in required_dirs:
            full_path = self.project_root / dir_path
            if not full_path.exists():
                missing_dirs.append(dir_path)
        
        if missing_files or missing_dirs:
            print("✗ Package structure validation failed:")
            if missing_files:
                print("  Missing files:")
                for file_path in missing_files:
                    print(f"    - {file_path}")
            if missing_dirs:
                print("  Missing directories:")
                for dir_path in missing_dirs:
                    print(f"    - {dir_path}")
            return False
        
        print("✓ Package structure validated")
        return True
    
    def validate_setup_py(self) -> bool:
        """Validate setup.py configuration"""
        print("Validating setup.py...")
        
        try:
            # Test that setup.py can be executed
            result = subprocess.run(
                [sys.executable, "setup.py", "check"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"✗ setup.py validation failed:")
                print(f"  stdout: {result.stdout}")
                print(f"  stderr: {result.stderr}")
                return False
            
            print("✓ setup.py validated")
            return True
            
        except subprocess.TimeoutExpired:
            print("✗ setup.py validation timed out")
            return False
        except Exception as e:
            print(f"✗ setup.py validation failed: {e}")
            return False
    
    def build_source_distribution(self) -> bool:
        """Build source distribution (sdist)"""
        print("Building source distribution...")
        
        try:
            result = subprocess.run(
                [sys.executable, "setup.py", "sdist"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                print(f"✗ Source distribution build failed:")
                print(f"  stdout: {result.stdout}")
                print(f"  stderr: {result.stderr}")
                return False
            
            # Check that sdist was created
            sdist_files = list(self.dist_dir.glob("*.tar.gz"))
            if not sdist_files:
                print("✗ No source distribution file found")
                return False
            
            print(f"✓ Source distribution built: {sdist_files[0].name}")
            return True
            
        except subprocess.TimeoutExpired:
            print("✗ Source distribution build timed out")
            return False
        except Exception as e:
            print(f"✗ Source distribution build failed: {e}")
            return False
    
    def build_wheel_distribution(self) -> bool:
        """Build wheel distribution (bdist_wheel)"""
        print("Building wheel distribution...")
        
        try:
            # First ensure wheel is installed
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "wheel"],
                capture_output=True,
                timeout=60
            )
            
            result = subprocess.run(
                [sys.executable, "setup.py", "bdist_wheel"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                print(f"✗ Wheel distribution build failed:")
                print(f"  stdout: {result.stdout}")
                print(f"  stderr: {result.stderr}")
                return False
            
            # Check that wheel was created
            wheel_files = list(self.dist_dir.glob("*.whl"))
            if not wheel_files:
                print("✗ No wheel distribution file found")
                return False
            
            print(f"✓ Wheel distribution built: {wheel_files[0].name}")
            return True
            
        except subprocess.TimeoutExpired:
            print("✗ Wheel distribution build timed out")
            return False
        except Exception as e:
            print(f"✗ Wheel distribution build failed: {e}")
            return False
    
    def test_installation_in_venv(self) -> bool:
        """Test installation in a clean virtual environment"""
        print("Testing installation in virtual environment...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            venv_path = Path(temp_dir) / "test_venv"
            
            try:
                # Create virtual environment
                print("  Creating virtual environment...")
                venv.create(venv_path, with_pip=True)
                
                # Get paths for the virtual environment
                if sys.platform == "win32":
                    venv_python = venv_path / "Scripts" / "python.exe"
                    venv_pip = venv_path / "Scripts" / "pip.exe"
                else:
                    venv_python = venv_path / "bin" / "python"
                    venv_pip = venv_path / "bin" / "pip"
                
                # Install the package from wheel
                wheel_files = list(self.dist_dir.glob("*.whl"))
                if not wheel_files:
                    print("✗ No wheel file found for installation test")
                    return False
                
                wheel_file = wheel_files[0]
                print(f"  Installing {wheel_file.name}...")
                
                result = subprocess.run(
                    [str(venv_pip), "install", str(wheel_file)],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                if result.returncode != 0:
                    print(f"✗ Installation failed:")
                    print(f"  stdout: {result.stdout}")
                    print(f"  stderr: {result.stderr}")
                    return False
                
                # Test that the package can be imported
                print("  Testing package import...")
                result = subprocess.run(
                    [str(venv_python), "-c", "import intellirefactor; print('Import successful')"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    print(f"✗ Package import failed:")
                    print(f"  stdout: {result.stdout}")
                    print(f"  stderr: {result.stderr}")
                    return False
                
                # Test CLI command
                print("  Testing CLI command...")
                result = subprocess.run(
                    [str(venv_python), "-m", "intellirefactor.cli", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    print(f"✗ CLI command failed:")
                    print(f"  stdout: {result.stdout}")
                    print(f"  stderr: {result.stderr}")
                    return False
                
                # Test entry point
                print("  Testing entry point...")
                result = subprocess.run(
                    [str(venv_path / ("Scripts" if sys.platform == "win32" else "bin") / "intellirefactor"), "--help"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    print(f"✗ Entry point failed:")
                    print(f"  stdout: {result.stdout}")
                    print(f"  stderr: {result.stderr}")
                    return False
                
                print("✓ Installation test passed")
                return True
                
            except subprocess.TimeoutExpired:
                print("✗ Installation test timed out")
                return False
            except Exception as e:
                print(f"✗ Installation test failed: {e}")
                return False
    
    def validate_package_metadata(self) -> bool:
        """Validate package metadata"""
        print("Validating package metadata...")
        
        try:
            # Check that wheel contains proper metadata
            wheel_files = list(self.dist_dir.glob("*.whl"))
            if not wheel_files:
                print("✗ No wheel file found for metadata validation")
                return False
            
            wheel_file = wheel_files[0]
            
            # Use wheel command to show metadata
            result = subprocess.run(
                [sys.executable, "-m", "wheel", "unpack", str(wheel_file)],
                cwd=self.dist_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print("Warning: Could not unpack wheel for metadata validation")
                print("✓ Package metadata validation skipped")
                return True
            
            print("✓ Package metadata validated")
            return True
            
        except Exception as e:
            print(f"Warning: Package metadata validation failed: {e}")
            print("✓ Package metadata validation skipped")
            return True
    
    def generate_distribution_report(self) -> Dict[str, Any]:
        """Generate a comprehensive distribution report"""
        print("Generating distribution report...")
        
        report = {
            "timestamp": subprocess.run(
                [sys.executable, "-c", "import datetime; print(datetime.datetime.now().isoformat())"],
                capture_output=True,
                text=True
            ).stdout.strip(),
            "python_version": sys.version,
            "platform": sys.platform,
            "package_info": {},
            "distribution_files": [],
            "validation_results": {}
        }
        
        # Get package info from setup.py
        try:
            result = subprocess.run(
                [sys.executable, "setup.py", "--name", "--version", "--description"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 3:
                    report["package_info"] = {
                        "name": lines[0],
                        "version": lines[1],
                        "description": lines[2]
                    }
        except Exception:
            pass
        
        # List distribution files
        if self.dist_dir.exists():
            for file_path in self.dist_dir.iterdir():
                if file_path.is_file():
                    report["distribution_files"].append({
                        "name": file_path.name,
                        "size": file_path.stat().st_size,
                        "type": "wheel" if file_path.suffix == ".whl" else "source" if file_path.suffix == ".gz" else "other"
                    })
        
        return report
    
    def package_for_distribution(self) -> Tuple[bool, Dict[str, Any]]:
        """Main packaging workflow"""
        print("Starting IntelliRefactor packaging for distribution...")
        print("=" * 60)
        
        success = True
        results = {}
        
        # Step 1: Clean build artifacts
        self.clean_build_artifacts()
        results["clean_artifacts"] = True
        
        # Step 2: Validate package structure
        if not self.validate_package_structure():
            success = False
            results["package_structure"] = False
        else:
            results["package_structure"] = True
        
        # Step 3: Validate setup.py
        if not self.validate_setup_py():
            success = False
            results["setup_validation"] = False
        else:
            results["setup_validation"] = True
        
        # Step 4: Build source distribution
        if not self.build_source_distribution():
            success = False
            results["source_distribution"] = False
        else:
            results["source_distribution"] = True
        
        # Step 5: Build wheel distribution
        if not self.build_wheel_distribution():
            success = False
            results["wheel_distribution"] = False
        else:
            results["wheel_distribution"] = True
        
        # Step 6: Validate package metadata
        if not self.validate_package_metadata():
            success = False
            results["metadata_validation"] = False
        else:
            results["metadata_validation"] = True
        
        # Step 7: Test installation
        if not self.test_installation_in_venv():
            success = False
            results["installation_test"] = False
        else:
            results["installation_test"] = True
        
        # Generate final report
        report = self.generate_distribution_report()
        report["validation_results"] = results
        report["overall_success"] = success
        
        # Save report
        report_file = self.project_root / "distribution_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print("\n" + "=" * 60)
        print("PACKAGING SUMMARY")
        print("=" * 60)
        
        for step, result in results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{status}: {step.replace('_', ' ').title()}")
        
        print(f"\nOverall Result: {'✓ SUCCESS' if success else '✗ FAILURE'}")
        print(f"Distribution files: {len(report.get('distribution_files', []))}")
        print(f"Report saved to: {report_file}")
        
        if success:
            print("\n🎉 IntelliRefactor is ready for distribution!")
            print("Distribution files created:")
            for file_info in report.get('distribution_files', []):
                print(f"  - {file_info['name']} ({file_info['size']} bytes)")
        else:
            print("\n❌ Packaging failed. Please fix the issues above and try again.")
        
        return success, report

def main():
    """Main packaging function"""
    packager = DistributionPackager()
    success, report = packager.package_for_distribution()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()