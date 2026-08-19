"""Unit tests for multi-vector OS and AI tool discovery."""

import unittest
from src.core.os_detector import OSDetector
from src.core.config_loader import ConfigLoader


class TestOSDetector(unittest.TestCase):
    def test_os_type_validity(self):
        """OS type must be one of windows, linux, or macos."""
        os_type = OSDetector.get_os_type()
        self.assertIn(os_type, ["windows", "linux", "macos"])

    def test_path_expansion(self):
        """Path expansion should properly resolve tildes and environment variables."""
        expanded_home = OSDetector.expand_path("~")
        self.assertTrue(expanded_home.exists())

    def test_running_processes_discovery(self):
        """Process enumeration should return a set of strings without crashing."""
        procs = OSDetector.get_running_processes()
        self.assertIsInstance(procs, set)

    def test_ide_extensions_discovery(self):
        """IDE extension discovery should return a set of extension IDs."""
        exts = OSDetector.get_installed_ide_extensions()
        self.assertIsInstance(exts, set)

    def test_tool_detection_pipeline(self):
        """Detection pipeline should evaluate policies without throwing exceptions."""
        loader = ConfigLoader()
        policies = loader.discover_policies()
        for p in policies:
            installed = OSDetector.is_tool_installed(p)
            self.assertIsInstance(installed, bool)


if __name__ == "__main__":
    unittest.main()
